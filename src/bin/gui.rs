//! bigtool GUI — browse EA `.big` archives, extract them, convert GNF textures, and pack folders.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use bigtool::big::{Archive, Record};
use bigtool::{pack as packlib, textures};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

const ACCENT: egui::Color32 = egui::Color32::from_rgb(94, 169, 255);

enum Msg {
    Progress { done: usize, total: usize, bytes: u64, total_bytes: u64, note: String },
    Done(String),
}

struct Job {
    rx: Receiver<Msg>,
    label: String,
    done: usize,
    total: usize,
    bytes: u64,
    total_bytes: u64,
    note: String,
    started: std::time::Instant,
}

struct Loaded {
    path: PathBuf,
    entries: Vec<Record>,
    summary: String,
}

pub struct App {
    archive: Option<Loaded>,
    filter: String,
    selected: Option<usize>,
    out_dir: Option<PathBuf>,
    decompress: bool,
    recurse: bool,
    skip_existing: bool,
    tab: Tab,
    job: Option<Job>,
    log: Vec<String>,
    tex_src: Option<PathBuf>,
    tex_out: Option<PathBuf>,
    pack_src: Option<PathBuf>,
    pack_out: Option<PathBuf>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Archive,
    Textures,
    Pack,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
        visuals.hyperlink_color = ACCENT;
        cc.egui_ctx.set_visuals(visuals);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        cc.egui_ctx.set_style(style);

        App {
            archive: None,
            filter: String::new(),
            selected: None,
            out_dir: None,
            decompress: true,
            recurse: true,
            skip_existing: false,
            tab: Tab::Archive,
            job: None,
            log: Vec::new(),
            tex_src: None,
            tex_out: None,
            pack_src: None,
            pack_out: None,
        }
    }

    fn log_line(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    fn open_archive(&mut self, path: PathBuf) {
        match Archive::open(&path) {
            Ok(arc) => {
                let d = arc.diagnostics();
                let entries = arc.records();
                let total_size: u64 = entries.iter().filter_map(|r| r.size).sum();
                let summary = format!(
                    "{} entries  ·  {}  ·  {} items on disk  ·  trie leaves {} {}  ·  out of bounds {}",
                    d.file_count,
                    human(d.file_size),
                    human(total_size),
                    d.trie_leaves,
                    if d.leaf_count_matches { "(match)" } else { "(MISMATCH)" },
                    d.out_of_bounds
                );
                if self.out_dir.is_none() {
                    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                    if let Some(parent) = path.parent() {
                        self.out_dir = Some(parent.join(format!("{stem}_extracted")));
                    }
                }
                self.log_line(format!("opened {} — {}", path.display(), summary));
                self.archive = Some(Loaded { path, entries, summary });
                self.selected = None;
            }
            Err(e) => self.log_line(format!("cannot open {}: {e}", path.display())),
        }
    }

    fn visible_rows_of(a: &Loaded, filter: &str) -> Vec<usize> {
        if filter.trim().is_empty() {
            return (0..a.entries.len()).collect();
        }
        let needle = filter.to_lowercase();
        a.entries
            .iter()
            .enumerate()
            .filter(|(_, r)| r.path.to_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    }

    fn export_selected(&mut self, as_dds: bool) {
        let Some(arc) = &self.archive else { return };
        let Some(idx) = self.selected else { return };
        let path = arc.path.clone();
        let entry = arc.entries[idx].path.clone();
        let base = std::path::Path::new(&entry)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "entry.bin".into());
        let decompress = self.decompress;

        let arc = match Archive::open(&path) {
            Ok(a) => a,
            Err(e) => {
                self.log_line(format!("cannot reopen archive: {e}"));
                return;
            }
        };
        let bytes = match arc.entry_bytes(idx, decompress) {
            Ok(b) => b,
            Err(e) => {
                self.log_line(format!("{entry}: {e}"));
                return;
            }
        };

        let (mut bytes, mut name) = (bytes, base);
        if as_dds {
            match textures::to_dds(&bytes) {
                Ok((dds, meta)) => {
                    self.log_line(format!(
                        "{}: {} x {} {:?}, {} mips",
                        entry, meta.width, meta.height, meta.format, meta.mips
                    ));
                    bytes = dds;
                    name = name.trim_end_matches(".gnf").to_string() + ".dds";
                }
                Err(e) => {
                    self.log_line(format!("{entry}: {e}"));
                    return;
                }
            }
        }

        if let Some(out) = rfd::FileDialog::new().set_file_name(&name).save_file() {
            match std::fs::write(&out, &bytes) {
                Ok(()) => self.log_line(format!("wrote {} ({})", out.display(), human(bytes.len() as u64))),
                Err(e) => self.log_line(format!("cannot write {}: {e}", out.display())),
            }
        }
    }

    fn start_extract(&mut self, only_selected: bool) {
        let Some(a) = &self.archive else { return };
        let Some(out) = self.out_dir.clone() else {
            self.log_line("choose an output folder first");
            return;
        };
        let (path, limit) = if only_selected {
            match self.selected {
                Some(i) => (a.path.clone(), Some(i + 1)),
                None => {
                    self.log_line("no entry selected");
                    return;
                }
            }
        } else {
            (a.path.clone(), None)
        };
        // extracting "up to index" would include everything before it; do a single-file pass instead
        let single = if only_selected { self.selected } else { None };
        let decompress = self.decompress;
        let recurse = self.recurse;
        let skip = self.skip_existing;

        let (tx, rx) = channel();
        let tx2: Sender<Msg> = tx.clone();
        thread::spawn(move || {
            let arc = match Archive::open(&path) {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx2.send(Msg::Done(format!("error: {e}")));
                    return;
                }
            };
            let mut progress = |done: usize, total: usize, bytes: u64, total_bytes: u64| {
                let _ = tx2.send(Msg::Progress {
                    done,
                    total,
                    bytes,
                    total_bytes,
                    note: String::new(),
                });
            };
            if let Some(idx) = single {
                // extract the archive but stop after the selected entry
                let rep = arc.extract(
                    &out, Some(idx + 1), false, decompress, skip, recurse, 0,
                    Some(&mut progress as &mut dyn FnMut(usize, usize, u64, u64)),
                );
                let _ = tx2.send(Msg::Done(format!(
                    "wrote {} file(s) (prefix up to entry {}), {} failed",
                    rep.written, idx, rep.failed
                )));
            } else {
                let rep = arc.extract(
                    &out, limit, false, decompress, skip, recurse, 0,
                    Some(&mut progress as &mut dyn FnMut(usize, usize, u64, u64)),
                );
                let _ = tx2.send(Msg::Done(format!(
                    "{} written, {} skipped, {} failed  ·  chunkzip {}  ·  chunkref {}  ·  nested {} archives / {} files",
                    rep.written, rep.skipped, rep.failed,
                    rep.decoded_chunkzip, rep.decoded_chunkref,
                    rep.nested_archives, rep.nested_files
                )));
            }
        });

        self.job = Some(Job {
            rx,
            label: if only_selected { "extracting entry".into() } else { "extracting archive".into() },
            done: 0,
            total: 0,
            bytes: 0,
            total_bytes: 0,
            note: String::new(),
            started: std::time::Instant::now(),
        });
    }

    fn start_textures(&mut self) {
        let (Some(src), Some(out)) = (self.tex_src.clone(), self.tex_out.clone()) else {
            self.log_line("choose a source folder and an output folder");
            return;
        };
        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut p = |done: usize, total: usize| {
                let _ = tx.send(Msg::Progress { done, total, bytes: 0, total_bytes: 0, note: String::new() });
            };
            let rep = textures::batch(&src, &out, true, Some(&mut p as &mut dyn FnMut(usize, usize)));
            let _ = tx.send(Msg::Done(format!(
                "converted {}  ·  {} already present  ·  {} unsupported  ·  {} failed",
                rep.converted, rep.already_present, rep.unsupported, rep.failed
            )));
        });
        self.job = Some(Job {
            rx,
            label: "converting textures".into(),
            done: 0,
            total: 0,
            bytes: 0,
            total_bytes: 0,
            note: String::new(),
            started: std::time::Instant::now(),
        });
    }

    fn start_pack(&mut self) {
        let (Some(src), Some(out)) = (self.pack_src.clone(), self.pack_out.clone()) else {
            self.log_line("choose a source folder and an output .big path");
            return;
        };
        let (tx, rx) = channel();
        thread::spawn(move || {
            match packlib::pack(&src, &out, None) {
                Ok(rep) => {
                    let _ = tx.send(Msg::Done(format!(
                        "packed {} files  ·  {} archive  ·  {} trie nodes",
                        rep.files,
                        human(rep.out_bytes),
                        rep.trie_nodes
                    )));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Done(format!("error: {e}")));
                }
            }
        });
        self.job = Some(Job {
            rx,
            label: "packing".into(),
            done: 0,
            total: 0,
            bytes: 0,
            total_bytes: 0,
            note: String::new(),
            started: std::time::Instant::now(),
        });
    }

    fn pump(&mut self) {
        let Some(job) = &mut self.job else { return };
        let mut finished = None;
        while let Ok(msg) = job.rx.try_recv() {
            match msg {
                Msg::Progress { done, total, bytes, total_bytes, note } => {
                    job.done = done;
                    job.total = total;
                    job.bytes = bytes;
                    job.total_bytes = total_bytes;
                    job.note = note;
                }
                Msg::Done(s) => finished = Some(s),
            }
        }
        if let Some(msg) = finished {
            let elapsed = job.started.elapsed().as_secs_f32();
            self.log_line(format!("{}  ({:.1}s)", msg, elapsed));
            self.job = None;
        }
    }

    fn ui_archive(&mut self, ui: &mut egui::Ui) {
        // taken out of `self` so the table can borrow it while the controls mutate other fields
        let Some(arc) = self.archive.take() else {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("No archive open");
                ui.label("Open a .big file, or drop one anywhere in this window.");
                ui.add_space(12.0);
                if ui.button("Open archive…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().add_filter("EA archive", &["big"]).pick_file() {
                        self.open_archive(p);
                    }
                }
            });
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(arc.path.file_name().unwrap_or_default().to_string_lossy()).strong());
            ui.label(egui::RichText::new(&arc.summary).weak());
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(240.0).hint_text("path contains…"));
            ui.separator();
            ui.checkbox(&mut self.decompress, "decompress chunkzip/chunkref");
            ui.checkbox(&mut self.recurse, "recurse into nested archives");
            ui.checkbox(&mut self.skip_existing, "skip existing");
        });

        let mut action: Option<bool> = None;
        let mut export: Option<bool> = None;
        ui.horizontal(|ui| {
            let out_label = self
                .out_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "choose output folder…".to_string());
            if ui.button("Output folder…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.out_dir = Some(p);
                }
            }
            ui.label(egui::RichText::new(out_label).weak());
            ui.separator();
            let busy = self.job.is_some();
            if ui.add_enabled(!busy, egui::Button::new("Extract all")).clicked() {
                action = Some(false);
            }
            if ui
                .add_enabled(!busy && self.selected.is_some(), egui::Button::new("Extract up to selection"))
                .clicked()
            {
                action = Some(true);
            }
            if ui
                .add_enabled(!busy && self.selected.is_some(), egui::Button::new("Export selected…"))
                .clicked()
            {
                action = Some(false);
                export = Some(false);
            }
            if ui
                .add_enabled(!busy && self.selected.is_some(), egui::Button::new("Export as DDS…"))
                .clicked()
            {
                action = Some(false);
                export = Some(true);
            }
        });

        ui.add_space(6.0);
        let rows = Self::visible_rows_of(&arc, &self.filter);
        let selected = self.selected;
        let mut clicked = None;
        let available = ui.available_height() - 8.0;

        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::remainder().at_least(280.0))
            .column(Column::exact(60.0))
            .column(Column::exact(110.0))
            .column(Column::exact(90.0))
            .max_scroll_height(available.max(120.0))
            .header(22.0, |mut header| {
                header.col(|ui| { ui.strong("Path"); });
                header.col(|ui| { ui.strong("Idx"); });
                header.col(|ui| { ui.strong("Address"); });
                header.col(|ui| { ui.strong("Size"); });
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let i = rows[row.index()];
                    let r = &arc.entries[i];
                    row.set_selected(Some(i) == selected);
                    row.col(|ui| { ui.label(&r.path); });
                    row.col(|ui| { ui.monospace(r.position.to_string()); });
                    row.col(|ui| match r.address {
                        Some(addr) => {
                            ui.monospace(format!("0x{addr:09x}"));
                        }
                        None => {
                            ui.colored_label(egui::Color32::LIGHT_RED, "unresolved");
                        }
                    });
                    row.col(|ui| {
                        if let Some(s) = r.size {
                            ui.monospace(human(s));
                        }
                    });
                    if row.response().clicked() {
                        clicked = Some(i);
                    }
                });
            });

        if let Some(i) = clicked {
            self.selected = Some(i);
        }
        self.archive = Some(arc);
        if let Some(as_dds) = export {
            self.export_selected(as_dds);
        } else if let Some(only_selected) = action {
            self.start_extract(only_selected);
        }
    }

    fn ui_textures(&mut self, ui: &mut egui::Ui) {
        ui.heading("GNF to DDS");
        ui.label("Converts every .gnf under a folder, mirroring subdirectories. Existing outputs are skipped.");
        ui.add_space(8.0);
        self.path_row(ui, "Source folder", Field::TexSrc);
        self.path_row(ui, "Output folder", Field::TexOut);
        ui.add_space(8.0);
        let busy = self.job.is_some();
        if ui.add_enabled(!busy, egui::Button::new("Convert")).clicked() {
            self.start_textures();
        }
    }

    fn ui_pack(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pack a folder into .big");
        ui.label("Writes the header, file-info table, name table, directory trie and 4 KiB-aligned data.");
        ui.add_space(8.0);
        self.path_row(ui, "Source folder", Field::PackSrc);
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Output .big…").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("EA archive", &["big"]).save_file() {
                    self.pack_out = Some(p);
                }
            }
            let label = self.pack_out.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "not set".into());
            ui.label(egui::RichText::new(label).weak());
        });
        ui.add_space(8.0);
        let busy = self.job.is_some();
        if ui.add_enabled(!busy, egui::Button::new("Pack")).clicked() {
            self.start_pack();
        }
    }

    fn path_row(&mut self, ui: &mut egui::Ui, label: &str, field: Field) {
        ui.horizontal(|ui| {
            if ui.button(format!("{label}…")).clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    match field {
                        Field::TexSrc => self.tex_src = Some(p),
                        Field::TexOut => self.tex_out = Some(p),
                        Field::PackSrc => self.pack_src = Some(p),
                    }
                }
            }
            let current = match field {
                Field::TexSrc => self.tex_src.clone(),
                Field::TexOut => self.tex_out.clone(),
                Field::PackSrc => self.pack_src.clone(),
            };
            let text = current.map(|p| p.display().to_string()).unwrap_or_else(|| "not set".into());
            ui.label(egui::RichText::new(text).weak());
        });
    }

    fn ui_progress(&mut self, ui: &mut egui::Ui) {
        let Some(job) = &self.job else {
            if self.log.is_empty() {
                ui.label(egui::RichText::new("Ready.").weak());
            } else {
                egui::ScrollArea::vertical().stick_to_bottom(true).max_height(110.0).show(ui, |ui| {
                    for line in &self.log {
                        ui.label(egui::RichText::new(line).monospace().size(12.0).weak());
                    }
                });
            }
            return;
        };

        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(egui::RichText::new(&job.label).strong());
        });
        let frac = if job.total > 0 { job.done as f32 / job.total as f32 } else { 0.0 };
        let text = if job.total > 0 {
            format!("{}/{}", job.done, job.total)
        } else if job.total_bytes > 0 {
            format!("{} / {}", human(job.bytes), human(job.total_bytes))
        } else {
            "working…".to_string()
        };
        ui.add(
            egui::ProgressBar::new(frac)
                .desired_width(f32::INFINITY)
                .animate(true)
                .text(text),
        );
        let elapsed = job.started.elapsed().as_secs_f32();
        ui.label(egui::RichText::new(format!("{elapsed:.1}s elapsed")).weak());
    }
}

enum Field {
    TexSrc,
    TexOut,
    PackSrc,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.theme() != egui::Theme::Dark {
            let mut visuals = egui::Visuals::dark();
            visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
            visuals.hyperlink_color = ACCENT;
            ctx.set_visuals(visuals);
            ctx.set_theme(egui::Theme::Dark);
        }
        self.pump();
        if self.job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        // drag & drop
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect()
        });
        if let Some(p) = dropped.into_iter().next() {
            if p.extension().map(|e| e.eq_ignore_ascii_case("big")).unwrap_or(false)
                || p.extension().map(|e| e.eq_ignore_ascii_case("elf")).unwrap_or(false)
            {
                self.open_archive(p);
            } else if p.is_dir() {
                self.tex_src = Some(p.clone());
                self.pack_src = Some(p);
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("bigtool");
                ui.label(egui::RichText::new(concat!("v", env!("CARGO_PKG_VERSION"))).weak());
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Archive, "Archive");
                ui.selectable_value(&mut self.tab, Tab::Textures, "Textures");
                ui.selectable_value(&mut self.tab, Tab::Pack, "Pack");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Open .big…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("EA archive", &["big"]).pick_file() {
                            self.open_archive(p);
                        }
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("bottom").resizable(true).min_height(90.0).show(ctx, |ui| {
            ui.add_space(4.0);
            self.ui_progress(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Archive => self.ui_archive(ui),
            Tab::Textures => self.ui_textures(ui),
            Tab::Pack => self.ui_pack(ui),
        });
    }
}

fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn main() -> eframe::Result<()> {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("bigtool-gui {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let startup: Option<PathBuf> = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .filter(|p| p.is_file());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([820.0, 520.0])
            .with_title("bigtool"),
        ..Default::default()
    };
    eframe::run_native(
        "bigtool",
        options,
        Box::new(move |cc| {
            let mut app = App::new(cc);
            if let Some(p) = startup.clone() {
                app.open_archive(p);
            }
            Ok(Box::new(app))
        }),
    )
}
