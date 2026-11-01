//! bigtool — reader/extractor for EA "EB" `.big` archives, plus PS4 GNF texture conversion.

mod big;
mod census;
mod chunkzip;
mod pack;
mod textures;

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand};
use indicatif::{HumanBytes, ProgressBar, ProgressDrawTarget, ProgressStyle};

use big::Archive;

#[derive(Parser)]
#[command(
    name = "bigtool",
    version,
    about = "bigtool — EA EB .big archives (NBA LIVE 19 / Ignite) and PS4 GNF textures",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Header and structural diagnostics
    Info {
        archive: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// File index
    List {
        archive: PathBuf,
        /// only entries whose path contains this substring
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
        /// cap the number of rows
        #[arg(short = 'n', long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    /// Validate pointers, payloads, and type-vs-extension
    Check {
        archive: PathBuf,
        /// how many entries to sample for the content checks
        #[arg(long, default_value_t = 4000)]
        sample: usize,
    },
    /// Classify payload types inside an archive
    Census {
        archive: PathBuf,
        /// only inspect the first N entries
        #[arg(long, default_value_t = 0)]
        sample: usize,
    },
    /// Extract files
    Extract {
        archive: PathBuf,
        #[arg(short = 'o', long)]
        out: PathBuf,
        #[arg(short = 'n', long)]
        limit: Option<usize>,
        /// drop the directory tree, write bare filenames
        #[arg(long)]
        flat: bool,
        /// unwrap chunkzip payloads
        #[arg(long)]
        decompress: bool,
        #[arg(long)]
        skip_existing: bool,
        #[arg(long)]
        no_progress: bool,
    },
    /// Convert GNF textures to DDS
    Textures {
        /// a .gnf file to convert (omit when using --batch)
        archive: Option<PathBuf>,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// SRC_DIR OUT_DIR — convert every .gnf under a directory
        #[arg(long, num_args = 2, value_names = ["SRC_DIR", "OUT_DIR"])]
        batch: Option<Vec<PathBuf>>,
        /// re-convert files whose output already exists
        #[arg(long)]
        force: bool,
        #[arg(long)]
        no_progress: bool,
    },
    /// Pack a directory tree into a new .big archive
    Pack {
        /// directory containing the files to pack
        source: PathBuf,
        #[arg(short = 'o', long)]
        out: PathBuf,
        /// copy header fields and per-entry metadata from this archive
        #[arg(long)]
        template: Option<PathBuf>,
    },
    /// Extract every *.big in a directory
    Batch {
        directory: PathBuf,
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        #[arg(long)]
        decompress: bool,
        #[arg(long)]
        skip_existing: bool,
        #[arg(long)]
        no_progress: bool,
    },
}

fn human(n: u64) -> String {
    HumanBytes(n).to_string()
}

fn fmt_eta(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--".to_string();
    }
    let s = secs as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

fn open(path: &Path) -> Option<Archive> {
    match Archive::open(path) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Info { archive, json } => cmd_info(&archive, json),
        Cmd::List {
            archive,
            filter,
            limit,
            json,
        } => cmd_list(&archive, filter.as_deref(), limit, json),
        Cmd::Check { archive, sample } => cmd_check(&archive, sample),
        Cmd::Census { archive, sample } => cmd_census(&archive, sample),
        Cmd::Extract {
            archive,
            out,
            limit,
            flat,
            decompress,
            skip_existing,
            no_progress,
        } => cmd_extract(&archive, &out, limit, flat, decompress, skip_existing, no_progress),
        Cmd::Textures {
            archive,
            out,
            batch,
            force,
            no_progress,
        } => cmd_textures(archive.as_deref(), out.as_deref(), batch, force, no_progress),
        Cmd::Pack {
            source,
            out,
            template,
        } => cmd_pack(&source, &out, template.as_deref()),
        Cmd::Batch {
            directory,
            out,
            decompress,
            skip_existing,
            no_progress,
        } => cmd_batch(&directory, out.as_deref(), decompress, skip_existing, no_progress),
    };
    std::process::exit(code);
}

fn cmd_info(path: &Path, json: bool) -> i32 {
    let Some(arc) = open(path) else { return 2 };
    let d = arc.diagnostics();

    if json {
        println!(
            "{{\"archive\":\"{}\",\"file_size\":{},\"version\":{},\"file_count\":{},\
\"trie_leaves\":{},\"leaf_count_matches\":{},\"usable_entries\":{},\"out_of_bounds\":{},\
\"sum_of_sizes\":{},\"union_of_ranges\":{},\"union_coverage\":{:.6},\"shared_bytes\":{},\
\"shared_ratio\":{:.6}}}",
            d.archive,
            d.file_size,
            arc.version,
            d.file_count,
            d.trie_leaves,
            d.leaf_count_matches,
            d.entries_usable,
            d.out_of_bounds,
            d.sum_of_sizes,
            d.union_of_ranges,
            d.union_coverage,
            d.shared_bytes,
            d.shared_ratio
        );
        return 0;
    }

    let ratio = if arc.real_size > 0 {
        d.sum_of_sizes as f64 / arc.real_size as f64
    } else {
        0.0
    };

    println!("archive          : {}", path.display());
    println!(
        "file size        : {} ({} bytes)",
        human(d.file_size),
        d.file_size
    );
    println!("version          : {}", arc.version);
    println!("flags            : 0x{:08x}", arc.flags);
    println!(
        "header length    : {} bytes{}",
        d.header_file_length,
        if d.header_length_wrapped {
            "  (wrapped: 32-bit field)"
        } else {
            ""
        }
    );
    println!(
        "entries          : {:<8} (trie leaves {}, match={})",
        d.file_count, d.trie_leaves, d.leaf_count_matches
    );
    println!(
        "entry table      : stride {} bytes, address shift {}",
        arc.stride, arc.addr_shift
    );
    println!(
        "usable entries   : {:<8} (out of bounds: {})",
        d.entries_usable, d.out_of_bounds
    );
    println!(
        "sum of sizes     : {}  ({:.4}x archive -- >1.0 means content dedup)",
        human(d.sum_of_sizes),
        ratio
    );
    println!(
        "union of ranges  : {}  ({:.4} coverage)",
        human(d.union_of_ranges),
        d.union_coverage
    );
    println!(
        "shared bytes     : {}  ({:.4} of archive)",
        human(d.shared_bytes),
        d.shared_ratio
    );
    0
}

fn cmd_list(path: &Path, filter: Option<&str>, limit: Option<usize>, json: bool) -> i32 {
    let Some(arc) = open(path) else { return 2 };

    let mut rows: Vec<_> = arc
        .records()
        .into_iter()
        .filter(|r| match filter {
            Some(f) => r.path.to_ascii_lowercase().contains(&f.to_ascii_lowercase()),
            None => true,
        })
        .collect();
    if let Some(limit) = limit {
        rows.truncate(limit);
    }

    if rows.is_empty() {
        println!("no entries matched");
        return 0;
    }

    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|r| {
                format!(
                    "{{\"idx\":{},\"path\":\"{}\",\"address\":{},\"size\":{}}}",
                    r.position,
                    r.path.replace('\\', "\\\\").replace('"', "\\\""),
                    r.address
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "null".into()),
                    r.size.map(|s| s.to_string()).unwrap_or_else(|| "null".into())
                )
            })
            .collect();
        println!("[{}]", items.join(","));
        return 0;
    }

    let width = rows.iter().map(|r| r.path.len()).max().unwrap_or(20).clamp(20, 100);

    for r in &rows {
        match (r.address, r.size) {
            (Some(addr), Some(size)) => println!(
                "  {:<width$}  idx={:<6}  addr=0x{:09x}  {}",
                r.path,
                r.position,
                addr,
                human(size),
                width = width
            ),
            _ => println!(
                "  {:<width$}  idx={:<6}  UNRESOLVED {}",
                r.path,
                r.position,
                r.error.clone().unwrap_or_default(),
                width = width
            ),
        }
    }
    println!("\n{} entries", rows.len());
    0
}

fn cmd_check(path: &Path, sample: usize) -> i32 {
    let Some(arc) = open(path) else { return 2 };
    let d = arc.diagnostics();

    println!("archive          : {}", path.display());
    println!(
        "file size        : {} ({} bytes)",
        human(d.file_size),
        d.file_size
    );
    println!(
        "entries          : {:<8} (trie leaves {}, match={})",
        d.file_count, d.trie_leaves, d.leaf_count_matches
    );
    println!(
        "usable entries   : {:<8} (out of bounds: {})",
        d.entries_usable, d.out_of_bounds
    );

    let mc = arc.magic_check(sample);
    println!(
        "content check    : {} checked, {} ok, {} unrecognized",
        mc.checked, mc.ok, mc.bad
    );
    for (name, addr, head) in &mc.bad_samples {
        println!("   unrecognized: {} @ 0x{:x} head={}", name, addr, head);
    }

    let ext = arc.extension_agreement(sample);
    if !ext.is_empty() {
        println!("type vs extension:");
        for (e, ok, total, rate) in ext {
            let flag = if ok == total { "" } else { "  <-- MISMATCH" };
            println!(
                "   {:<7} {}/{} agree ({:.0}%){}",
                e,
                ok,
                total,
                rate * 100.0,
                flag
            );
        }
    }

    if d.out_of_bounds > 0 || !d.leaf_count_matches {
        return 1;
    }
    0
}

fn cmd_census(path: &Path, sample: usize) -> i32 {
    let Some(arc) = open(path) else { return 2 };
    let c = census::census(&arc, sample);

    println!("{}", "=".repeat(78));
    println!(
        "{}  entries={}  sampled={}",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        c.entries,
        c.sampled
    );
    if c.sampled == 0 {
        return 0;
    }
    for (kind, n, exts) in &c.kinds {
        let pct = 100.0 * *n as f64 / c.sampled as f64;
        let ext_str = exts
            .iter()
            .map(|(e, cnt)| format!("{e}:{cnt}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {:<16} {:>6}  ({:5.1}%)   {}", kind, n, pct, ext_str);
    }
    if !c.unknown_heads.is_empty() {
        println!("  top unknown heads:");
        for (h, cnt) in &c.unknown_heads {
            println!("     {}  x{}", h, cnt);
        }
    }
    0
}

fn bar_for(len: u64, no_progress: bool, label: &str) -> Option<ProgressBar> {
    if no_progress {
        return None;
    }
    let pb = ProgressBar::new(len);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    let style = ProgressStyle::with_template(
        "{spinner} {bar:28.cyan/blue} {percent:>3}%  {bytes}/{total_bytes}  {msg}",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar());
    pb.set_style(style);
    pb.set_message(label.to_string());
    Some(pb)
}

fn cmd_extract(
    path: &Path,
    out: &Path,
    limit: Option<usize>,
    flat: bool,
    decompress: bool,
    skip_existing: bool,
    no_progress: bool,
) -> i32 {
    let Some(arc) = open(path) else { return 2 };

    let (planned, total_bytes) = {
        let mut r = arc.records();
        if let Some(l) = limit {
            r.truncate(l);
        }
        let bytes: u64 = r
            .iter()
            .filter(|x| x.address.is_some())
            .map(|x| x.size.unwrap_or(0))
            .sum();
        (r.len(), bytes)
    };

    let pb = bar_for(total_bytes, no_progress, "extracting");
    let start = Instant::now();

    let mut tick = |done: usize, total: usize, bytes: u64, _tb: u64| {
        if let Some(pb) = pb.as_ref() {
            pb.set_position(bytes);
            let elapsed = start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { bytes as f64 / elapsed } else { 0.0 };
            let eta = if rate > 0.0 {
                (total_bytes.saturating_sub(bytes)) as f64 / rate
            } else {
                f64::INFINITY
            };
            pb.set_message(format!(
                "{done}/{total} files  {}/s  eta {}",
                human(rate as u64),
                fmt_eta(eta)
            ));
        }
    };

    let rep = arc.extract(
        out,
        limit,
        flat,
        decompress,
        skip_existing,
        Some(&mut tick as &mut dyn FnMut(usize, usize, u64, u64)),
    );

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    println!("output           : {}", out.display());
    println!(
        "extracted        : {} written, {} skipped, {} failed",
        rep.written, rep.skipped, rep.failed
    );
    if decompress {
        println!(
            "chunkzip         : {} decoded, {} left as container",
            rep.decoded_chunkzip, rep.chunkzip_left_wrapped
        );
        for (name, why) in &rep.decode_errors {
            println!("   not decoded: {} ({})", name, why);
        }
    }
    for (name, why) in &rep.errors {
        println!("   error: {} ({})", name, why);
    }
    println!(
        "elapsed          : {:.1}s ({} planned)",
        start.elapsed().as_secs_f64(),
        planned
    );

    if rep.failed == 0 {
        0
    } else {
        1
    }
}

fn cmd_textures(
    src: Option<&Path>,
    out: Option<&Path>,
    batch: Option<Vec<PathBuf>>,
    force: bool,
    no_progress: bool,
) -> i32 {
    if let Some(dirs) = batch {
        if dirs.len() != 2 {
            eprintln!("error: --batch needs SRC_DIR OUT_DIR");
            return 2;
        }
        let (src_dir, out_dir) = (&dirs[0], &dirs[1]);
        let pb = bar_for(0, no_progress, "converting");
        let start = Instant::now();
        let mut tick = |done: usize, total: usize| {
            if let Some(pb) = pb.as_ref() {
                if pb.length() != Some(total as u64) {
                    pb.set_length(total as u64);
                }
                pb.set_position(done as u64);
            }
        };
        let rep = textures::batch(
            src_dir,
            out_dir,
            !force,
            Some(&mut tick as &mut dyn FnMut(usize, usize)),
        );
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
        let total = rep.converted + rep.unsupported + rep.failed + rep.already_present;
        println!(
            "converted {} of {}  (skipped {} already present, {} unsupported, {} failed) in {:.1}s",
            rep.converted,
            total,
            rep.already_present,
            rep.unsupported,
            rep.failed,
            start.elapsed().as_secs_f64()
        );
        let mut reasons = rep.reasons;
        reasons.sort_by(|a, b| b.1.cmp(&a.1));
        for (reason, count) in reasons.iter().take(8) {
            println!("   {:>4} x {}", count, reason);
        }
        return if rep.failed == 0 { 0 } else { 1 };
    }

    let Some(src) = src else {
        eprintln!("error: give a .gnf file, or --batch SRC_DIR OUT_DIR");
        return 2;
    };

    let data = match std::fs::read(src) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}: {}", src.display(), e);
            return 2;
        }
    };

    let info = match textures::parse(&data) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };
    println!(
        "GNF: {}x{}  format=0x{:x} mips={}  payload={}  file={}",
        info.width, info.height, info.format, info.mips, info.data_size, info.file_size
    );

    let (dds, meta) = match textures::to_dds(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };

    let dst = match out {
        Some(o) => o.to_path_buf(),
        None => src.with_extension("dds"),
    };
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&dst, &dds) {
        eprintln!("error: cannot write {}: {}", dst.display(), e);
        return 1;
    }
    println!(
        "wrote {} {} bytes  ({} {}x{}, {} mips, payload {} of {} expected)",
        dst.display(),
        dds.len(),
        meta.format,
        meta.width,
        meta.height,
        meta.mips,
        meta.payload,
        meta.expected
    );
    0
}

fn cmd_pack(src: &Path, out: &Path, template: Option<&Path>) -> i32 {
    let start = Instant::now();
    match pack::pack(src, out, template) {
        Ok(rep) => {
            println!("output           : {}", out.display());
            println!("files            : {}", rep.files);
            println!("data bytes       : {}", human(rep.data_bytes));
            println!("archive size     : {}", human(rep.out_bytes));
            println!("trie nodes       : {}", rep.trie_nodes);
            println!(
                "template metadata: {}",
                if rep.used_template { "used" } else { "none" }
            );
            println!("elapsed          : {:.1}s", start.elapsed().as_secs_f64());
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_batch(
    dir: &Path,
    out: Option<&Path>,
    decompress: bool,
    skip_existing: bool,
    no_progress: bool,
) -> i32 {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {}: {}", dir.display(), e);
            return 2;
        }
    };
    let mut archives: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e.to_string_lossy().eq_ignore_ascii_case("big"))
                .unwrap_or(false)
        })
        .collect();
    archives.sort();

    if archives.is_empty() {
        eprintln!("error: no .big archives in {}", dir.display());
        return 2;
    }

    let mut failures = 0;
    for archive in archives {
        let stem = archive
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "out".to_string());
        let target = match out {
            Some(root) => root.join(&stem),
            None => dir.join(&stem),
        };
        println!("\n=== {} -> {} ===", archive.display(), target.display());
        let code = cmd_extract(
            &archive,
            &target,
            None,
            false,
            decompress,
            skip_existing,
            no_progress,
        );
        if code != 0 {
            failures += 1;
        }
    }

    if failures == 0 {
        0
    } else {
        1
    }
}
