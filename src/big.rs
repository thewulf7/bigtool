//! Reader/extractor for EA "EB" `.big` archives v3 (NBA LIVE 19 / Ignite engine).
//!
//! Reverse-engineered from `eboot.elf` via Ghidra; see the project's `big-archive-format.md` for
//! the full derivation and the Ghidra addresses.
//!
//! ## The indexing rule
//!
//! The file-info table is **parallel to the flat name table** — position *i* in the name table
//! describes entry *i*. The directory trie supplies each file's *path*; its leaf field 3 is a
//! hash-like identifier, NOT an index into the file-info table. Using field 3 as an index produces
//! plausible-looking but wrong data for a large share of entries. The error is invisible to lenient
//! content checks and only shows up when comparing payload type against file extension.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::chunkzip;

pub const ENTRY_TABLE_OFFSET: usize = 0x30;
pub const STRIDE_LONG: usize = 0x14;
pub const STRIDE_SHORT: usize = 0x10;

pub const CHUNK_MAGICS: &[&[u8]] = &[
    b"chunkzip",
    b"SBle",
    b"data",
    b"GB.STRM",
    b"GD.STRM",
    b"<?xml",
    b"EB\x00",
    b"{",
    b"[",
    b"GNF ",
    b"STrm",
    b"\x1a\x45\xdf\xa3", // EBML (Matroska / WebM)
    b"OggS",
    b"RIFF",
    b"WAVE",
    b"ID3",
    b"PK\x03\x04",
    b"\x1f\x8b", // gzip
    b"RFPK",
    b"\x10\xfb",
    b"\x90\xfb", // EA RefPack-style headers
    b"\xef\xbb\xbf", // UTF-8 BOM
    b"DB\x00",   // EA DB container
];

pub const BINARY_MAGICS: &[&[u8]] = &[b"RIFF", b"DDS ", b"\x89PNG", b"\x7fELF"];

/// Formats whose containers carry no stable leading magic (subtitle scripts, On2 VP6 streams).
pub const MEDIA_EXTS: &[&str] = &[
    ".sub", ".vp6", ".mkv", ".mp4", ".webm", ".bik", ".bk2", ".ogg", ".wav", ".wmv",
];

#[derive(Debug)]
pub struct NotAnArchive(pub String);

impl std::fmt::Display for NotAnArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NotAnArchive {}

#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Leaf {
    pub prefix: Vec<String>,
    pub name: String,
    /// The trie node's third field. It is a hash-like identifier, NOT an index into the file-info
    /// table; kept because it identifies the node when debugging a name→data mapping.
    #[allow(dead_code)]
    pub third: u32,
}

#[derive(Clone, Debug)]
pub struct Record {
    /// Full path below the archive root, `/`-separated.
    pub path: String,
    /// Position in the file-info table (what `list` shows as `idx=`).
    pub position: usize,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub error: Option<String>,
}

impl Record {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn extension(&self) -> String {
        match self.name().rfind('.') {
            Some(i) => self.name()[i..].to_ascii_lowercase(),
            None => String::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Diagnostics {
    pub archive: String,
    pub file_size: u64,
    pub header_file_length: u32,
    pub header_length_wrapped: bool,
    pub trie_leaves: usize,
    pub file_count: usize,
    pub leaf_count_matches: bool,
    pub entries_usable: usize,
    pub out_of_bounds: usize,
    pub sum_of_sizes: u64,
    pub union_of_ranges: u64,
    pub union_coverage: f64,
    pub shared_bytes: u64,
    pub shared_ratio: f64,
}

fn be32(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() {
        return 0;
    }
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub struct Archive {
    pub path: PathBuf,
    pub real_size: u64,
    pub data: Mmap,
    pub version: u16,
    pub file_count: usize,
    pub flags: u32,
    pub trie_off0: usize,
    pub trie_off1: usize,
    pub name_len: usize,
    pub header_length: u32,
    pub addr_shift: u32,
    pub stride: usize,
    pub leaves: Vec<Leaf>,
    pub info: Vec<Option<EntryInfo>>,
    names: Vec<String>,
}

impl Archive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)
            .map_err(|e| format!("{}: cannot open ({})", path.display(), e))?;
        let real_size = file.metadata()?.len();
        if real_size < ENTRY_TABLE_OFFSET as u64 {
            return Err(Box::new(NotAnArchive(format!(
                "{}: file too small to be an EB archive",
                path.display()
            ))));
        }
        // SAFETY: the mapping is read-only and the file is not mutated during the run.
        let data = unsafe { Mmap::map(&file)? };

        if &data[0..2] != b"EB" {
            return Err(Box::new(NotAnArchive(format!(
                "{}: not an EB .big archive (magic={:?})",
                path.display(),
                &data[0..2]
            ))));
        }

        let version = u16::from_be_bytes([data[2], data[3]]);
        let file_count = be32(&data, 4) as usize;
        let flags = be32(&data, 8);
        let trie_off0 = be32(&data, 12) as usize;
        let trie_off1 = be32(&data, 16) as usize;
        let name_len = data[20] as usize;
        let header_length = be32(&data, 28);
        let addr_shift = (data[10] & 0x3F) as u32;
        let stride = if data[9] & 1 != 0 {
            STRIDE_LONG
        } else {
            STRIDE_SHORT
        };

        let mut arc = Archive {
            path,
            real_size,
            data,
            version,
            file_count,
            flags,
            trie_off0,
            trie_off1,
            name_len,
            header_length,
            addr_shift,
            stride,
            leaves: Vec::new(),
            info: Vec::new(),
            names: Vec::new(),
        };
        arc.leaves = arc.walk_trie();
        arc.index_file_info();
        arc.names = arc.flat_names();
        Ok(arc)
    }

    fn walk_trie(&self) -> Vec<Leaf> {
        let buf: &[u8] = &self.data;
        let off1 = self.trie_off0 + self.trie_off1;
        let u5 = be32(buf, off1) as usize;
        let node_base = off1 + 4;
        let child_base = off1 + u5 + 8;
        let u6 = be32(buf, off1 + u5 + 4) as usize;
        let str_base = off1 + u5 + u6 + 0xC;

        fn component(buf: &[u8], str_base: usize, off: u32) -> String {
            let start = str_base + off as usize;
            if start >= buf.len() {
                return String::new();
            }
            let end = buf[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[start..end]).to_string()
        }

        fn rec(
            buf: &[u8],
            node_base: usize,
            child_base: usize,
            str_base: usize,
            idx: u32,
            prefix: &[String],
            depth: usize,
            seen: &mut std::collections::HashSet<u32>,
            out: &mut Vec<Leaf>,
        ) {
            if depth > 64 || !seen.insert(idx) {
                return;
            }
            let off = node_base + idx as usize * 20;
            if off + 20 > buf.len() {
                return;
            }
            let name_off = be32(buf, off);
            let is_dir = be32(buf, off + 4);
            // node layout: { name_off, is_dir, unused, third, fourth }
            let third = be32(buf, off + 12);
            let fourth = be32(buf, off + 16);
            let name = component(buf, str_base, name_off);

            if is_dir == 0 {
                let base = child_base + fourth as usize * 4;
                let mut child_prefix: Vec<String> = prefix.to_vec();
                child_prefix.push(name);
                for k in 0..third as usize {
                    let child = be32(buf, base + k * 4);
                    rec(
                        buf,
                        node_base,
                        child_base,
                        str_base,
                        child,
                        &child_prefix,
                        depth + 1,
                        seen,
                        out,
                    );
                }
            } else {
                out.push(Leaf {
                    prefix: prefix.to_vec(),
                    name,
                    third,
                });
            }
        }

        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        rec(
            buf,
            node_base,
            child_base,
            str_base,
            0,
            &[],
            0,
            &mut seen,
            &mut out,
        );
        out
    }

    fn index_file_info(&mut self) {
        let mut info = Vec::with_capacity(self.file_count);
        for pos in 0..self.file_count {
            let off = ENTRY_TABLE_OFFSET + pos * self.stride;
            if off + self.stride > self.data.len() {
                info.push(None);
                continue;
            }
            let addr_units = be32(&self.data, off);
            let alt = be32(&self.data, off + 4);
            let size = be32(&self.data, off + 8);
            // Record is { addr_units, stored_size, other }. Which of the last two carries the
            // stored length varies: in the 12 top-level archives field 2 is always 0 and field 3
            // is the length; in ~30 nested archives field 2 holds the length and field 3 is a
            // constant (0x100100), so trusting field 3 first pushed every entry out of bounds.
            info.push(Some(EntryInfo {
                address: (addr_units as u64) << self.addr_shift,
                size: if alt != 0 { alt as u64 } else { size as u64 },
            }));
        }
        self.info = info;
    }

    /// Names in file-info order: the flat name table is parallel to the file-info table.
    fn flat_names(&self) -> Vec<String> {
        let buf: &[u8] = &self.data;
        let mut off = self.trie_off0 + 2;
        let mut names = Vec::with_capacity(self.file_count);
        for _ in 0..self.file_count {
            if off >= buf.len() || self.name_len == 0 {
                names.push(String::new());
                continue;
            }
            let end = (off + self.name_len).min(buf.len());
            let raw = &buf[off..end];
            let cut = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            names.push(String::from_utf8_lossy(&raw[..cut]).to_string());
            off += self.name_len;
        }
        names
    }

    /// One record per file, in file-info order, with the trie supplying paths.
    pub fn records(&self) -> Vec<Record> {
        let mut by_name: HashMap<&str, Vec<&Vec<String>>> = HashMap::new();
        for leaf in &self.leaves {
            by_name.entry(leaf.name.as_str()).or_default().push(&leaf.prefix);
        }

        let mut out = Vec::with_capacity(self.names.len());
        for (pos, name) in self.names.iter().enumerate() {
            let prefix: Vec<String> = match by_name.get_mut(name.as_str()) {
                Some(list) if !list.is_empty() => list.remove(0).clone(),
                _ => Vec::new(),
            };
            let mut parts = prefix;
            parts.push(name.clone());
            let path = parts
                .iter()
                .filter(|p| !p.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join("/");

            match self.info.get(pos).and_then(|o| o.as_ref()) {
                Some(e) => out.push(Record {
                    path,
                    position: pos,
                    address: Some(e.address),
                    size: Some(e.size),
                    error: None,
                }),
                None => out.push(Record {
                    path,
                    position: pos,
                    address: None,
                    size: None,
                    error: Some("no file-info entry for position".to_string()),
                }),
            }
        }
        out
    }

    pub fn diagnostics(&self) -> Diagnostics {
        let mut intervals: Vec<(u64, u64)> = Vec::new();
        let mut oob = 0usize;
        for r in self.records() {
            let (Some(addr), Some(size)) = (r.address, r.size) else {
                continue;
            };
            let end = addr.saturating_add(size);
            if end > self.real_size {
                oob += 1;
                continue;
            }
            intervals.push((addr, end));
        }
        let entries_usable = intervals.len();

        let mut sorted = intervals.clone();
        sorted.sort_unstable();
        let mut union = 0u64;
        let mut cur: Option<(u64, u64)> = None;
        for (s, e) in &sorted {
            match cur {
                None => cur = Some((*s, *e)),
                Some((cs, ce)) => {
                    if *s <= ce {
                        cur = Some((cs, (*e).max(ce)));
                    } else {
                        union += ce - cs;
                        cur = Some((*s, *e));
                    }
                }
            }
        }
        if let Some((cs, ce)) = cur {
            union += ce - cs;
        }

        let mut events: Vec<(u64, i32)> = Vec::with_capacity(intervals.len() * 2);
        for (s, e) in &intervals {
            events.push((*s, 1));
            events.push((*e, -1));
        }
        events.sort_unstable();
        let mut depth = 0i32;
        let mut shared = 0u64;
        let mut prev: Option<u64> = None;
        for (pos, delta) in &events {
            if let Some(p) = prev {
                if depth > 1 {
                    shared += pos.saturating_sub(p);
                }
            }
            depth += delta;
            prev = Some(*pos);
        }

        let sum_of_sizes: u64 = intervals.iter().map(|(s, e)| e - s).sum();
        let denom = if self.real_size > 0 {
            self.real_size as f64
        } else {
            1.0
        };

        Diagnostics {
            archive: self
                .path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            file_size: self.real_size,
            header_file_length: self.header_length,
            header_length_wrapped: self.header_length as u64 != self.real_size,
            trie_leaves: self.leaves.len(),
            file_count: self.file_count,
            leaf_count_matches: self.leaves.len() == self.file_count,
            entries_usable,
            out_of_bounds: oob,
            sum_of_sizes,
            union_of_ranges: union,
            union_coverage: union as f64 / denom,
            shared_bytes: shared,
            shared_ratio: shared as f64 / denom,
        }
    }

    fn read_head(&self, addr: u64, n: usize) -> &[u8] {
        let start = addr as usize;
        if start >= self.data.len() {
            return &[];
        }
        let end = (start + n).min(self.data.len());
        &self.data[start..end]
    }

    fn same(head: &[u8], magic: &[u8]) -> bool {
        head.len() >= magic.len() && &head[..magic.len()] == magic
    }

    fn matches_any(head: &[u8], list: &[&[u8]]) -> bool {
        list.iter().any(|m| Self::same(head, m))
    }

    pub fn magic_check(&self, sample: usize) -> MagicCheck {
        let mut ok = 0usize;
        let mut bad = 0usize;
        let mut bad_samples: Vec<(String, u64, String)> = Vec::new();
        let mut n = 0usize;

        for r in self.records() {
            if n >= sample {
                break;
            }
            let (Some(addr), Some(_size)) = (r.address, r.size) else {
                continue;
            };
            if addr + 8 > self.real_size {
                continue;
            }
            n += 1;
            let head = self.read_head(addr, 8);
            if head.len() < 8 {
                continue;
            }
            let printable = head[..4].iter().all(|&b| (32..127).contains(&b));
            let is_mp4 = &head[4..8] == b"ftyp";
            let is_media_ext = MEDIA_EXTS.contains(&r.extension().as_str());

            if Self::matches_any(head, CHUNK_MAGICS)
                || Self::matches_any(head, BINARY_MAGICS)
                || printable
                || is_mp4
                || is_media_ext
            {
                ok += 1;
            } else {
                bad += 1;
                if bad_samples.len() < 8 {
                    bad_samples.push((
                        r.path.clone(),
                        addr,
                        head.iter().map(|b| format!("{b:02x}")).collect(),
                    ));
                }
            }
        }
        MagicCheck {
            checked: ok + bad,
            ok,
            bad,
            bad_samples,
        }
    }

    /// Compare payload type against the declared extension. This is the check that catches
    /// mis-indexed entries: a wrong mapping still yields in-range addresses and plausible binary,
    /// but a `.xml` entry will not start with markup.
    pub fn extension_agreement(&self, sample: usize) -> Vec<(String, usize, usize, f64)> {
        let expect: &[(&str, &[&[u8]])] = &[
            (".xml", &[b"<?xml", b"\xef\xbb\xbf", b"<"]),
            (".json", &[b"{", b"["]),
            (".lua", &[b"--", b"GameAI", b"return", b"local", b"{"]),
            (".big", &[b"EB"]),
        ];
        let text_exts = [".xml", ".json", ".lua"];
        let mut stats: HashMap<String, (usize, usize)> = HashMap::new();
        let mut n = 0usize;

        for r in self.records() {
            if n >= sample {
                break;
            }
            let (Some(addr), Some(size)) = (r.address, r.size) else {
                continue;
            };
            let ext = r.extension();
            let Some(prefixes) = expect.iter().find(|(e, _)| *e == ext).map(|(_, p)| *p) else {
                continue;
            };
            if addr + 8 > self.real_size {
                continue;
            }
            n += 1;

            let mut head_bytes = self.read_head(addr, (size.min(2 << 20)) as usize).to_vec();
            let mut head: &[u8] = &head_bytes;
            if chunkzip::is_chunkzip(&head_bytes) {
                match chunkzip::decode(&head_bytes) {
                    Ok(plain) => {
                        head_bytes = plain;
                        head = &head_bytes;
                    }
                    Err(_) => continue, // cannot judge a container we cannot unwrap
                }
            }

            let mut ok = Self::matches_any(head, prefixes)
                || prefixes.iter().any(|p| head.starts_with(p));
            if !ok && text_exts.contains(&ext.as_str()) {
                ok = head
                    .iter()
                    .take(6)
                    .all(|&b| (32..127).contains(&b) || b == 9 || b == 10 || b == 13);
            }
            let slot = stats.entry(ext).or_insert((0, 0));
            slot.1 += 1;
            if ok {
                slot.0 += 1;
            }
        }

        let mut out: Vec<(String, usize, usize, f64)> = stats
            .into_iter()
            .map(|(ext, (ok, total))| {
                let rate = if total > 0 { ok as f64 / total as f64 } else { 0.0 };
                (ext, ok, total, rate)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Extract entries to `out_dir`. `progress` is called after each entry so a CLI can render a
    /// bar without this module knowing about terminals.
    /// Raw bytes of one entry, optionally unwrapped from a chunkzip/chunkref container.
    pub fn entry_bytes(&self, index: usize, decompress: bool) -> Result<Vec<u8>, String> {
        let rec = self
            .records()
            .get(index)
            .cloned()
            .ok_or_else(|| format!("no entry at index {index}"))?;
        let (address, size) = match (rec.address, rec.size) {
            (Some(a), Some(s)) => (a, s),
            _ => return Err(format!("{} is unresolved", rec.path)),
        };
        let start = address as usize;
        let end = start.saturating_add(size as usize);
        if end > self.data.len() {
            return Err(format!("{} runs past the end of the archive", rec.path));
        }
        let mut buf = self.data[start..end].to_vec();
        if decompress {
            if crate::chunkzip::is_chunkzip(&buf) {
                buf = crate::chunkzip::decode(&buf)?;
            } else if crate::chunkref::is_chunkref(&buf) {
                buf = crate::chunkref::decode(&buf)?.0;
            }
        }
        Ok(buf)
    }

    pub fn extract(
        &self,
        out_dir: &Path,
        limit: Option<usize>,
        flat: bool,
        decompress: bool,
        skip_existing: bool,
        recurse: bool,
        depth: usize,
        progress: Option<&mut dyn FnMut(usize, usize, u64, u64)>,
    ) -> ExtractReport {
        let mut planned = self.records();
        if let Some(limit) = limit {
            planned.truncate(limit);
        }
        self.extract_plan(out_dir, planned, flat, decompress, skip_existing, recurse, depth, progress)
    }

    /// Extract only the entries at the given file-info positions.
    pub fn extract_only(
        &self,
        out_dir: &Path,
        indices: &[usize],
        flat: bool,
        decompress: bool,
        skip_existing: bool,
        recurse: bool,
        depth: usize,
        progress: Option<&mut dyn FnMut(usize, usize, u64, u64)>,
    ) -> ExtractReport {
        let all = self.records();
        let planned: Vec<Record> = indices.iter().filter_map(|i| all.get(*i).cloned()).collect();
        self.extract_plan(out_dir, planned, flat, decompress, skip_existing, recurse, depth, progress)
    }

    fn extract_plan(
        &self,
        out_dir: &Path,
        planned: Vec<Record>,
        flat: bool,
        decompress: bool,
        skip_existing: bool,
        recurse: bool,
        depth: usize,
        mut progress: Option<&mut dyn FnMut(usize, usize, u64, u64)>,
    ) -> ExtractReport {
        let mut rep = ExtractReport::default();
        let total_files = planned.len();
        let total_bytes: u64 = planned
            .iter()
            .filter(|r| r.address.is_some())
            .map(|r| r.size.unwrap_or(0))
            .sum();
        let mut bytes_done = 0u64;
        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        let _ = std::fs::create_dir_all(out_dir);

        for (i, r) in planned.iter().enumerate() {
            let (Some(addr), Some(size)) = (r.address, r.size) else {
                rep.failed += 1;
                if rep.errors.len() < 20 {
                    rep.errors.push((
                        r.path.clone(),
                        r.error.clone().unwrap_or_else(|| "unresolved".to_string()),
                    ));
                }
                if let Some(p) = progress.as_mut() {
                    p(i + 1, total_files, bytes_done, total_bytes);
                }
                continue;
            };

            if addr + size > self.real_size {
                rep.failed += 1;
                if rep.errors.len() < 20 {
                    rep.errors
                        .push((r.path.clone(), "range exceeds archive size".to_string()));
                }
                if let Some(p) = progress.as_mut() {
                    p(i + 1, total_files, bytes_done, total_bytes);
                }
                continue;
            }

            let rel = if flat {
                r.name().to_string()
            } else {
                r.path.clone()
            };
            let out_path = out_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));

            if !seen.insert(out_path.clone()) {
                rep.skipped += 1;
                bytes_done += size;
                if let Some(p) = progress.as_mut() {
                    p(i + 1, total_files, bytes_done, total_bytes);
                }
                continue;
            }
            if skip_existing && out_path.exists() {
                rep.skipped += 1;
                bytes_done += size;
                if let Some(p) = progress.as_mut() {
                    p(i + 1, total_files, bytes_done, total_bytes);
                }
                continue;
            }

            if let Some(parent) = out_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let start = addr as usize;
            let payload = &self.data[start..start + size as usize];

            let written_bytes: std::borrow::Cow<[u8]> = if decompress && chunkzip::is_chunkzip(payload)
            {
                match chunkzip::decode(payload) {
                    Ok(plain) => {
                        rep.decoded_chunkzip += 1;
                        std::borrow::Cow::Owned(plain)
                    }
                    Err(why) => {
                        rep.chunkzip_left_wrapped += 1;
                        if rep.decode_errors.len() < 10 {
                            rep.decode_errors.push((r.path.clone(), why));
                        }
                        std::borrow::Cow::Borrowed(payload)
                    }
                }
            } else {
                std::borrow::Cow::Borrowed(payload)
            };

            // chunkref holds RefPack streams that decompress to a nested .big archive
            let written_bytes: std::borrow::Cow<[u8]> =
                if decompress && crate::chunkref::is_chunkref(&written_bytes) {
                    match crate::chunkref::decode(&written_bytes) {
                        Ok((inner, _info)) => {
                            rep.decoded_chunkref += 1;
                            std::borrow::Cow::Owned(inner)
                        }
                        Err(why) => {
                            if rep.chunkref_errors.len() < 10 {
                                rep.chunkref_errors.push((r.path.clone(), why));
                            }
                            written_bytes
                        }
                    }
                } else {
                    written_bytes
                };

            match File::create(&out_path).and_then(|mut f| f.write_all(&written_bytes)) {
                Ok(()) => rep.written += 1,
                Err(e) => {
                    rep.failed += 1;
                    if rep.errors.len() < 20 {
                        rep.errors.push((r.path.clone(), e.to_string()));
                    }
                }
            }

            // recurse into an archive payload, writing its contents beside it
            if recurse && depth < MAX_RECURSE_DEPTH && written_bytes.len() > 4
                && &written_bytes[0..2] == b"EB"
            {
                rep.nested_archives += 1;
                let sub_dir = out_dir.join(rel_for_nested(&out_path, out_dir));
                if let Some(sub) = extract_bytes(&written_bytes, &sub_dir, decompress, recurse, depth + 1)
                {
                    rep.nested_files += sub.written;
                    rep.decoded_chunkzip += sub.decoded_chunkzip;
                    rep.nested_failed += sub.failed + sub.nested_failed;
                }
            }

            bytes_done += size;
            if let Some(p) = progress.as_mut() {
                p(i + 1, total_files, bytes_done, total_bytes);
            }
        }

        rep
    }
}


pub const MAX_RECURSE_DEPTH: usize = 4;

/// Directory name for a nested archive's contents: the archive path relative to `out_dir`, without
/// its extension.
fn rel_for_nested(path: &Path, out_dir: &Path) -> PathBuf {
    let rel = path.strip_prefix(out_dir).unwrap_or(path);
    let mut p = PathBuf::new();
    p.push(rel);
    p.set_extension("");
    p
}

/// Extract an archive held in memory by spilling it to a temporary file.
fn extract_bytes(
    payload: &[u8],
    out_dir: &Path,
    decompress: bool,
    recurse: bool,
    depth: usize,
) -> Option<ExtractReport> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("bigtool_nested_{}_{}.big", std::process::id(), n));
    std::fs::write(&tmp, payload).ok()?;
    let result = match Archive::open(&tmp) {
        Ok(arc) => Some(arc.extract(out_dir, None, false, decompress, false, recurse, depth, None)),
        Err(_) => None,
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

#[derive(Default, Debug)]
pub struct ExtractReport {
    pub written: usize,
    pub skipped: usize,
    pub failed: usize,
    pub errors: Vec<(String, String)>,
    pub decoded_chunkzip: usize,
    pub chunkzip_left_wrapped: usize,
    pub decode_errors: Vec<(String, String)>,
    pub decoded_chunkref: usize,
    pub chunkref_errors: Vec<(String, String)>,
    pub nested_archives: usize,
    pub nested_files: usize,
    pub nested_failed: usize,
}

#[derive(Debug)]
pub struct MagicCheck {
    pub checked: usize,
    pub ok: usize,
    pub bad: usize,
    pub bad_samples: Vec<(String, u64, String)>,
}

