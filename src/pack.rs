//! Write EA "EB" `.big` v3 archives.
//!
//! The writer reproduces the layout the reader (and, by construction, the game's loader) expects:
//!
//! ```text
//! 0x00            32-byte header
//! 0x30            file-info table        n * stride (16 or 20), one record per file
//!                 zero padding           ~one byte per file, then the u16 at trie offset
//! trie_off0+2     flat name table        n * name_len
//! trie_off0+trie_off1  trie block        [u32 20*n][nodes][u32 4*m][children][u32 len][strings]
//! data_start      file data              every record 4 KiB aligned (addr_units << shift)
//! ```
//!
//! Per-entry metadata in the record tail (8 bytes at offset 12) is not understood; it is copied
//! from a `--template` archive when the path matches, otherwise zeroed.
//!
//! The trie leaf's third field is NOT a data index: in shipped archives it counts down from
//! `n-1` to `0` along the walk. Data is associated by position in the flat name table, so the
//! writer keeps that invariant by assigning thirds in the same descending pattern.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::big::Archive;

const HEADER_LEN: usize = 0x20;
const ENTRY_TABLE_OFFSET: u64 = 0x30;

pub struct PackOptions {
    pub name_len: usize,
    pub stride: usize,
    pub shift: u32,
    pub flags: u32,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            name_len: 0,
            stride: 20,
            shift: 12,
            flags: 0x0051_0c00,
        }
    }
}

pub struct PackReport {
    pub files: usize,
    pub data_bytes: u64,
    pub out_bytes: u64,
    pub trie_nodes: usize,
    pub used_template: bool,
}

struct Node {
    name: String,
    is_file: bool,
    children: Vec<usize>,
    third: u32,
}

#[derive(Clone, Default)]
struct EntryMeta {
    tail: [u8; 8],
    third: Option<u32>,
}

fn align_up(x: u64, a: u64) -> u64 {
    if a == 0 {
        return x;
    }
    (x + a - 1) / a * a
}

fn collect_files(root: &Path) -> std::io::Result<Vec<(String, PathBuf, u64)>> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf, u64)>) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = entry.metadata()?;
            if meta.is_dir() {
                walk(&path, root, out)?;
            } else if meta.is_file() {
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let name = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((name, path.clone(), meta.len()));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Read per-path metadata (record tail, trie third) from an existing archive.
fn template_meta(path: &Path) -> std::io::Result<(HashMap<String, EntryMeta>, Option<PackOptions>)> {
    let mut map = HashMap::new();
    let Ok(arc) = Archive::open(path) else {
        return Ok((map, None));
    };

    // trie thirds, keyed by path
    let mut thirds: HashMap<String, u32> = HashMap::new();
    for prefix in arc.leaves.iter() {
        let mut parts: Vec<&str> = prefix.prefix.iter().map(|s| s.as_str()).collect();
        parts.push(prefix.name.as_str());
        let key = parts
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("/");
        thirds.insert(key, prefix.third);
    }

    for rec in arc.records() {
        let (Some(addr), _) = (rec.address, rec.size) else {
            continue;
        };
        let mut tail = [0u8; 8];
        // record tail (bytes 12..20) for 20-byte records
        for pos in 0..arc.info.len() {
            if arc.info[pos].as_ref().map(|e| e.address) != Some(addr) {
                continue;
            }
            let off = ENTRY_TABLE_OFFSET as usize + pos * arc.stride;
            if arc.stride >= 20 && off + 20 <= arc.data.len() {
                tail.copy_from_slice(&arc.data[off + 12..off + 20]);
            }
            break;
        }
        map.insert(
            rec.path.clone(),
            EntryMeta {
                tail,
                third: thirds.get(&rec.path).copied(),
            },
        );
    }

    let opts = PackOptions {
        name_len: arc.name_len,
        stride: arc.stride,
        shift: arc.addr_shift,
        flags: arc.flags,
    };
    Ok((map, Some(opts)))
}

pub fn pack(src: &Path, out: &Path, template: Option<&Path>) -> std::io::Result<PackReport> {
    let (meta, tpl_opts) = match template {
        Some(t) => template_meta(t)?,
        None => (HashMap::new(), None),
    };
    let mut opts = tpl_opts.unwrap_or_default();

    let files = collect_files(src)?;
    if files.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source directory contains no files",
        ));
    }
    let n = files.len();

    // name_len must hold every basename plus its NUL
    let need = files
        .iter()
        .map(|(name, _, _)| name.rsplit('/').next().unwrap_or(name).len() + 1)
        .max()
        .unwrap_or(1);
    if opts.name_len < need {
        opts.name_len = need;
    }
    let name_len = opts.name_len;
    let stride = if opts.stride == 16 { 16 } else { 20 };
    let shift = opts.shift;
    let unit = 1u64 << shift;

    // ---- directory tree
    let mut nodes: Vec<Node> = vec![Node {
        name: String::new(),
        is_file: false,
        children: Vec::new(),
        third: 0,
    }];
    let mut file_node = vec![0usize; n];

    for (i, (name, _, _)) in files.iter().enumerate() {
        let mut cur = 0usize;
        for comp in name.split('/') {
            let existing = nodes[cur]
                .children
                .iter()
                .copied()
                .find(|&c| nodes[c].name == comp);
            cur = match existing {
                Some(c) => c,
                None => {
                    let idx = nodes.len();
                    nodes.push(Node {
                        name: comp.to_string(),
                        is_file: false,
                        children: Vec::new(),
                        third: 0,
                    });
                    let parent = cur;
                    nodes[parent].children.push(idx);
                    idx
                }
            };
        }
        nodes[cur].is_file = true;
        file_node[i] = cur;
    }

    // thirds: template values where available, else count down along the walk
    let mut leaves: Vec<usize> = Vec::new();
    {
        let mut stack = vec![0usize];
        while let Some(idx) = stack.pop() {
            if nodes[idx].is_file {
                leaves.push(idx);
            }
            for &c in nodes[idx].children.iter().rev() {
                stack.push(c);
            }
        }
    }
    let leaf_count = leaves.len();
    let mut walk_order: HashMap<usize, usize> = HashMap::with_capacity(leaf_count);
    for (order, &idx) in leaves.iter().enumerate() {
        walk_order.insert(idx, order);
    }
    for (i, (path, _, _)) in files.iter().enumerate() {
        let idx = file_node[i];
        let order = walk_order.get(&idx).copied().unwrap_or(i);
        nodes[idx].third = match meta.get(path).and_then(|m| m.third) {
            Some(t) => t,
            None => (leaf_count - 1 - order) as u32,
        };
    }

    // ---- serialise trie
    let mut strings: Vec<u8> = Vec::new();
    let mut string_off: HashMap<String, u32> = HashMap::new();
    let mut child_indices: Vec<u32> = Vec::new();

    struct NodeOut {
        name_off: u32,
        is_dir: u32,
        third: u32,
        fourth: u32,
    }
    let mut out_nodes: Vec<NodeOut> = Vec::with_capacity(nodes.len());

    for node in nodes.iter() {
        let name_off = *string_off.entry(node.name.clone()).or_insert_with(|| {
            let off = strings.len() as u32;
            strings.extend_from_slice(node.name.as_bytes());
            strings.push(0);
            off
        });
        if node.is_file {
            out_nodes.push(NodeOut {
                name_off,
                is_dir: 1,
                third: node.third,
                fourth: 0,
            });
        } else {
            let start = child_indices.len() as u32;
            for &c in &node.children {
                child_indices.push(c as u32);
            }
            out_nodes.push(NodeOut {
                name_off,
                is_dir: 0,
                third: node.children.len() as u32,
                fourth: start,
            });
        }
    }

    let nodes_bytes = out_nodes.len() * 20;
    let children_bytes = child_indices.len() * 4;
    let trie_size = 12 + nodes_bytes + children_bytes + strings.len();

    // ---- layout
    let entry_table_bytes = n * stride;
    let gap = n as u64; // observed zero gap, ~one byte per file
    let trie_off0 = align_up(ENTRY_TABLE_OFFSET + entry_table_bytes as u64 + gap, 16);
    let names_off = trie_off0 + 2;
    let names_bytes = (n * name_len) as u64;
    let off1 = align_up(names_off + names_bytes, 16);
    let trie_off1 = off1 - trie_off0;
    let data_start = align_up(off1 + trie_size as u64, 4096);

    // ---- data offsets
    let mut addresses = Vec::with_capacity(n);
    let mut cursor = data_start;
    for (_, _, size) in files.iter() {
        addresses.push(cursor);
        cursor = align_up(cursor + size, unit);
    }
    let _total_len = cursor;

    // ---- write
    let f = File::create(out)?;
    let mut w = BufWriter::with_capacity(1 << 20, f);

    let mut header = [0u8; HEADER_LEN];
    header[0] = b'E';
    header[1] = b'B';
    header[2..4].copy_from_slice(&3u16.to_be_bytes());
    header[4..8].copy_from_slice(&(n as u32).to_be_bytes());
    header[8..12].copy_from_slice(&opts.flags.to_be_bytes());
    header[12..16].copy_from_slice(&(trie_off0 as u32).to_be_bytes());
    header[16..20].copy_from_slice(&(trie_off1 as u32).to_be_bytes());
    header[20] = name_len.min(255) as u8;
    header[21] = 0; // unknown, zero in shipped archives when unset
    header[22..24].copy_from_slice(&0u16.to_be_bytes());
    header[24..28].copy_from_slice(&0u32.to_be_bytes());
    header[28..32].copy_from_slice(&0u32.to_be_bytes()); // patched after writing
    w.write_all(&header)?;
    // 16 bytes of padding between the header and the file-info table (table starts at 0x30)
    w.write_all(&[0u8; (ENTRY_TABLE_OFFSET as usize) - HEADER_LEN])?;

    // entry table
    let mut table = vec![0u8; entry_table_bytes];
    for (i, (name, _, size)) in files.iter().enumerate() {
        let base = i * stride;
        let units = (addresses[i] >> shift) as u32;
        table[base..base + 4].copy_from_slice(&units.to_be_bytes());
        table[base + 4..base + 8].copy_from_slice(&0u32.to_be_bytes());
        table[base + 8..base + 12].copy_from_slice(&(*size as u32).to_be_bytes());
        if stride >= 20 {
            let tail = meta.get(name).map(|m| m.tail).unwrap_or([0u8; 8]);
            table[base + 12..base + 20].copy_from_slice(&tail);
        }
    }
    w.write_all(&table)?;

    // zero gap up to trie_off0
    let mut pos = ENTRY_TABLE_OFFSET + entry_table_bytes as u64;
    let zeros = vec![0u8; (trie_off0 - pos) as usize];
    w.write_all(&zeros)?;
    pos = trie_off0;
    w.write_all(&0u16.to_be_bytes())?; // u16 ahead of the name table
    pos += 2;

    // name table
    debug_assert_eq!(pos, names_off);
    let mut names_block = vec![0u8; names_bytes as usize];
    for (i, (name, _, _)) in files.iter().enumerate() {
        let base = i * name_len;
        let base_name = name.rsplit('/').next().unwrap_or(name).as_bytes();
        let len = base_name.len().min(name_len - 1);
        names_block[base..base + len].copy_from_slice(&base_name[..len]);
    }
    w.write_all(&names_block)?;
    pos += names_bytes;

    // pad to trie
    if off1 > pos {
        w.write_all(&vec![0u8; (off1 - pos) as usize])?;
    }

    // trie block
    w.write_all(&(nodes_bytes as u32).to_be_bytes())?;
    for node in &out_nodes {
        w.write_all(&node.name_off.to_be_bytes())?;
        w.write_all(&node.is_dir.to_be_bytes())?;
        w.write_all(&0u32.to_be_bytes())?; // unused
        w.write_all(&node.third.to_be_bytes())?;
        w.write_all(&node.fourth.to_be_bytes())?;
    }
    w.write_all(&(children_bytes as u32).to_be_bytes())?;
    for c in &child_indices {
        w.write_all(&c.to_be_bytes())?;
    }
    w.write_all(&(strings.len() as u32).to_be_bytes())?;
    w.write_all(&strings)?;

    // pad to data
    let after_trie = off1 + trie_size as u64;
    if data_start > after_trie {
        w.write_all(&vec![0u8; (data_start - after_trie) as usize])?;
    }

    // data, 4 KiB aligned per record
    let mut wrote = data_start;
    for (i, (_, path, size)) in files.iter().enumerate() {
        if addresses[i] > wrote {
            w.write_all(&vec![0u8; (addresses[i] - wrote) as usize])?;
            wrote = addresses[i];
        }
        let data = fs::read(path)?;
        w.write_all(&data)?;
        wrote += data.len() as u64;
        let _ = size;
    }
    w.flush()?;

    // patch the true length (the field is 32-bit and wraps on huge archives)
    let mut f = w.into_inner().map_err(|e| e.into_error())?;
    f.seek(SeekFrom::Start(28))?;
    f.write_all(&(wrote as u32).to_be_bytes())?;
    f.flush()?;

    Ok(PackReport {
        files: n,
        data_bytes: wrote - data_start,
        out_bytes: wrote,
        trie_nodes: out_nodes.len(),
        used_template: template.is_some(),
    })
}
