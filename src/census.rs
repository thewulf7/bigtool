//! Census the payloads of a `.big` archive without extracting: read each entry's first bytes and
//! group by detected container type plus file extension.

use std::collections::HashMap;

use crate::big::{Archive, MEDIA_EXTS};

pub fn kind_of(head: &[u8], ext: &str) -> &'static str {
    let starts = |p: &[u8]| head.len() >= p.len() && &head[..p.len()] == p;

    if starts(b"chunkzip") {
        return "chunkzip";
    }
    if starts(b"GD.STRM") {
        return "GD.STRM";
    }
    if starts(b"GD.DATA") {
        return "GD.DATA";
    }
    if starts(b"EB") {
        return "EB(nested .big)";
    }
    if starts(b"<?xml") || starts(b"\xef\xbb\xbf") {
        return "XML/text";
    }
    if starts(b"GNF ") || starts(b"GDF") {
        return "GNF?";
    }
    if starts(b"DDS ") || starts(b"\x89PNG") {
        return "image";
    }
    if starts(b"RIFF") {
        return "RIFF";
    }
    if starts(b"\x1a\x45\xdf\xa3") {
        return "matroska";
    }
    if starts(b"DB\x00") {
        return "DB";
    }
    if starts(b"SB") {
        return "SBle/soundbank";
    }
    if MEDIA_EXTS.contains(&ext) {
        return "media";
    }
    if head.len() >= 4 && head[..4].iter().all(|&b| (32..127).contains(&b)) {
        return "ascii-other";
    }
    "binary-unknown"
}

pub struct Census {
    pub entries: usize,
    pub sampled: usize,
    pub kinds: Vec<(&'static str, usize, Vec<(String, usize)>)>,
    pub unknown_heads: Vec<(String, usize)>,
}

pub fn census(arc: &Archive, sample: usize) -> Census {
    let mut recs: Vec<_> = arc.records().into_iter().filter(|r| r.address.is_some()).collect();
    if sample > 0 {
        recs.truncate(sample);
    }

    let mut kinds: HashMap<&'static str, usize> = HashMap::new();
    let mut ext_by_kind: HashMap<&'static str, HashMap<String, usize>> = HashMap::new();
    let mut unknown: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;

    for r in &recs {
        let (Some(addr), _) = (r.address, r.size) else {
            continue;
        };
        if addr + 8 > arc.real_size {
            continue;
        }
        let start = addr as usize;
        let end = (start + 8).min(arc.data.len());
        let head = &arc.data[start..end];

        let ext = {
            let e = r.extension();
            if e.is_empty() {
                "(none)".to_string()
            } else {
                e
            }
        };
        let k = kind_of(head, &ext);
        *kinds.entry(k).or_insert(0) += 1;
        *ext_by_kind.entry(k).or_default().entry(ext).or_insert(0) += 1;
        if k == "binary-unknown" {
            let hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
            *unknown.entry(hex).or_insert(0) += 1;
        }
        total += 1;
    }

    let mut kind_rows: Vec<(&'static str, usize, Vec<(String, usize)>)> = kinds
        .into_iter()
        .map(|(k, n)| {
            let mut exts: Vec<(String, usize)> = ext_by_kind
                .remove(k)
                .map(|m| m.into_iter().collect())
                .unwrap_or_default();
            exts.sort_by(|a, b| b.1.cmp(&a.1));
            exts.truncate(5);
            (k, n, exts)
        })
        .collect();
    kind_rows.sort_by(|a, b| b.1.cmp(&a.1));

    let mut unknown_heads: Vec<(String, usize)> = unknown.into_iter().collect();
    unknown_heads.sort_by(|a, b| b.1.cmp(&a.1));
    unknown_heads.truncate(6);

    Census {
        entries: arc.leaves.len(),
        sampled: total,
        kinds: kind_rows,
        unknown_heads,
    }
}
