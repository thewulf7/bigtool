//! EA `chunkzip` v2 container decoder.
//!
//! Layout (established empirically against NBA LIVE 19 archives):
//!
//! ```text
//! 0x00  8s  "chunkzip"
//! 0x08 u32  version = 2
//! 0x0c u32  total decompressed size
//! 0x10 u32  chunk payload size (0x20000)
//! 0x14 u32  chunk count
//! 0x18 u32  descriptor size = 16
//! 0x1c u32  reserved
//! 0x20      descriptor / frame region; chunk 0 stream starts at 0x30
//! ```
//!
//! Each chunk is RAW DEFLATE (window bits -15) — there is no zlib header anywhere, which is why
//! naive zlib-based tools fail. Chunk i>0 was compressed with the previous 32 KiB of decompressed
//! output as a preset dictionary (`deflateSetDictionary`), so it only inflates when given that
//! dictionary; without it you get "invalid distance too far back".
//!
//! Between chunks sit frame marker bytes whose width varies (10, 11 and 17 observed), so the gap
//! is not modelled: a small forward window is scanned and a candidate is accepted only when it
//! inflates to exactly the expected chunk payload size. The final result is always checked
//! against the declared total, so a wrong candidate can never be silently accepted.

use flate2::{Decompress, FlushDecompress, Status};

pub const MAGIC: &[u8] = b"chunkzip";
const DICT_WINDOW: usize = 32768;
const SCAN: usize = 32;
const MAX_CHUNK_PAYLOAD: usize = 64 << 20;
const MAX_NODES: usize = 200_000;

pub fn is_chunkzip(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

fn be32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

struct Header {
    total: usize,
    chunk_payload: usize,
    nchunks: usize,
}

fn parse_header(data: &[u8]) -> Result<Header, String> {
    if data.len() < 0x30 || !is_chunkzip(data) {
        return Err("not a chunkzip container".to_string());
    }
    let version = be32(data, 8).ok_or("truncated header")?;
    let total = be32(data, 12).ok_or("truncated header")? as usize;
    let chunk_payload = be32(data, 16).ok_or("truncated header")? as usize;
    let nchunks = be32(data, 20).ok_or("truncated header")? as usize;
    let desc_size = be32(data, 24).ok_or("truncated header")?;

    if version != 2 {
        return Err(format!("unsupported chunkzip version {version}"));
    }
    if desc_size != 16 || nchunks == 0 {
        return Err(format!(
            "unexpected descriptor size {desc_size} / chunk count {nchunks}"
        ));
    }
    if chunk_payload == 0 || chunk_payload > MAX_CHUNK_PAYLOAD {
        return Err(format!("implausible chunk payload size {chunk_payload}"));
    }
    Ok(Header {
        total,
        chunk_payload,
        nchunks,
    })
}

/// Inflate `input` as raw DEFLATE with an optional preset dictionary, accepting the result only
/// when it is exactly `expected` bytes. Returns the payload and how many input bytes it consumed.
///
/// The output buffer is `expected + 1` bytes on purpose: that is what makes "produced more than
/// promised" detectable instead of looking like a short read.
fn inflate_exact(
    input: &[u8],
    expected: usize,
    dict: Option<&[u8]>,
) -> Option<(Vec<u8>, usize)> {
    if input.is_empty() {
        return None;
    }
    let mut dec = Decompress::new(false); // raw deflate, no zlib header
    if let Some(dict) = dict {
        if dec.set_dictionary(dict).is_err() {
            return None;
        }
    }

    let mut out = vec![0u8; expected + 1];
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;

    loop {
        let before_in = dec.total_in() as usize;
        let before_out = dec.total_out() as usize;

        let status = match dec.decompress(&input[in_pos..], &mut out[out_pos..], FlushDecompress::None)
        {
            Ok(s) => s,
            Err(_) => return None,
        };

        in_pos += dec.total_in() as usize - before_in;
        out_pos += dec.total_out() as usize - before_out;

        match status {
            Status::StreamEnd => break,
            _ => {
                if out_pos > expected {
                    return None; // stream wants to emit more than the chunk may hold
                }
                let stalled = in_pos == before_in && out_pos == before_out;
                if stalled || in_pos >= input.len() {
                    return None; // truncated or malformed: the stream never terminated
                }
            }
        }
    }

    if out_pos != expected {
        return None;
    }
    out.truncate(expected);
    Some((out, in_pos))
}

fn dict_of(out: &[u8]) -> Option<&[u8]> {
    if out.is_empty() {
        return None;
    }
    let start = out.len().saturating_sub(DICT_WINDOW);
    Some(&out[start..])
}

/// Try to frame one chunk at `pos`.
///
/// The gap between chunks is a frame marker of variable width (10, 11 and 17 bytes observed) and
/// it is consistent within a container, so the previously detected gap is tried first. A chunk may
/// also be stored uncompressed, either behind a 16-byte descriptor whose size field matches, or
/// as a bare run of `expected` bytes.
fn try_chunk(
    data: &[u8],
    pos: usize,
    expected: usize,
    out: &[u8],
    last_gap: usize,
    scan: usize,
    is_last: bool,
) -> Option<(Vec<u8>, usize, usize)> {
    let mut order: Vec<usize> = Vec::with_capacity(scan + 2);
    // For the final chunk the frame gap is exact: whatever is left over after its payload.
    if is_last {
        let tail_gap = data.len().saturating_sub(pos + expected);
        if tail_gap < scan {
            order.push(tail_gap);
        }
    }
    if last_gap > 0 && last_gap < scan && !order.contains(&last_gap) {
        order.push(last_gap);
    }
    for off in 0..scan {
        if !order.contains(&off) {
            order.push(off);
        }
    }

    for off in &order {
        let cand = pos + off;
        if cand >= data.len() {
            continue;
        }
        if let Some((piece, consumed)) = inflate_exact(&data[cand..], expected, dict_of(out)) {
            return Some((piece, cand + consumed, *off));
        }
    }

    // Stored chunk behind a 16-byte descriptor { f0, f1, size, flag }.
    for off in &order {
        let start = pos + off;
        let end = start + 16;
        if end + expected > data.len() {
            continue;
        }
        let size =
            u32::from_be_bytes([data[start + 8], data[start + 9], data[start + 10], data[start + 11]])
                as usize;
        if size == expected {
            return Some((data[end..end + expected].to_vec(), end + expected, *off));
        }
    }

    // Bare stored run: for the final chunk this consumes the rest of the container exactly, which
    // is unambiguous; elsewhere only the container's established gap is trusted.
    let mut bare: Vec<usize> = Vec::new();
    if is_last {
        let tail_gap = data.len().saturating_sub(pos + expected);
        if tail_gap < scan {
            bare.push(tail_gap);
        }
    }
    if last_gap > 0 && !bare.contains(&last_gap) {
        bare.push(last_gap);
    }
    for off in bare {
        let start = pos + off;
        if start + expected <= data.len() {
            return Some((data[start..start + expected].to_vec(), start + expected, off));
        }
    }
    None
}

/// Fast path: walk chunks in order, scanning a small window for each chunk's framing.
pub fn decode_greedy(data: &[u8]) -> Result<Vec<u8>, String> {
    let h = parse_header(data)?;
    let mut out: Vec<u8> = Vec::with_capacity(h.total);
    let mut pos = 0x30usize;
    let mut last_gap = 0usize;

    for i in 0..h.nchunks {
        let expected = h.chunk_payload.min(h.total.saturating_sub(out.len()));
        if expected == 0 {
            return Err(format!("chunk {i} extends past the declared total"));
        }
        let scan = if i == 0 { 1 } else { SCAN };

        match try_chunk(data, pos, expected, &out, last_gap, scan, i + 1 == h.nchunks) {
            Some((piece, next, gap)) => {
                out.extend_from_slice(&piece);
                pos = next;
                last_gap = gap;
            }
            None => return Err(format!("chunk {i}: no candidate produced {expected} bytes")),
        }
    }

    if out.len() != h.total {
        return Err(format!(
            "decoded {} bytes but container declares {}",
            out.len(),
            h.total
        ));
    }
    Ok(out)
}

/// Slow path: depth-first search over per-chunk framings, for containers that mix DEFLATE chunks
/// with stored (uncompressed) chunks behind a 16-byte descriptor. A framing is accepted only when
/// the whole decode matches the declared total.
pub fn decode_backtracking(data: &[u8]) -> Result<Vec<u8>, String> {
    let h = parse_header(data)?;
    let scan = 64usize;
    let mut failed: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    let mut nodes = 0usize;
    let mut out: Vec<u8> = Vec::with_capacity(h.total);


    #[allow(clippy::too_many_arguments)]
    fn rec(
        data: &[u8],
        h: &Header,
        scan: usize,
        i: usize,
        pos: usize,
        last_gap: usize,
        out: &mut Vec<u8>,
        failed: &mut std::collections::HashSet<(usize, usize)>,
        nodes: &mut usize,
    ) -> bool {
        *nodes += 1;
        if *nodes > MAX_NODES {
            return false;
        }
        if i == h.nchunks {
            return out.len() == h.total;
        }
        if failed.contains(&(i, pos)) {
            return false;
        }

        let expected = h.chunk_payload.min(h.total.saturating_sub(out.len()));
        if expected == 0 {
            failed.insert((i, pos));
            return false;
        }

        let span = if i == 0 { 1 } else { scan };
        let mut order: Vec<usize> = Vec::with_capacity(span + 1);
        if last_gap > 0 && last_gap < span {
            order.push(last_gap);
        }
        for off in 0..span {
            if !order.contains(&off) {
                order.push(off);
            }
        }

        let is_last = i + 1 == h.nchunks;
        for off in &order {
            let cand = pos + off;
            if cand >= data.len() {
                continue;
            }
            if let Some((piece, consumed)) = inflate_exact(&data[cand..], expected, dict_of(out)) {
                let base = out.len();
                out.extend_from_slice(&piece);
                if rec(data, h, scan, i + 1, cand + consumed, *off, out, failed, nodes) {
                    return true;
                }
                out.truncate(base);
            }
        }

        // Stored chunk behind a 16-byte descriptor, at any framing offset.
        for off in &order {
            let start = pos + off;
            let end = start + 16;
            if end + expected > data.len() {
                continue;
            }
            let size = u32::from_be_bytes([
                data[start + 8],
                data[start + 9],
                data[start + 10],
                data[start + 11],
            ]) as usize;
            if size != expected {
                continue;
            }
            let base = out.len();
            out.extend_from_slice(&data[end..end + expected]);
            if rec(data, h, scan, i + 1, end + expected, *off, out, failed, nodes) {
                return true;
            }
            out.truncate(base);
        }

        // Bare stored run at the container's usual gap (exact for the final chunk).
        let mut bare: Vec<usize> = Vec::new();
        if is_last {
            let tail_gap = data.len().saturating_sub(pos + expected);
            if tail_gap < scan {
                bare.push(tail_gap);
            }
        }
        if last_gap > 0 && !bare.contains(&last_gap) {
            bare.push(last_gap);
        }
        for g in bare {
            let start = pos + g;
            if start + expected <= data.len() {
                let base = out.len();
                out.extend_from_slice(&data[start..start + expected]);
                if rec(data, h, scan, i + 1, start + expected, g, out, failed, nodes) {
                    return true;
                }
                out.truncate(base);
            }
        }

        failed.insert((i, pos));
        false
    }

    if rec(data, &h, scan, 0, 0x30, 0, &mut out, &mut failed, &mut nodes) {
        Ok(out)
    } else {
        Err("no framing produced a verified decode".to_string())
    }
}

/// Decode a chunkzip container: greedy first, backtracking if that fails.
pub fn decode(data: &[u8]) -> Result<Vec<u8>, String> {
    match decode_greedy(data) {
        Ok(v) => Ok(v),
        Err(e) => decode_backtracking(data).map_err(|_| e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_non_container() {
        assert!(!is_chunkzip(b"not a container"));
        assert!(decode(b"short").is_err());
    }

    #[test]
    fn header_rejects_bad_version() {
        let mut d = vec![0u8; 0x40];
        d[..8].copy_from_slice(b"chunkzip");
        d[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert!(parse_header(&d).is_err());
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// A container whose final chunk is stored (not deflated) behind a frame gap, which is the
    /// shape that used to fail with "no candidate produced N bytes".
    #[test]
    fn decodes_stored_final_chunk_with_frame_gap() {
        let first = b"ABCDEFGH";
        let last = b"ijkl";
        let mut d = Vec::new();
        d.extend_from_slice(b"chunkzip");
        d.extend_from_slice(&2u32.to_be_bytes()); // version
        d.extend_from_slice(&(12u32).to_be_bytes()); // total
        d.extend_from_slice(&(8u32).to_be_bytes()); // chunk payload size
        d.extend_from_slice(&(2u32).to_be_bytes()); // chunk count
        d.extend_from_slice(&(16u32).to_be_bytes()); // descriptor size
        d.extend_from_slice(&0u32.to_be_bytes());
        d.resize(0x30, 0);
        d.extend_from_slice(&raw_deflate(first));
        d.extend_from_slice(&[0u8; 10]); // frame gap
        d.extend_from_slice(last);

        assert_eq!(decode(&d).unwrap(), b"ABCDEFGHijkl".to_vec());
    }
}
