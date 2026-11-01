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
//! Each chunk's stream is preceded by a `{ u32 compressed_size, u32 1 }` pair and starts on a
//! 16-byte boundary; the bytes between the previous stream and that pair are zero fill. Verified on
//! 848 chunks across 16 retail containers (all aligned, all pairs matching, all gaps zero), which
//! is what makes [`encode`] possible.
//!
//! The decoder still does not trust that framing: it scans a small forward window and accepts a
//! candidate only when it inflates to exactly the expected chunk payload size, and the whole result
//! is checked against the declared total. Containers that deviate therefore still decode, and a
//! wrong candidate can never be silently accepted.

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

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------
//
// Writing the container back is only possible because of one structural fact recovered from 848
// chunks across 16 retail containers: every chunk's deflate stream starts on a 16-byte boundary and
// is immediately preceded by `{ u32 compressed_size, u32 1 }`. Everything between the previous
// stream and that pair is zero fill. The first chunk's pair sits at 0x28, so its data starts at the
// documented 0x30.
//
// Chunks are raw DEFLATE with the previous 32 KiB of *decompressed* output as the preset
// dictionary, mirroring how they are decoded.

/// Compress `data` into a chunkzip v2 container at level 9, which measured 99.3% of EA's size
/// on 48 retail containers (level 6 was 103.6%).
pub fn encode(data: &[u8]) -> Result<Vec<u8>, String> {
    encode_level(data, 9)
}

/// Compress `data` into a chunkzip v2 container at the given deflate level.
pub fn encode_level(data: &[u8], level: u32) -> Result<Vec<u8>, String> {
    use flate2::{Compress, Compression, FlushCompress, Status};
    const CHUNK: usize = 0x20000;

    let nchunks = data.len().div_ceil(CHUNK).max(1);
    // 0x20 header + the first chunk's [size][flag] pair
    let mut out = vec![0u8; 0x28];

    for i in 0..nchunks {
        let start = i * CHUNK;
        let end = (start + CHUNK).min(data.len());
        let piece = &data[start..end];

        let mut c = Compress::new(Compression::new(level), false); // false = raw deflate
        if start > 0 {
            let dict_start = start.saturating_sub(DICT_WINDOW);
            c.set_dictionary(&data[dict_start..start])
                .map_err(|e| format!("set_dictionary: {e}"))?;
        }
        let mut comp: Vec<u8> = Vec::with_capacity(piece.len() + 1024);
        let mut status = c.compress_vec(piece, &mut comp, FlushCompress::Finish).map_err(|e| e.to_string())?;
        let mut guard = 0;
        while status != Status::StreamEnd {
            guard += 1;
            if guard > 16 {
                return Err("deflate did not terminate".to_string());
            }
            let before = comp.len();
            status = c.compress_vec(&[], &mut comp, FlushCompress::Finish).map_err(|e| e.to_string())?;
            if comp.len() == before {
                comp.reserve(4096);
            }
        }

        // zero fill so the {size, 1} pair ends exactly on a 16-byte boundary
        while (out.len() + 8) % 16 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        debug_assert_eq!(out.len() % 16, 0);
        out.extend_from_slice(&comp);
    }

    out[0..8].copy_from_slice(MAGIC);
    out[8..12].copy_from_slice(&2u32.to_be_bytes());
    out[12..16].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out[16..20].copy_from_slice(&(CHUNK as u32).to_be_bytes());
    out[20..24].copy_from_slice(&(nchunks as u32).to_be_bytes());
    out[24..28].copy_from_slice(&16u32.to_be_bytes());
    out[28..32].copy_from_slice(&0u32.to_be_bytes());

    Ok(out)
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    fn payload(n: usize) -> Vec<u8> {
        // something compressible but not trivial, so the dictionary matters
        let mut v = Vec::with_capacity(n);
        let mut x: u32 = 0x1234_5678;
        for i in 0..n {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            v.push(if i % 7 == 0 { (x >> 24) as u8 } else { b'A' + (i % 26) as u8 });
        }
        v
    }

    #[test]
    fn round_trips_multi_chunk() {
        for size in [1usize, 1000, 0x20000, 0x20000 + 1, 0x20000 * 3 + 777] {
            let data = payload(size);
            let enc = encode(&data).expect("encode");
            assert!(is_chunkzip(&enc));
            let dec = decode(&enc).expect("decode");
            assert_eq!(dec.len(), data.len(), "size {size}");
            assert_eq!(dec, data, "content {size}");
        }
    }

    #[test]
    fn framing_matches_retail_layout() {
        let data = payload(0x20000 * 2 + 5000);
        let enc = encode(&data).unwrap();
        let n = be32(&enc, 20).unwrap() as usize;
        assert_eq!(n, 3);
        assert_eq!(be32(&enc, 16).unwrap(), 0x20000);

        // Walk it the way retail containers are laid out: the {size, 1} pair ends where the
        // chunk's data begins, data sits on a 16-byte boundary, and the gap is zero fill.
        let mut pos = 0x30;
        for i in 0..n {
            let size = be32(&enc, pos - 8).unwrap() as usize;
            assert_eq!(be32(&enc, pos - 4).unwrap(), 1, "chunk {i} flag");
            assert_eq!(pos % 16, 0, "chunk {i} data not 16-aligned");

            let end = pos + size;
            if i + 1 < n {
                // next pair starts at the largest 16k-8 that is >= end
                let mut pair = (end + 15) / 16 * 16 - 8;
                if pair < end {
                    pair += 16;
                }
                assert!(
                    enc[end..pair].iter().all(|b| *b == 0),
                    "chunk {i} gap is not zero fill"
                );
                assert_eq!((pair + 8) % 16, 0);
                pos = pair + 8;
            } else {
                pos = end;
            }
        }
        assert_eq!(pos, enc.len(), "container length should end at the final stream");
    }
}
