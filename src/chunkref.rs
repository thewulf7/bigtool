//! EA `chunkref` container.
//!
//! A chunkref entry is not an archive: it holds a **sequence of RefPack streams** that decompress to
//! a nested `.big` archive. Layout (big-endian):
//!
//! ```text
//! 0x00  8s  "chunkref"
//! 0x08 u32  version (2)
//! 0x0c u32  total uncompressed size
//! 0x10 u32  chunk size (0x20000)
//! 0x14 u32  chunk count
//! 0x18      padding, then the first RefPack stream
//! ```
//!
//! Streams are padded apart, and the `0x10FB` magic also occurs inside compressed data, so streams
//! are walked sequentially using the exact byte count each one consumes, then the next magic is
//! located within a small window.

use crate::refpack;

pub fn is_chunkref(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == b"chunkref"
}

fn be32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[allow(dead_code)] // reported by the CLI when verbose
pub struct ChunkRefInfo {
    pub version: u32,
    pub total: u32,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

/// Decode a chunkref container into its payload (normally a complete nested `.big`).
pub fn decode(data: &[u8]) -> Result<(Vec<u8>, ChunkRefInfo), String> {
    if !is_chunkref(data) {
        return Err("not a chunkref container".to_string());
    }
    let version = be32(data, 8).ok_or("truncated chunkref header")?;
    let total = be32(data, 12).ok_or("truncated chunkref header")?;
    let chunk_size = be32(data, 16).ok_or("truncated chunkref header")?;
    let chunk_count = be32(data, 20).ok_or("truncated chunkref header")?;

    // first stream: scan a short header area for the RefPack magic
    let mut pos = match data[24..].windows(2).position(|w| w[0] == 0x10 && w[1] == 0xFB) {
        Some(p) => 24 + p,
        None => return Err("no RefPack stream found in chunkref".to_string()),
    };

    let mut out: Vec<u8> = Vec::with_capacity(total as usize);
    let want = chunk_count.max(1);
    for _ in 0..want {
        let (piece, consumed) = refpack::decompress_consumed(data, pos)?;
        out.extend_from_slice(&piece);
        pos += consumed;
        // chunks are padded apart before the next stream starts
        let window_end = data.len().min(pos + 64);
        match data[pos..window_end].windows(2).position(|w| w[0] == 0x10 && w[1] == 0xFB) {
            Some(p) => pos += p,
            None => break,
        }
    }

    Ok((
        out,
        ChunkRefInfo {
            version,
            total,
            chunk_size,
            chunk_count,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_container() {
        assert!(!is_chunkref(b"chunkzip"));
        assert!(decode(b"chunkref").is_err());
    }
}
