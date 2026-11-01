//! EA RefPack (QFS) decompression.
//!
//! RefPack is an LZ77-style codec used across EA titles. A stream begins with a 16-bit header whose
//! low byte is `0xFB`; the high byte carries flags (`0x8000` selects a 4-byte rather than 3-byte
//! output-size field, `0x0100` means a compressed-size field is present). The body is a sequence of
//! control bytes:
//!
//! ```text
//! 0xxxxxxx  short form: f 0..1023, n 3..10,  d 0..3
//! 10xxxxxx  long form:  f 0..16384, n 4..67, d 0..3
//! 110xxxxx  very long:  f 0..131071, n 5..1028, d 0..3
//! 111xxxxx  literal run (deterministic length) or end of stream
//! ```
//!
//! `consumed()` reporting matters: chunkref containers hold several padded streams back to back, so
//! the caller needs to know exactly how many input bytes each stream used.
//!
//! Algorithm follows pySAGE's reference implementation (ClementJ18/pySAGE, MIT).

#[allow(dead_code)] // used by callers and tests
pub fn is_refpack(data: &[u8]) -> bool {
    data.len() >= 2 && data[1] == 0xFB
}

fn copy_ref(out: &mut Vec<u8>, distance: usize, length: usize) -> Result<(), String> {
    if distance == 0 || distance > out.len() {
        return Err(format!(
            "back-reference reaches before the start of the output (distance {distance} at {})",
            out.len()
        ));
    }
    let mut remaining = length;
    let mut start = out.len() - distance;
    // overlapping runs are how RefPack encodes repeats: copy in chunks no larger than `distance`
    while remaining > 0 {
        let n = remaining.min(distance);
        for k in 0..n {
            let b = out[start + k];
            out.push(b);
        }
        start += n;
        remaining -= n;
    }
    Ok(())
}

/// Decompress one RefPack stream starting at `offset`.
/// Returns the output and the exact number of input bytes consumed.
pub fn decompress_consumed(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), String> {
    if data.len() < offset + 6 {
        return Err("RefPack stream too short for a header".to_string());
    }
    let first = data[offset];
    let second = data[offset + 1];
    if second != 0xFB {
        return Err(format!("not a RefPack stream (magic {:02x}{:02x})", first, second));
    }
    let flags = ((first as u16) << 8) | second as u16;
    let size_width = if flags & 0x8000 != 0 { 4 } else { 3 };
    let mut pos = offset + 2;
    if flags & 0x0100 != 0 {
        pos += size_width;
    }
    if pos + size_width > data.len() {
        return Err("RefPack stream too short for its size field".to_string());
    }
    let mut unpacked: usize = 0;
    for i in 0..size_width {
        unpacked = (unpacked << 8) | data[pos + i] as usize;
    }
    pos += size_width;

    let mut out: Vec<u8> = Vec::with_capacity(unpacked);
    let n = data.len();

    loop {
        if pos >= n {
            return Err("RefPack stream ends mid-command".to_string());
        }
        let b = data[pos];
        pos += 1;

        if b & 0x80 == 0 {
            // short form
            if pos >= n {
                return Err("truncated short form".to_string());
            }
            let second_b = data[pos];
            pos += 1;
            let run = (b & 3) as usize;
            if pos + run > n {
                return Err("truncated literal run".to_string());
            }
            out.extend_from_slice(&data[pos..pos + run]);
            pos += run;
            let distance = (((b & 0x60) as usize) << 3) + second_b as usize + 1;
            let length = (((b & 0x1C) >> 2) as usize) + 3;
            copy_ref(&mut out, distance, length)?;
            continue;
        }
        if b & 0x40 == 0 {
            // long form
            if pos + 2 > n {
                return Err("truncated long form".to_string());
            }
            let second_b = data[pos];
            let third = data[pos + 1];
            pos += 2;
            let run = (second_b >> 6) as usize;
            if pos + run > n {
                return Err("truncated literal run".to_string());
            }
            out.extend_from_slice(&data[pos..pos + run]);
            pos += run;
            let distance = (((second_b & 0x3F) as usize) << 8) + third as usize + 1;
            let length = ((b & 0x3F) as usize) + 4;
            copy_ref(&mut out, distance, length)?;
            continue;
        }
        if b & 0x20 == 0 {
            // very long form
            if pos + 3 > n {
                return Err("truncated very-long form".to_string());
            }
            let second_b = data[pos];
            let third = data[pos + 1];
            let fourth = data[pos + 2];
            pos += 3;
            let run = (b & 3) as usize;
            if pos + run > n {
                return Err("truncated literal run".to_string());
            }
            out.extend_from_slice(&data[pos..pos + run]);
            pos += run;
            let distance =
                ((((b & 0x10) >> 4) as usize) << 16) + ((second_b as usize) << 8) + third as usize + 1;
            let length = ((((b & 0x0C) >> 2) as usize) << 8) + fourth as usize + 5;
            copy_ref(&mut out, distance, length)?;
            continue;
        }
        let run = (((b & 0x1F) as usize) << 2) + 4;
        if run <= 112 {
            if pos + run > n {
                return Err("truncated literal run".to_string());
            }
            out.extend_from_slice(&data[pos..pos + run]);
            pos += run;
            continue;
        }
        // stop code: trailing literals, then the stream ends
        let run = (b & 3) as usize;
        if pos + run > n {
            return Err("truncated trailing literal".to_string());
        }
        out.extend_from_slice(&data[pos..pos + run]);
        pos += run;
        break;
    }

    if out.len() != unpacked {
        return Err(format!(
            "decoded {} bytes but the stream declares {}",
            out.len(),
            unpacked
        ));
    }
    Ok((out, pos - offset))
}

/// Convenience wrapper for a stream that starts at the beginning of `data`.
#[allow(dead_code)] // used by tests
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    decompress_consumed(data, 0).map(|(out, _)| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal-only stream: header (0x10FB, 3-byte size), one 0xE? literal command, stop code.
    fn literal_stream(payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.push(0x10);
        s.push(0xFB);
        let size = payload.len() as u32;
        s.push(((size >> 16) & 0xFF) as u8);
        s.push(((size >> 8) & 0xFF) as u8);
        s.push((size & 0xFF) as u8);
        // 0xE0 | n encodes a literal run of (n<<2)+4 for n in 1..=28
        let n = (payload.len().saturating_sub(4)) >> 2;
        s.push(0xE0 | (n as u8));
        s.extend_from_slice(payload);
        s.push(0xFC); // stop
        s
    }

    #[test]
    fn decodes_literal_stream() {
        let payload = b"HELLO!!!";
        let stream = literal_stream(payload);
        let (out, used) = decompress_consumed(&stream, 0).unwrap();
        assert_eq!(out, payload);
        assert!(used <= stream.len());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(!is_refpack(b"\x10\xAA"));
        assert!(decompress(b"\x10\xAA\x00\x00\x00").is_err());
    }
}
