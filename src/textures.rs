//! EA/PS4 GNF texture → DDS conversion.
//!
//! Layout (little-endian), confirmed against GFD-Studio's `GNFTexture` reader/writer:
//!
//! ```text
//! 0x00 u32  magic "GNF "
//! 0x04 u32  contentsSize (0xF8 = 248)
//! 0x08 u8   version (2)
//! 0x09 u8   textureCount (1)
//! 0x0a u8   alignment (8)
//! 0x0b u8   unused
//! 0x0c u32  streamSize == total file size
//! 0x10 u32  word0
//! 0x14 u32  word1: SurfaceFormat = (word1 & 0x03f00000) >> 20
//! 0x18 u32  word2: Width  = (word2 & 0x00003fff) + 1
//!                   Height = ((word2 & 0x0fffc000) >> 14) + 1
//! 0x1c u32  word3: BaseMipLevel = (word3 >> 12) & 0xf
//!                   LastMipLevel = (word3 >> 16) & 0xf
//! ```
//!
//! Texture data starts at `0x08 + contentsSize` and is `streamSize - contentsSize - 8` bytes,
//! stored block-swizzled in PS4 Morton/Z order: the block grid is walked in 8x8 block tiles and
//! within a tile blocks follow a Z-order curve.

use std::fs;
use std::path::{Path, PathBuf};

pub const GNF_MAGIC: &[u8] = b"GNF ";

#[derive(Clone, Copy)]
pub struct SurfaceFormat {
    pub name: &'static str,
    pub block_size: usize,
    pub fourcc: Option<&'static [u8; 4]>,
    pub dxgi: Option<u32>,
}

pub fn surface_format(fmt: u32) -> Option<SurfaceFormat> {
    let f = |name, block_size, fourcc: Option<&'static [u8; 4]>, dxgi| SurfaceFormat {
        name,
        block_size,
        fourcc,
        dxgi,
    };
    Some(match fmt {
        0x0A => f("RGBA8", 4, None, None),
        0x23 => f("BC1", 8, Some(b"DXT1"), None),
        0x24 => f("BC2", 16, Some(b"DXT3"), None),
        0x25 => f("BC3", 16, Some(b"DXT5"), None),
        0x26 => f("BC4", 8, Some(b"ATI1"), None),
        0x27 => f("BC5", 16, Some(b"ATI2"), None),
        0x28 => f("BC6", 16, None, Some(95)),
        0x29 => f("BC7", 16, None, Some(98)),
        _ => return None,
    })
}

fn u32le(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug)]
pub struct GnfError(pub String);

impl std::fmt::Display for GnfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for GnfError {}

#[derive(Debug, Clone)]
#[allow(dead_code)] // full header kept for callers that report details
pub struct GnfInfo {
    pub version: u8,
    pub textures: u8,
    pub alignment: u8,
    pub stream_size: u32,
    pub contents_size: u32,
    pub format: u32,
    pub width: usize,
    pub height: usize,
    pub mips: usize,
    pub data_offset: usize,
    pub data_size: usize,
    pub file_size: usize,
}

pub fn parse(data: &[u8]) -> Result<GnfInfo, GnfError> {
    if data.len() < 0x30 || &data[..4] != GNF_MAGIC {
        let magic: String = data
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        return Err(GnfError(format!("not a GNF file (magic=0x{magic})")));
    }
    let contents_size = u32le(data, 4);
    let version = data[8];
    let textures = data[9];
    let alignment = data[10];
    let stream_size = u32le(data, 12);
    let w1 = u32le(data, 0x14);
    let w2 = u32le(data, 0x18);
    let w3 = u32le(data, 0x1C);

    let fmt = (w1 & 0x03F0_0000) >> 20;
    let width = ((w2 & 0x0000_3FFF) + 1) as usize;
    let height = (((w2 & 0x0FFF_C000) >> 14) + 1) as usize;
    let last_mip = ((w3 & 0x000F_0000) >> 16) as usize;

    let data_offset = 8 + contents_size as usize;
    let data_size = (stream_size as i64 - contents_size as i64 - 8).max(0) as usize;

    Ok(GnfInfo {
        version,
        textures,
        alignment,
        stream_size,
        contents_size,
        format: fmt,
        width,
        height,
        mips: last_mip + 1,
        data_offset,
        data_size,
        file_size: data.len(),
    })
}

/// Z-order (Morton) index of tile slot `t` inside an `sx * sy` block tile.
fn morton(t: usize, sx: usize, sy: usize) -> usize {
    let mut num1 = 1usize;
    let mut num2 = 1usize;
    let mut num3 = t;
    let mut num4 = sx;
    let mut num5 = sy;
    let mut num6 = 0usize;
    let mut num7 = 0usize;

    while num4 > 1 || num5 > 1 {
        if num4 > 1 {
            num6 += num2 * (num3 & 1);
            num3 >>= 1;
            num2 *= 2;
            num4 >>= 1;
        }
        if num5 > 1 {
            num7 += num1 * (num3 & 1);
            num3 >>= 1;
            num1 *= 2;
            num5 >>= 1;
        }
    }
    num7 * sx + num6
}

/// Undo the PS4 8x8-tile Morton swizzle over one block-compressed surface or mip level.
pub fn deswizzle(data: &[u8], width: usize, height: usize, block_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let height_blocks = (height / 4).max(1);
    let width_blocks = (width / 4).max(1);
    let h_tiles = height_blocks.div_ceil(8);
    let w_tiles = width_blocks.div_ceil(8);
    let mut src = 0usize;

    for ty in 0..h_tiles {
        for tx in 0..w_tiles {
            for t in 0..64usize {
                let pi = morton(t, 8, 8);
                let by = ty * 8 + pi / 8;
                let bx = tx * 8 + pi % 8;
                if bx < width_blocks && by < height_blocks {
                    let dst = block_size * (by * width_blocks + bx);
                    if dst + block_size <= out.len() && src + block_size <= data.len() {
                        out[dst..dst + block_size]
                            .copy_from_slice(&data[src..src + block_size]);
                    }
                }
                src += block_size;
            }
        }
    }
    out
}

pub fn mip_sizes(width: usize, height: usize, block_size: usize, mips: usize) -> Vec<usize> {
    let mut sizes = Vec::with_capacity(mips);
    let (mut w, mut h) = (width, height);
    for _ in 0..mips {
        if block_size == 4 {
            sizes.push(w.max(1) * h.max(1) * 4);
        } else {
            sizes.push(w.div_ceil(4).max(1) * h.div_ceil(4).max(1) * block_size);
        }
        w = (w / 2).max(1);
        h = (h / 2).max(1);
    }
    sizes
}

fn dds_header(
    width: usize,
    height: usize,
    mips: usize,
    fmt: SurfaceFormat,
    data_len: usize,
) -> Vec<u8> {
    let mut flags: u32 = 0x1 | 0x2 | 0x4 | 0x1000 | 0x20000 | 0x80000;
    if mips > 1 {
        flags |= 0x20000;
    }

    let mut hdr = vec![0u8; 128];
    hdr[0..4].copy_from_slice(b"DDS ");
    hdr[4..8].copy_from_slice(&124u32.to_le_bytes());
    hdr[8..12].copy_from_slice(&flags.to_le_bytes());
    hdr[12..16].copy_from_slice(&(height as u32).to_le_bytes());
    hdr[16..20].copy_from_slice(&(width as u32).to_le_bytes());
    hdr[20..24].copy_from_slice(&(data_len as u32).to_le_bytes());
    hdr[24..28].copy_from_slice(&0u32.to_le_bytes());
    hdr[28..32].copy_from_slice(&(mips as u32).to_le_bytes());
    hdr[76..80].copy_from_slice(&32u32.to_le_bytes());
    hdr[80..84].copy_from_slice(&0x4u32.to_le_bytes());

    match fmt.fourcc {
        Some(fourcc) => hdr[84..88].copy_from_slice(fourcc),
        None => {
            hdr[84..88].copy_from_slice(b"DX10");
            // DXGI format, resource dimension = 3 (TEXTURE2D), misc, array size 1, misc2
            let dxgi = fmt.dxgi.unwrap_or(98);
            let mut dx10 = Vec::with_capacity(20);
            dx10.extend_from_slice(&dxgi.to_le_bytes());
            dx10.extend_from_slice(&3u32.to_le_bytes());
            dx10.extend_from_slice(&0u32.to_le_bytes());
            dx10.extend_from_slice(&1u32.to_le_bytes());
            dx10.extend_from_slice(&0u32.to_le_bytes());
            hdr.extend_from_slice(&dx10);
        }
    }
    hdr[108..112].copy_from_slice(&0x1000u32.to_le_bytes());
    hdr
}

#[derive(Debug, Clone)]
pub struct DdsMeta {
    pub format: &'static str,
    pub width: usize,
    pub height: usize,
    pub mips: usize,
    pub payload: usize,
    pub expected: usize,
}

pub fn to_dds(data: &[u8]) -> Result<(Vec<u8>, DdsMeta), GnfError> {
    let info = parse(data)?;
    let fmt = surface_format(info.format).ok_or_else(|| {
        GnfError(format!("unsupported surface format 0x{:x}", info.format))
    })?;

    let (w, h) = (info.width, info.height);
    let mut mips = info.mips;

    let body_start = info.data_offset.min(data.len());
    let body_end = (info.data_offset + info.data_size).min(data.len());
    let body = &data[body_start..body_end];

    let mut sizes = mip_sizes(w, h, fmt.block_size, mips);
    let mut total: usize = sizes.iter().sum();
    if info.data_size < total {
        // keep only the mips the payload can actually supply
        let mut keep = 0usize;
        let mut acc = 0usize;
        for s in &sizes {
            if acc + s > info.data_size {
                break;
            }
            acc += s;
            keep += 1;
        }
        mips = keep.max(1);
        sizes.truncate(mips);
        total = sizes.iter().sum();
    }

    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut off = 0usize;
    let (mut cw, mut ch) = (w, h);
    for size in &sizes {
        let end = (off + size).min(body.len());
        let chunk = if off < body.len() {
            &body[off..end]
        } else {
            &[][..]
        };
        out.extend_from_slice(&deswizzle(chunk, cw, ch, fmt.block_size));
        off += size;
        cw = (cw / 2).max(1);
        ch = (ch / 2).max(1);
    }

    let header = dds_header(w, h, mips, fmt, out.len());
    let meta = DdsMeta {
        format: fmt.name,
        width: w,
        height: h,
        mips,
        payload: out.len(),
        expected: total,
    };
    let mut all = Vec::with_capacity(header.len() + out.len());
    all.extend_from_slice(&header);
    all.extend_from_slice(&out);
    Ok((all, meta))
}

#[derive(Debug, Default)]
pub struct BatchReport {
    pub converted: usize,
    pub already_present: usize,
    pub unsupported: usize,
    pub failed: usize,
    pub reasons: Vec<(String, usize)>,
}

fn add_reason(rep: &mut BatchReport, reason: String) {
    if let Some(slot) = rep.reasons.iter_mut().find(|(r, _)| *r == reason) {
        slot.1 += 1;
    } else {
        rep.reasons.push((reason, 1));
    }
}

fn walk_gnf(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_gnf(&p, out);
        } else if p
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase() == "gnf")
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

/// Convert every `.gnf` under `src_dir` into `out_dir`, mirroring subdirectories. Resumable:
/// existing outputs are skipped unless `force` is set.
pub fn batch(
    src_dir: &Path,
    out_dir: &Path,
    skip_existing: bool,
    mut progress: Option<&mut dyn FnMut(usize, usize)>,
) -> BatchReport {
    let mut files = Vec::new();
    walk_gnf(src_dir, &mut files);
    files.sort();
    let total = files.len();
    let mut rep = BatchReport::default();

    for (i, src) in files.iter().enumerate() {
        let rel = src.strip_prefix(src_dir).unwrap_or(src);
        let dst = out_dir.join(rel).with_extension("dds");

        if skip_existing {
            if let Ok(meta) = fs::metadata(&dst) {
                if meta.len() > 128 {
                    rep.already_present += 1;
                    if let Some(p) = progress.as_mut() {
                        p(i + 1, total);
                    }
                    continue;
                }
            }
        }

        match fs::read(src) {
            Ok(data) => match to_dds(&data) {
                Ok((dds, _meta)) => {
                    if let Some(parent) = dst.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    match fs::write(&dst, &dds) {
                        Ok(()) => rep.converted += 1,
                        Err(e) => {
                            rep.failed += 1;
                            add_reason(&mut rep, format!("write error: {e}"));
                        }
                    }
                }
                Err(e) => {
                    rep.unsupported += 1;
                    add_reason(&mut rep, e.0);
                }
            },
            Err(e) => {
                rep.failed += 1;
                add_reason(&mut rep, format!("read error: {e}"));
            }
        }

        if let Some(p) = progress.as_mut() {
            p(i + 1, total);
        }
    }
    rep
}
