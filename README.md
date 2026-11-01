# bigtool

Reader and extractor for EA **"EB" `.big` archives** (NBA LIVE 19 / Ignite engine), with a PS4
**GNF → DDS** texture converter. Single static binary, no runtime dependencies.

Reverse-engineered from `eboot.elf` in Ghidra rather than guessed: the community never produced a
working extractor for this archive variant, and every fixed-stride assumption fails because the
layout is a **directory trie plus a parallel flat name table**, not a flat name→offset list.

## Install

```bash
cargo install --git https://github.com/thewulf7/bigtool
```

or grab a prebuilt binary from [Releases](https://github.com/thewulf7/bigtool/releases).

## Commands

```
bigtool info     ARCHIVE            header + structural diagnostics
bigtool list     ARCHIVE            file index with positions, addresses, sizes
bigtool check    ARCHIVE            validate pointers, payloads, and type-vs-extension
bigtool census   ARCHIVE            classify payload types (chunkzip/RSF/GNF/media/...)
bigtool extract  ARCHIVE -o DIR     write files to disk
bigtool pack     DIR -o ARCHIVE     build a .big from a directory tree
bigtool textures FILE.gnf           convert one GNF texture to DDS
bigtool textures --batch SRC OUT    convert every GNF under a directory
bigtool batch    DIR -o OUT         extract every *.big in a directory
```

Useful flags: `--decompress` (unwrap `chunkzip` payloads), `--flat` (no directory tree),
`-n N` (cap entries), `--skip-existing`, `--no-progress`, `--json` (`info` / `list`),
`-f SUBSTR` (`list`), `--force` (`textures`).

## Examples

```bash
bigtool info graphics_full.big
bigtool list anim.big -f lua
bigtool census patch.big
bigtool extract anim.big -o out/anim --decompress
bigtool textures --batch extracted_textures/ dds/ 
bigtool batch /path/to/game -o out --decompress
```

## Verified results

Validated against the 12 shipped archives from the retail PS4 package — not fixtures. Every
number below comes from running the tool on the real data:

| Archive | Entries | Union coverage | Content check |
|---|---|---|---|
| `graphics_full.big` | 26 952 | 0.9962 | 4000/4000 |
| `patch_post_fix.big` | 19 118 | 0.9963 | 4000/4000 |
| `graphics_demo.big` | 24 842 | 0.9949 | 4000/4000 |
| `graphics_fix.big` | 6 432 | 0.9936 | 3999/4000 |
| `anim.big` | 2 656 | 0.9932 | 2 656/2 656 |
| `audio_fix_demo.big` | 319 | 0.9995 | 316/319 |
| `patch.big` | 2 202 | 0.9981 | 2 201/2 202 |
| `patch_post_fix_b.big` | 2 608 | 0.9982 | 2 608/2 608 |
| `fe_fix_demo.big` | 2 430 | 0.9987 | 2 363/2 430 |
| `patch_b.big` | 58 | 0.9997 | 58/58 |
| `audio_full.big` | 6 | 1.0000 | 6/6 |
| `fe_full.big` | 251 | 0.9985 | 251/251 |

Trie leaf counts equal `fileCount` and out-of-bounds entries are 0 in all twelve. The remaining
`check` misses are payload types the recogniser does not know — On2 VP6 streams, `.sub` subtitle
scripts, soundbank variants — not bad data; they extract byte-exact regardless.

Decisive evidence the index mapping is right: after extracting `graphics_full.big` (26 952
entries), payload type and extension separate perfectly — **16 314 `.gnf` files are all `GNF `
textures**, **10 437 `.mcd` files are all `RSF\0` model containers**, and 30 `.dds` files are all
`DDS `.

## Format notes

### Archive header (32 bytes)

| Offset | Type | Field |
|---|---|---|
| `0x00` | 2s | `"EB"` |
| `0x02` | u16 BE | version = 3 |
| `0x04` | u32 BE | fileCount |
| `0x08` | u32 BE | flags |
| `0x0c` | u32 BE | trie offset (base) |
| `0x10` | u32 BE | trie offset (relative) |
| `0x14` | u8 | name length (flat table stride) |
| `0x16` | u16 BE | unknown |
| `0x1c` | u32 BE | file length (wraps modulo 2^32 above 4 GiB) |
| `0x30` | — | file-info table (16- or 20-byte stride) |

Each file-info record is `{ addr_units, alt, size }` big-endian; `address = addr_units << shift`
where `shift = buf[0x0a] & 0x3f`, and `size == 0` falls back to `alt`.

### The indexing rule

The file-info table is **parallel to the flat name table**: position *i* names entry *i*. The
directory trie supplies each file's *path*; its leaf field is a hash-like identifier, **not** an
index into the file-info table. Using that leaf field as an index yields in-range addresses and
plausible-looking binary that is silently wrong for most entries — the symptom is extracted XML
and JSON files containing EA Reflection geometry instead of markup.

### chunkzip v2

```
0x00  8s  "chunkzip"
0x08 u32  version = 2
0x0c u32  total decompressed size
0x10 u32  chunk payload size (0x20000)
0x14 u32  chunk count
0x18 u32  descriptor size = 16
0x20      descriptor region; chunk 0 stream starts at 0x30
```

Chunks are **raw DEFLATE** (`window bits -15`, no zlib header), and chunk *i>0* was compressed
with the previous 32 KiB of decompressed output as a preset dictionary — inflating without it
fails with "invalid distance too far back". Each chunk is preceded by a frame marker whose width
varies per container (10, 11, 12, 17 and 23 bytes observed), so the decoder scans a small window
and accepts a candidate only when it inflates to exactly the expected size. The final chunk is
handled exactly: whatever remains after its payload is the frame gap, which resolves containers
whose last chunk is stored rather than deflated. Every decode is checked against the declared
total, so a wrong framing can never be accepted silently.

### GNF textures

Little-endian header; `SurfaceFormat = (word1 & 0x03f00000) >> 20`, width/height packed into
`word2`, mip count in `word3`. Data starts at `0x08 + contentsSize` and is **Morton/Z-order block
swizzled** in 8×8 block tiles, which this tool undoes per mip level.

Formats handled: BC1 (0x23), BC2, BC3, BC4, BC5, BC6, BC7 and RGBA8 (0x0a). Unsupported formats
are skipped and reported by name rather than written corrupt.

## Packing

`pack` rebuilds an archive from a directory tree — the reverse of `extract`:

```bash
bigtool pack extracted/patch_b -o patch_b_new.big --template patch_b.big
```

It writes the header, file-info table, flat name table, directory trie and a 4 KiB-aligned data
section. `--template` copies the header parameters (entry stride, name length, flags, address
shift) and the per-entry metadata in the record tail from an existing archive, so a modified tree
repacks into a drop-in replacement; without it the defaults are stride 20, name length sized to the
longest basename, and shift 12.

Round-trip is verified byte-exact by the tool's own reader:

| Tree | Files | pack + extract |
|---|---|---|
| `patch_b` | 58 | identical |
| `anim` (91 directories) | 2 656 | identical |
| fresh tree, no template | 5 (incl. duplicate basenames) | identical |

### What packing does not do yet

- **Payloads are written uncompressed.** Shipped archives wrap many entries in `chunkzip`; the
  loader distinguishes by magic and every archive already contains uncompressed entries, but a
  repacked archive is therefore larger than the original. Re-compression is not implemented.
- The **8-byte record tail** copied from the template (or zeroed without one) is not understood. If
  it encodes a compression flag rather than build metadata, a repacked archive would need
  `chunkzip` payloads to satisfy it — that is the first thing to check if the game rejects one.
- The directory trie is rebuilt from scratch, so node order may differ from the shipped archive
  (for `anim`: 2 747 nodes versus 2 746). Paths, names and data all round-trip.

## Performance

Extracting `anim.big` (2 656 files, 1.5 GB, chunkzip decoded) on a Windows host:

| Implementation | Time |
|---|---|
| Python (zlib + mmap window) | 67 s |
| This Rust build (release, mmap) | 6.3 s |

Roughly **10× faster**, from memory-mapping the whole archive and skipping the per-chunk probe
pass the Python version needed.

## Compatibility with the Python tool

Outputs were compared byte-for-byte against the original Python implementation:

| Test | Result |
|---|---|
| `patch_b.big` extraction (58 files) | identical SHA-256 for all 58 |
| `graphics_full.big`, 120 entries, `--decompress` | identical, 120/120 chunkzip decoded |
| `anim.big` extraction (2 656 files) | identical, 2 552 chunkzip decoded |
| GNF → DDS (40 textures, BC1/BC5/BC7) | identical bytes |
| `info` / `list` / `census` / `check` | same entries, addresses, sizes, classifications |

## Known limits

- Archives ≥ 4 GiB store a wrapped 32-bit length; the real file size from the OS is used instead.
- A nested `.big` archive without a directory trie (they store flat basenames) is extracted with
  basenames only; this build falls back instead of failing.
- One payload out of ~150 000 is truncated inside the retail archive itself
  (`dyckman_floorgarden_norm.gnf` declares 11 chunks / 1 403 136 bytes but is 5 301 bytes short),
  so it is extracted as the raw container.
- `Format8` (single-channel) and `Format32_32_32_32` textures are detected and skipped.
- Cube and array textures are emitted as a single 2D surface.
- `SBle`, `data`, `GD.STRM`, `RSF\0` and `DB\0` payloads are returned as stored — those are
  separate container formats, not `.big` concerns.

## Changelog

**1.2.0**
- `pack`: build a `.big` from a directory tree, with `--template` for drop-in replacement of a
  shipped archive. Round-trip verified byte-exact (58 and 2 656 file trees).
- `check` recognises `RSF ` model containers and `chunkref` stubs as known payloads.

**1.1.1**
- chunkzip: the frame gap is detected per container and tried first, and the final chunk's gap is
  derived exactly from the bytes remaining — which decodes containers whose last chunk is stored
  rather than deflated. Recovers ~460 FE textures that previously stayed wrapped.
- Nested `.big` archives that carry no directory trie now extract with flat basenames.

**1.1.0** — first Rust release: `info`, `list`, `check`, `census`, `extract`, `textures`, `batch`.

## License

MIT. Contains no game data and no keys; you supply your own legally obtained archives.
