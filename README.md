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
bigtool extract  ARCHIVE -o DIR     write files to disk (--recurse for nested archives)
bigtool pack     DIR -o ARCHIVE     build a .big from a directory tree
bigtool textures FILE.gnf           convert one GNF texture to DDS
bigtool textures --batch SRC OUT    convert every GNF under a directory
bigtool batch    DIR -o OUT         extract every *.big in a directory
```

Useful flags: `--decompress` (unwrap `chunkzip` / `chunkref` payloads), `--recurse` (extract
archives found inside archives), `--flat` (no directory tree),
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

Each file-info record is `{ addr_units, stored_size, other }` big-endian, with
`address = addr_units << shift` where `shift = buf[0x0a] & 0x3f`.

Which of the last two fields carries the stored length varies by archive, and getting it wrong is
silent until ranges overflow:

- the twelve top-level archives keep field 2 at **0** and store the length in field 3;
- about thirty nested archives do the opposite: field 2 holds the length and field 3 is a constant
  `0x100100`.

So the rule is "field 2 when non-zero, otherwise field 3". Trusting field 3 first put 220 entries
across 30 archives out of bounds; with the corrected rule all 1 609 archives pack cleanly.

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

## Nested archives and `chunkref`

Entries inside a `.big` often hold another archive. Two container types appear:

| Container | Magic | Contents |
|---|---|---|
| `chunkzip` | `chunkzip` | chunked raw DEFLATE, string data and most assets |
| `chunkref` | `chunkref` | N × RefPack streams that decompress to a nested `.big` |

`--recurse` unwraps both and extracts what it finds, writing an archive's contents into a sibling
directory named after it (`fe/online/core/scriptpod.big` → `fe/online/core/scriptpod/`).
`chunkref` entries are replaced on disk by the real archive they referenced, so the output tree
contains no stubs.

RefPack is EA's LZ77 variant: `0x10FB` header, flag-driven size field, four control forms. Chunkref
chunks are padded apart, and the magic also occurs inside compressed data, so streams are walked
sequentially using exact consumed-byte counts rather than by scanning for magic.

Measured on `fe_fix_demo.big` (4.5 GiB, one command, 46 s):

```
extracted        : 2430 written, 0 skipped, 0 failed
chunkzip         : 16498 decoded, 0 left as container
chunkref         : 621 unwrapped
nested           : 1241 archives, 28415 files (220 inner entries unreadable)
```

Recursion stops at depth 4. All 1 609 archives now extract without unreadable entries.

## Desktop app

`bigtool-gui` is an egui front-end — one binary, no Electron, no Node:

```bash
cargo build --release --features gui     # -> target/release/bigtool-gui.exe
bigtool-gui some_archive.big             # or just open it and drop the file in
```

| Panel | What it does |
|---|---|
| Archive | entry table with path/idx/address/size, filter box, extract all or up to a selection, export one entry, export a `.gnf` entry straight to `.dds` |
| Textures | batch `.gnf` → `.dds` over a folder tree |
| Pack | folder → `.big` |

Extraction runs on a worker thread with a live progress bar, and the log reports the same figures
the CLI prints. The output folder defaults to `<archive>_extracted` beside the archive, so
"Extract all" works without picking a directory first.

The GUI calls the same library the CLI does — verified by extracting `patch_b.big` through both and
comparing: 2 112 files, 2 112 byte-identical, 0 differences.

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

- **`--compress` controls how payloads are stored:

| value | behaviour |
|---|---|
| `auto` (default) | chunkzip where the `--template` archive did — retail stores 2 553 of 2 656 `anim.big` entries that way |
| `all` | chunkzip every entry above 64 bytes |
| `none` | raw bytes |

Compression matters: repacking `patch_b.big` uncompressed produced ~600 MB against the 410 MB
shipped file. With `--compress auto` the result is **409.16 MiB against 429.55 MB — 99.9% of the
shipped size** — and repacked `anim.big` is 1 021.9 MB against 1 024.9 MB.

### Writing chunkzip containers

The encoder relies on the framing recovered from 848 chunks in 16 retail containers: every chunk's
raw-DEFLATE stream starts on a 16-byte boundary, immediately preceded by
`{ u32 compressed_size, u32 1 }`, with zero fill back to the previous stream. Chunks after the first
are compressed against the previous 32 KiB of *decompressed* output.

Compression is level 9: across 48 retail containers that came to **99.3% of EA's own size**
(level 6 was 103.6%), with zero round-trip failures.

Payloads are written uncompressed.** Shipped archives wrap many entries in `chunkzip`; the
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

**1.5.0**
- `extract --entry <index|substring>` extracts exactly one entry; an ambiguous selector lists the
  candidates instead of guessing.
- `pack --compress auto|all|none`: payloads are written as chunkzip containers again, matching the
  template's per-entry choice. Repacked archives land at 99.9% of the shipped size instead of ~150%.
- `chunkzip::encode`: raw DEFLATE at level 9 with the 32 KiB preset dictionary, in the recovered
  retail framing (16-byte-aligned streams, `{size, 1}` pair before each, zero fill between).
- Verified: `patch_b.big` repacked and re-extracted byte-identical (58/58), `anim.big` likewise
  (2 656/2 656).
- The GUI gained "Extract selected" (one entry, not a prefix) and pack options for template and
  payload storage.

**1.4.0**
- Desktop app (`bigtool-gui`): archive browser, extract with live progress, single-entry export,
  `.gnf` → `.dds` export from inside an archive, texture batch, and packing.
- The CLI and the app now share a library crate instead of each owning the modules.
- `Archive::entry_bytes()` reads one entry's payload, optionally unwrapping chunkzip/chunkref.

**1.3.1**
- Fixed the file-info record length field: field 2 is the stored length when non-zero, otherwise
  field 3. Field 3 is a constant `0x100100` in ~30 nested archives, which had pushed 220 entries out
  of bounds. All 1 609 archives now extract cleanly (`fe_fix_demo`: 28 635 nested files, up 220).
- Same correction applied to the Python reference implementation.

**1.3.0**
- `extract --recurse`: unwrap `chunkref` (RefPack) containers and extract archives found inside
  archives, to depth 4. On `fe_fix_demo.big` that is 1 241 nested archives and 28 415 files in one
  46 s pass.
- RefPack decoder with consumed-byte tracking (`refpack.rs`), chunkref container reader
  (`chunkref.rs`), and unit tests for both.
- Nested failures are reported separately from top-level ones instead of being merged.

**1.1.1**
- chunkzip: the frame gap is detected per container and tried first, and the final chunk's gap is
  derived exactly from the bytes remaining — which decodes containers whose last chunk is stored
  rather than deflated. Recovers ~460 FE textures that previously stayed wrapped.
- Nested `.big` archives that carry no directory trie now extract with flat basenames.

**1.1.0** — first Rust release: `info`, `list`, `check`, `census`, `extract`, `textures`, `batch`.

## License

MIT. Contains no game data and no keys; you supply your own legally obtained archives.
