# `lau-bigfun-rs`

A Rust library and CLI tool for inspecting, querying, and unpacking bigfile archives shipped with the *Legend*-era *Tomb Raider* games:

- *Tomb Raider: Legend*
- *Tomb Raider: Anniversary*
- *Tomb Raider: Underworld*
- *Lara Croft and the Guardian of Light*

You must use your own legally obtained game files with this tool. None are or will be provided here.

## Scope & Status

This is a hobby project intended to support specific content export tools being developed for the *Legend*-era *Tomb Raider* games. Variants of the "bigfile" archive format used by other games will not be supported.

This tool is feature complete and will receive long-term maintenance. Please report bugs as issues; feature requests are out of scope. Pull requests are closed, but forks are welcome.

## Features

- **Cross-Platform Archive Support:** Reads single-file (`.dat`, `.000`) and multi-part (`.000`..`.NNN`) archives across PC and console releases, automatically detecting TOC byte order (`little` / `big`) and virtual segment strides.
- **Filename Hash Resolution:** Resolves `CRC-32/BZIP2` path hashes through filelists you supply with `--filelist`, with `__unknown/<hash>.bin` fallback naming. No filelists are bundled.
- **Archive Inspection & Filtering:** Reports part geometry, hash resolution coverage, and SKU distributions, and filters TOC entries by substring, glob pattern, unresolved status, or SKU bitmask.
- **Single-Asset & Parallel Unpacking:** Transparently inflates `zlib`-compressed payloads (or exports raw bytes) to `stdout`, a single file, or a sanitized directory tree across worker threads.
- **Structured JSON Output:** Emits versioned `"schema": 1` JSON across all subcommands for scripting and `jq` pipelines.

## Installation

Each [release](https://github.com/EitrLicht/lau-bigfun-rs/releases) includes a standalone Windows x64 `lau-bigfun.exe` (no Visual C++ runtime needed), built from the tagged commit by this repository's release workflow. Verify a download with the GitHub CLI (signed in with `gh auth login`):

```bash
gh attestation verify lau-bigfun-<version>-x86_64-pc-windows-msvc.zip --repo EitrLicht/lau-bigfun-rs --signer-workflow EitrLicht/lau-bigfun-rs/.github/workflows/release.yml
```

The executable is not code-signed, so Windows SmartScreen may warn the first time it runs.

To build from source instead:

```bash
# Install the `lau-bigfun` binary locally
cargo install --path .

# Or build in release mode (`target/release/lau-bigfun`)
cargo build --release
```

## Filelists

Archives store only path hashes, so asset names come from filelists you supply with `--filelist`. No filelists are bundled, and what happens without one depends on the command:

| Command | Without `--filelist` |
| :--- | :--- |
| `list` or `unpack` with a `--filter` or `--glob` that can only match a path | **Fails, so a filelist is required.** |
| `list` or `unpack` with a filter that can match a hash (e.g. `--filter 0x5ff9` or `--glob '0x5ff9*'`) | Warns, and the filter still runs against hashes. |
| `list` or `unpack` with `--unresolved` | Warns and selects every entry. |
| `list` | Warns and shows `<unknown>` for every name. |
| `unpack` | Warns and writes every file to `__unknown/<hash>.bin`. |
| `info` | Works, but reports 0% resolved names. |
| `extract` | Works by path or hash, but `--json` reports a `null` name for a hash target. |
| `hash` | Works, and does not use a filelist. |

A filelist that names none of the archive's hashes, such as one for a different game or release, makes `list`, `extract` and `unpack` warn; `info` shows it as 0% resolved names.

## TOC SKU Codes

It is the responsibility of the operator or caller to translate and interpret bigfile entry SKU codes. Human-readable aliases have been intentionally excluded to keep this codebase agnostic across games and releases.

## Quick Start

```bash
# Inspect archive summary, physical parts, hash resolution coverage, and SKU masks
lau-bigfun info /path/to/archive_dir_or_file --filelist names.txt

# List TOC entries (filtered by substring, repeatable glob, or JSON output)
lau-bigfun list /path/to/bigfile.000 --filelist names.txt --filter lara --limit 20
lau-bigfun list /path/to/bigfile.000 --filelist names.txt --glob 'pc-w/*.drm' --glob '**/vo/lara/*.mul'
lau-bigfun list /path/to/bigfile.000 --filelist names.txt --limit 0 --json | jq '.entries[0]'

# Without a filelist, entries stay unnamed
lau-bigfun list /path/to/bigfile.000 --limit 20

# Compute 32-bit CRC-32/BZIP2 hashes for asset paths
lau-bigfun hash 'pc-w\lara.drm' 'pc-w\alister.drm'

# Extract a single asset by path or hex hash (to a file or piped via stdout)
lau-bigfun extract /path/to/bigfile.000 'pc-w\lara.drm' -o lara.drm --sku-mask 0x1
lau-bigfun extract /path/to/bigfile.000 'pc-w\lara.drm' --sku-mask 0x1 | xxd | head

# Unpack an entire archive (or filtered subset) to an output directory
lau-bigfun unpack /path/to/bigfile.000 -o ./unpacked --filelist names.txt --sku-mask 0x1 --engine-sku-match
lau-bigfun unpack /path/to/bigfile.000 -o ./unpacked --filelist names.txt --glob 'pc-w/*.drm'
```

## CLI Reference

### Subcommands

| Subcommand | Description |
| :--- | :--- |
| `info <ARCHIVE>` | Display archive metadata, part geometry, hash resolution coverage, and SKU breakdown. |
| `list <ARCHIVE>` | List and filter Table of Contents (FAT) entries (`-l` / `--limit <N>`, default `50`; `0` = unlimited). When the limit hides entries, a note on `stderr` says how many matched. |
| `extract <ARCHIVE> <TARGET>` | Extract a single entry by path or `0x<hash:08x>` to `-o <FILE>` or `stdout` (`--variant <N>` selects the 0-based index among `--sku-mask` matches; with neither it nor `--engine-sku-match`, it takes the first and, when several match, says how to choose). A failed read keeps an existing `<FILE>`; on `stdout` it can leave partial output and exits non-zero. |
| `unpack <ARCHIVE> -o <DIR>` | Unpack all or filtered entries across worker threads (`-j` / `--jobs <N>`, default `0` = auto-detect cores). |
| `hash <PATH>...` | Compute the 32-bit `CRC-32/BZIP2` hash for one or more asset paths. |

### Archive & Dictionary Options (`info`, `list`, `extract`, `unpack`)

| Option | Description |
| :--- | :--- |
| `--endian <auto\|little\|big>` | TOC byte order (aliases `le`, `be`; default `auto`). Auto-detects `little` (PC/PS2/PSP/Xbox) vs. `big` (PS3/Xbox 360/Wii) from FAT and part geometry, or enforces the specified order strictly. |
| `--segment-length <BYTES>` | Virtual segment stride in hex or decimal (e.g. `0x7ff00000` or `0x09600000`). Auto-detected from 1 MiB-aligned multi-part spill boundaries when omitted. A given value is used only if it is 1 MiB-aligned and every part file and record fits it. |
| `--single-part` | Open exactly the given file as one archive: no gathering of numbered `.000`, `.001`, ... parts and no `.dat` name resolution. For games whose numbered files are separate archives, each with its own TOC (e.g. `PATCH.000` and `PATCH.001`). Takes a file, not a directory; conflicts with `--segment-length`. |
| `--filelist <FILE>` | Load a UTF-8 or Latin-1 filename list with one asset path per line, written as the game hashes it (e.g. `pc-w\lara.drm`). Blank lines and lines starting with `#` are ignored. Repeatable, and later lists override earlier ones on a matching hash. See [Filelists](#filelists) for what each command does without one. |

### Filtering & Extraction Options

`--filter`, `--glob`, and `--unresolved` are mutually exclusive on `list` and `unpack`, and can be combined with `--sku-mask`:

| Option | Applies To | Description |
| :--- | :--- | :--- |
| `-f`, `--filter <STR>` | `list`, `unpack` | Case-insensitive substring match on resolved path or `0x<hash:08x>` (`/` and `\` are equivalent; leading slashes stripped). |
| `-g`, `--glob <PATTERN>` | `list`, `unpack` | Repeatable whole-path, case-insensitive glob match (`*` matches within one folder, `**` crosses folders; any match counts). |
| `--unresolved` | `list`, `unpack` | Select only entries whose hash is not resolved by the active filelist (`--filter` and `--glob` never match fallback labels). |
| `--sku-mask <MASK>` | `list`, `extract`, `unpack` | Filter entries where `(entry.sku_flags & mask) == mask` (hex or decimal, e.g. `0x1`). |
| `--engine-sku-match` | `extract`, `unpack` | For each name, select only the record the game engine's lookup order picks among those matching `--sku-mask` within this archive (requires `--sku-mask`; conflicts with `--variant`). |
| `--variant-layout <MODE>` | `unpack` | Disambiguate colliding SKU variants via `sku-dir` (default, `sku_<hex>/` when ambiguous), `always-sku-dir`, or `suffix` (`.sku_<hex>`). |
| `--raw` | `extract`, `unpack` | Write raw on-disk bytes without inflating `zlib`-compressed payloads. |
| `--max-output-bytes <BYTES>` | `unpack` | Refuse to start if the planned output exceeds this many bytes (hex or decimal; `0` for no limit). Defaults to 16 times the size of the archive on disk, since records can share stored bytes and expand far beyond it. This bounds expansion; free disk space is not checked. |
| `--dry-run` | `unpack` | Report the files and bytes the unpack would write, without writing anything. The count is bytes written, not the disk space their blocks take up, and a planned output over `--max-output-bytes` is reported with a warning instead of refused. The destination is not checked, so a real unpack can still fail to create or write it. |

`unpack` follows symbolic links already inside the output directory, except that a link to a directory on another filesystem fails, because files are moved into place from under the output directory.

### Global Options

| Option | Description |
| :--- | :--- |
| `--json` | Emit a versioned `"schema": 1` root object on `stdout` (`info`, `list`, `hash`, `unpack`, and `extract -o <FILE>`). Pretty-printed on TTYs, compact when piped; errors remain plain text on `stderr`. `extract` reports `name` from a path target or, for a hash target, from `--filelist`, and `variant` as the index among all variants of the hash (reproducible with `--variant <N>` alone). `list` reports `total_matching`, the entries that matched before `--limit`. With `--dry-run`, `unpack` adds `"dry_run": true`, and its counts are what it would write. |
| `-q`, `--quiet` | Suppress non-error status messages on `stderr`. |

## Development

```bash
cargo test
```

The oracle tests in `tests/lau_oracle_integration.rs` check the library against exact counts and content checksums from the retail PC releases, using your own game files and complete filelists. They are marked `#[ignore]`, so `cargo test` skips them; set the variables below and run them with `cargo test -- --ignored`:

| Game | Archive directory | Filelist |
| :--- | :--- | :--- |
| *Legend* | `LAU_BIGFUN_TRL_TEST_ARCHIVE_DIR` | `LAU_BIGFUN_TRL_TEST_FILELIST` |
| *Anniversary* | `LAU_BIGFUN_TRA_TEST_ARCHIVE_DIR` | `LAU_BIGFUN_TRA_TEST_FILELIST` |
| *Underworld* | `LAU_BIGFUN_TRU_TEST_ARCHIVE_DIR` | `LAU_BIGFUN_TRU_TEST_FILELIST` |

Within that run, checks for an unset variable are skipped. An archive variable needs its filelist variable set too, and a set variable whose path is missing or invalid fails the tests instead of skipping them.

Parsers of untrusted input are fuzzed with `cargo-fuzz` on the nightly toolchain. The targets are `fat_parse`, `archive_read`, `filelist_load`, `sanitize_path`, and `glob_filter`:

```bash
cargo +nightly fuzz run fat_parse
```

When `fuzz/seeds/<target>` exists, pass it as a second corpus so the fuzzer starts from inputs that get past archive validation. The fuzzer writes new inputs to the first corpus, which must already exist:

```bash
mkdir -p fuzz/corpus/archive_read
cargo +nightly fuzz run archive_read fuzz/corpus/archive_read fuzz/seeds/archive_read
```

## Disclaimer

The source code maintained in this repository is AI-generated. The feature specifications and engineering prompts behind it were shaped by human experience and ambition.

This project is not affiliated with or endorsed by Crystal Dynamics or CDE Entertainment Ltd. Trademarks belong to their respective owners.
