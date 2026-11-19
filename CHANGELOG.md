# Changelog

Notable changes to `lau-bigfun`, newest first. Versions not listed here were never published.

## 0.5.0 - 2026-11-19

The library changes under **Changed** are breaking. The command-line tool is used as before; it gains the fixes under **Fixed**, one of which can change where `unpack` writes a file.

### Added

- `Bigfile::open_entry_at` opens an entry's stored bytes from an offset, as stored and never decompressed, so several threads can each read their own part of one entry. A compressed entry's bytes from an offset cannot be decompressed on their own, so it suits uncompressed entries and raw copies. An offset past the end of the entry fails with the new `BigfileError::OffsetPastEntryEnd`.
- This changelog, which also ships in the crate's package and the Windows download.
- `LAU_BIGFUN_REQUIRE_ORACLES=1` makes the oracle tests fail when one of their variables is unset, instead of skipping its checks (see the README's Development section).

### Changed (breaking for library users)

- `BigfileError`, `FatError`, `FilelistError` and `NonLatin1CharError` are `#[non_exhaustive]`, so later releases can add to them without a breaking change. **A `match` on one of the error enums outside this crate needs a wildcard arm (`_ => …`), and `NonLatin1CharError` can no longer be built with a struct literal.**
- `HashDictionary::relative_path_or_fallback` returns the new `RelativeOutputPath`, with named `path` and `resolved` fields, instead of a `(PathBuf, bool)` tuple, so the flag cannot be read the wrong way round. **Read `.path` and `.resolved`, or destructure with `RelativeOutputPath { path, resolved, .. }`.**
- `Bigfile::locate_coords` is renamed `Bigfile::locate`, and returns the new `EntryLocation`, with named `part_index` and `offset_in_part` fields, instead of a `(usize, u64)` tuple. Locations still compare, sort (in disk order) and hash like the tuple did. **Call `locate`, and read `.part_index` and `.offset_in_part`, or destructure with `EntryLocation { part_index, offset_in_part, .. }`.**
- A part file that cannot be opened, or whose size or identity cannot be read, fails with the new `BigfileError::PartOpen`, which names the part, and a folder of parts that cannot be listed, even partway through, fails with the new `BigfileError::ArchiveDirectory`, which names the folder, instead of `BigfileError::Io`. **Code that matched `BigfileError::Io` for a missing or unreadable part or folder should match `PartOpen` and `ArchiveDirectory` too.**

### Fixed

- `extract` and `unpack` refuse, before writing anything, to write to a destination that is a part file of the archive being read, directly, through a symbolic link, or on Unix through a hard link, failing with the new `BigfileError::OutputIsArchivePart`. `unpack --dry-run` refuses it too. Before, `extract bigfile.000 <name> -o bigfile.000` replaced the archive part with the extracted entry.
- On Windows, archive parts are opened sharing only reading, so while the tool reads them no other program can write to them or rename them. Opening an archive now fails if another program already has one of its parts open for writing, such as an update in progress, with an error that names the part and says so.
- `unpack` starts at most 64 worker threads (the new `MAX_UNPACK_JOBS`), however many `--jobs` asks for, and warns when it asks for more. It carries on with fewer when the system cannot start them all, instead of stopping with a panic.
- A filelist over 64 MiB fails with the new `FilelistError::TooLarge` instead of being read whole, so passing an archive part as `--filelist` no longer tries to load gigabytes into memory.
- A path segment that is `..` apart from surrounding spaces or control characters, such as `.. `, now steps back like `..` instead of being dropped. This can change where such an entry unpacks; no retail filelist has such a padded segment.

## 0.4.0 - 2026-11-17

### Changed (breaking for library users)

The command-line tool's dependencies are now optional, so a program that only reads archives no longer builds them:

| Feature | What it adds |
|---|---|
| `cli` (default) | The `lau-bigfun` binary, plus `unpack`, `clap`, `serde` and `serde_json` |
| `unpack` | The `filter` and `unpack` modules, plus `globset` |

With `default-features = false`, the crate now builds only the archive-reading modules. **If your `Cargo.toml` already sets `default-features = false` and you use `filter` or `unpack`, add `features = ["unpack"]`.**

The command-line tool itself is unchanged.

### Added

- The README points to downloadable filelists for these games, which `--filelist` reads as they are.
- The README explains how to use only the library.

## 0.3.1 - 2026-11-14

### Changed (breaking)

What 0.2.1 called **SKU** flags and masks are now **specialisation** ("spec") flags and masks, the engine's own name for them. Everything that used the old name is renamed, and the old names are no longer accepted:

| | 0.2.1 | 0.3.1 |
|---|---|---|
| CLI flags | `--sku-mask`, `--engine-sku-match` | `--spec-mask`, `--engine-spec-match` |
| `--variant-layout` values | `sku-dir`, `always-sku-dir` | `spec-dir`, `always-spec-dir` |
| JSON fields | `sku_flags`, `sku_counts`, `sku_mask` | `spec_flags`, `spec_counts`, `spec_mask` |
| JSON `"schema"` (every command) | `1` | `2` |
| Unpack folders and suffixes | `sku_<hex>/`, `.sku_<hex>` | `spec_<hex>/`, `.spec_<hex>` |
| Text output | `sku=…`, `Distinct SKU masks` | `spec=…`, `Distinct spec flags` |
| Library | `Entry::sku_flags`, `*_sku_mask` lookups | `Entry::spec_flags`, `*_spec_mask` lookups |

**Unpack into a fresh folder.** `unpack` never deletes existing files, so unpacking into a folder that 0.2.1 already filled leaves the old `sku_*` folders next to the new `spec_*` ones.

`extract`'s messages now name the `--spec-mask` flag.

### Added

- The crate is published on crates.io: `cargo install lau-bigfun` installs the tool on any platform with Rust.

## 0.2.1 - 2026-11-14

First public release: a library and command-line tool for inspecting, querying and unpacking the bigfile archives of the *Legend*-era *Tomb Raider* games.

- `info`: part geometry, hash-resolution coverage and SKU breakdown
- `list`: browse the table of contents, filtered by substring, glob pattern, unresolved status or SKU mask
- `extract`: one entry to a file or `stdout`
- `unpack`: all or filtered entries into a sanitized directory tree, across worker threads
- `hash`: CRC-32/BZIP2 path hashes for asset names

Single-file and multi-part archives are supported, with the byte order and segment length detected automatically (`--segment-length` overrides it). Commands can emit versioned JSON (`--json`) for scripting.
