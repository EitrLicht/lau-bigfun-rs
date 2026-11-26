# Changelog

Notable changes to `lau-bigfun`, newest first. Versions not listed here were never published.

## 0.5.2 - 2026-11-26

### Added

- `FilelistError::NulCharacter` and `FilelistError::InvalidUtf16`, for the filelist cases under **Fixed**.
- `BigfileError::AmbiguousSegmentLength`, for the segment-length case under **Fixed**.
- `trim_name` trims the whitespace around a name the way filelists and the command-line tool's `extract` and `hash` do: like `str::trim`, but keeping `U+0085` and the no-break space `U+00A0`, which a name can hold.

### Changed

- The crate's description, its documentation's first line and the command-line tool's `about` text describe *Legend*-era *Tomb Raider* bigfile archives instead of listing three of the games: the description and documentation say "reading and unpacking", the `about` text "Inspects and unpacks".
- `COM0` and `LPT0`, which Microsoft's file-naming documentation lists as reserved device names, are escaped like `COM1`–`COM9` and `LPT1`–`LPT9`: an entry named `com0.txt` unpacks as `_com0.txt`. None of the retail PC filelists has such a name.
- Error messages no longer repeat their source when the source chain is printed, for example by `anyhow`'s `{:#}`: each error that wraps another still returns it from `source()`, but leaves it out of its own message. **Code that prints only an error's message (`{err}`) no longer shows the cause, such as the OS error, so print the `source()` chain to keep it.** The command-line tool now prints the chain, so its output is unchanged, except that on Windows the hint about a part another program has open now comes before the OS error, and an invalid `--glob` pattern is reported as `invalid glob pattern '<pattern>': error parsing glob '<normalized pattern>': <reason>`, where the normalized pattern has `/` separators and no leading slash.

### Fixed

- A filelist saved as UTF-16 with a byte order mark, as Windows PowerShell 5.1 writes with `>`, loads its names; it loaded without an error but named nothing. One that starts with the mark but isn't valid UTF-16 fails with `FilelistError::InvalidUtf16`.
- A filelist line holding a NUL character fails with `FilelistError::NulCharacter` at that line, since no name can hold one. That catches UTF-16 without a byte order mark, which also loaded as names that matched nothing.
- A lone carriage return ends a filelist line, as `\n` and `\r\n` do, so a file with classic Mac line endings no longer loads as one name.
- Opening a multi-part archive without a segment length no longer silently picks one of two that fit, which read the wrong bytes for some records. That happens when part 0 is a multiple of 1 MiB and has an empty record exactly at its end, and part 1's first data lies further in. Such an archive now fails with `AmbiguousSegmentLength`. **An archive that opened before may now fail this way; choose the length with `OpenOptions::segment_length`.** The command-line tool asks for `--segment-length`. The three retail PC archives are unaffected.
- Detecting the byte order no longer briefly needs several times part 0's size in memory when the archive's entry count, read in the other byte order, also fits part 0: hash order is now checked as the hashes are read, so the wrong reading fails within 64 KiB once its hashes are out of order, as a misread table's almost always are. A crafted 152 MB part 0 peaked at 513 MB before and 5 MB now; the retail PC archives were never affected.
- The `<ARCHIVE>` help says that any numbered part, not only `.000`, gathers every part of the archive.
- An explicit segment length that doesn't fit reports `SegmentLengthMismatch` only when the archive fits the segment length its records show, and no other. Otherwise the archive's own error is reported, instead of being blamed on the override.
- A numbered part that is a symbolic link whose target can't be read, such as a dangling link, is reported with `BigfileError::PartOpen` instead of being left out, which opened the archive with fewer parts and gave a misleading record error.
- Filelist lines and `extract`'s path target no longer lose a no-break space (`U+00A0`) or `U+0085` at either end. Both are Latin-1, so a name can hold them, and trimming them made the name hash differently from the game's. Other whitespace is still trimmed.
- `hash` trims each name as filelists and `extract` do, so all three give the same hash for the same text; it hashed a padded name untrimmed.
- Glob patterns that are each valid but too large to compile together are reported as such, instead of as the invalid pattern `'<globset>'`.
- A path filter with filelists that supplied no paths no longer advises passing `--filelist`, and a bad numeric argument no longer names its value twice.
- `unpack --dry-run --quiet` now still warns when the planned output is over `--max-output-bytes`. The warning stands in for the error a real unpack gives, so `--quiet` no longer hides it.
- Documentation that disagreed with the code: the README's install commands now pass `--locked`, so they build with the dependency versions the release was tested with, and its feature list names the commands that emit JSON instead of claiming all of them; the README's command for verifying a download now names the file as released (`lau-bigfun-v<version>-x86_64-pc-windows-msvc.zip`); `unpack --dry-run`'s help and the README no longer say the destination goes unchecked: a planned output file that is, or links to, an archive part fails the dry run; `--variant-layout`'s help no longer says `suffix` keeps flat paths; `info` without a filelist reports no resolved names rather than 0%, which an empty archive shows as 100%; and the README and `unpack_archive` now say that a symbolic link to a file where an output file goes is replaced by the file, not written through, unless it leads to an archive part.

## 0.5.1 - 2026-11-19

### Fixed

- On Windows, on a drive where Windows cannot resolve a path's own spelling, `extract` and `unpack` now also recognise an archive part named with different letter case in a script beyond Latin-1, such as Cyrillic or Greek, and refuse it with `BigfileError::OutputIsArchivePart`. The part was already safe, because it is opened sharing only reading, but the write failed with Windows' less clear sharing error instead.

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
