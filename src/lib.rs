//! `lau-bigfun` — library and CLI for reading and unpacking *Legend*-era *Tomb Raider* bigfile
//! archives.
//!
//! Modules:
//! - [`format`](mod@format) — Sector (`2048` B), block (`1 MiB`), and logical volume geometry.
//! - [`hash`] — Case-insensitive ASCII `tolower` + MSB-first `CRC-32/BZIP2` path hashing.
//! - [`fat`] — File Allocation Table (`Entry`, `Fat`) parsing, validation, and specialisation-aware lookup.
//! - [`archive`] — Physical part file discovery (`.000`..`.NNN` / `.dat`), segment boundary verification, whole or streamed raw/zlib entry reads, and resolution across stacked archives in a caller-chosen priority order.
//! - [`filelist`] — Hash dictionary built from caller-supplied filelists.
//! - [`path`] — Traversal-safe sanitization of archive paths and output path comparison.
//! - [`filter`] (feature `unpack`) — Entry filtering by case-insensitive substring, compiled glob set, or resolution status.
//! - [`unpack`] (feature `unpack`) — Single-entry and batch extraction supporting spec masks and multi-variant disambiguation.
//!
//! # Features
//!
//! - `unpack` — the `filter` and `unpack` modules, which add the `globset` dependency.
//! - `cli` (default) — `unpack` plus the `lau-bigfun` binary and its argument parsing and JSON
//!   output dependencies.
//!
//! A library user that only reads archives can turn both off with `default-features = false`.
//!
//! # Example
//!
//! Reads one asset the way the game engine would, stacking a patch over its base archive, highest
//! priority first. The patch is opened in the base archive's byte order, which is known once the
//! base has opened, rather than detected again:
//!
//! ```no_run
//! use lau_bigfun::{ArchiveSet, Bigfile, OpenOptions, name_hash};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let base = Bigfile::open("/path/to/game/bigfile.000")?;
//! let options = OpenOptions {
//!     endian: Some(base.endian()),
//!     ..OpenOptions::default()
//! };
//! let patch = Bigfile::open_with_options("/path/to/game/patch.000", options)?;
//! let archives = [patch, base];
//! let set = ArchiveSet::new(&archives);
//!
//! let hash = name_hash(r"pc-w\lara.drm")?;
//! if let Some(found) = set.resolve(hash, 0x1) {
//!     let bytes = found.archive.read_entry(found.entry, false)?;
//!     let source = found.archive.part_paths()[0].display();
//!     println!("read {} bytes from {source}", bytes.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Streams an entry through [`std::io::Read`] instead of loading it whole, here stopping after
//! its first bytes:
//!
//! ```no_run
//! use std::io::Read;
//!
//! use lau_bigfun::{Bigfile, name_hash};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let archive = Bigfile::open("/path/to/game")?;
//! let hash = name_hash(r"pc-w\lara.drm")?;
//! if let Some(entry) = archive.find_with_spec_mask(hash, 0x1) {
//!     let mut header = [0u8; 16];
//!     archive.open_entry(entry, false)?.read_exact(&mut header)?;
//!     println!("{header:02x?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Bigfile::open_entry_at`] opens an entry's stored bytes from an offset instead, so several
//! threads can each read their own part of one entry.

// Docs of always-built items link to `filter` and `unpack` items. The default build resolves
// every link, and its docs are checked with broken links denied; without `unpack` those links
// render as plain text instead of failing the build.
#![cfg_attr(not(feature = "unpack"), allow(rustdoc::broken_intra_doc_links))]

pub mod archive;
pub mod fat;
pub mod filelist;
#[cfg(feature = "unpack")]
pub mod filter;
pub mod format;
pub mod hash;
pub mod path;
#[cfg(feature = "unpack")]
pub mod unpack;

pub use archive::{
    ArchiveSet, Bigfile, BigfileError, EntryLocation, EntryReader, OpenOptions, ResolvedEntry,
};
pub use fat::{Entry, Fat, FatError};
pub use filelist::{FilelistError, HashDictionary, RelativeOutputPath};
#[cfg(feature = "unpack")]
pub use filter::{EntryFilter, FilterError};
pub use format::{Endian, HexLabel};
pub use hash::{NonLatin1CharError, name_hash, name_hash_bytes, trim_name};
#[cfg(feature = "unpack")]
pub use unpack::{
    MAX_UNPACK_JOBS, UnpackOptions, UnpackReport, VariantLayout, extract_entry, unpack_archive,
    unpack_archive_set,
};

#[cfg(test)]
pub(crate) mod test_support;

/// Checks that [`FilelistError`], [`NonLatin1CharError`], [`RelativeOutputPath`] and
/// [`EntryLocation`] stay `#[non_exhaustive]`, as samples of the public types that carry it: each
/// example compiles only without the attribute. `BigfileError` and `FatError` are not checked,
/// since a match on all their variants would go stale. Update the [`FilelistError`] match when a
/// variant is added: a match that misses one fails to compile with the attribute removed too, so
/// the check would stop working.
#[cfg(doctest)]
mod non_exhaustive_guards {
    /// A `match` on every [`FilelistError`](crate::FilelistError) variant still needs a wildcard
    /// arm outside the crate.
    ///
    /// ```compile_fail,E0004
    /// use lau_bigfun::FilelistError;
    ///
    /// fn line(err: &FilelistError) -> Option<usize> {
    ///     match err {
    ///         FilelistError::Io { .. }
    ///         | FilelistError::TooLarge { .. }
    ///         | FilelistError::InvalidUtf16 { .. } => None,
    ///         FilelistError::InvalidFilename { line, .. } | FilelistError::NulCharacter { line } => {
    ///             Some(*line)
    ///         }
    ///     }
    /// }
    /// ```
    struct FilelistErrorMatch;

    /// [`NonLatin1CharError`](crate::NonLatin1CharError) cannot be built with a struct literal
    /// outside the crate.
    ///
    /// ```compile_fail,E0639
    /// let _ = lau_bigfun::NonLatin1CharError { ch: 'ā', byte_offset: 0 };
    /// ```
    struct NonLatin1CharErrorLiteral;

    /// [`RelativeOutputPath`](crate::RelativeOutputPath) cannot be built with a struct literal
    /// outside the crate.
    ///
    /// ```compile_fail,E0639
    /// let _ = lau_bigfun::RelativeOutputPath {
    ///     path: std::path::PathBuf::from("pc-w/lara.drm"),
    ///     resolved: true,
    /// };
    /// ```
    struct RelativeOutputPathLiteral;

    /// [`EntryLocation`](crate::EntryLocation) cannot be built with a struct literal outside the
    /// crate.
    ///
    /// ```compile_fail,E0639
    /// let _ = lau_bigfun::EntryLocation {
    ///     part_index: 0,
    ///     offset_in_part: 0,
    /// };
    /// ```
    struct EntryLocationLiteral;
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::format::{BLOCK_BYTE_COUNT, BLOCK_SECTOR_COUNT, SECTOR_BYTE_COUNT};
    use crate::test_support::{
        ArchiveRecord, FatRow, TempDir, build_part0_bytes, write_archive, write_part0,
        zlib_compress,
    };

    /// Path of the compressed entry in [`write_two_entry_archive`].
    const LARA_PATH: &str = r"pc-w\lara.drm";
    /// Path of the stored entry in [`write_two_entry_archive`].
    const ALISTER_PATH: &str = r"pc-w\alister.drm";
    /// Inflated bytes of the [`LARA_PATH`] entry in [`write_two_entry_archive`].
    const RAW_LARA: &[u8] = b"compressed lara payload that repeats repeats repeats repeats!";
    /// Bytes of the [`ALISTER_PATH`] entry in [`write_two_entry_archive`].
    const RAW_ALISTER: &[u8] = b"uncompressed alister payload bytes 1234567890";

    /// Writes a one-part archive holding [`RAW_ALISTER`] stored and [`RAW_LARA`] zlib-compressed.
    fn write_two_entry_archive(prefix: &str) -> TempDir {
        let dir = TempDir::new(prefix);
        let z_lara = zlib_compress(RAW_LARA);
        let records = [
            ArchiveRecord::stored(name_hash(ALISTER_PATH).unwrap(), 0xFFFF_F7E1, RAW_ALISTER),
            ArchiveRecord::zlib(
                name_hash(LARA_PATH).unwrap(),
                0xFFFF_FFFF,
                &z_lara,
                u32::try_from(RAW_LARA.len()).unwrap(),
            ),
        ];
        write_archive(dir.join("bigfile.000"), Endian::Little, &records);
        dir
    }

    #[test]
    fn reads_archive_entries_end_to_end() {
        let dir = write_two_entry_archive("single_part");
        let hash_a = name_hash(LARA_PATH).unwrap();
        let hash_b = name_hash(ALISTER_PATH).unwrap();

        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!((bf.entries().len(), bf.segment_length()), (2, None));
        assert_eq!(
            bf.read_entry(&bf.find(hash_b)[0], false).unwrap(),
            RAW_ALISTER
        );
        assert_eq!(
            bf.read_entry(&bf.find(hash_a)[0], true).unwrap(),
            zlib_compress(RAW_LARA)
        );
        assert_eq!(bf.read_entry(&bf.find(hash_a)[0], false).unwrap(), RAW_LARA);
    }

    #[cfg(feature = "unpack")]
    #[test]
    fn unpacks_archive_entries_end_to_end() {
        let dir = write_two_entry_archive("single_part_unpack");
        let bf = Bigfile::open(&dir).unwrap();

        let out_dir = dir.join("unpacked");
        let mut dict = HashDictionary::new();
        dict.load_str(LARA_PATH).unwrap();
        let report = unpack_archive(&bf, &dict, &out_dir, &UnpackOptions::default()).unwrap();
        assert_eq!(report.extracted_files, 2);
        assert_eq!(fs::read(out_dir.join("pc-w/lara.drm")).unwrap(), RAW_LARA);
    }

    /// Writes a two-part archive whose part 1 starts at a one-block stride and is `part1_len` bytes.
    fn create_one_block_stride_archive(prefix: &str, part1_len: usize) -> TempDir {
        let dir = TempDir::new(prefix);
        let records = [
            FatRow {
                name_hash: 0x1000_0001,
                size: 16,
                sector_number: 1,
                spec_flags: 1,
                deflated_size: 0,
            },
            FatRow {
                name_hash: 0x1000_0002,
                size: 16,
                sector_number: BLOCK_SECTOR_COUNT,
                spec_flags: 1,
                deflated_size: 0,
            },
        ];
        let part0 = build_part0_bytes(
            Endian::Little,
            (SECTOR_BYTE_COUNT as usize) + 100,
            &records,
            &[],
        );
        fs::write(dir.join("bigfile.000"), &part0).unwrap();
        fs::write(dir.join("bigfile.001"), vec![0xABu8; part1_len]).unwrap();
        dir
    }

    #[test]
    fn detects_custom_block_aligned_segment_stride() {
        let dir = create_one_block_stride_archive("custom_stride", SECTOR_BYTE_COUNT as usize);
        let stride_bytes = u64::from(BLOCK_BYTE_COUNT);

        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(bf.segment_length(), Some(stride_bytes));
        assert_eq!(
            bf.locate(&bf.entries()[1]).unwrap(),
            EntryLocation {
                part_index: 1,
                offset_in_part: 0
            }
        );

        let bf_dat = Bigfile::open(dir.join("BIGFILE.DAT")).unwrap();
        assert_eq!(bf_dat.segment_length(), Some(stride_bytes));

        let bf_match = Bigfile::open_with_options(
            &dir,
            OpenOptions {
                segment_length: Some(stride_bytes),
                endian: None,
                single_part: false,
            },
        )
        .unwrap();
        assert_eq!(bf_match.segment_length(), Some(stride_bytes));
    }

    #[test]
    fn rejects_segment_length_not_matching_detected_stride() {
        let dir = create_one_block_stride_archive("stride_mismatch", SECTOR_BYTE_COUNT as usize);
        let opts = OpenOptions {
            segment_length: Some(u64::from(BLOCK_BYTE_COUNT) * 2),
            endian: None,
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, opts).unwrap_err();
        assert!(matches!(err, BigfileError::SegmentLengthMismatch { .. }));
    }

    #[test]
    fn rejects_part_larger_than_segment_stride() {
        let dir =
            create_one_block_stride_archive("stride_oversized", BLOCK_BYTE_COUNT as usize + 16);
        let err_oversized = Bigfile::open(&dir).unwrap_err();
        assert!(matches!(
            err_oversized,
            BigfileError::PartExceedsSegmentLength { part_index: 1, .. }
        ));
    }

    #[test]
    fn detects_overrunning_record() {
        let dir = TempDir::new("overrun");
        write_part0(
            dir.join("bigfile.000"),
            Endian::Little,
            2,
            &[FatRow {
                name_hash: 0x1234_5678,
                size: 3000,
                sector_number: 5,
                spec_flags: 1,
                deflated_size: 0,
            }],
            &[],
        );

        let err = Bigfile::open(&dir).unwrap_err();
        assert!(matches!(err, BigfileError::RecordOverrunsPart { .. }));
    }

    #[test]
    fn detects_record_overlapping_fat() {
        let dir = TempDir::new("overlap_fat");
        write_part0(
            dir.join("bigfile.000"),
            Endian::Little,
            2,
            &[FatRow {
                name_hash: 0x1234_5678,
                size: 128,
                sector_number: 0,
                spec_flags: 1,
                deflated_size: 0,
            }],
            &[],
        );

        let err = Bigfile::open(&dir).unwrap_err();
        assert!(matches!(err, BigfileError::RecordOverlapsFat { .. }));
    }
}
