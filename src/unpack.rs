//! High-level archive extraction and SKU/locale variant path disambiguation.

use std::path::Path;

use crate::archive::{ArchiveSet, Bigfile, BigfileError};
use crate::filelist::HashDictionary;
use crate::filter::EntryFilter;

mod execute;
mod plan;

pub use execute::extract_entry;
use execute::{create_parent_directories, extract_items};
use plan::{build_extraction_plan, planned_output_bytes, select_archive_entries};

/// Policy for laying out files when multiple FAT records share the same `name_hash` (e.g. per-SKU
/// or per-language variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VariantLayout {
    /// Place entries with a unique `name_hash` directly at `<out_dir>/<path>`, and place entries
    /// that have multiple selected variants under `<out_dir>/sku_<sku_flags:08x>/<path>`.
    #[default]
    SkuSubdirWhenAmbiguous,

    /// Always place every entry under `<out_dir>/sku_<sku_flags:08x>/<path>`.
    AlwaysSkuSubdir,

    /// Keep flat directory structure and append `.sku_<sku_flags:08x>` before the file extension
    /// when multiple variants exist for the same `name_hash`.
    FilenameSuffix,
}

/// Configuration options for [`unpack_archive`] and [`unpack_archive_set`].
#[derive(Debug, Clone, Default)]
pub struct UnpackOptions {
    /// Optional SKU bitmask filter (`(entry.sku_flags & mask) == mask`).
    pub sku_mask: Option<u32>,
    /// If `true` when `sku_mask` is set, selects at most one matching record per unique
    /// `name_hash`, using the lookup order of [`Bigfile::find_with_sku_mask`] within each archive
    /// and [`ArchiveSet::resolve`] across a set.
    pub single_match_per_hash: bool,
    /// Layout policy when multiple records with the same `name_hash` are selected for extraction.
    pub variant_layout: VariantLayout,
    /// If `true`, write raw stored bytes without inflating zlib-compressed entries.
    pub raw: bool,
    /// Optional entry filter (substring, glob set, or unresolved) matched against each entry.
    pub filter: Option<EntryFilter>,
    /// Number of parallel worker threads (`0` = auto-detect available CPU parallelism, `1` = single-threaded).
    ///
    /// Each worker streams entries through one reusable chunk buffer of at most 1 MiB
    /// (`O(jobs * 1 MiB)` peak buffer memory, independent of entry size).
    pub jobs: usize,
    /// Refuses the extraction before anything is written if its planned output exceeds this many
    /// bytes (`None` = no limit). Records can share stored bytes, so a small archive can otherwise
    /// write far more than its own size.
    pub max_output_bytes: Option<u64>,
    /// If `true`, plans the extraction and returns its report without writing anything, not even
    /// `out_dir`. The report counts what an unpack with the same options would write, and
    /// [`max_output_bytes`](Self::max_output_bytes) is not enforced, so a planned output over the
    /// limit is still reported. The destination is not checked: a dry run succeeds even where a
    /// real unpack could not create or write `out_dir`, or would run out of disk space.
    pub dry_run: bool,
}

impl UnpackOptions {
    /// The SKU mask to resolve each hash with when selecting one record per hash, or `None` when
    /// every matching record is selected.
    #[inline]
    #[must_use]
    pub(crate) fn resolution_mask(&self) -> Option<u32> {
        self.sku_mask.filter(|_| self.single_match_per_hash)
    }

    /// Checks `planned` output bytes against [`max_output_bytes`](Self::max_output_bytes).
    ///
    /// # Errors
    ///
    /// [`BigfileError::OutputLimitExceeded`] when `planned` is over the limit.
    pub fn check_output_limit(&self, planned: u64) -> Result<(), BigfileError> {
        match self.max_output_bytes {
            Some(limit) if planned > limit => {
                Err(BigfileError::OutputLimitExceeded { planned, limit })
            }
            _ => Ok(()),
        }
    }
}

/// Summary statistics returned by [`unpack_archive`] and [`unpack_archive_set`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnpackReport {
    /// Number of files written to disk, or on a dry run, the number that would be written.
    pub extracted_files: usize,
    /// Number of bytes written to disk, or on a dry run, the number that would be written.
    pub extracted_bytes: u64,
    /// Number of extracted entries whose path hash matched the [`HashDictionary`].
    pub resolved_entries: usize,
    /// Number of extracted entries that fell back to `__unknown/<hash>.bin`.
    pub unknown_entries: usize,
    /// Number of TOC records not extracted, because they failed `sku_mask` or `filter` or another
    /// record was selected for their hash.
    pub skipped_entries: usize,
    /// Number of extracted entries taken from an archive ahead of the last one in the set, such as a
    /// patch or DLC pack stacked over its base archive.
    pub higher_priority_entries: usize,
}

/// Extracts entries from `bigfile` into `out_dir` according to `options` and `dict`.
///
/// Each worker thread streams entries through one reusable chunk buffer of at most 1 MiB into a
/// hidden staging directory under `out_dir`, renaming each file into place once it is complete.
/// Symbolic links already inside `out_dir` are followed, except that a link to a directory on
/// another filesystem fails, because files are moved into place from under `out_dir`.
///
/// # Errors
///
/// - [`BigfileError::OutputLimitExceeded`] before anything is written, when the planned output is
///   larger than [`UnpackOptions::max_output_bytes`] and this is not a dry run.
/// - [`BigfileError::OutputPath`] when an output directory or file cannot be created, written or
///   moved into place.
/// - Any error reading an entry, as [`Bigfile::read_entry`] describes.
///
/// Extraction stops at the first failure. Files already moved into place stay, and the failed
/// entry's destination is left untouched.
pub fn unpack_archive(
    bigfile: &Bigfile,
    dict: &HashDictionary,
    out_dir: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, BigfileError> {
    let set = ArchiveSet::new(std::slice::from_ref(bigfile));
    unpack_archive_set(set, dict, out_dir, options)
}

/// Extracts entries from `set` into `out_dir` as [`unpack_archive`] does, taking each name from the
/// archive that resolves it (see [`ArchiveSet::resolve`]).
///
/// # Errors
///
/// Fails like [`unpack_archive`], and with [`BigfileError::ResolutionRequiresSkuMatch`] when `set`
/// holds several archives but `options` lacks `sku_mask` or `single_match_per_hash`, which
/// resolving a name across archives needs.
pub fn unpack_archive_set(
    set: ArchiveSet<'_>,
    dict: &HashDictionary,
    out_dir: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, BigfileError> {
    let archives = set.archives();
    if archives.len() > 1 && options.resolution_mask().is_none() {
        return Err(BigfileError::ResolutionRequiresSkuMatch);
    }
    let selection = select_archive_entries(set, dict, options);
    let plan = build_extraction_plan(&selection, out_dir, options.variant_layout);
    let planned = planned_output_bytes(&plan.items, options.raw);
    let extracted_bytes = if options.dry_run {
        planned
    } else {
        options.check_output_limit(planned)?;
        create_parent_directories(&plan.unique_dirs)?;
        extract_items(archives, &plan.items, out_dir, options.raw, options.jobs)?
    };

    Ok(UnpackReport {
        extracted_files: plan.items.len(),
        extracted_bytes,
        resolved_entries: plan.resolved_entries,
        unknown_entries: plan.unknown_entries,
        skipped_entries: selection.skipped_entries,
        higher_priority_entries: plan
            .items
            .iter()
            .filter(|item| item.archive_rank + 1 < archives.len())
            .count(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::format::Endian;
    use crate::hash::name_hash;
    use crate::test_support::{
        ArchiveRecord, TempDir, open_patched_pair, write_archive, write_patched_archives,
        write_shared_sector_archive, zlib_compress,
    };

    fn create_multi_variant_test_archive(tmp: &TempDir) -> (Bigfile, HashDictionary, Vec<u8>) {
        let mut dict = HashDictionary::new();
        dict.load_str("pc-w\\alpha.drm\npc-w\\beta.drm\npc-w\\gamma.drm\npc-w\\delta.drm")
            .unwrap();
        let alpha_z = zlib_compress(b"alpha_sku1_inflated_payload_bytes");

        let h = |s| name_hash(s).unwrap();
        let mut records = vec![
            ArchiveRecord::zlib(h(r"pc-w\alpha.drm"), 1, &alpha_z, 33),
            ArchiveRecord::stored(h(r"pc-w\alpha.drm"), 3, b"alpha_sku3_raw"),
            ArchiveRecord::stored(h(r"pc-w\beta.drm"), 1, b"beta_payload"),
            ArchiveRecord::stored(h(r"pc-w\gamma.drm"), 2, b"gamma_payload"),
            ArchiveRecord::stored(h(r"pc-w\delta.drm"), 1, b"delta_payload"),
            ArchiveRecord::stored(0xDEAD_BEEF, 1, b"unknown_payload"),
        ];
        records.sort_by_key(|r| r.hash);
        let archive_path = tmp.join("bigfile.000");
        write_archive(&archive_path, Endian::Little, &records);
        (Bigfile::open(&archive_path).unwrap(), dict, alpha_z)
    }

    #[test]
    fn unpack_archive_extracts_across_parallel_workers() {
        let tmp = TempDir::new("parallel");
        let (bf, dict, _) = create_multi_variant_test_archive(&tmp);

        let out_parallel = tmp.join("out_parallel");
        let report = unpack_archive(
            &bf,
            &dict,
            &out_parallel,
            &UnpackOptions {
                jobs: 4,
                ..UnpackOptions::default()
            },
        )
        .unwrap();
        assert_eq!(report.extracted_files, 6);
        assert_eq!(report.resolved_entries, 5);
        assert_eq!(report.unknown_entries, 1);
        assert_eq!(report.skipped_entries, 0);
        assert_eq!(
            fs::read(out_parallel.join("sku_00000001/pc-w/alpha.drm")).unwrap(),
            b"alpha_sku1_inflated_payload_bytes"
        );
        assert_eq!(
            fs::read(out_parallel.join("sku_00000003/pc-w/alpha.drm")).unwrap(),
            b"alpha_sku3_raw"
        );
        assert_eq!(
            fs::read(out_parallel.join("__unknown/deadbeef.bin")).unwrap(),
            b"unknown_payload"
        );
    }

    /// Archive holding one record per `(hash, size, deflated_size)`, all stored at sector 1.
    fn open_shared_sector_archive(tmp: &TempDir, records: &[(u32, u32, i32)]) -> Bigfile {
        let path = tmp.join("bigfile.000");
        write_shared_sector_archive(&path, records);
        Bigfile::open(&path).unwrap()
    }

    fn unpack_with_limit(bf: &Bigfile, out: &Path, raw: bool, limit: u64) -> BigfileError {
        let options = UnpackOptions {
            raw,
            max_output_bytes: Some(limit),
            ..UnpackOptions::default()
        };
        unpack_archive(bf, &HashDictionary::new(), out, &options).unwrap_err()
    }

    #[test]
    fn output_limit_is_checked_before_anything_is_written() {
        let tmp = TempDir::new("limit_before_write");
        let bf = open_shared_sector_archive(&tmp, &[(0x1, 100, 0), (0x2, 100, 0)]);
        let out = tmp.join("out");

        let err = unpack_with_limit(&bf, &out, false, 199);

        assert!(matches!(
            err,
            BigfileError::OutputLimitExceeded {
                planned: 200,
                limit: 199
            }
        ));
        assert!(!out.exists());
    }

    #[test]
    fn output_limit_allows_output_of_exactly_the_limit() {
        let tmp = TempDir::new("limit_exact");
        let bf = open_shared_sector_archive(&tmp, &[(0x1, 100, 0), (0x2, 100, 0)]);
        let options = UnpackOptions {
            max_output_bytes: Some(200),
            ..UnpackOptions::default()
        };
        let out = tmp.join("out");

        let report = unpack_archive(&bf, &HashDictionary::new(), &out, &options).unwrap();

        assert_eq!(report.extracted_bytes, 200);
    }

    #[test]
    fn output_limit_counts_stored_size_when_raw() {
        let tmp = TempDir::new("limit_raw");
        let bf = open_shared_sector_archive(&tmp, &[(0x1, 5000, 40)]);
        let out = tmp.join("out");

        let err = unpack_with_limit(&bf, &out, true, 39);

        assert!(matches!(
            err,
            BigfileError::OutputLimitExceeded { planned: 40, .. }
        ));
    }

    #[test]
    fn output_limit_counts_inflated_size_of_compressed_entries() {
        let tmp = TempDir::new("limit_inflated");
        let bf = open_shared_sector_archive(&tmp, &[(0x1, 5000, 40)]);
        let out = tmp.join("out");

        let err = unpack_with_limit(&bf, &out, false, 4999);

        assert!(matches!(
            err,
            BigfileError::OutputLimitExceeded { planned: 5000, .. }
        ));
    }

    #[test]
    fn always_sku_subdir_places_unique_hash_under_its_sku() {
        let tmp = TempDir::new("always_sku");
        let path = tmp.join("bigfile.000");
        let hash = name_hash(r"pc-w\lara.drm").unwrap();
        write_archive(
            &path,
            Endian::Little,
            &[ArchiveRecord::stored(hash, 0x7, b"lara")],
        );
        let mut dict = HashDictionary::new();
        dict.load_str(r"pc-w\lara.drm").unwrap();
        let options = UnpackOptions {
            variant_layout: VariantLayout::AlwaysSkuSubdir,
            ..UnpackOptions::default()
        };
        let out = tmp.join("out");

        unpack_archive(&Bigfile::open(&path).unwrap(), &dict, &out, &options).unwrap();

        let expected = out.join("sku_00000007/pc-w/lara.drm");
        assert_eq!(fs::read(expected).unwrap(), b"lara");
    }

    /// Writes and opens an archive holding one record, `0xdeadbeef`, which unpacks unnamed to
    /// `__unknown/deadbeef.bin`.
    fn open_unnamed_record_archive(tmp: &TempDir) -> Bigfile {
        let path = tmp.join("bigfile.000");
        let record = ArchiveRecord::stored(0xDEAD_BEEF, 1, b"payload");
        write_archive(&path, Endian::Little, &[record]);
        Bigfile::open(&path).unwrap()
    }

    #[test]
    fn failed_rename_names_the_destination() {
        let tmp = TempDir::new("error_names_dest");
        let bf = open_unnamed_record_archive(&tmp);
        let out = tmp.join("out");
        let dest = out.join("__unknown/deadbeef.bin");
        fs::create_dir_all(dest.join("blocker")).unwrap();
        let options = UnpackOptions::default();

        let err = unpack_archive(&bf, &HashDictionary::new(), &out, &options).unwrap_err();

        assert!(matches!(err, BigfileError::OutputPath { path, .. } if path == dest));
    }

    #[test]
    fn failed_directory_creation_names_the_directory() {
        let tmp = TempDir::new("error_names_dir");
        let bf = open_unnamed_record_archive(&tmp);
        let out = tmp.join("out");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("__unknown"), b"file in the way").unwrap();
        let options = UnpackOptions::default();

        let err = unpack_archive(&bf, &HashDictionary::new(), &out, &options).unwrap_err();

        let expected = out.join("__unknown");
        assert!(matches!(err, BigfileError::OutputPath { path, .. } if path == expected));
    }

    #[test]
    fn unpack_archive_honors_single_match_per_hash() {
        let tmp = TempDir::new("engine_sku");
        let (bf, dict, _) = create_multi_variant_test_archive(&tmp);

        let out_dir = tmp.join("out_engine_sku");
        let report = unpack_archive(
            &bf,
            &dict,
            &out_dir,
            &UnpackOptions {
                sku_mask: Some(0x0000_0001),
                single_match_per_hash: true,
                variant_layout: VariantLayout::FilenameSuffix,
                raw: false,
                filter: Some(EntryFilter::substring("alpha")),
                jobs: 1,
                max_output_bytes: None,
                dry_run: false,
            },
        )
        .unwrap();
        assert_eq!(report.extracted_files, 1);
        assert_eq!(report.skipped_entries, 5);
        assert_eq!(
            fs::read(out_dir.join("pc-w/alpha.drm")).unwrap(),
            b"alpha_sku3_raw"
        );
    }

    #[test]
    fn unpack_archive_keeps_compressed_bytes_in_raw_mode() {
        let tmp = TempDir::new("raw_compressed");
        let (bf, dict, alpha_z) = create_multi_variant_test_archive(&tmp);

        let out_dir = tmp.join("out_raw");
        let options = UnpackOptions {
            variant_layout: VariantLayout::FilenameSuffix,
            raw: true,
            filter: Some(EntryFilter::substring("alpha")),
            jobs: 1,
            ..UnpackOptions::default()
        };
        unpack_archive(&bf, &dict, &out_dir, &options).unwrap();
        let stored = fs::read(out_dir.join("pc-w/alpha.sku_00000001.drm")).unwrap();
        assert_eq!(stored, alpha_z);
    }

    /// Opens a patch and base archive, in resolution order, whose records share their indexes.
    fn create_patched_pair(tmp: &TempDir) -> [Bigfile; 2] {
        let base_path = write_patched_archives(
            tmp,
            &[
                ArchiveRecord::stored(0x1000, 1, b"base one"),
                ArchiveRecord::stored(0x2000, 1, b"base two"),
            ],
            &[ArchiveRecord::stored(0x1000, 1, b"patched one")],
        );
        open_patched_pair(&base_path)
    }

    fn resolving_options(jobs: usize) -> UnpackOptions {
        UnpackOptions {
            sku_mask: Some(1),
            single_match_per_hash: true,
            jobs,
            ..UnpackOptions::default()
        }
    }

    #[test]
    fn unpack_archive_set_prefers_patch_record() {
        let tmp = TempDir::new("set_unpack");
        let archives = create_patched_pair(&tmp);
        let set = ArchiveSet::new(&archives);
        let out_dir = tmp.join("out");
        let dict = HashDictionary::new();
        let report = unpack_archive_set(set, &dict, &out_dir, &resolving_options(1)).unwrap();
        assert_eq!((report.extracted_files, report.skipped_entries), (2, 1));
        assert_eq!(report.higher_priority_entries, 1);
        let patched = fs::read(out_dir.join("__unknown/00001000.bin")).unwrap();
        assert_eq!(patched, b"patched one");
    }

    #[test]
    fn unpack_archive_set_keeps_records_sharing_an_index_apart() {
        let tmp = TempDir::new("set_index");
        let (base_payload, patch_payload) = (vec![0xAAu8; 1 << 21], vec![0x55u8; 1 << 21]);
        let base = [ArchiveRecord::stored(0x1000, 1, base_payload.as_slice())];
        let patch = [ArchiveRecord::stored(0x1001, 1, patch_payload.as_slice())];
        let archives = open_patched_pair(&write_patched_archives(&tmp, &base, &patch));
        let out_dir = tmp.join("out");

        let dict = HashDictionary::new();
        let set = ArchiveSet::new(&archives);
        unpack_archive_set(set, &dict, &out_dir, &resolving_options(2)).unwrap();
        assert_eq!(
            fs::read(out_dir.join("__unknown/00001000.bin")).unwrap(),
            base_payload
        );
        assert_eq!(
            fs::read(out_dir.join("__unknown/00001001.bin")).unwrap(),
            patch_payload
        );
    }

    #[test]
    fn unpack_archive_set_requires_sku_match_across_archives() {
        let tmp = TempDir::new("set_mask");
        let archives = create_patched_pair(&tmp);
        let set = ArchiveSet::new(&archives);
        let dict = HashDictionary::new();
        let err = unpack_archive_set(set, &dict, &tmp, &UnpackOptions::default());
        assert!(matches!(err, Err(BigfileError::ResolutionRequiresSkuMatch)));
    }

    #[test]
    fn unpack_archive_set_accepts_plain_options_for_single_archive() {
        let tmp = TempDir::new("set_single");
        write_archive(
            tmp.join("bigfile.000"),
            Endian::Little,
            &[ArchiveRecord::stored(0x1000, 1, b"only")],
        );
        let bf = Bigfile::open(tmp.join("bigfile.000")).unwrap();
        let set = ArchiveSet::new(std::slice::from_ref(&bf));
        let out_dir = tmp.join("out");
        let options = UnpackOptions::default();
        let report = unpack_archive_set(set, &HashDictionary::new(), &out_dir, &options).unwrap();
        assert_eq!(
            (report.extracted_files, report.higher_priority_entries),
            (1, 0)
        );
    }

    /// Writes a four-entry archive whose third entry (hash `0x1000_0002`, sector 3) claims to be
    /// zlib-compressed but holds 16 zero-valued bytes, which are not a zlib stream, so inflating it
    /// fails.
    fn create_corrupt_compressed_archive(tmp: &TempDir) -> Bigfile {
        let records = [
            ArchiveRecord::stored(0x1000_0000, 1, &[0; 32]),
            ArchiveRecord::stored(0x1000_0001, 1, &[0; 32]),
            ArchiveRecord::zlib(0x1000_0002, 1, &[0; 16], 32),
            ArchiveRecord::stored(0x1000_0003, 1, &[0; 32]),
        ];
        let archive_path = tmp.join("bigfile.000");
        write_archive(&archive_path, Endian::Little, &records);
        Bigfile::open(&archive_path).unwrap()
    }

    /// Counts [`StagingDir`] directories left directly under `out_dir`.
    fn staging_dir_count(out_dir: &Path) -> usize {
        fs::read_dir(out_dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(execute::STAGING_DIR_PREFIX)
            })
            .count()
    }

    fn unpack_with_jobs(
        bf: &Bigfile,
        out_dir: &Path,
        jobs: usize,
    ) -> Result<UnpackReport, BigfileError> {
        let options = UnpackOptions {
            jobs,
            ..UnpackOptions::default()
        };
        unpack_archive(bf, &HashDictionary::new(), out_dir, &options)
    }

    #[test]
    fn unpack_archive_leaves_no_partial_file_on_error() {
        let tmp = TempDir::new("partial_file");
        let bf = create_corrupt_compressed_archive(&tmp);
        let out_dir = tmp.join("out");

        assert!(unpack_with_jobs(&bf, &out_dir, 1).is_err());
        assert!(out_dir.join("__unknown/10000001.bin").is_file());
        assert!(!out_dir.join("__unknown/10000002.bin").exists());
        assert_eq!(staging_dir_count(&out_dir), 0);
    }

    #[test]
    fn unpack_archive_keeps_existing_file_when_entry_fails() {
        let tmp = TempDir::new("keep_existing");
        let bf = create_corrupt_compressed_archive(&tmp);
        let out_dir = tmp.join("out");
        let existing = out_dir.join("__unknown/10000002.bin");
        fs::create_dir_all(existing.parent().unwrap()).unwrap();
        fs::write(&existing, b"previous run").unwrap();

        assert!(unpack_with_jobs(&bf, &out_dir, 1).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"previous run");
    }

    #[test]
    fn extract_entry_creates_parent_directories() {
        let tmp = TempDir::new("extract_entry");
        let bf = create_corrupt_compressed_archive(&tmp);
        let dest = tmp.join("nested/dir/out.bin");

        let written = extract_entry(&bf, &bf.entries()[0], false, &dest).unwrap();
        assert_eq!(written, 32);
        assert_eq!(fs::read(&dest).unwrap().len(), 32);
        assert_eq!(staging_dir_count(dest.parent().unwrap()), 0);
    }

    #[test]
    fn extract_entry_keeps_existing_file_when_entry_fails() {
        let tmp = TempDir::new("extract_entry_keep");
        let bf = create_corrupt_compressed_archive(&tmp);
        let dest = tmp.join("out.bin");
        fs::write(&dest, b"previous run").unwrap();

        assert!(extract_entry(&bf, &bf.entries()[2], false, &dest).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"previous run");
        assert_eq!(staging_dir_count(&tmp), 0);
    }

    #[cfg(unix)]
    #[test]
    fn extract_entry_writes_through_symlink() {
        let tmp = TempDir::new("extract_entry_link");
        let bf = create_corrupt_compressed_archive(&tmp);
        let (target, link) = (tmp.join("target.bin"), tmp.join("link.bin"));
        fs::write(&target, b"old").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        extract_entry(&bf, &bf.entries()[0], false, &link).unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read(&target).unwrap().len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn extract_entry_creates_dangling_symlink_target() {
        let tmp = TempDir::new("extract_entry_dangling");
        let bf = create_corrupt_compressed_archive(&tmp);
        let link = tmp.join("link.bin");
        std::os::unix::fs::symlink("target.bin", &link).unwrap();

        extract_entry(&bf, &bf.entries()[0], false, &link).unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read(tmp.join("target.bin")).unwrap().len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn extract_entry_rejects_symlink_loop() {
        let tmp = TempDir::new("extract_entry_loop");
        let bf = create_corrupt_compressed_archive(&tmp);
        let link = tmp.join("loop.bin");
        std::os::unix::fs::symlink("loop.bin", &link).unwrap();

        assert!(extract_entry(&bf, &bf.entries()[0], false, &link).is_err());
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    }

    #[test]
    fn extract_entry_writes_directly_to_null_device() {
        let tmp = TempDir::new("extract_entry_device");
        let bf = create_corrupt_compressed_archive(&tmp);
        let null = Path::new(if cfg!(windows) { "NUL" } else { "/dev/null" });

        assert_eq!(
            extract_entry(&bf, &bf.entries()[0], false, null).unwrap(),
            32
        );
        assert!(!fs::symlink_metadata(null).is_ok_and(|meta| meta.is_file()));
    }

    #[test]
    fn unpack_archive_removes_staging_dir_after_success() {
        let tmp = TempDir::new("staging_cleanup");
        let (bf, dict, _) = create_multi_variant_test_archive(&tmp);
        let out_dir = tmp.join("out");

        unpack_archive(&bf, &dict, &out_dir, &UnpackOptions::default()).unwrap();
        assert_eq!(staging_dir_count(&out_dir), 0);
    }

    #[test]
    fn unpack_archive_parallel_workers_propagate_decompression_error() {
        let tmp = TempDir::new("parallel_err");
        let bf = create_corrupt_compressed_archive(&tmp);
        let err = unpack_with_jobs(&bf, &tmp.join("out"), 4).unwrap_err();
        assert!(matches!(
            err,
            BigfileError::DecompressError {
                index: 2,
                name_hash: 0x1000_0002,
                ..
            }
        ));
    }

    fn dry_run_options() -> UnpackOptions {
        UnpackOptions {
            dry_run: true,
            ..UnpackOptions::default()
        }
    }

    #[test]
    fn dry_run_reports_what_a_real_unpack_writes() {
        let tmp = TempDir::new("dry_run_report");
        let (bf, dict, _) = create_multi_variant_test_archive(&tmp);

        let planned = unpack_archive(&bf, &dict, &tmp.join("planned"), &dry_run_options());
        let written = unpack_archive(&bf, &dict, &tmp.join("written"), &UnpackOptions::default());

        assert_eq!(planned.unwrap(), written.unwrap());
    }

    #[test]
    fn dry_run_writes_nothing() {
        let tmp = TempDir::new("dry_run_nothing");
        let (bf, dict, _) = create_multi_variant_test_archive(&tmp);
        let out = tmp.join("out");

        unpack_archive(&bf, &dict, &out, &dry_run_options()).unwrap();

        assert!(!out.exists());
    }

    #[test]
    fn dry_run_reports_output_over_the_limit() {
        let tmp = TempDir::new("dry_run_limit");
        let bf = open_shared_sector_archive(&tmp, &[(1, 2048, 0), (2, 2048, 0)]);
        let options = UnpackOptions {
            max_output_bytes: Some(1),
            ..dry_run_options()
        };

        let report = unpack_archive(&bf, &HashDictionary::new(), &tmp.join("out"), &options);

        assert_eq!(report.unwrap().extracted_bytes, 4096);
    }

    #[test]
    fn dry_run_counts_higher_priority_entries_like_a_real_unpack() {
        let tmp = TempDir::new("dry_run_patch");
        let archives = create_patched_pair(&tmp);
        let set = ArchiveSet::new(&archives);
        let dict = HashDictionary::new();
        let dry_run = UnpackOptions {
            dry_run: true,
            ..resolving_options(1)
        };

        let planned = unpack_archive_set(set, &dict, &tmp.join("planned"), &dry_run);
        let written = unpack_archive_set(set, &dict, &tmp.join("written"), &resolving_options(1));

        assert_eq!(planned.unwrap(), written.unwrap());
    }
}
