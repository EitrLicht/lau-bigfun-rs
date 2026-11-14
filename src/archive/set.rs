//! Ordered archive sets that resolve one record across stacked archives.
//!
//! Games mount several whole archives, such as a patch over its base, and take each name from the
//! first archive in their priority order that holds it. The order is game-specific, so callers open
//! the archives and pass them highest priority first.

use super::Bigfile;
use crate::fat::Entry;

/// One record resolved across archives, with the archive its offsets refer to.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedEntry<'a> {
    /// Archive holding `entry`.
    pub archive: &'a Bigfile,
    /// Position of `archive` in the resolution order.
    pub archive_rank: usize,
    /// The selected record.
    pub entry: &'a Entry,
}

/// Borrowed archives in resolution order, highest priority first.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveSet<'a> {
    archives: &'a [Bigfile],
}

impl<'a> ArchiveSet<'a> {
    /// Orders `archives` for resolution, highest priority first.
    #[inline]
    #[must_use]
    pub const fn new(archives: &'a [Bigfile]) -> Self {
        Self { archives }
    }

    /// Archives in resolution order.
    #[inline]
    #[must_use]
    pub const fn archives(self) -> &'a [Bigfile] {
        self.archives
    }

    /// Asks the archives in order and returns the first record [`Bigfile::find_with_spec_mask`]
    /// selects. A record must pass `spec_mask`, so a name whose records in one archive all fail falls
    /// through to the next archive in the order.
    #[must_use]
    pub fn resolve(self, name_hash: u32, spec_mask: u32) -> Option<ResolvedEntry<'a>> {
        self.archives
            .iter()
            .enumerate()
            .find_map(|(archive_rank, archive)| {
                let entry = archive.find_with_spec_mask(name_hash, spec_mask)?;
                Some(ResolvedEntry {
                    archive,
                    archive_rank,
                    entry,
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ArchiveRecord, TempDir, open_patched_pair, write_patched_archives};

    const SHARED: u32 = 0x1000;
    const BASE_ONLY: u32 = 0x2000;

    /// Writes a base archive and a `patch.000`, where the patch holds `SHARED` with `patch_flags`.
    fn create_patched_archives(prefix: &str, patch_flags: u32) -> TempDir {
        let dir = TempDir::new(prefix);
        write_patched_archives(
            &dir,
            &[
                ArchiveRecord::stored(SHARED, 0b11, b"base shared"),
                ArchiveRecord::stored(BASE_ONLY, 0b11, b"base only"),
            ],
            &[ArchiveRecord::stored(SHARED, patch_flags, b"patch shared")],
        );
        dir
    }

    /// Opens the patched pair in `dir` in resolution order.
    fn open_pair(dir: &TempDir) -> [Bigfile; 2] {
        open_patched_pair(&dir.join("bigfile.000"))
    }

    #[test]
    fn resolve_prefers_passing_patch_record() {
        let archives = open_pair(&create_patched_archives("set_patch", 0b01));
        let set = ArchiveSet::new(&archives);
        let resolved = set.resolve(SHARED, 0b01).unwrap();
        assert_eq!(
            (resolved.archive_rank, resolved.archive.stem()),
            (0, "patch")
        );
    }

    #[test]
    fn resolve_falls_through_when_patch_records_fail_mask() {
        let archives = open_pair(&create_patched_archives("set_fall", 0b01));
        let set = ArchiveSet::new(&archives);
        let resolved = set.resolve(SHARED, 0b10).unwrap();
        assert_eq!(
            (resolved.archive_rank, resolved.archive.stem()),
            (1, "bigfile")
        );
    }

    #[test]
    fn resolve_reaches_base_for_hash_absent_from_patch() {
        let archives = open_pair(&create_patched_archives("set_base", 0b01));
        let set = ArchiveSet::new(&archives);
        assert_eq!(set.resolve(BASE_ONLY, 0b01).unwrap().archive_rank, 1);
    }

    #[test]
    fn resolve_rejects_hash_absent_from_every_archive() {
        let archives = open_pair(&create_patched_archives("set_none", 0b01));
        let set = ArchiveSet::new(&archives);
        assert!(set.resolve(0x3000, 0).is_none());
    }
}
