//! Planning an extraction: choosing records, resolving output paths and sizing the result.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::{UnpackOptions, VariantLayout};
use crate::archive::ArchiveSet;
use crate::fat::{Entry, Fat};
use crate::filelist::HashDictionary;
use crate::filter::EntryFilter;
use crate::path::{append_stem_suffix, normalized_rel_key, parent_dir};

#[inline]
const fn needs_spec_disambiguation(layout: VariantLayout, total_selected_for_hash: usize) -> bool {
    match layout {
        VariantLayout::AlwaysSpecSubdir => true,
        VariantLayout::SpecSubdirWhenAmbiguous | VariantLayout::FilenameSuffix => {
            total_selected_for_hash > 1
        }
    }
}

/// Formats the relative output path for a variant by applying any filename stem suffix
/// (`.spec_<hex>` and/or `.v{occ}`) and any `spec_<hex>/` directory prefix orthogonally.
fn format_variant_rel_path(
    base_rel_path: &Path,
    spec_flags: u32,
    layout: VariantLayout,
    disambiguate: bool,
    same_spec_occurrence_index: usize,
) -> PathBuf {
    let mut suffix = String::new();
    if disambiguate && layout == VariantLayout::FilenameSuffix {
        suffix.push_str(&format!(".spec_{spec_flags:08x}"));
    }
    if same_spec_occurrence_index > 0 {
        suffix.push_str(&format!(".v{same_spec_occurrence_index}"));
    }
    let rel = if suffix.is_empty() {
        base_rel_path.to_path_buf()
    } else {
        append_stem_suffix(base_rel_path, &suffix)
    };
    if disambiguate
        && matches!(
            layout,
            VariantLayout::AlwaysSpecSubdir | VariantLayout::SpecSubdirWhenAmbiguous
        )
    {
        PathBuf::from(format!("spec_{spec_flags:08x}")).join(rel)
    } else {
        rel
    }
}

struct SelectedCandidate<'a> {
    archive_rank: usize,
    entry: &'a Entry,
    base_rel: PathBuf,
    is_resolved: bool,
    total_for_hash: usize,
}

pub(super) struct SelectionResult<'a> {
    selected: Vec<SelectedCandidate<'a>>,
    pub(super) skipped_entries: usize,
}

struct PlannedRelItem<'a> {
    archive_rank: usize,
    entry: &'a Entry,
    rel: RelPath,
}

/// A relative output path and its comparison key ([`normalized_rel_key`]), built together by
/// [`RelPath::new`]. Replace a `RelPath` whole rather than editing its fields, so the key keeps
/// matching the path.
struct RelPath {
    path: PathBuf,
    key: String,
}

impl RelPath {
    /// Pairs `path` with its comparison key.
    fn new(path: PathBuf) -> Self {
        let key = normalized_rel_key(&path);
        Self { path, key }
    }
}

/// The first free candidate [`first_free_rel_path`] found, and the occurrence number that made it.
struct FreeRelPath {
    occurrence: usize,
    rel: RelPath,
}

pub(super) struct PlannedExtraction<'a> {
    pub(super) archive_rank: usize,
    pub(super) entry: &'a Entry,
    pub(super) dest_path: PathBuf,
}

pub(super) struct ExtractionPlan<'a> {
    pub(super) items: Vec<PlannedExtraction<'a>>,
    pub(super) unique_dirs: HashSet<PathBuf>,
    pub(super) resolved_entries: usize,
    pub(super) unknown_entries: usize,
}

/// Pass 1: Scans contiguous hash runs in the FAT of each archive in `set` and selects entries
/// matching `options`.
pub(super) fn select_archive_entries<'a>(
    set: ArchiveSet<'a>,
    dict: &HashDictionary,
    options: &UnpackOptions,
) -> SelectionResult<'a> {
    let archives = set.archives();
    let record_count = archives.iter().map(|a| a.entries().len()).sum();
    let mut selection = SelectionResult {
        selected: Vec::with_capacity(record_count),
        skipped_entries: 0,
    };
    let mut chosen_buf = Vec::new();
    for (archive_rank, archive) in archives.iter().enumerate() {
        for run in archive.hash_runs() {
            select_entries_from_run(set, archive_rank, run, options, &mut chosen_buf);
            let hash = run[0].name_hash;
            let filtered_out = |f: &EntryFilter| !f.matches(hash, dict.get(hash));
            if chosen_buf.is_empty() || options.filter.as_ref().is_some_and(filtered_out) {
                selection.skipped_entries += run.len();
                continue;
            }
            selection.add_run(archive_rank, run, &chosen_buf, dict);
        }
    }
    selection
}

impl<'a> SelectionResult<'a> {
    /// Adds `chosen`, the records picked from the hash run `run` of the archive at `archive_rank`,
    /// as candidates named from `dict`, and counts the rest of `run` as skipped.
    fn add_run(
        &mut self,
        archive_rank: usize,
        run: &[Entry],
        chosen: &[&'a Entry],
        dict: &HashDictionary,
    ) {
        let output = dict.relative_path_or_fallback(run[0].name_hash);
        self.skipped_entries += run.len() - chosen.len();
        let total_for_hash = chosen.len();
        self.selected
            .extend(chosen.iter().map(|&entry| SelectedCandidate {
                archive_rank,
                entry,
                base_rel: output.path.clone(),
                is_resolved: output.resolved,
                total_for_hash,
            }));
    }
}

/// Selects matching records from a single contiguous `name_hash` run of the archive at
/// `archive_rank` into `out`. In single-match
/// mode, the one selected record is taken only from the archive that resolves the hash, so a hash
/// held by several archives is selected once.
fn select_entries_from_run<'a>(
    set: ArchiveSet<'a>,
    archive_rank: usize,
    run: &'a [Entry],
    options: &UnpackOptions,
    out: &mut Vec<&'a Entry>,
) {
    out.clear();
    match options.resolution_mask() {
        Some(mask) => {
            let resolved = set.resolve(run[0].name_hash, mask);
            out.extend(
                resolved
                    .filter(|resolved| resolved.archive_rank == archive_rank)
                    .map(|resolved| resolved.entry),
            );
        }
        None => out.extend(Fat::filter_spec_mask(run, options.spec_mask)),
    }
}

/// Tries the output paths `candidate(n)` for `n = first, first + 1, ...` and returns the first
/// whose comparison key `is_taken` does not reject.
fn first_free_rel_path(
    first: usize,
    candidate: impl Fn(usize) -> PathBuf,
    is_taken: impl Fn(&str) -> bool,
) -> FreeRelPath {
    let mut occurrence = first;
    loop {
        let rel = RelPath::new(candidate(occurrence));
        if !is_taken(&rel.key) {
            return FreeRelPath { occurrence, rel };
        }
        occurrence += 1;
    }
}

/// Relative output paths claimed for the selected records.
struct RelativePlan<'a> {
    items: Vec<PlannedRelItem<'a>>,
    claimed: ClaimedPaths,
}

impl<'a> RelativePlan<'a> {
    /// Claims a unique relative output path for every record in `selection`, in selection order.
    fn claim_all(selection: &SelectionResult<'a>, layout: VariantLayout) -> Self {
        let count = selection.selected.len();
        let mut plan = Self {
            items: Vec::with_capacity(count),
            claimed: ClaimedPaths::with_capacity(count),
        };
        for candidate in &selection.selected {
            let rel = plan.claimed.claim_variant_path(candidate, layout);
            plan.items.push(PlannedRelItem {
                archive_rank: candidate.archive_rank,
                entry: candidate.entry,
                rel,
            });
        }
        plan
    }

    /// Ensures no planned output file path collides with any ancestor directory of another
    /// planned file, renaming such files with `.file` (or `.file.v{N}`).
    fn resolve_file_dir_collisions(&mut self) {
        let dir_keys = collect_ancestor_dir_keys(&self.items);
        if dir_keys.is_empty() {
            return;
        }
        for item in &mut self.items {
            if dir_keys.contains(&item.rel.key) {
                item.rel = self
                    .claimed
                    .claim_file_path_beside_dir(&item.rel.path, &dir_keys);
            }
        }
    }
}

/// The comparison key of every claimed relative output path, mapped to the next `.v{N}`
/// occurrence to try when another record wants that path.
struct ClaimedPaths {
    next_occurrence: HashMap<String, usize>,
}

impl ClaimedPaths {
    /// An empty set with room for `count` paths.
    fn with_capacity(count: usize) -> Self {
        Self {
            next_occurrence: HashMap::with_capacity(count),
        }
    }

    /// Records `rel` as claimed, with `.v1` as the next occurrence to try for it, and returns it.
    fn claim(&mut self, rel: RelPath) -> RelPath {
        self.next_occurrence.insert(rel.key.clone(), 1);
        rel
    }

    /// Claims a unique case-insensitive relative output path for `candidate`, disambiguating
    /// colliding paths with `.v{N}` suffixes.
    fn claim_variant_path(
        &mut self,
        candidate: &SelectedCandidate<'_>,
        layout: VariantLayout,
    ) -> RelPath {
        let disambiguate = needs_spec_disambiguation(layout, candidate.total_for_hash);
        let spec_flags = candidate.entry.spec_flags;
        let candidate_path = |occurrence| {
            format_variant_rel_path(
                &candidate.base_rel,
                spec_flags,
                layout,
                disambiguate,
                occurrence,
            )
        };
        let initial = RelPath::new(candidate_path(0));
        let Some(&next_occurrence) = self.next_occurrence.get(&initial.key) else {
            return self.claim(initial);
        };
        let free = first_free_rel_path(next_occurrence, candidate_path, |key| {
            self.next_occurrence.contains_key(key)
        });
        self.next_occurrence
            .insert(initial.key, free.occurrence + 1);
        self.claim(free.rel)
    }

    /// Claims `rel_path` with `.file` (or `.file.v{N}`) appended to its stem, for a file path that
    /// collides with one of the ancestor directory keys `dir_keys`.
    fn claim_file_path_beside_dir(
        &mut self,
        rel_path: &Path,
        dir_keys: &HashSet<String>,
    ) -> RelPath {
        let candidate = |n| match n {
            0 => append_stem_suffix(rel_path, ".file"),
            n => append_stem_suffix(rel_path, &format!(".file.v{n}")),
        };
        let free = first_free_rel_path(0, candidate, |key| {
            dir_keys.contains(key) || self.next_occurrence.contains_key(key)
        });
        self.claim(free.rel)
    }
}

/// Pass 2: Resolves output paths, collects unique parent directories, and sorts tasks by sector.
pub(super) fn build_extraction_plan<'a>(
    selection: &SelectionResult<'a>,
    out_dir: &Path,
    layout: VariantLayout,
) -> ExtractionPlan<'a> {
    let mut rel_plan = RelativePlan::claim_all(selection, layout);
    rel_plan.resolve_file_dir_collisions();

    let mut items: Vec<PlannedExtraction<'a>> = rel_plan
        .items
        .into_iter()
        .map(|item| PlannedExtraction {
            archive_rank: item.archive_rank,
            entry: item.entry,
            dest_path: out_dir.join(item.rel.path),
        })
        .collect();

    let unique_dirs = collect_unique_parent_dirs(&items);
    // Order by archive, then physical sector, so single-thread unpacks read sequentially and
    // parallel workers claim each archive's items in non-decreasing offset order.
    items.sort_unstable_by_key(|item| {
        (
            item.archive_rank,
            item.entry.sector_number,
            item.entry.index,
        )
    });

    let resolved_entries = selection.selected.iter().filter(|c| c.is_resolved).count();
    ExtractionPlan {
        items,
        unique_dirs,
        resolved_entries,
        unknown_entries: selection.selected.len() - resolved_entries,
    }
}

/// Collects normalized case-insensitive relative keys for all ancestor directories of `rel_items`
/// by slicing the already-normalized `'/'`-separated `item.rel.key`.
fn collect_ancestor_dir_keys(rel_items: &[PlannedRelItem<'_>]) -> HashSet<String> {
    let mut dir_keys = HashSet::new();
    for item in rel_items {
        let mut slice = item.rel.key.as_str();
        while let Some(slash_idx) = slice.rfind('/') {
            slice = &slice[..slash_idx];
            if slice.is_empty() || dir_keys.contains(slice) {
                break;
            }
            dir_keys.insert(slice.to_string());
        }
    }
    dir_keys
}

/// Collects all unique parent directories across the finalized extraction items.
fn collect_unique_parent_dirs(items: &[PlannedExtraction<'_>]) -> HashSet<PathBuf> {
    let mut unique_dirs = HashSet::new();
    for item in items {
        let parent = parent_dir(&item.dest_path);
        if !unique_dirs.contains(parent) {
            unique_dirs.insert(parent.to_path_buf());
        }
    }
    unique_dirs
}

/// Total bytes `items` will write, read raw when `raw` is set (see [`Entry::read_len`]). Entry
/// reads enforce these sizes, so the total bounds the output before anything is written.
pub(super) fn planned_output_bytes(items: &[PlannedExtraction<'_>], raw: bool) -> u64 {
    items.iter().fold(0u64, |total, item| {
        total.saturating_add(u64::from(item.entry.read_len(raw)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_entry;

    fn plan_dest_paths(entries: &[Entry], rels: &[&str]) -> Vec<PathBuf> {
        let selection = SelectionResult {
            selected: entries
                .iter()
                .zip(rels)
                .map(|(entry, &p)| SelectedCandidate {
                    archive_rank: 0,
                    entry,
                    base_rel: PathBuf::from(p),
                    is_resolved: true,
                    total_for_hash: 1,
                })
                .collect(),
            skipped_entries: 0,
        };
        build_extraction_plan(
            &selection,
            Path::new("/out"),
            VariantLayout::SpecSubdirWhenAmbiguous,
        )
        .items
        .into_iter()
        .map(|i| i.dest_path)
        .collect()
    }

    #[test]
    fn file_dir_disambiguation_skips_a_taken_file_suffix() {
        let entries = [
            sample_entry(0, 0x1111_1111, 1, 1),
            sample_entry(1, 0x2222_2222, 2, 1),
            sample_entry(2, 0x3333_3333, 3, 1),
        ];
        assert_eq!(
            plan_dest_paths(&entries, &["dir", "dir/x", "dir.file/y"]),
            vec![
                PathBuf::from("/out/dir.file.v1"),
                PathBuf::from("/out/dir/x"),
                PathBuf::from("/out/dir.file/y"),
            ]
        );
    }

    #[test]
    fn disambiguates_colliding_sanitized_paths_in_forward_order() {
        let entries = [
            sample_entry(0, 0x1111_1111, 1, 1),
            sample_entry(1, 0x2222_2222, 2, 1),
            sample_entry(2, 0x3333_3333, 3, 1),
            sample_entry(3, 0x4444_4444, 4, 1),
        ];
        let rels = [
            "pc-w/lara.drm",
            "pc-w/lara.drm",
            "pc-w/lara.v1.drm",
            "pc-w/lara.drm",
        ];
        assert_eq!(
            plan_dest_paths(&entries, &rels),
            vec![
                PathBuf::from("/out/pc-w/lara.drm"),
                PathBuf::from("/out/pc-w/lara.v1.drm"),
                PathBuf::from("/out/pc-w/lara.v1.v1.drm"),
                PathBuf::from("/out/pc-w/lara.v2.drm"),
            ]
        );
    }

    #[test]
    fn disambiguates_colliding_sanitized_paths_in_reverse_order() {
        let entries = [
            sample_entry(0, 0x1111_1111, 1, 1),
            sample_entry(1, 0x2222_2222, 2, 1),
            sample_entry(2, 0x3333_3333, 3, 1),
        ];
        let rels = ["pc-w/lara.v1.drm", "pc-w/lara.drm", "pc-w/lara.drm"];
        assert_eq!(
            plan_dest_paths(&entries, &rels),
            vec![
                PathBuf::from("/out/pc-w/lara.v1.drm"),
                PathBuf::from("/out/pc-w/lara.drm"),
                PathBuf::from("/out/pc-w/lara.v2.drm"),
            ]
        );
        assert_eq!(
            normalized_rel_key(Path::new(r"PC-W\Lara.v1.DRM")),
            normalized_rel_key(Path::new("pc-w/lara.v1.drm"))
        );
    }

    #[test]
    fn disambiguates_paths_differing_only_in_latin1_case() {
        let entries = [
            sample_entry(0, 0x1111_1111, 1, 1),
            sample_entry(1, 0x2222_2222, 2, 1),
        ];
        assert_eq!(
            plan_dest_paths(&entries, &["pc-w/caf\u{c9}.drm", "pc-w/caf\u{e9}.drm"]),
            vec![
                PathBuf::from("/out/pc-w/caf\u{c9}.drm"),
                PathBuf::from("/out/pc-w/caf\u{e9}.v1.drm"),
            ]
        );
    }

    #[test]
    fn build_extraction_plan_disambiguates_file_vs_dir_collision() {
        let entries = [
            sample_entry(0, 0x1111_1111, 1, 1),
            sample_entry(1, 0x2222_2222, 2, 1),
        ];
        assert_eq!(
            plan_dest_paths(&entries, &["pc-w/foo", "pc-w/foo/bar.drm"]),
            vec![
                PathBuf::from("/out/pc-w/foo.file"),
                PathBuf::from("/out/pc-w/foo/bar.drm"),
            ]
        );
    }

    #[test]
    fn format_variant_rel_path_supports_all_variant_layouts() {
        use VariantLayout::{
            AlwaysSpecSubdir as Always, FilenameSuffix as Suffix,
            SpecSubdirWhenAmbiguous as Ambiguous,
        };
        let fmt = |rel: &str, layout, multi, occ| {
            format_variant_rel_path(Path::new(rel), 0x0000_0003, layout, multi, occ)
        };
        assert_eq!(
            fmt("pc-w/lara.drm", Ambiguous, false, 0),
            Path::new("pc-w/lara.drm")
        );
        assert_eq!(
            fmt("pc-w/lara.drm", Ambiguous, true, 0),
            Path::new("spec_00000003/pc-w/lara.drm")
        );
        assert_eq!(
            fmt("pc-w/lara.drm", Always, true, 0),
            Path::new("spec_00000003/pc-w/lara.drm")
        );
        assert_eq!(
            fmt("pc-w/lara.drm", Suffix, true, 0),
            Path::new("pc-w/lara.spec_00000003.drm")
        );
        assert_eq!(
            fmt("pc-w/lara.drm", Suffix, true, 1),
            Path::new("pc-w/lara.spec_00000003.v1.drm")
        );
        assert_eq!(
            fmt("README", Suffix, true, 1),
            Path::new("README.spec_00000003.v1")
        );
        assert_eq!(
            fmt("pc-w/trailing.", Suffix, true, 1),
            Path::new("pc-w/trailing.spec_00000003.v1")
        );
    }
}
