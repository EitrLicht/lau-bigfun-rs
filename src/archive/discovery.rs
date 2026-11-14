//! Discovery and opening of an archive's ordered physical part files.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use super::{Bigfile, BigfileError};
use crate::path::parent_dir;

/// Bundle of discovered physical archive part files and metadata.
pub(super) struct DiscoveredParts {
    pub(super) dir_path: PathBuf,
    pub(super) stem: String,
    pub(super) part_paths: Vec<PathBuf>,
    pub(super) part_files: Vec<File>,
    pub(super) part_sizes: Vec<u64>,
}

/// Cached regular-file directory entry with precomputed ASCII-lowercased filename.
#[derive(Debug, Clone)]
struct DirFileEntry {
    name: String,
    name_lower: String,
    path: PathBuf,
}

/// Classification of the user-supplied archive target path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    /// Directory path (`target.is_dir()`): discover `bigfile.000`..`bigfile.NNN`, fallback `bigfile.dat`.
    Directory,
    /// Numbered part path (`<stem>.000`..`<stem>.999`): discover `<stem>.000`..`<stem>.NNN` only.
    NumberedPart,
    /// Virtual or monolithic `.dat` path (`<stem>.dat`): discover `<stem>.000`..`<stem>.NNN`, fallback `<stem>.dat`.
    DatFile,
    /// Explicit archive file path opened as it is if it is a regular file: a custom name (e.g.
    /// `custom.big` or `archive.bin`), or any path when parts are not discovered from the name.
    OtherFile,
}

/// The archive path the user gave, with the directory, stem and kind that say where and how to
/// look for its part files.
struct ArchiveTarget<'a> {
    /// The path as given.
    path: &'a Path,
    /// Directory that holds the part files.
    dir: PathBuf,
    /// File stem the part files are named after (`bigfile` for a directory).
    stem: String,
    /// How to look for the part files: numbered parts, a `.dat` fallback, or the file as named.
    kind: TargetKind,
}

impl<'a> ArchiveTarget<'a> {
    /// Classifies `path` as a directory or a part, `.dat` or other file. With `single_part`, a
    /// file is opened as it is (`OtherFile`) and a directory is refused.
    fn resolve(path: &'a Path, single_part: bool) -> Result<Self, BigfileError> {
        let no_parts = || BigfileError::NoPartsFound(path.to_path_buf());
        if path.is_dir() {
            if single_part {
                return Err(no_parts());
            }
            return Ok(Self {
                path,
                dir: path.to_path_buf(),
                stem: "bigfile".to_string(),
                kind: TargetKind::Directory,
            });
        }

        let dir = parent_dir(path).to_path_buf();
        let stem = path
            .file_stem()
            .or_else(|| path.file_name())
            .and_then(|s| s.to_str())
            .ok_or_else(no_parts)?
            .to_string();
        let kind = if single_part {
            TargetKind::OtherFile
        } else {
            match path.extension().and_then(|s| s.to_str()) {
                Some(ext) if is_numbered_part_extension(ext) => TargetKind::NumberedPart,
                Some(ext) if is_dat_extension(ext) => TargetKind::DatFile,
                _ => TargetKind::OtherFile,
            }
        };
        Ok(Self {
            path,
            dir,
            stem,
            kind,
        })
    }

    /// Resolves the ordered part file paths this target names, according to its kind.
    fn part_paths(&self) -> Result<Vec<PathBuf>, BigfileError> {
        if self.kind == TargetKind::OtherFile {
            // The listing only matches the name's case, so a directory that cannot be listed still
            // opens the file under the name it was given.
            let dir_entries = read_sorted_dir_entries(&self.dir).unwrap_or_default();
            return Ok(find_named_file(self.path, &dir_entries)
                .into_iter()
                .collect());
        }

        let dir_entries = read_sorted_dir_entries(&self.dir)?;
        let mut paths = discover_numbered_part_paths(&self.stem, &dir_entries);
        if paths.is_empty() && matches!(self.kind, TargetKind::Directory | TargetKind::DatFile) {
            let explicit_dat = (self.kind == TargetKind::DatFile).then_some(self.path);
            if let Some(fallback) = find_dat_fallback_path(&self.stem, explicit_dat, &dir_entries) {
                paths.push(fallback);
            }
        }
        Ok(paths)
    }
}

impl Bigfile {
    /// Discovers and opens ordered physical part files (`.000`, `.001`, ... or single `.dat`) for
    /// `target`, or, when `single_part` is set, opens exactly `target` as the only part.
    pub(super) fn discover_parts(
        target: &Path,
        single_part: bool,
    ) -> Result<DiscoveredParts, BigfileError> {
        let target = ArchiveTarget::resolve(target, single_part)?;
        let part_paths = target.part_paths()?;
        if part_paths.is_empty() {
            return Err(BigfileError::NoPartsFound(target.path.to_path_buf()));
        }

        let (part_files, part_sizes) = open_part_files(&part_paths)?;
        let actual_stem = part_paths[0]
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&target.stem)
            .to_string();

        Ok(DiscoveredParts {
            dir_path: target.dir,
            stem: actual_stem,
            part_paths,
            part_files,
            part_sizes,
        })
    }
}

/// Returns `true` if `ext` is a 3-digit numbered part extension (`"000"`..`"999"`).
#[inline]
fn is_numbered_part_extension(ext: &str) -> bool {
    ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit())
}

/// Returns `true` if `ext` matches `"dat"` (ASCII case-insensitive).
#[inline]
fn is_dat_extension(ext: &str) -> bool {
    ext.eq_ignore_ascii_case("dat")
}

/// Reads regular-file directory entries sorted by `(name_lower, name)` for deterministic
/// case-insensitive matching across all filesystems without per-probe `stat` syscalls.
fn read_sorted_dir_entries(dir_path: &Path) -> Result<Vec<DirFileEntry>, BigfileError> {
    let rd = match fs::read_dir(dir_path) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(BigfileError::Io(e)),
    };

    let mut entries: Vec<DirFileEntry> = rd
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type()
                .is_ok_and(|ft| ft.is_file() || (ft.is_symlink() && e.path().is_file()))
        })
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let name_lower = name.to_ascii_lowercase();
            Some(DirFileEntry {
                name,
                name_lower,
                path: e.path(),
            })
        })
        .collect();

    entries.sort_unstable_by(|a, b| {
        a.name_lower
            .cmp(&b.name_lower)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(entries)
}

/// Discovers sequential `<stem>.000`, `<stem>.001`, ... (`.000`..`.999`) part paths.
fn discover_numbered_part_paths(
    requested_stem: &str,
    dir_entries: &[DirFileEntry],
) -> Vec<PathBuf> {
    (0u32..1000)
        .map_while(|idx| find_in_dir_entries(dir_entries, &part_file_name(requested_stem, idx)))
        .collect()
}

/// Looks up a filename in `dir_entries` (preferring an exact case match before falling back to
/// the first deterministic case-insensitive match).
fn find_in_dir_entries(dir_entries: &[DirFileEntry], expected_name: &str) -> Option<PathBuf> {
    let expected_name_lower = expected_name.to_ascii_lowercase();
    let start = dir_entries.partition_point(|e| e.name_lower < expected_name_lower);
    let end = dir_entries[start..].partition_point(|e| e.name_lower == expected_name_lower) + start;
    let matches = &dir_entries[start..end];
    matches
        .iter()
        .find(|e| e.name == expected_name)
        .or_else(|| matches.first())
        .map(|e| e.path.clone())
}

/// Resolves a monolithic `<stem>.dat` fallback when no `.000` parts exist: an explicit `.dat`
/// target (see [`find_named_file`]), otherwise `<stem>.dat`.
fn find_dat_fallback_path(
    requested_stem: &str,
    explicit_dat_target: Option<&Path>,
    dir_entries: &[DirFileEntry],
) -> Option<PathBuf> {
    match explicit_dat_target {
        Some(target) => find_named_file(target, dir_entries),
        None => find_in_dir_entries(dir_entries, &format!("{requested_stem}.dat")),
    }
}

/// Finds the file `target` names in `dir_entries` by its file name, ignoring case, or returns
/// `target` as given if it is a file.
///
/// An existing target can be missing from the listing under the name it was given, such as a
/// Windows 8.3 short name or a name Unicode-normalized differently from the stored one.
fn find_named_file(target: &Path, dir_entries: &[DirFileEntry]) -> Option<PathBuf> {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| find_in_dir_entries(dir_entries, name))
        .or_else(|| target.is_file().then(|| target.to_path_buf()))
}

/// Opens all discovered part files and queries their physical byte lengths.
fn open_part_files(part_paths: &[PathBuf]) -> io::Result<(Vec<File>, Vec<u64>)> {
    let mut part_files = Vec::with_capacity(part_paths.len());
    let mut part_sizes = Vec::with_capacity(part_paths.len());
    for path in part_paths {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        part_files.push(file);
        part_sizes.push(size);
    }
    Ok((part_files, part_sizes))
}

/// File name of part `index` of the archive named `stem`: `<stem>.000`, `<stem>.001`, ...
pub(super) fn part_file_name(stem: &str, index: u32) -> String {
    format!("{stem}.{index:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, write_one_empty_record};

    #[test]
    fn target_resolution_isolates_numbered_parts_from_other_files() {
        let dir = TempDir::new("target_resolution");

        fs::create_dir_all(dir.join("bigfile.000")).unwrap();
        fs::create_dir_all(dir.join("BIGFILE.DAT")).unwrap();
        assert!(matches!(
            Bigfile::open(&dir).unwrap_err(),
            BigfileError::NoPartsFound(_)
        ));
        fs::remove_dir(dir.join("bigfile.000")).unwrap();
        fs::remove_dir(dir.join("BIGFILE.DAT")).unwrap();

        let part1_path = dir.join("bigfile.001");
        write_one_empty_record(&part1_path);
        assert!(matches!(
            Bigfile::open(&part1_path).unwrap_err(),
            BigfileError::NoPartsFound(_)
        ));
        fs::remove_file(&part1_path).unwrap();

        let part0_path = dir.join("bigfile.000");
        write_one_empty_record(&part0_path);
        assert!(matches!(
            Bigfile::open(dir.join("bigfile.txt")).unwrap_err(),
            BigfileError::NoPartsFound(_)
        ));
        let via_dat = Bigfile::open(dir.join("bigfile.dat")).unwrap();
        assert_eq!(via_dat.part_paths(), &[part0_path]);

        let custom_path = dir.join("custom.big");
        write_one_empty_record(&custom_path);
        let via_custom = Bigfile::open(&custom_path).unwrap();
        assert_eq!(via_custom.part_paths(), &[custom_path]);
    }

    #[test]
    fn find_dat_fallback_prefers_exact_case_match() {
        let synthetic_entries = vec![
            DirFileEntry {
                name: "BIGFILE.DAT".to_string(),
                name_lower: "bigfile.dat".to_string(),
                path: PathBuf::from("/dir/BIGFILE.DAT"),
            },
            DirFileEntry {
                name: "BigFile.DAT".to_string(),
                name_lower: "bigfile.dat".to_string(),
                path: PathBuf::from("/dir/BigFile.DAT"),
            },
        ];
        assert_eq!(
            find_dat_fallback_path(
                "BigFile",
                Some(Path::new("/dir/BigFile.DAT")),
                &synthetic_entries
            ),
            Some(PathBuf::from("/dir/BigFile.DAT"))
        );
    }

    #[test]
    fn dat_fallback_accepts_an_explicit_file_the_listing_does_not_name() {
        let dir = TempDir::new("dat_unlisted");
        let target = dir.join("bigfile.dat");
        fs::write(&target, b"monolithic").unwrap();
        let found = find_dat_fallback_path("bigfile", Some(&target), &[]);
        assert_eq!(found, Some(target));
    }
}
