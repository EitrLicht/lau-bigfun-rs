//! Discovery and opening of an archive's ordered physical part files.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use super::{Bigfile, BigfileError};
use crate::path::{FileId, parent_dir};

/// Bundle of discovered physical archive part files and metadata.
pub(super) struct DiscoveredParts {
    pub(super) dir_path: PathBuf,
    pub(super) stem: String,
    pub(super) part_paths: Vec<PathBuf>,
    pub(super) part_files: Vec<File>,
    pub(super) part_sizes: Vec<u64>,
    pub(super) part_ids: Vec<FileId>,
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

        let opened = open_part_files(&part_paths)?;
        let actual_stem = part_paths[0]
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&target.stem)
            .to_string();

        Ok(DiscoveredParts {
            dir_path: target.dir,
            stem: actual_stem,
            part_paths,
            part_files: opened.files,
            part_sizes: opened.sizes,
            part_ids: opened.ids,
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
///
/// A folder that does not exist has no entries. Any other failure to list it, including one
/// partway through the listing, fails with [`BigfileError::ArchiveDirectory`], so a part is never
/// silently left out of the archive.
fn read_sorted_dir_entries(dir_path: &Path) -> Result<Vec<DirFileEntry>, BigfileError> {
    let listing_error = |source| BigfileError::ArchiveDirectory {
        path: dir_path.to_path_buf(),
        source,
    };
    let listing = match fs::read_dir(dir_path) {
        Ok(listing) => listing,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(listing_error(source)),
    };
    let listed = listing
        .collect::<io::Result<Vec<_>>>()
        .map_err(listing_error)?;

    let mut entries: Vec<DirFileEntry> = listed
        .into_iter()
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

/// The open part files of an archive, with the byte length and identity of each. Identities are
/// only taken when the `unpack` feature, the only reader of them, is built; otherwise `ids` is
/// empty.
struct OpenedParts {
    files: Vec<File>,
    sizes: Vec<u64>,
    ids: Vec<FileId>,
}

/// Share mode for opening part files on Windows: other handles may read a part, but not write to
/// it or rename it while the archive is open. `std` would also share writing and deletion.
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

/// Opens the part file at `path` for reading. On Windows it shares only reading, so nothing can
/// write to the part or rename it while the archive is open, and opening fails if another handle
/// already has the part open for writing. Unix has no equivalent.
///
/// Renaming another file over the part's own name is refused too, but not over a second hard
/// link to it, which only unlinks that name and leaves the part's data in place. For the part's
/// own name, the destination check in `extract` and `unpack` refuses the output before anything
/// is staged, rather than leaving a failed rename partway through an extraction.
fn open_part(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(FILE_SHARE_READ);
    }
    options.open(path)
}

/// Hint for a part that could not be opened because another program holds it: on Windows, a
/// sharing violation (OS error 32) means a handle that may write the part is open. Empty for any
/// other failure.
pub(super) fn sharing_hint(err: &io::Error) -> &'static str {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    if cfg!(windows) && err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
        "; another program has it open for writing, so close that program or wait for it to finish"
    } else {
        ""
    }
}

/// Opens all discovered part files and records each one's physical byte length and, with the
/// `unpack` feature, its identity, failing with [`BigfileError::PartOpen`] naming the first part
/// that cannot be.
fn open_part_files(part_paths: &[PathBuf]) -> Result<OpenedParts, BigfileError> {
    let id_count = if cfg!(feature = "unpack") {
        part_paths.len()
    } else {
        0
    };
    let mut opened = OpenedParts {
        files: Vec::with_capacity(part_paths.len()),
        sizes: Vec::with_capacity(part_paths.len()),
        ids: Vec::with_capacity(id_count),
    };
    for path in part_paths {
        let part_error = |source| BigfileError::PartOpen {
            path: path.clone(),
            source,
        };
        let file = open_part(path).map_err(part_error)?;
        let meta = file.metadata().map_err(part_error)?;
        opened.sizes.push(meta.len());
        // On Windows an identity costs a file open per part, so it is skipped where nothing uses it.
        if cfg!(feature = "unpack") {
            let id = FileId::from_metadata(&meta, path).map_err(part_error)?;
            opened.ids.push(id);
        }
        opened.files.push(file);
    }
    Ok(opened)
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
    fn opening_a_part_that_fails_names_the_part() {
        let dir = TempDir::new("part_open_fails");
        let missing = dir.join("bigfile.000");

        let err = open_part_files(std::slice::from_ref(&missing))
            .err()
            .unwrap();

        assert!(
            matches!(&err, BigfileError::PartOpen { path, .. } if *path == missing),
            "{err:?}"
        );
    }

    #[test]
    fn opening_a_part_whose_folder_cannot_be_listed_names_the_folder() {
        let dir = TempDir::new("list_fails");
        let not_a_folder = dir.join("notadir");
        write_one_empty_record(&not_a_folder);

        let err = Bigfile::open(not_a_folder.join("bigfile.000")).unwrap_err();

        assert!(
            matches!(&err, BigfileError::ArchiveDirectory { path, .. } if *path == not_a_folder),
            "{err:?}"
        );
    }

    #[test]
    fn other_open_failures_get_no_sharing_hint() {
        assert_eq!(sharing_hint(&io::ErrorKind::NotFound.into()), "");
    }

    #[cfg(windows)]
    #[test]
    fn a_sharing_violation_gets_a_hint() {
        assert!(!sharing_hint(&io::Error::from_raw_os_error(32)).is_empty());
    }

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
