//! Path handling for extraction: sanitizing archive paths and comparing output paths.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// Converts an archive path (such as `pc-w\lara.drm` or `\tr8\assets\foo.png`) into a
/// normalized, traversal-safe relative [`PathBuf`] suitable for joining onto an extraction directory.
///
/// A `..` segment steps back out of the segment before it, the way a filesystem resolves it, so
/// `pc-w\sndstrm\..\cinstream\a.mul` becomes `pc-w/cinstream/a.mul`. So does a segment that is
/// `..` once its surrounding spaces and control characters are trimmed, such as `.. `. At the
/// start of the path there is nothing to step out of, so the result never climbs above the
/// extraction directory.
#[must_use]
pub fn sanitize_relative_path(archive_path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    let without_drive = strip_drive_prefix(archive_path);

    for raw_segment in without_drive.split(['\\', '/']) {
        if is_parent_segment(raw_segment) {
            out.pop();
        } else if let Some(cleaned) = sanitize_segment(raw_segment) {
            out.push(cleaned.as_ref());
        }
    }

    if out.as_os_str().is_empty() {
        out.push("unnamed.bin");
    }
    out
}

/// Returns `true` if `segment` is `..`, ignoring surrounding spaces and control characters, which
/// sanitizing would strip anyway.
#[inline]
fn is_parent_segment(segment: &str) -> bool {
    segment.trim_matches(|c: char| c == ' ' || c.is_control()) == ".."
}

/// Strips a leading Windows drive prefix (`C:` or `C:\`) if present.
#[inline]
fn strip_drive_prefix(path: &str) -> &str {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        &path[2..]
    } else {
        path
    }
}

/// Trims leading colons, spaces, and control characters, and trailing dots, colons, spaces,
/// and control characters from a raw path segment in unified passes.
#[inline]
fn trim_segment_affixes(segment: &str) -> &str {
    segment
        .trim_start_matches(|c: char| c == ':' || c == ' ' || c.is_control())
        .trim_end_matches(|c: char| c == '.' || c == ':' || c == ' ' || c.is_control())
}

/// Returns `true` if `c` is a control character or forbidden in Windows/NTFS filenames.
#[inline]
fn is_forbidden_filename_char(c: char) -> bool {
    c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*')
}

/// Returns `true` if `segment`'s stem (before the first `'.'`, with trailing spaces and dots
/// stripped) matches a Windows/NTFS reserved DOS device name (`CON`, `PRN`, `AUX`, `NUL`,
/// `CONIN$`, `CONOUT$`, `COM1`–`COM9`, `LPT1`–`LPT9`, `COM¹`–`COM³`, `LPT¹`–`LPT³`).
#[inline]
fn is_windows_reserved_stem(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches([' ', '.']);
    let is_port =
        |prefix: &str| prefix.eq_ignore_ascii_case("com") || prefix.eq_ignore_ascii_case("lpt");
    match stem.split_at_checked(3) {
        Some((name, "")) => ["con", "prn", "aux", "nul"]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved)),
        Some((prefix, number)) if is_port(prefix) => {
            matches!(number.as_bytes(), [b'1'..=b'9'])
                || matches!(number, "\u{00b9}" | "\u{00b2}" | "\u{00b3}")
        }
        _ => stem.eq_ignore_ascii_case("conin$") || stem.eq_ignore_ascii_case("conout$"),
    }
}

/// Validates and sanitizes a single path segment, rejecting empty, `.`, and `..` traversal
/// segments, trimming trailing dots/spaces, replacing control or Windows-invalid characters,
/// and escaping Windows reserved device stems.
#[inline]
fn sanitize_segment(segment: &str) -> Option<Cow<'_, str>> {
    let trimmed = trim_segment_affixes(segment);
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }

    let cleaned: Cow<'_, str> = if trimmed.contains(is_forbidden_filename_char) {
        Cow::Owned(trimmed.replace(is_forbidden_filename_char, "_"))
    } else {
        Cow::Borrowed(trimmed)
    };

    if is_windows_reserved_stem(&cleaned) {
        Some(Cow::Owned(format!("_{cleaned}")))
    } else {
        Some(cleaned)
    }
}

/// Folds a path character for case-insensitive comparison: `\` becomes `/`, and ASCII and
/// Latin-1 uppercase letters (`A`-`Z`, `À`-`Þ` except `×`) become lowercase. Latin-1 is the
/// full domain of archive path names (see [`crate::hash::name_hash`]).
#[inline]
#[must_use]
pub(crate) const fn fold_path_char(c: char) -> char {
    match forward_slash(c) {
        c @ ('A'..='Z' | 'À'..='Ö' | 'Ø'..='Þ') => (c as u8 + 0x20) as char,
        c => c,
    }
}

/// Turns an archive path's `\` separator into the `/` that output paths and matching use.
#[inline]
#[must_use]
pub(crate) const fn forward_slash(c: char) -> char {
    if c == '\\' { '/' } else { c }
}

/// Returns `s` with every `\` separator turned into `/`, the string form of [`forward_slash`],
/// borrowing `s` when it has none.
#[cfg(feature = "unpack")]
#[must_use]
pub(crate) fn to_forward_slashes(s: &str) -> Cow<'_, str> {
    if s.contains('\\') {
        // `str::replace` finds each `\` with a fast byte search instead of rebuilding `s` one
        // character at a time.
        Cow::Owned(s.replace('\\', "/"))
    } else {
        Cow::Borrowed(s)
    }
}

/// Returns the directory that holds `path`: its parent, or `.` for a bare file name.
#[inline]
#[must_use]
pub(crate) fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Returns the comparison key of the output path `path`: `/` separators, with ASCII and Latin-1
/// letters folded to lowercase. Two output paths whose keys are equal name the same file on a
/// case-insensitive filesystem, so unpack renames all but one of them.
#[must_use]
pub fn normalized_rel_key(path: &Path) -> String {
    path.to_string_lossy().chars().map(fold_path_char).collect()
}

/// Identity of an existing file, equal for any two paths that reach it: its device and inode on
/// Unix, so symbolic and hard links compare equal, and a key of its canonical path on Windows,
/// which resolves symbolic links and letter case but not hard links (see `windows_path_key`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileId(#[cfg(unix)] (u64, u64), #[cfg(windows)] String);

impl FileId {
    /// Identifies the file at `path`, whose metadata is `meta`. On Unix the identity comes from
    /// `meta` alone, so for a file that is already open it stays right however `path` changes
    /// later. On Windows it is the key of the canonical path, or of the absolute path on a drive
    /// where that cannot be resolved, so that identifying a file never stops an archive from
    /// opening and either spelling of one file gives the same key.
    ///
    /// # Errors
    ///
    /// Never on Unix. On Windows, fails like [`std::path::absolute`] when even the absolute path
    /// cannot be formed.
    pub(crate) fn from_metadata(meta: &std::fs::Metadata, path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            Ok(Self((meta.dev(), meta.ino())))
        }
        #[cfg(windows)]
        {
            let _ = meta;
            let resolved = std::fs::canonicalize(path).or_else(|_| std::path::absolute(path))?;
            Ok(Self(windows_path_key(&resolved)))
        }
    }

    /// Identifies the file `path` reaches, following links.
    ///
    /// # Errors
    ///
    /// Fails like [`std::fs::metadata`], such as when `path` does not exist, and otherwise like
    /// [`Self::from_metadata`].
    #[cfg(feature = "unpack")]
    pub(crate) fn of(path: &Path) -> std::io::Result<Self> {
        Self::from_metadata(&std::fs::metadata(path)?, path)
    }
}

/// Comparison key of an absolute Windows path: without a `\\?\` verbatim prefix, with `/`
/// separators and letters folded by [`fold_windows_path_char`]. The canonical (verbatim) and
/// absolute spellings of one path give the same key, as do spellings that differ only in letter
/// case, which Windows filesystems ignore. Unlike [`normalized_rel_key`], whose archive names are
/// Latin-1, it folds letters of any script, since an absolute path can hold any.
#[cfg(any(windows, test))]
fn windows_path_key(path: &Path) -> String {
    let text = path.to_string_lossy();
    let unprefixed = match text.strip_prefix(r"\\?\UNC\") {
        Some(unc) => Cow::Owned(format!(r"\\{unc}")),
        None => Cow::Borrowed(text.strip_prefix(r"\\?\").unwrap_or(&text)),
    };
    unprefixed.chars().map(fold_windows_path_char).collect()
}

/// Folds a character of a Windows path for [`windows_path_key`]: `\` becomes `/`, and a letter
/// with a one-character uppercase form becomes that form. Windows filesystems compare names one
/// character at a time through an uppercase table, so a letter whose uppercase is several
/// characters, such as `ß`, stays as it is.
#[cfg(any(windows, test))]
fn fold_windows_path_char(c: char) -> char {
    let c = forward_slash(c);
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

/// Appends `suffix` to the file stem of `path`, before any extension.
#[cfg(feature = "unpack")]
pub(crate) fn append_stem_suffix(path: &Path, suffix: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("entry");
    let new_filename = match path
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
    {
        Some(ext) => format!("{stem}{suffix}.{ext}"),
        None => format!("{stem}{suffix}"),
    };
    if parent.as_os_str().is_empty() {
        PathBuf::from(new_filename)
    } else {
        parent.join(new_filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_key_ignores_the_verbatim_prefix() {
        assert_eq!(
            windows_path_key(Path::new(r"\\?\C:\Games\TR\bigfile.000")),
            windows_path_key(Path::new(r"C:\Games\TR\bigfile.000"))
        );
    }

    #[test]
    fn windows_key_keeps_the_server_of_a_verbatim_unc_path() {
        assert_eq!(
            windows_path_key(Path::new(r"\\?\UNC\server\share\bigfile.000")),
            windows_path_key(Path::new(r"\\server\share\bigfile.000"))
        );
    }

    #[test]
    fn windows_key_ignores_letter_case() {
        assert_eq!(
            windows_path_key(Path::new(r"C:\Games\TR\BIGFILE.000")),
            windows_path_key(Path::new(r"c:\games\tr\bigfile.000"))
        );
    }

    #[test]
    fn windows_key_ignores_letter_case_beyond_latin1() {
        assert_eq!(
            windows_path_key(Path::new(r"D:\Игры\Λάρα\BIGFILE.000")),
            windows_path_key(Path::new(r"d:\игры\λάρα\bigfile.000"))
        );
    }

    #[test]
    fn windows_key_keeps_a_letter_whose_uppercase_is_two_letters() {
        assert_ne!(
            windows_path_key(Path::new(r"C:\Straße\bigfile.000")),
            windows_path_key(Path::new(r"C:\STRASSE\bigfile.000"))
        );
    }

    #[cfg(feature = "unpack")]
    #[test]
    fn to_forward_slashes_applies_forward_slash_to_every_char() {
        for s in [
            r"pc-w\units\lara.drm",
            "\\tr8\\caf\u{e9}\\",
            "pc-w/lara.drm",
            r"\\",
            "",
        ] {
            let per_char: String = s.chars().map(forward_slash).collect();
            assert_eq!(to_forward_slashes(s), per_char, "{s:?}");
        }
    }

    #[test]
    fn keeps_multibyte_stem_spanning_device_prefix_length() {
        let sanitized = sanitize_relative_path("ab\u{e9}.drm");
        assert_eq!(sanitized, PathBuf::from("ab\u{e9}.drm"));
    }

    #[test]
    fn sanitizes_unsafe_path_components() {
        for (raw, expected) in [
            (r"pc-w\units\lara.drm", "pc-w/units/lara.drm"),
            (r"\..\..\etc\passwd", "etc/passwd"),
            (r"C:pc-w\lara.drm", "pc-w/lara.drm"),
            (r"C:\pc-w\lara.drm", "pc-w/lara.drm"),
            (r"pc-w\foo.bin:$DATA", "pc-w/foo.bin_$DATA"),
            (r"pc-w\units\.. \lara.drm. ", "pc-w/lara.drm"),
            ("pc-w\\foo.\t.", "pc-w/foo"),
            (r"pc-w\con\nul.drm", "pc-w/_con/_nul.drm"),
            (
                r"pc-w\nul .txt\com1.bin\lpt9",
                "pc-w/_nul .txt/_com1.bin/_lpt9",
            ),
        ] {
            assert_eq!(sanitize_relative_path(raw), PathBuf::from(expected));
        }
    }

    #[test]
    fn resolves_parent_segment_against_the_segment_before_it() {
        assert_eq!(
            sanitize_relative_path(r"pc-w\sndstrm\..\cinstream\a.mul"),
            PathBuf::from("pc-w/cinstream/a.mul")
        );
    }

    #[test]
    fn segment_that_cleans_to_parent_steps_back() {
        for raw in [
            r"pc-w\sndstrm\.. \cinstream\a.mul",
            r"pc-w\sndstrm\ ..\cinstream\a.mul",
            "pc-w\\sndstrm\\..\u{7}\\cinstream\\a.mul",
        ] {
            assert_eq!(
                sanitize_relative_path(raw),
                PathBuf::from("pc-w/cinstream/a.mul"),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn parent_segments_never_climb_above_the_root() {
        for (raw, expected) in [
            (r"pc-w\..\..\a.mul", "a.mul"),
            (r"..\pc-w\a.mul", "pc-w/a.mul"),
            (r"pc-w\a.mul\..", "pc-w"),
        ] {
            assert_eq!(
                sanitize_relative_path(raw),
                PathBuf::from(expected),
                "{raw}"
            );
        }
    }

    #[test]
    fn sanitizes_degenerate_paths_to_unnamed_bin() {
        for degenerate in [
            "",
            "   ",
            "...",
            ".\t.",
            " .\r. ",
            r"\..\.\",
            r"C:\",
            "\x00\x01:",
        ] {
            assert_eq!(
                sanitize_relative_path(degenerate),
                PathBuf::from("unnamed.bin"),
                "expected unnamed.bin for {degenerate:?}"
            );
        }
    }

    #[test]
    fn validates_windows_reserved_device_stems() {
        assert_eq!(trim_segment_affixes(" :foo.\t. "), "foo");
        assert_eq!(trim_segment_affixes(".\t."), "");
        for reserved in [
            "CON",
            "prn.txt",
            "Aux .drm",
            "nul..bin",
            "com1.tar.gz",
            "LPT9",
            "com\u{00b9}.txt",
            "lpt\u{00b3}",
            "CONIN$",
            "conout$.txt",
        ] {
            assert!(is_windows_reserved_stem(reserved));
        }
        for normal in ["com", "com0", "com10", "console.drm", "lara.drm"] {
            assert!(!is_windows_reserved_stem(normal));
        }
    }
}
