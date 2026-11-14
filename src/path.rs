//! Path handling for extraction: sanitizing archive paths and comparing output paths.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// Converts an archive path (such as `pc-w\lara.drm` or `\tr8\assets\foo.png`) into a
/// normalized, traversal-safe relative [`PathBuf`] suitable for joining onto an extraction directory.
///
/// A `..` segment steps back out of the segment before it, the way a filesystem resolves it, so
/// `pc-w\sndstrm\..\cinstream\a.mul` becomes `pc-w/cinstream/a.mul`. At the start of the path
/// there is nothing to step out of, so the result never climbs above the extraction directory.
#[must_use]
pub fn sanitize_relative_path(archive_path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    let without_drive = strip_drive_prefix(archive_path);

    for raw_segment in without_drive.split(['\\', '/']) {
        if raw_segment == ".." {
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

/// Appends `suffix` to the file stem of `path`, before any extension.
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
            (r"pc-w\.. \lara.drm. ", "pc-w/lara.drm"),
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
