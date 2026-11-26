//! Entry filtering by case-insensitive substring, compiled glob set, or resolution status.

use std::borrow::Cow;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use thiserror::Error;

use crate::format::HexLabel;
use crate::path::{fold_path_char, to_forward_slashes};

/// Error returned when compiling a glob [`EntryFilter`].
#[derive(Debug, Error)]
#[error("{}", Self::describe(.pattern.as_deref()))]
pub struct FilterError {
    /// The pattern that is not a valid glob, or `None` when every pattern is valid but they could
    /// not be compiled together.
    pattern: Option<String>,
    #[source]
    source: globset::Error,
}

impl FilterError {
    /// The message for a failure at `pattern`, or at compiling every pattern together.
    fn describe(pattern: Option<&str>) -> String {
        match pattern {
            Some(pattern) => format!("invalid glob pattern '{pattern}'"),
            None => "the glob patterns could not be compiled together".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
enum EntryFilterKind {
    Substring(Vec<char>),
    Glob { set: GlobSet, needs_names: bool },
    Unresolved,
}

/// Compiled entry filter matching resolved archive paths, `0x<hash:08x>` hex hashes,
/// or unresolved entries.
#[derive(Debug, Clone)]
pub struct EntryFilter(EntryFilterKind);

impl EntryFilter {
    /// Creates a case-insensitive (ASCII and Latin-1) substring filter with normalized path
    /// separators.
    #[must_use]
    pub fn substring(filter: &str) -> Self {
        Self(EntryFilterKind::Substring(
            trim_leading_separators(filter)
                .chars()
                .map(fold_path_char)
                .collect(),
        ))
    }

    /// Compiles glob patterns into a case-insensitive [`EntryFilter`] that matches an entry when any
    /// of them does, so no patterns give a filter that matches nothing.
    ///
    /// Leading `/` and `\` characters are stripped and `\` is normalized to `/`. Single `*`
    /// matches within a single path component (`literal_separator(true)`), while `**` matches
    /// across directory boundaries.
    ///
    /// # Errors
    ///
    /// [`FilterError`] when a pattern is not a valid glob, or when the patterns are each valid but
    /// too large to compile together.
    pub fn from_globs<I, S>(patterns: I) -> Result<Self, FilterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut builder = GlobSetBuilder::new();
        let mut needs_names = false;
        for raw in patterns {
            let raw = raw.as_ref();
            let norm = normalize_glob_text(raw);
            needs_names |= !glob_may_match_hash_label(&norm);
            let glob = GlobBuilder::new(&norm)
                .case_insensitive(true)
                .literal_separator(true)
                .build()
                .map_err(|source| FilterError {
                    pattern: Some(raw.to_string()),
                    source,
                })?;
            builder.add(glob);
        }
        let set = builder.build().map_err(|source| FilterError {
            pattern: None,
            source,
        })?;
        Ok(Self(EntryFilterKind::Glob { set, needs_names }))
    }

    /// Creates a filter that matches only entries whose hash is not resolved by the dictionary.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self(EntryFilterKind::Unresolved)
    }

    /// Returns `true` if a pattern in this filter can only match a resolved path, never a
    /// `0x<hash:08x>` label, so the filter needs a populated dictionary.
    ///
    /// The substring check is exact. The glob check is conservative: it can return `false` for a
    /// glob that no label satisfies.
    #[must_use]
    pub fn needs_names(&self) -> bool {
        match &self.0 {
            EntryFilterKind::Substring(needle) => !substring_fits_hash_label(needle),
            EntryFilterKind::Glob { needs_names, .. } => *needs_names,
            EntryFilterKind::Unresolved => false,
        }
    }

    /// Returns `true` if the entry (`name_hash` and optional `resolved_path`) matches this filter.
    #[must_use]
    pub fn matches(&self, name_hash: u32, resolved_path: Option<&str>) -> bool {
        let label = HexLabel::new(name_hash);
        let hex = label.as_str();
        match &self.0 {
            EntryFilterKind::Substring(needle) => {
                resolved_path.is_some_and(|p| contains_folded(trim_leading_separators(p), needle))
                    || contains_folded(hex, needle)
            }
            EntryFilterKind::Glob { set, .. } => {
                resolved_path.is_some_and(|p| set.is_match(normalize_glob_text(p).as_ref()))
                    || set.is_match(hex)
            }
            EntryFilterKind::Unresolved => resolved_path.is_none(),
        }
    }
}

/// Strips leading `/` and `\` path separator characters from `s`.
#[inline]
fn trim_leading_separators(s: &str) -> &str {
    s.trim_start_matches(['/', '\\'])
}

/// Strips leading `/` and `\` characters and converts remaining `\` separators to `/`.
#[inline]
fn normalize_glob_text(s: &str) -> Cow<'_, str> {
    to_forward_slashes(trim_leading_separators(s))
}

/// Returns `true` if `haystack` contains the already-folded `needle` under [`fold_path_char`]
/// equivalence without allocating temporary strings.
#[inline]
fn contains_folded(haystack: &str, needle: &[char]) -> bool {
    needle.is_empty()
        || haystack.char_indices().any(|(start, _)| {
            let mut folded = haystack[start..].chars().map(fold_path_char);
            needle.iter().all(|&n| folded.next() == Some(n))
        })
}

/// Returns `true` if the already-folded `needle` can occur in a `0x<hash:08x>` label: an optional
/// `0x` or `x` prefix followed by at most 8 hex digits.
fn substring_fits_hash_label(needle: &[char]) -> bool {
    let digits = needle
        .strip_prefix(&['0', 'x'])
        .or_else(|| needle.strip_prefix(&['x']))
        .unwrap_or(needle);
    digits.len() <= 8 && digits.iter().all(char::is_ascii_hexdigit)
}

/// Returns `true` if the normalized `glob` may match a whole `0x<hash:08x>` label.
///
/// Leading `**/` components can match nothing, so they are skipped, and a glob made only of them
/// matches anything. The rest must start with `0` or glob syntax, and every literal outside
/// `[...]` classes and `{...}` alternatives must be a label character. Classes and alternatives
/// are assumed to match, so this can return `true` for a glob that no label satisfies, but never
/// `false` for one that a label satisfies.
fn glob_may_match_hash_label(glob: &str) -> bool {
    let mut rest = glob;
    while let Some(after) = rest.strip_prefix("**/") {
        rest = after;
    }
    if !rest.is_empty() && !rest.starts_with(['0', '*', '?', '[', '{']) {
        return false;
    }
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' | '?' | 'x' | 'X' => {}
            '[' => skip_glob_class(&mut chars),
            '{' => skip_glob_alternatives(&mut chars),
            c if c.is_ascii_hexdigit() => {}
            _ => return false,
        }
    }
    true
}

/// Advances `chars` past the rest of a `[...]` class whose `[` was just read, as `globset` reads
/// it: one optional leading `!` or `^` negates the class, the member after it is taken as it is
/// (even `]`, `!` or `^`), and the next `]` closes the class.
fn skip_glob_class(chars: &mut std::str::Chars<'_>) {
    if chars.as_str().starts_with(['!', '^']) {
        chars.next();
    }
    if chars.next().is_some() {
        let _ = chars.any(|c| c == ']');
    }
}

/// Advances `chars` past the rest of a `{...}` alternative group whose `{` was just read,
/// including nested groups and any `[...]` classes inside it.
fn skip_glob_alternatives(chars: &mut std::str::Chars<'_>) {
    let mut depth = 1usize;
    while let Some(c) = chars.next() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            '[' => skip_glob_class(chars),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::assert_source_not_in_message;

    #[test]
    fn entry_filter_substring_normalizes_separators() {
        let hash = 0x5FF9_1900;
        let matches = |p, f| EntryFilter::substring(f).matches(hash, p);
        assert!(matches(Some(r"\tr7\pc-w\objectlist.txt"), r"\tr7\pc-w"));
        assert!(matches(Some("tr7/pc-w/objectlist.txt"), r"\tr7\pc-w"));
        assert!(matches(Some(r"\tr7\pc-w\objectlist.txt"), "tr7/pc-w"));
        assert!(matches(
            Some(r"\TR7\PC-W\ObjectList.TXT"),
            r"\Tr7\Pc-W\OBJECTLIST"
        ));
        assert!(matches(Some("pc-w/lara.drm"), "0x5ff91900"));
        assert!(matches(Some("pc-w/lara.drm"), "0X5FF91900"));
        assert!(matches(Some("pc-w/lara.drm"), "5FF91900"));
        assert!(matches(None, "5ff91900"));
        assert!(matches(None, "/"));
        assert!(!matches(None, "lara"));
    }

    #[test]
    fn entry_filter_substring_folds_latin1_case() {
        let filter = EntryFilter::substring("CAF\u{c9}");
        assert!(filter.matches(0x1, Some("pc-w\\caf\u{e9}.drm")));
        assert!(!filter.matches(0x1, Some("pc-w\\cafe.drm")));
        assert_eq!(fold_path_char('\u{d7}'), '\u{d7}');
    }

    #[test]
    fn entry_filter_glob_matches_normalized_paths() {
        let hash = 0x5FF9_1900;
        let single = EntryFilter::from_globs(["pc-w/*.drm"]).unwrap();
        assert!(single.matches(hash, Some(r"pc-w\lara.drm")));
        assert!(single.matches(hash, Some("PC-W/LARA.DRM")));
        assert!(!single.matches(hash, Some(r"pc-w\sub\lara.drm")));

        let multi = EntryFilter::from_globs([r"\tr7\pc-w\*.txt", "**/vo/lara/*.mul"]).unwrap();
        assert!(multi.matches(hash, Some(r"\tr7\pc-w\objectlist.txt")));
        assert!(multi.matches(hash, Some(r"pc-w\audio\streams\vo\lara\test.mul")));
        assert!(!multi.matches(hash, Some(r"pc-w\lara.drm")));

        let hex_glob = EntryFilter::from_globs(["0X5FF9*"]).unwrap();
        assert!(hex_glob.matches(hash, Some(r"pc-w\lara.drm")));
        assert!(hex_glob.matches(hash, None));

        let bin_glob = EntryFilter::from_globs(["**/*.bin"]).unwrap();
        assert!(!bin_glob.matches(hash, None));
    }

    #[test]
    fn entry_filter_glob_rejects_invalid_pattern() {
        let err = EntryFilter::from_globs([r"\tr7\[unclosed"]).unwrap_err();
        assert_eq!(err.to_string(), r"invalid glob pattern '\tr7\[unclosed'");
    }

    #[test]
    fn no_glob_patterns_match_nothing() {
        let filter = EntryFilter::from_globs(Vec::<&str>::new()).unwrap();

        assert!(!filter.matches(0x5FF9_1900, Some(r"pc-w\lara.drm")));
    }

    #[test]
    fn patterns_too_large_to_compile_together_name_no_pattern() {
        let err = EntryFilter::from_globs(["?".repeat(200_000)]).unwrap_err();

        assert_eq!(
            err.to_string(),
            "the glob patterns could not be compiled together"
        );
    }

    #[test]
    fn glob_message_leaves_the_parse_error_to_source() {
        let err = EntryFilter::from_globs([r"\tr7\[unclosed"]).unwrap_err();

        let cause = assert_source_not_in_message::<globset::Error>(&err);

        // globset's message holds the pattern and the reason, so check the reason on its own too.
        let reason = cause.kind().to_string();
        assert!(!err.to_string().contains(&reason), "{err}");
    }

    #[test]
    fn substring_needs_names_unless_it_fits_a_hash_label() {
        for needle in ["lara", "a-b", "fx", "00x1", "0123456789", "0x123456789"] {
            assert!(EntryFilter::substring(needle).needs_names(), "{needle}");
        }
        for needle in ["0x5ff91900", "0X5FF9", "x5ff", "5FF9", "/5ff9", r"\0x5f"] {
            assert!(!EntryFilter::substring(needle).needs_names(), "{needle}");
        }
    }

    #[test]
    fn glob_needs_names_unless_it_may_match_a_hash_label() {
        for glob in [
            "pc-w/*.drm",
            "5ff*",
            "x5ff*",
            "**/5ff9*",
            "0x5ff9*/*",
            "**/*.bin",
            "0x-5ff9*",
        ] {
            let filter = EntryFilter::from_globs([glob]).unwrap();
            assert!(filter.needs_names(), "{glob}");
        }
        for glob in [
            "0x5ff9*",
            "/0x5ff9*",
            "*",
            "0x[0-9]*",
            "{0x1*,0x2*}",
            "**/0x5ff9*",
            "{0x5ff9*,pc-w/*.drm}",
            "0x[!g]*",
            "0x[]]*",
            "**/",
            "{0x{1,2}*,a}",
            "[!!]x{1,[2]g}*",
            "[^^]x{1,[2]g}*",
        ] {
            let filter = EntryFilter::from_globs([glob]).unwrap();
            assert!(!filter.needs_names(), "{glob}");
        }
    }

    #[test]
    fn glob_with_leading_globstar_matches_a_hash_label() {
        let filter = EntryFilter::from_globs(["**/0x5ff9*"]).unwrap();
        assert!(filter.matches(0x5FF9_1900, None));
    }

    #[test]
    fn glob_alternative_matches_a_hash_label_without_a_name() {
        let filter = EntryFilter::from_globs(["{0x5ff9*,pc-w/*.drm}"]).unwrap();
        assert!(filter.matches(0x5FF9_1900, None));
    }

    #[test]
    fn glob_class_of_a_negation_mark_closes_at_the_next_bracket() {
        let filter = EntryFilter::from_globs(["[!!]x{1,[2]g}*"]).unwrap();
        assert!(filter.matches(0x1234_5678, None));
    }

    #[test]
    fn glob_needs_names_when_any_pattern_needs_them() {
        let filter = EntryFilter::from_globs(["0x5ff9*", "pc-w/*.drm"]).unwrap();
        assert!(filter.needs_names());
    }

    #[test]
    fn unresolved_filter_does_not_need_names() {
        assert!(!EntryFilter::unresolved().needs_names());
    }

    #[test]
    fn entry_filter_unresolved_matches_only_unnamed_entries() {
        let f = EntryFilter::unresolved();
        assert!(f.matches(0xDEAD_BEEF, None));
        assert!(!f.matches(0x5FF9_1900, Some(r"pc-w\lara.drm")));
    }
}
