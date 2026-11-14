//! Compiles the first line of the input as a glob and matches it against the second, and checks
//! that a glob which matches a hash label is never reported as needing names.
//!
//! The hash is the second line read as hex when it parses as one, so inputs can steer the label,
//! and otherwise the second line's name hash.

#![no_main]

use lau_bigfun::{EntryFilter, name_hash_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let (pattern, path) = data.split_once('\n').unwrap_or((data, ""));
    let hash = u32::from_str_radix(path.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| name_hash_bytes(path.as_bytes()));
    if let Ok(filter) = EntryFilter::from_globs([pattern]) {
        let _ = filter.matches(hash, Some(path));
        if filter.matches(hash, None) {
            assert!(!filter.needs_names(), "{pattern:?} matches {hash:#010x}");
        }
    }
    let _ = EntryFilter::substring(pattern).matches(hash, Some(path));
});
