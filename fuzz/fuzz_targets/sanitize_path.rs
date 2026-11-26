//! Checks that any path sanitizes to relative components that are safe on every platform.

#![no_main]

use std::path::{Component, Path};

use lau_bigfun::path::sanitize_relative_path;
use libfuzzer_sys::fuzz_target;

fn is_reserved_device(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or("");
    let stem = stem.trim_end_matches([' ', '.']).to_ascii_lowercase();
    matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || stem
        .strip_prefix("com")
        .or_else(|| stem.strip_prefix("lpt"))
        .is_some_and(|port| {
            matches!(
                port,
                "0" | "1"
                    | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{b9}"
                    | "\u{b2}"
                    | "\u{b3}"
            )
        })
}

fn assert_safe(path: &Path) {
    assert!(path.is_relative(), "{path:?}");
    assert!(path.components().next().is_some(), "{path:?}");
    for component in path.components() {
        let Component::Normal(segment) = component else {
            panic!("unsafe component in {path:?}");
        };
        let segment = segment.to_str().unwrap();
        let forbidden = |c: char| c.is_control() || r#":<>"|?*\/"#.contains(c);
        assert!(!segment.contains(forbidden), "{path:?}");
        assert!(!segment.ends_with(['.', ' ']), "{path:?}");
        assert!(!is_reserved_device(segment), "{path:?}");
    }
}

fuzz_target!(|data: &str| {
    assert_safe(&sanitize_relative_path(data));
});
