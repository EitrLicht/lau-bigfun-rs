//! Helpers shared by the fuzz targets.

use std::fs;
use std::path::PathBuf;

/// Returns a directory private to this fuzzing process, for targets that must read from files.
#[must_use]
pub fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lau_bigfun_fuzz_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}
