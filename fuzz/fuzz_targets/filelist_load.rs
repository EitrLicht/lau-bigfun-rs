//! Loads arbitrary bytes as a filelist and checks that the dictionary holds no more entries than
//! the lines it loaded, and is empty exactly when none loaded.

#![no_main]

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use lau_bigfun::HashDictionary;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    static FILE: OnceLock<PathBuf> = OnceLock::new();
    let file = FILE.get_or_init(|| lau_bigfun_fuzz::scratch_dir().join("filelist.txt"));
    fs::write(file, data).unwrap();

    let mut dict = HashDictionary::new();
    if let Ok(loaded) = dict.load_file(file) {
        // Lines that hash alike share one entry, so there are never more entries than lines.
        assert!(dict.len() <= loaded);
        assert_eq!(dict.is_empty(), loaded == 0);
    }
});
