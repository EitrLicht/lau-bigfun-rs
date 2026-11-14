//! Parses arbitrary bytes as a FAT, then exercises every lookup on the entries it accepts.

#![no_main]

use lau_bigfun::{Endian, Fat};
use libfuzzer_sys::fuzz_target;

/// The single-record lookup must find a record exactly when the run holds a matching one.
fn assert_lookup_agrees_with_filter(fat: &Fat, hash: u32, mask: u32) {
    let found = fat.find_with_spec_mask(hash, mask);
    assert_eq!(
        found.is_some(),
        fat.find_all_with_spec_mask(hash, mask).next().is_some()
    );
    assert!(found.is_none_or(|entry| entry.name_hash == hash && entry.matches_spec_mask(mask)));
}

fn exercise(fat: &Fat) {
    for entry in fat.entries() {
        let _ = (
            entry.stored_size(),
            entry.logical_offset(),
            entry.is_compressed(),
        );
        let _ = fat.find_all(entry.name_hash);
        assert_lookup_agrees_with_filter(fat, entry.name_hash, entry.spec_flags);
        assert_lookup_agrees_with_filter(fat, entry.name_hash, entry.spec_flags ^ 1);
    }
    for run in fat.hash_runs() {
        assert!(run.iter().all(|entry| entry.name_hash == run[0].name_hash));
    }
    let _ = fat.header_byte_size();
}

fuzz_target!(|data: &[u8]| {
    let file_len = Some(data.len() as u64);
    for endian in [None, Some(Endian::Little), Some(Endian::Big)] {
        if let Ok(fat) = Fat::parse_bounded(&mut &*data, file_len, endian) {
            exercise(&fat);
        }
    }
    if let Ok(fat) = Fat::parse(&mut &*data) {
        exercise(&fat);
    }
});
