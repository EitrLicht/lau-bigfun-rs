//! Opens arbitrary bytes as a one- to three-part archive, reads the entries it accepts, and
//! resolves them through a copy of the archive opened as its patch.
//!
//! [`lau_bigfun_fuzz::write_archive_parts`] describes the input's layout.

#![no_main]

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use lau_bigfun::{ArchiveSet, Bigfile, BigfileError, Entry, OpenOptions};
use lau_bigfun_fuzz::{MAX_ARCHIVE_PARTS, write_archive_parts};
use libfuzzer_sys::fuzz_target;

/// Entries read per input, so a large TOC cannot dominate the run.
const MAX_ENTRIES: usize = 64;
/// Read size for streamed reads, small and odd so payloads take many uneven reads.
const STREAM_STEP: usize = 509;

/// Reads `entry` through [`Bigfile::open_entry`] in reads of [`STREAM_STEP`] bytes.
fn read_streamed(bf: &Bigfile, entry: &Entry, raw: bool) -> Option<Vec<u8>> {
    read_in_steps(bf.open_entry(entry, raw).ok()?)
}

/// Reads `reader` to its end in reads of [`STREAM_STEP`] bytes.
fn read_in_steps(mut reader: impl Read) -> Option<Vec<u8>> {
    let (mut out, mut buf) = (Vec::new(), [0u8; STREAM_STEP]);
    loop {
        match reader.read(&mut buf).ok()? {
            0 => return Some(out),
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Streamed and whole reads of `entry` must fail together or return the same bytes.
fn check_streamed_read(bf: &Bigfile, entry: &Entry, raw: bool) -> Option<Vec<u8>> {
    let whole = bf.read_entry(entry, raw).ok();
    assert_eq!(read_streamed(bf, entry, raw), whole);
    whole
}

/// Reads of `entry` through [`Bigfile::open_entry_at`] must return the tail of its stored bytes
/// `stored` from each offset up to their end, and opening past their end must fail.
fn check_reads_from_offsets(bf: &Bigfile, entry: &Entry, stored: &[u8]) {
    let inside = entry.name_hash as usize % (stored.len() + 1);
    for offset in [0, inside, stored.len()] {
        let reader = bf.open_entry_at(entry, offset as u64).unwrap();
        assert_eq!(read_in_steps(reader).as_deref(), Some(&stored[offset..]));
    }
    let past_end = bf.open_entry_at(entry, stored.len() as u64 + 1);
    assert!(matches!(
        past_end,
        Err(BigfileError::OffsetPastEntryEnd { .. })
    ));
}

fn read_entries(bf: &Bigfile) {
    let mut chunk = Vec::new();
    for entry in bf.entries().iter().take(MAX_ENTRIES) {
        if let Some(stored) = check_streamed_read(bf, entry, true) {
            check_reads_from_offsets(bf, entry, &stored);
        }
        let inflated = check_streamed_read(bf, entry, false);
        let copied = bf.read_entry_into(entry, false, &mut chunk, &mut io::sink());
        assert_eq!(copied.ok(), inflated.map(|bytes| bytes.len() as u64));
    }
}

/// Opens a copy of every part of the archive as its patch, so every record must resolve from it.
/// Patch parts left by an earlier input are removed first.
fn resolve_through_patch(dir: &Path, bf: Bigfile) {
    for index in 0..MAX_ARCHIVE_PARTS {
        let patch_part = dir.join(format!("patch.{index:03}"));
        match bf.part_paths().get(index) {
            Some(part) => {
                fs::copy(part, patch_part).unwrap();
            }
            None => {
                let _ = fs::remove_file(patch_part);
            }
        }
    }
    let options = OpenOptions {
        segment_length: None,
        endian: Some(bf.endian()),
        single_part: false,
    };
    // The patch is a copy of an archive `Bigfile::open` just accepted, opened in its byte order,
    // so it must open too.
    let patch = Bigfile::open_with_options(dir.join("patch.000"), options).unwrap();
    let archives = [patch, bf];
    let set = ArchiveSet::new(&archives);
    for entry in archives[1].entries().iter().take(MAX_ENTRIES) {
        let resolved = set.resolve(entry.name_hash, entry.spec_flags).unwrap();
        assert_eq!(resolved.archive_rank, 0);
    }
}

fuzz_target!(|data: &[u8]| {
    let dir = lau_bigfun_fuzz::scratch_dir();
    if write_archive_parts(dir, data).is_some()
        && let Ok(bf) = Bigfile::open(dir.join("bigfile.000"))
    {
        read_entries(&bf);
        resolve_through_patch(dir, bf);
    }
});
