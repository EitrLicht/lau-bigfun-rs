//! Opens arbitrary bytes as a one- to three-part archive and reads the entries it accepts.
//!
//! The input is a part count byte, then a little-endian `u16` length for each part but the last,
//! then the part bytes.

#![no_main]

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use lau_bigfun::{ArchiveSet, Bigfile, BigfileError, Entry, OpenOptions};
use libfuzzer_sys::fuzz_target;

const MAX_PARTS: usize = 3;
/// Entries read per input, so a large TOC cannot dominate the run.
const MAX_ENTRIES: usize = 64;
/// Read size for streamed reads, small and odd so payloads take many uneven reads.
const STREAM_STEP: usize = 509;

fn write_parts(dir: &Path, data: &[u8]) -> Option<()> {
    let (&count, mut rest) = data.split_first()?;
    let count = usize::from(count) % MAX_PARTS + 1;
    for index in 0..MAX_PARTS {
        let path = dir.join(format!("bigfile.{index:03}"));
        if index >= count {
            let _ = fs::remove_file(path);
            continue;
        }
        let len = if index + 1 == count {
            rest.len()
        } else {
            let (prefix, tail) = rest.split_first_chunk::<2>()?;
            rest = tail;
            usize::from(u16::from_le_bytes(*prefix)).min(rest.len())
        };
        let (part, tail) = rest.split_at(len);
        rest = tail;
        fs::write(path, part).ok()?;
    }
    Some(())
}

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

/// Opens the archive's first part again as its own patch, so every record must resolve from it.
fn resolve_through_patch(dir: &Path, bf: Bigfile) {
    fs::copy(dir.join("bigfile.000"), dir.join("patch.000")).unwrap();
    let options = OpenOptions {
        segment_length: None,
        endian: Some(bf.endian()),
        single_part: false,
    };
    let Ok(patch) = Bigfile::open_with_options(dir.join("patch.000"), options) else {
        return;
    };
    let archives = [patch, bf];
    let set = ArchiveSet::new(&archives);
    for entry in archives[1].entries().iter().take(MAX_ENTRIES) {
        let resolved = set.resolve(entry.name_hash, entry.spec_flags).unwrap();
        assert_eq!(resolved.archive_rank, 0);
    }
}

fuzz_target!(|data: &[u8]| {
    let dir = lau_bigfun_fuzz::scratch_dir();
    if write_parts(dir, data).is_some()
        && let Ok(bf) = Bigfile::open(dir.join("bigfile.000"))
    {
        read_entries(&bf);
        resolve_through_patch(dir, bf);
    }
});
