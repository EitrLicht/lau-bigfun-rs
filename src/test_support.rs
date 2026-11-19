//! Shared test fixtures used across library and CLI unit tests.

#![allow(dead_code)]

use std::fs;
use std::io::{self, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::ZlibEncoder;

use crate::archive::{Bigfile, OpenOptions};
use crate::fat::Entry;
use crate::format::{
    BLOCK_SECTOR_COUNT, Endian, SECTOR_BYTE_COUNT, fat_byte_len, sector_logical_offset,
};

/// One FAT record for [`build_fat_bytes`], its fields named as in [`Entry`], which also numbers
/// the records; the FAT stores no index.
#[derive(Clone, Copy, Default)]
pub(crate) struct FatRow {
    pub(crate) name_hash: u32,
    pub(crate) size: u32,
    pub(crate) sector_number: u32,
    pub(crate) spec_flags: u32,
    pub(crate) deflated_size: i32,
}

/// One record for [`write_archive`]: its TOC fields and the bytes stored for it.
#[derive(Clone, Copy)]
pub(crate) struct ArchiveRecord<'a> {
    pub(crate) hash: u32,
    spec_flags: u32,
    payload: &'a [u8],
    /// Size the TOC declares: the payload's length when stored, the inflated size when compressed.
    size: u32,
    compressed: bool,
}

impl<'a> ArchiveRecord<'a> {
    /// Record whose `payload` is stored as it is.
    pub(crate) fn stored(hash: u32, spec_flags: u32, payload: &'a [u8]) -> Self {
        Self {
            hash,
            spec_flags,
            payload,
            size: u32::try_from(payload.len()).unwrap(),
            compressed: false,
        }
    }

    /// Record storing the zlib stream `zlib` and declaring `inflated_size` bytes, which need not
    /// match what the stream inflates to.
    pub(crate) const fn zlib(
        hash: u32,
        spec_flags: u32,
        zlib: &'a [u8],
        inflated_size: u32,
    ) -> Self {
        Self {
            hash,
            spec_flags,
            payload: zlib,
            size: inflated_size,
            compressed: true,
        }
    }

    /// The record's FAT row, with its payload at `sector`.
    fn fat_row(&self, sector: u32) -> FatRow {
        let deflated_size = if self.compressed {
            i32::try_from(self.payload.len()).unwrap()
        } else {
            0
        };
        FatRow {
            name_hash: self.hash,
            size: self.size,
            sector_number: sector,
            spec_flags: self.spec_flags,
            deflated_size,
        }
    }
}

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(prefix: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lau_bigfun_test_{}_{}_{}_{}",
            prefix,
            std::process::id(),
            nanos,
            seq
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// [`Write`] that fails every call with the given error kind.
pub(crate) struct FailingWriter(pub(crate) io::ErrorKind);

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(self.0, "stream error"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(self.0, "stream error"))
    }
}

#[inline]
const fn encode_u32(endian: Endian, value: u32) -> [u8; 4] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

/// Serializes a bigfile FAT header (`count`, `hashes[count]`, `records[count]`) in `endian`
/// byte order from `records`.
pub(crate) fn build_fat_bytes(endian: Endian, records: &[FatRow]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fat_byte_len(records.len()).unwrap());
    buf.extend_from_slice(&encode_u32(endian, u32::try_from(records.len()).unwrap()));
    for record in records {
        buf.extend_from_slice(&encode_u32(endian, record.name_hash));
    }
    for record in records {
        buf.extend_from_slice(&encode_u32(endian, record.size));
        buf.extend_from_slice(&encode_u32(endian, record.sector_number));
        buf.extend_from_slice(&encode_u32(endian, record.spec_flags));
        buf.extend_from_slice(&encode_u32(endian, record.deflated_size.cast_unsigned()));
    }
    buf
}

/// Returns `data` as a zlib stream.
pub(crate) fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Number of sectors needed to store `byte_count` bytes.
pub(crate) const fn sector_count(byte_count: u32) -> u32 {
    byte_count.div_ceil(SECTOR_BYTE_COUNT)
}

/// Builds a part 0 that is valid in both byte orders: its record count byte-swaps to a smaller
/// count that still fits, and all-zero records read the same either way.
pub(crate) fn build_ambiguous_part0() -> Vec<u8> {
    let total_bytes = (SECTOR_BYTE_COUNT * 650) as usize;
    let records = vec![FatRow::default(); 0x0001_0000];
    build_part0_bytes(Endian::Big, total_bytes, &records, &[])
}

/// Builds a two-sector part 0 from `records`, all at sector 1 with spec flags `1`, so their
/// planned output can far exceed the part's size. Each row gives only its name hash, size and
/// deflated size, leaving the sector and spec flags at zero for this to set.
fn build_shared_sector_part0(records: &[FatRow]) -> Vec<u8> {
    let fat: Vec<_> = records
        .iter()
        .map(|&record| {
            assert!(
                record.sector_number == 0 && record.spec_flags == 0,
                "a shared-sector row leaves its sector and spec flags at zero; the helper sets these itself"
            );
            FatRow {
                sector_number: 1,
                spec_flags: 1,
                ..record
            }
        })
        .collect();
    build_part0_bytes(Endian::Little, (SECTOR_BYTE_COUNT * 2) as usize, &fat, &[])
}

/// Writes the two-sector part 0 of [`build_shared_sector_part0`] to `path`.
pub(crate) fn write_shared_sector_archive(path: impl AsRef<Path>, records: &[FatRow]) {
    fs::write(path, build_shared_sector_part0(records)).unwrap();
}

/// An uncompressed 10-byte [`Entry`] for tests that need entries without an archive.
pub(crate) const fn sample_entry(index: usize, name_hash: u32, sector: u32, spec: u32) -> Entry {
    Entry {
        index,
        name_hash,
        size: 10,
        sector_number: sector,
        spec_flags: spec,
        deflated_size: 0,
    }
}

/// Writes a single-part archive in `endian` byte order from `records`, in the order given (sorted
/// by hash), each payload in its own sectors after the FAT.
pub(crate) fn write_archive(path: impl AsRef<Path>, endian: Endian, records: &[ArchiveRecord<'_>]) {
    let layout = RecordLayout::new(records, first_payload_sector(records.len()));
    write_part0(
        path,
        endian,
        layout.end_sector,
        &layout.rows,
        &layout.payloads,
    );
}

/// Writes a little-endian archive with a 1 MiB segment length under `dir`: `bigfile.000` holds
/// `part0` after the FAT and `bigfile.001` holds `part1` from its first byte. Hashes must be
/// sorted across both slices, `part0` before `part1`, and `part1` must start with a record holding
/// data, from which opening detects the segment length.
pub(crate) fn write_two_part_archive(
    dir: &Path,
    part0: &[ArchiveRecord<'_>],
    part1: &[ArchiveRecord<'_>],
) {
    assert!(
        part0
            .iter()
            .chain(part1)
            .is_sorted_by_key(|record| record.hash),
        "hashes must be sorted across both parts"
    );
    assert!(
        part1
            .first()
            .is_some_and(|record| !record.payload.is_empty()),
        "part 1 must start with a record holding data"
    );
    let first = RecordLayout::new(part0, first_payload_sector(part0.len() + part1.len()));
    let second = RecordLayout::new(part1, BLOCK_SECTOR_COUNT);
    assert!(
        first.end_sector <= BLOCK_SECTOR_COUNT,
        "part 0 overflows its segment"
    );
    let rows: Vec<_> = first.rows.iter().chain(&second.rows).copied().collect();
    let part0_path = dir.join("bigfile.000");
    write_part0(
        part0_path,
        Endian::Little,
        first.end_sector,
        &rows,
        &first.payloads,
    );

    let part1_sectors = second.end_sector - BLOCK_SECTOR_COUNT;
    let mut part1_bytes = vec![0u8; usize::try_from(sector_logical_offset(part1_sectors)).unwrap()];
    place_payloads(&mut part1_bytes, BLOCK_SECTOR_COUNT, &second.payloads);
    fs::write(dir.join("bigfile.001"), part1_bytes).unwrap();
}

/// First sector after a FAT of `record_count` records, where the test archives start payloads.
fn first_payload_sector(record_count: usize) -> u32 {
    sector_count(u32::try_from(fat_byte_len(record_count).unwrap()).unwrap()).max(1)
}

/// Records laid out one after another, each payload in its own sectors.
struct RecordLayout<'a> {
    /// Each record's FAT row.
    rows: Vec<FatRow>,
    /// Each record's `(sector_number, payload)`.
    payloads: Vec<(u32, &'a [u8])>,
    /// First sector after the last payload.
    end_sector: u32,
}

impl<'a> RecordLayout<'a> {
    /// Lays `records` out in the order given, the first starting at `first_sector`.
    fn new(records: &[ArchiveRecord<'a>], first_sector: u32) -> Self {
        let mut layout = Self {
            rows: Vec::with_capacity(records.len()),
            payloads: Vec::with_capacity(records.len()),
            end_sector: first_sector,
        };
        for record in records {
            layout.rows.push(record.fat_row(layout.end_sector));
            layout.payloads.push((layout.end_sector, record.payload));
            layout.end_sector += sector_count(u32::try_from(record.payload.len()).unwrap());
        }
        layout
    }
}

/// Writes each `(file name, hash)` under `dir` as a separate archive holding one stored record of
/// `hash` with spec flags `1` and the bytes `b"payload"`.
pub(crate) fn write_one_record_archives(dir: &Path, archives: &[(&str, u32)]) {
    for &(name, hash) in archives {
        let record = ArchiveRecord::stored(hash, 1, b"payload");
        write_archive(dir.join(name), Endian::Little, &[record]);
    }
}

/// Cuts the file at `path` down to `len` bytes, as if it ended early after it was opened.
pub(crate) fn truncate_file(path: impl AsRef<Path>, len: u64) {
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(len).unwrap();
}

/// File name [`write_patched_archives`] gives the patch and [`open_patched_pair`] opens it by.
const PATCH_FILE_NAME: &str = "patch.000";

/// Writes `bigfile.000` from `base` and `patch.000` from `patch` under `dir`, returning the path of
/// `bigfile.000`.
pub(crate) fn write_patched_archives(
    dir: &Path,
    base: &[ArchiveRecord<'_>],
    patch: &[ArchiveRecord<'_>],
) -> PathBuf {
    let base_path = dir.join("bigfile.000");
    write_archive(&base_path, Endian::Little, base);
    write_archive(dir.join(PATCH_FILE_NAME), Endian::Little, patch);
    base_path
}

/// Opens the `patch.000` beside `base_path`, in the byte order of the archive at `base_path`, and
/// returns both in resolution order.
pub(crate) fn open_patched_pair(base_path: &Path) -> [Bigfile; 2] {
    let base = Bigfile::open(base_path).unwrap();
    let options = OpenOptions {
        endian: Some(base.endian()),
        ..OpenOptions::default()
    };
    let patch_path = base_path.with_file_name(PATCH_FILE_NAME);
    [
        Bigfile::open_with_options(patch_path, options).unwrap(),
        base,
    ]
}

/// Writes a part 0 of `sectors` sectors to `path` (see [`build_part0_bytes`]).
pub(crate) fn write_part0(
    path: impl AsRef<Path>,
    endian: Endian,
    sectors: u32,
    records: &[FatRow],
    payloads: &[(u32, &[u8])],
) {
    let total_bytes = usize::try_from(sector_logical_offset(sectors)).unwrap();
    fs::write(
        path,
        build_part0_bytes(endian, total_bytes, records, payloads),
    )
    .unwrap();
}

/// Writes to `path` a two-sector part 0 holding one empty record at sector 1.
pub(crate) fn write_one_empty_record(path: impl AsRef<Path>) {
    let record = FatRow {
        name_hash: 0x5FF9_1900,
        size: 0,
        sector_number: 1,
        spec_flags: 1,
        deflated_size: 0,
    };
    write_part0(path, Endian::Little, 2, &[record], &[]);
}

/// Builds a synthetic part-0 byte image of `total_bytes` length containing the serialized FAT
/// at offset 0 and each `(sector_number, payload)` written at `sector_number * 2048`.
pub(crate) fn build_part0_bytes(
    endian: Endian,
    total_bytes: usize,
    records: &[FatRow],
    payloads: &[(u32, &[u8])],
) -> Vec<u8> {
    let fat = build_fat_bytes(endian, records);
    let mut part0 = vec![0u8; total_bytes.max(fat.len())];
    part0[..fat.len()].copy_from_slice(&fat);
    place_payloads(&mut part0, 0, payloads);
    part0
}

/// Copies each `(sector_number, payload)` into `part`, a part file whose first byte is logical
/// sector `first_sector`.
fn place_payloads(part: &mut [u8], first_sector: u32, payloads: &[(u32, &[u8])]) {
    for &(sector, data) in payloads {
        let start = usize::try_from(sector_logical_offset(sector - first_sector)).unwrap();
        part[start..start + data.len()].copy_from_slice(data);
    }
}

#[test]
#[should_panic(expected = "sets these itself")]
fn shared_sector_rows_cannot_choose_their_sector() {
    build_shared_sector_part0(&[FatRow {
        name_hash: 0x1,
        size: 100,
        sector_number: 5,
        ..FatRow::default()
    }]);
}

#[test]
#[should_panic(expected = "sets these itself")]
fn shared_sector_rows_cannot_choose_their_spec_flags() {
    build_shared_sector_part0(&[FatRow {
        name_hash: 0x1,
        size: 100,
        spec_flags: 0x2,
        ..FatRow::default()
    }]);
}
