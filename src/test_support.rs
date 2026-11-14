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
use crate::format::{Endian, SECTOR_BYTE_COUNT, fat_byte_len, sector_logical_offset};

/// One record for [`write_archive`]: its TOC fields and the bytes stored for it.
#[derive(Clone, Copy)]
pub(crate) struct ArchiveRecord<'a> {
    pub(crate) hash: u32,
    sku_flags: u32,
    payload: &'a [u8],
    /// Size the TOC declares: the payload's length when stored, the inflated size when compressed.
    size: u32,
    compressed: bool,
}

impl<'a> ArchiveRecord<'a> {
    /// Record whose `payload` is stored as it is.
    pub(crate) const fn stored(hash: u32, sku_flags: u32, payload: &'a [u8]) -> Self {
        Self {
            hash,
            sku_flags,
            payload,
            size: payload.len() as u32,
            compressed: false,
        }
    }

    /// Record storing the zlib stream `zlib` and declaring `inflated_size` bytes, which need not
    /// match what the stream inflates to.
    pub(crate) const fn zlib(
        hash: u32,
        sku_flags: u32,
        zlib: &'a [u8],
        inflated_size: u32,
    ) -> Self {
        Self {
            hash,
            sku_flags,
            payload: zlib,
            size: inflated_size,
            compressed: true,
        }
    }

    /// The record's `(name_hash, size, sector_number, sku_flags, deflated_size)` TOC fields.
    const fn toc_fields(&self, sector: u32) -> (u32, u32, u32, u32, i32) {
        let deflated = if self.compressed {
            self.payload.len() as i32
        } else {
            0
        };
        (self.hash, self.size, sector, self.sku_flags, deflated)
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
/// byte order from `(name_hash, size, sector_number, sku_flags, deflated_size)` tuples.
pub(crate) fn build_fat_bytes(endian: Endian, records: &[(u32, u32, u32, u32, i32)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fat_byte_len(records.len()).unwrap());
    buf.extend_from_slice(&encode_u32(endian, records.len() as u32));
    for &(hash, _, _, _, _) in records {
        buf.extend_from_slice(&encode_u32(endian, hash));
    }
    for &(_, size, sector, sku, deflated) in records {
        buf.extend_from_slice(&encode_u32(endian, size));
        buf.extend_from_slice(&encode_u32(endian, sector));
        buf.extend_from_slice(&encode_u32(endian, sku));
        buf.extend_from_slice(&encode_u32(endian, deflated as u32));
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
    let records = vec![(0, 0, 0, 0, 0); 0x0001_0000];
    build_part0_bytes(Endian::Big, total_bytes, &records, &[])
}

/// Builds a two-sector part 0 from `(name_hash, size, deflated_size)` records that all point at
/// sector 1, so their planned output can far exceed the part's size.
fn build_shared_sector_part0(records: &[(u32, u32, i32)]) -> Vec<u8> {
    let fat: Vec<_> = records
        .iter()
        .map(|&(hash, size, deflated)| (hash, size, 1, 1, deflated))
        .collect();
    build_part0_bytes(Endian::Little, (SECTOR_BYTE_COUNT * 2) as usize, &fat, &[])
}

/// Writes the two-sector part 0 of [`build_shared_sector_part0`] to `path`.
pub(crate) fn write_shared_sector_archive(path: impl AsRef<Path>, records: &[(u32, u32, i32)]) {
    fs::write(path, build_shared_sector_part0(records)).unwrap();
}

/// An uncompressed 10-byte [`Entry`] for tests that need entries without an archive.
pub(crate) const fn sample_entry(index: usize, name_hash: u32, sector: u32, sku: u32) -> Entry {
    Entry {
        index,
        name_hash,
        size: 10,
        sector_number: sector,
        sku_flags: sku,
        deflated_size: 0,
    }
}

/// Writes a single-part archive in `endian` byte order from `records`, in the order given (sorted
/// by hash), each payload in its own sectors after the FAT.
pub(crate) fn write_archive(path: impl AsRef<Path>, endian: Endian, records: &[ArchiveRecord<'_>]) {
    let fat_len = fat_byte_len(records.len()).unwrap();
    let mut next_sector = sector_count(fat_len as u32).max(1);
    let mut fat_records = Vec::with_capacity(records.len());
    let mut payloads = Vec::with_capacity(records.len());
    for record in records {
        fat_records.push(record.toc_fields(next_sector));
        payloads.push((next_sector, record.payload));
        next_sector += sector_count(record.payload.len() as u32);
    }
    write_part0(path, endian, next_sector, &fat_records, &payloads);
}

/// Writes each `(file name, hash)` under `dir` as a separate archive holding one stored record of
/// `hash` with SKU flags `1` and the bytes `b"payload"`.
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
    records: &[(u32, u32, u32, u32, i32)],
    payloads: &[(u32, &[u8])],
) {
    let total_bytes = sector_logical_offset(sectors) as usize;
    fs::write(
        path,
        build_part0_bytes(endian, total_bytes, records, payloads),
    )
    .unwrap();
}

/// Writes to `path` a two-sector part 0 holding one empty record at sector 1.
pub(crate) fn write_one_empty_record(path: impl AsRef<Path>) {
    write_part0(path, Endian::Little, 2, &[(0x5FF9_1900, 0, 1, 1, 0)], &[]);
}

/// Builds a synthetic part-0 byte image of `total_bytes` length containing the serialized FAT
/// at offset 0 and each `(sector_number, payload)` written at `sector_number * 2048`.
pub(crate) fn build_part0_bytes(
    endian: Endian,
    total_bytes: usize,
    records: &[(u32, u32, u32, u32, i32)],
    payloads: &[(u32, &[u8])],
) -> Vec<u8> {
    let fat = build_fat_bytes(endian, records);
    let mut part0 = vec![0u8; total_bytes.max(fat.len())];
    part0[..fat.len()].copy_from_slice(&fat);
    for &(sector, data) in payloads {
        let start = sector_logical_offset(sector) as usize;
        part0[start..start + data.len()].copy_from_slice(data);
    }
    part0
}
