//! TRLAU File Allocation Table (FAT) structures, deserialization, and lookup.

use std::cmp::Ordering;
use std::io::{self, Read};

use thiserror::Error;

use crate::format::{
    Endian, FAT_COUNT_BYTES, FAT_HASH_BYTES, HexLabel, RECORD_STRIDE, fat_byte_len,
    sector_logical_offset,
};

/// Errors that can occur when parsing or validating a bigfile FAT.
///
/// Each variant except [`Io`](Self::Io) names the byte order the FAT was read in, since byte-order
/// detection tries both.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FatError {
    /// Reading the FAT failed.
    #[error("I/O error while reading FAT: {0}")]
    Io(#[from] io::Error),

    /// The input ends before the hashes and records its entry count declares.
    #[error(
        "bigfile FAT truncated ({endian}): expected {expected} bytes for {count} entries, got {actual}"
    )]
    Truncated {
        /// Byte order the FAT was read in.
        endian: Endian,
        /// Entry count read from the FAT header.
        count: u32,
        /// Bytes the hashes and records need after the 4-byte count, or `usize::MAX` when that
        /// size overflows.
        expected: usize,
        /// Bytes available for them.
        actual: usize,
    },

    /// A name hash is lower than the one before it, so the table is not sorted by hash.
    #[error(
        "FAT hashes ({endian}) are not sorted in non-decreasing order at index {index}: {} > {}", HexLabel::new(*.prev), HexLabel::new(*.curr)
    )]
    UnsortedHashes {
        /// Byte order the FAT was read in.
        endian: Endian,
        /// Position of the out-of-order record.
        index: usize,
        /// Hash of the record before it.
        prev: u32,
        /// Hash of the out-of-order record.
        curr: u32,
    },

    /// A record's `deflated_size` is negative.
    #[error(
        "FAT record {index} (hash {}, {endian}) has negative deflated_size {deflated_size}", HexLabel::new(*.name_hash)
    )]
    NegativeDeflatedSize {
        /// Byte order the FAT was read in.
        endian: Endian,
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// The negative value read.
        deflated_size: i32,
    },
}

/// Metadata describing a single file record in the bigfile FAT.
///
/// On-disk layout in `bigfile.000` (`@0x04 + 4*count + 16*index`, in archive endianness):
/// - `+0x00`: `u32 size` (uncompressed byte size)
/// - `+0x04`: `u32 sector_number` (logical start sector; byte offset = `sector_number * 2048`)
/// - `+0x08`: `u32 spec_flags` (the engine's specialisation bitmask; what each bit selects is
///   game-specific)
/// - `+0x0C`: `i32 deflated_size` (compressed size; `0` => stored uncompressed)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Zero-based index of this record in the FAT.
    pub index: usize,
    /// 32-bit `CRC-32/BZIP2` hash of the lowercased asset path.
    pub name_hash: u32,
    /// Uncompressed size in bytes.
    pub size: u32,
    /// Starting sector index in the logical archive address space.
    pub sector_number: u32,
    /// The engine's specialisation bitmask. What each bit selects is game-specific.
    pub spec_flags: u32,
    /// Compressed size in bytes (`0` means stored uncompressed).
    pub deflated_size: i32,
}

impl Entry {
    /// Physical byte count stored on disk (`deflated_size` if compressed, otherwise `size`).
    #[inline]
    #[must_use]
    pub const fn stored_size(&self) -> u32 {
        if self.is_compressed() {
            self.deflated_size.cast_unsigned()
        } else {
            self.size
        }
    }

    /// Byte offset of the entry in the concatenated logical archive (`sector_number * 2048`).
    #[inline]
    #[must_use]
    pub const fn logical_offset(&self) -> u64 {
        sector_logical_offset(self.sector_number)
    }

    /// Returns `true` if this entry is stored zlib-compressed (`deflated_size > 0`).
    #[inline]
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.deflated_size > 0
    }

    /// Returns `true` if reading this entry inflates it: it is compressed and `raw` is `false`.
    #[inline]
    #[must_use]
    pub(crate) const fn is_inflated_on_read(&self, raw: bool) -> bool {
        !raw && self.is_compressed()
    }

    /// Bytes a read of this entry yields: its inflated `size` when
    /// [`is_inflated_on_read`](Self::is_inflated_on_read), otherwise its stored bytes.
    #[cfg(feature = "unpack")]
    #[inline]
    #[must_use]
    pub(crate) const fn read_len(&self, raw: bool) -> u32 {
        if self.is_inflated_on_read(raw) {
            self.size
        } else {
            self.stored_size()
        }
    }

    /// Tests whether this entry satisfies `spec_mask` using the engine's bitwise rule
    /// `(entry.spec_flags & spec_mask) == spec_mask`.
    #[inline]
    #[must_use]
    pub const fn matches_spec_mask(&self, spec_mask: u32) -> bool {
        (self.spec_flags & spec_mask) == spec_mask
    }
}

/// A [`Fat::try_auto_endian`] attempt in one byte order that failed, handing back the `state` it
/// was given so the other byte order can be tried with it.
pub(crate) struct FailedAttempt<S, E> {
    /// The state the attempt was given.
    pub(crate) state: S,
    /// Why it failed.
    pub(crate) error: E,
}

/// The result of the first byte order [`Fat::try_auto_endian`] tried that worked.
pub(crate) struct Detected<T> {
    /// The attempt's result.
    pub(crate) value: T,
    /// The other byte order, when it was never tried because the preferred one worked.
    pub(crate) untried: Option<Endian>,
}

/// The errors from both byte orders when neither worked.
pub(crate) struct BothFailed<E> {
    /// The error of the preferred byte order, tried first.
    pub(crate) preferred: E,
    /// The error of the other byte order.
    pub(crate) other: E,
}

/// Tomb Raider LAU File Allocation Table.
#[derive(Debug, Clone)]
pub struct Fat {
    entries: Vec<Entry>,
    endian: Endian,
}

/// Most bytes (8 MiB) reserved up front for a buffer whose final length comes from an untrusted
/// header, such as a FAT's entry count or an entry's inflated size, so a corrupt value fails
/// once the data runs out instead of exhausting memory.
pub(crate) const MAX_UNTRUSTED_RESERVATION: usize = 8 * 1024 * 1024;

// A record is four 32-bit words, which `Fat::decode_entry` reads one by one.
const _: () = assert!(RECORD_STRIDE == 4 * 4);

/// Byte layout of a FAT body (`count` hashes, then `count` records) under one byte order.
#[derive(Debug, Clone, Copy)]
struct TableLayout {
    endian: Endian,
    count: u32,
    /// Bytes of the hash array, which the record array follows.
    hashes_len: usize,
    /// Bytes of the whole body after the 4-byte entry count.
    body_len: usize,
}

impl TableLayout {
    /// Reads the entry count from `header` in `endian` order and sizes the body, failing if its
    /// size overflows `usize`.
    fn new(header: [u8; 4], endian: Endian) -> Result<Self, FatError> {
        let count = endian.read_u32(header);
        let hashes_len = (count as usize).checked_mul(FAT_HASH_BYTES);
        let fat_len = fat_byte_len(count as usize);
        let (Some(hashes_len), Some(fat_len)) = (hashes_len, fat_len) else {
            return Err(FatError::Truncated {
                endian,
                count,
                expected: usize::MAX,
                actual: 0,
            });
        };
        Ok(Self {
            endian,
            count,
            hashes_len,
            body_len: fat_len - FAT_COUNT_BYTES,
        })
    }

    /// Error for a body of which only `actual` bytes are available.
    const fn truncated(&self, actual: usize) -> FatError {
        FatError::Truncated {
            endian: self.endian,
            count: self.count,
            expected: self.body_len,
            actual,
        }
    }

    /// Fails before reading if a file of `max_file_bytes` cannot hold the count and the body.
    fn check_fits(&self, max_file_bytes: Option<u64>) -> Result<(), FatError> {
        let Some(max_bytes) = max_file_bytes else {
            return Ok(());
        };
        let available = max_bytes.saturating_sub(FAT_COUNT_BYTES as u64);
        if self.body_len as u64 > available {
            return Err(self.truncated(usize::try_from(available).unwrap_or(usize::MAX)));
        }
        Ok(())
    }

    /// Reads the rest of the body into `buf`, which may already hold its start from an earlier
    /// byte-order candidate, and returns the body. The first reservation is capped so a corrupt
    /// count fails with [`FatError::Truncated`] instead of exhausting memory.
    fn read_body<'b, R: Read>(
        &self,
        reader: &mut R,
        buf: &'b mut Vec<u8>,
    ) -> Result<&'b [u8], FatError> {
        let needed = self.body_len.saturating_sub(buf.len());
        if needed > 0 {
            buf.reserve(needed.min(MAX_UNTRUSTED_RESERVATION));
            reader.take(needed as u64).read_to_end(buf)?;
        }
        let len = buf.len();
        buf.get(..self.body_len).ok_or_else(|| self.truncated(len))
    }
}

impl Fat {
    /// Parses and validates the FAT from the start of a `bigfile.000` / `BIGFILE.DAT` stream,
    /// automatically detecting TOC byte order.
    ///
    /// # Errors
    ///
    /// Fails like [`Self::parse_bounded`].
    pub fn parse<R: Read>(reader: &mut R) -> Result<Self, FatError> {
        Self::parse_bounded(reader, None, None)
    }

    /// Parses and validates the FAT, optionally checking against the known physical byte size
    /// of `bigfile.000` (`max_file_bytes`) and using `endian_override` (or auto-detecting byte
    /// order when `None`).
    ///
    /// # Errors
    ///
    /// - [`FatError::Io`] when reading fails.
    /// - [`FatError::Truncated`] when the input, or `max_file_bytes`, is too short for the entry
    ///   count.
    /// - [`FatError::UnsortedHashes`] or [`FatError::NegativeDeflatedSize`] when a record is
    ///   invalid.
    ///
    /// When auto-detecting and both byte orders fail, the error is from the order that reads the
    /// smaller entry count, which is tried first.
    pub fn parse_bounded<R: Read>(
        reader: &mut R,
        max_file_bytes: Option<u64>,
        endian_override: Option<Endian>,
    ) -> Result<Self, FatError> {
        let header = Self::read_header(reader)?;
        let mut buf = Vec::new();
        match endian_override {
            Some(endian) => Self::try_candidate(reader, &mut buf, header, max_file_bytes, endian),
            None => Self::parse_auto_endian(reader, &mut buf, header, max_file_bytes),
        }
    }

    /// Reads the 4-byte entry count that starts the FAT, still in its stored byte order.
    pub(crate) fn read_header<R: Read>(reader: &mut R) -> Result<[u8; 4], FatError> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        Ok(header)
    }

    /// The byte orders to try when detecting the FAT's, in order: the one that reads `header` as
    /// the smaller entry count first (`Little` on ties), then the other.
    #[inline]
    #[must_use]
    pub(crate) const fn auto_endian_order(header: [u8; 4]) -> [Endian; 2] {
        if Endian::Big.read_u32(header) < Endian::Little.read_u32(header) {
            [Endian::Big, Endian::Little]
        } else {
            [Endian::Little, Endian::Big]
        }
    }

    /// Tries `attempt` with the preferred byte order for `header`, then with the other one if that
    /// fails, handing `state` (such as the reader and buffer an attempt reads with) from the first
    /// attempt to the second. Returns the first success, or both errors.
    pub(crate) fn try_auto_endian<S, T, E>(
        header: [u8; 4],
        state: S,
        mut attempt: impl FnMut(S, Endian) -> Result<T, FailedAttempt<S, E>>,
    ) -> Result<Detected<T>, BothFailed<E>> {
        let [preferred, other] = Self::auto_endian_order(header);
        match attempt(state, preferred) {
            Ok(value) => Ok(Detected {
                value,
                untried: Some(other),
            }),
            Err(first) => match attempt(first.state, other) {
                Ok(value) => Ok(Detected {
                    value,
                    untried: None,
                }),
                Err(second) => Err(BothFailed {
                    preferred: first.error,
                    other: second.error,
                }),
            },
        }
    }

    /// Auto-detects FAT byte order from the FAT alone through [`Self::try_auto_endian`], keeping
    /// the first order whose size and entries are valid and otherwise reporting the preferred
    /// order's error. [`Bigfile`](crate::archive::Bigfile) runs the same loop with the volume
    /// layout checked under each order as well.
    fn parse_auto_endian<R: Read>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        header: [u8; 4],
        max_file_bytes: Option<u64>,
    ) -> Result<Self, FatError> {
        Self::try_auto_endian(header, (), |(), endian| {
            Self::try_candidate(reader, buf, header, max_file_bytes, endian)
                .map_err(|error| FailedAttempt { state: (), error })
        })
        .map(|detected| detected.value)
        .map_err(|both| both.preferred)
    }

    /// Parses the FAT body in `endian` byte order: checks that it fits in `max_file_bytes`, reads
    /// what `buf` does not already hold, then decodes and validates the entries. `reader` must be
    /// positioned just past the header and whatever `buf` already holds, so attempts in different
    /// byte orders can share one buffer.
    pub(crate) fn try_candidate<R: Read>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        header: [u8; 4],
        max_file_bytes: Option<u64>,
        endian: Endian,
    ) -> Result<Self, FatError> {
        let layout = TableLayout::new(header, endian)?;
        layout.check_fits(max_file_bytes)?;
        let body = layout.read_body(reader, buf)?;
        let (hashes, records) = body.split_at(layout.hashes_len);
        let entries = Self::decode_entries(hashes, records, endian);
        Self::validate_entries(&entries, endian)?;
        Ok(Self { entries, endian })
    }

    /// Decodes a single [`Entry`] from its hash and its record's four 32-bit words in `endian`
    /// order.
    #[inline]
    const fn decode_entry(
        index: usize,
        hash: [u8; 4],
        record: [[u8; 4]; 4],
        endian: Endian,
    ) -> Entry {
        let [size, sector_number, spec_flags, deflated_size] = record;
        Entry {
            index,
            name_hash: endian.read_u32(hash),
            size: endian.read_u32(size),
            sector_number: endian.read_u32(sector_number),
            spec_flags: endian.read_u32(spec_flags),
            deflated_size: endian.read_i32(deflated_size),
        }
    }

    /// Decodes the entries from parallel hash and record byte slices in `endian` order.
    fn decode_entries(hashes: &[u8], records: &[u8], endian: Endian) -> Vec<Entry> {
        let (hashes, _) = hashes.as_chunks::<FAT_HASH_BYTES>();
        let (records, _) = records.as_chunks::<4>().0.as_chunks::<4>();
        std::iter::zip(hashes, records)
            .enumerate()
            .map(|(index, (&hash, &record))| Self::decode_entry(index, hash, record, endian))
            .collect()
    }

    /// Validates invariants for a single entry (`deflated_size >= 0` and sorted `name_hash`).
    #[inline]
    fn validate_entry(
        index: usize,
        prev_hash: Option<u32>,
        entry: &Entry,
        endian: Endian,
    ) -> Result<(), FatError> {
        if entry.deflated_size < 0 {
            return Err(FatError::NegativeDeflatedSize {
                endian,
                index,
                name_hash: entry.name_hash,
                deflated_size: entry.deflated_size,
            });
        }
        if let Some(prev) = prev_hash
            && prev > entry.name_hash
        {
            return Err(FatError::UnsortedHashes {
                endian,
                index,
                prev,
                curr: entry.name_hash,
            });
        }
        Ok(())
    }

    /// Validates all entries in the table.
    fn validate_entries(entries: &[Entry], endian: Endian) -> Result<(), FatError> {
        let mut prev_hash = None;
        for (i, entry) in entries.iter().enumerate() {
            Self::validate_entry(i, prev_hash, entry, endian)?;
            prev_hash = Some(entry.name_hash);
        }
        Ok(())
    }

    /// Returns the detected or configured byte order of this FAT.
    #[inline]
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Returns the total number of records in the FAT.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the FAT contains zero records.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the slice of all entries in TOC order.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Returns an iterator yielding contiguous slices of entries sharing the same `name_hash`.
    #[inline]
    pub fn hash_runs(&self) -> impl Iterator<Item = &[Entry]> {
        self.entries.chunk_by(|a, b| a.name_hash == b.name_hash)
    }

    /// Returns the total byte size of the on-disk FAT header (`4 + 20 * count`).
    #[inline]
    #[must_use]
    pub fn header_byte_size(&self) -> usize {
        fat_byte_len(self.entries.len()).unwrap_or(usize::MAX)
    }

    /// Returns all entries matching `target_hash` in TOC order ($O(\log N)$ binary search).
    ///
    /// Because `hashes` are sorted non-decreasing, all specialisation variants for a given path
    /// hash occupy a contiguous slice.
    #[must_use]
    pub fn find_all(&self, target_hash: u32) -> &[Entry] {
        let start = self.entries.partition_point(|e| e.name_hash < target_hash);
        let end = self.entries[start..].partition_point(|e| e.name_hash == target_hash) + start;
        &self.entries[start..end]
    }

    /// Returns an iterator over `entries` whose `spec_flags` satisfy `spec_mask`
    /// (or all `entries` when `spec_mask` is `None`).
    #[inline]
    pub fn filter_spec_mask(
        entries: &[Entry],
        spec_mask: Option<u32>,
    ) -> impl Iterator<Item = &Entry> {
        entries
            .iter()
            .filter(move |e| spec_mask.is_none_or(|mask| e.matches_spec_mask(mask)))
    }

    /// Returns an iterator over all entries matching `target_hash` whose `spec_flags` satisfy `spec_mask`
    /// (`(entry.spec_flags & spec_mask) == spec_mask`).
    #[inline]
    pub fn find_all_with_spec_mask(
        &self,
        target_hash: u32,
        spec_mask: u32,
    ) -> impl Iterator<Item = &Entry> {
        Self::filter_spec_mask(self.find_all(target_hash), Some(spec_mask))
    }

    /// Finds the entry selected by the game engine's lookup order for `target_hash` and
    /// `spec_mask`, where `spec_flags` must satisfy `(entry.spec_flags & spec_mask) == spec_mask`.
    ///
    /// That order tries the record a binary search lands on, then walks down through the rest of
    /// the hash's run, then up. The landing record depends only on `target_hash` and the table, so
    /// this can differ from the first matching record when several records of a run match.
    ///
    /// This covers one archive only. When a game stacks several archives, such as a patch over its
    /// base, the record it loads can come from another archive; [`ArchiveSet`](crate::ArchiveSet)
    /// resolves a name across them.
    #[must_use]
    pub fn find_with_spec_mask(&self, target_hash: u32, spec_mask: u32) -> Option<&Entry> {
        let landing = self.engine_landing_index(target_hash)?;
        let (below, from_landing) = self.entries.split_at(landing);
        let (landing_entry, above) = from_landing.split_first()?;
        let same_hash = |entry: &&Entry| entry.name_hash == target_hash;
        std::iter::once(landing_entry)
            .chain(below.iter().rev().take_while(same_hash))
            .chain(above.iter().take_while(same_hash))
            .find(|entry| entry.matches_spec_mask(spec_mask))
    }

    /// Returns the index the engine's binary search lands on for `target_hash`, tracking the
    /// remaining span above and below the midpoint separately as it does.
    #[must_use]
    fn engine_landing_index(&self, target_hash: u32) -> Option<usize> {
        let count = self.entries.len();
        let mut mid = count / 2;
        let (mut span_up, mut span_down) = (count - mid, mid + 1);
        loop {
            match target_hash.cmp(&self.entries.get(mid)?.name_hash) {
                Ordering::Equal => return Some(mid),
                Ordering::Greater if span_up < 2 => return None,
                Ordering::Less if span_down < 2 => return None,
                Ordering::Greater => {
                    let step = span_up / 2;
                    mid += step;
                    span_down = step;
                    span_up -= step;
                }
                Ordering::Less => {
                    let step = span_down / 2;
                    mid = mid.checked_sub(step)?;
                    span_up = step;
                    span_down -= step;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::test_support::{FatRow, build_fat_bytes};

    /// Parses a FAT from `(name_hash, spec_flags)` pairs, with each record's size set to its index.
    fn fat_from_hash_flags(records: &[(u32, u32)]) -> Fat {
        let records: Vec<_> = records
            .iter()
            .enumerate()
            .map(|(index, &(hash, flags))| FatRow {
                name_hash: hash,
                size: u32::try_from(index).unwrap(),
                sector_number: 1,
                spec_flags: flags,
                deflated_size: 0,
            })
            .collect();
        Fat::parse(&mut Cursor::new(build_fat_bytes(Endian::Little, &records))).unwrap()
    }

    fn found_index(fat: &Fat, hash: u32, mask: u32) -> Option<usize> {
        fat.find_with_spec_mask(hash, mask).map(|entry| entry.index)
    }

    const LOOKUP_HASH: u32 = 0x2000;

    #[test]
    fn find_with_spec_mask_starts_at_landing_record() {
        let records =
            [10, LOOKUP_HASH, LOOKUP_HASH, LOOKUP_HASH, 0xFFFF_FFF0].map(|hash| (hash, 1));
        assert_eq!(
            found_index(&fat_from_hash_flags(&records), LOOKUP_HASH, 1),
            Some(2)
        );
    }

    #[test]
    fn find_with_spec_mask_prefers_record_below_failing_landing() {
        let flags = [
            (10, 1),
            (LOOKUP_HASH, 1),
            (LOOKUP_HASH, 0),
            (LOOKUP_HASH, 1),
            (0xFFFF_FFF0, 1),
        ];
        assert_eq!(
            found_index(&fat_from_hash_flags(&flags), LOOKUP_HASH, 1),
            Some(1)
        );
    }

    #[test]
    fn find_with_spec_mask_walks_up_after_exhausting_records_below() {
        let flags = [
            (10, 1),
            (LOOKUP_HASH, 0),
            (LOOKUP_HASH, 0),
            (LOOKUP_HASH, 1),
            (0xFFFF_FFF0, 1),
        ];
        assert_eq!(
            found_index(&fat_from_hash_flags(&flags), LOOKUP_HASH, 1),
            Some(3)
        );
    }

    #[test]
    fn find_with_spec_mask_stops_at_run_boundaries() {
        let flags = [(0x1000, 1), (LOOKUP_HASH, 0), (LOOKUP_HASH, 0), (0x3000, 1)];
        assert_eq!(
            found_index(&fat_from_hash_flags(&flags), LOOKUP_HASH, 1),
            None
        );
    }

    #[test]
    fn find_with_spec_mask_rejects_absent_hash_in_empty_table() {
        assert_eq!(found_index(&fat_from_hash_flags(&[]), LOOKUP_HASH, 0), None);
    }

    fn assert_every_hash_found(records: &[(u32, u32)]) {
        let fat = fat_from_hash_flags(records);
        let all_found = records
            .iter()
            .all(|&(hash, _)| fat.engine_landing_index(hash).is_some());
        assert!(all_found, "{} records", records.len());
    }

    #[test]
    fn engine_search_lands_on_every_hash_for_all_run_layouts() {
        for count in 1..=12u32 {
            for layout in 0..1u32 << (count - 1) {
                let starts_run = |i: u32| i == 0 || (layout >> (i - 1)) & 1 == 0;
                let records: Vec<_> = (0..count)
                    .scan(0, |hash, i| {
                        *hash += u32::from(starts_run(i));
                        Some((*hash, 0))
                    })
                    .collect();
                assert_every_hash_found(&records);
            }
        }
    }

    #[test]
    fn engine_search_lands_on_every_hash_in_large_table() {
        let records: Vec<_> = (0..20_000).map(|hash| (hash, 0)).collect();
        assert_every_hash_found(&records);
    }

    /// A little-endian FAT of four records: an uncompressed one, two sharing hash `0x2000` (the
    /// second compressed to 120 bytes), and another uncompressed one.
    fn four_record_fat() -> Fat {
        let bytes = build_fat_bytes(
            Endian::Little,
            &[
                FatRow {
                    name_hash: 0x1000,
                    size: 100,
                    sector_number: 1,
                    spec_flags: 0xFFFF_F7E1,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x2000,
                    size: 200,
                    sector_number: 2,
                    spec_flags: 0xFFFF_F7E1,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x2000,
                    size: 250,
                    sector_number: 3,
                    spec_flags: 0xFFFF_F7E2,
                    deflated_size: 120,
                },
                FatRow {
                    name_hash: 0x3000,
                    size: 300,
                    sector_number: 4,
                    spec_flags: 0xFFFF_FFFF,
                    deflated_size: 0,
                },
            ],
        );
        Fat::parse(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn parses_valid_little_endian_fat_records() {
        let fat = four_record_fat();
        assert_eq!(fat.endian(), Endian::Little);
        assert_eq!(fat.len(), 4);
        let third = &fat.entries()[2];
        assert_eq!(
            (third.name_hash, third.size, third.sector_number),
            (0x2000, 250, 3)
        );
        assert_eq!((third.spec_flags, third.deflated_size), (0xFFFF_F7E2, 120));
    }

    #[test]
    fn hash_runs_group_records_sharing_a_hash() {
        let run_lengths: Vec<usize> = four_record_fat().hash_runs().map(<[Entry]>::len).collect();
        assert_eq!(run_lengths, [1, 2, 1]);
    }

    #[test]
    fn find_all_returns_every_record_of_a_hash_in_order() {
        let fat = four_record_fat();
        let sizes: Vec<u32> = fat
            .find_all(0x2000)
            .iter()
            .map(|entry| entry.size)
            .collect();
        assert_eq!(sizes, [200, 250]);
    }

    #[test]
    fn entry_without_a_deflated_size_is_stored_uncompressed() {
        let fat = four_record_fat();
        let entry = &fat.entries()[1];
        assert!(!entry.is_compressed());
        assert_eq!(entry.stored_size(), entry.size);
    }

    #[test]
    fn entry_with_a_deflated_size_is_stored_compressed() {
        let fat = four_record_fat();
        let entry = &fat.entries()[2];
        assert!(entry.is_compressed());
        assert_eq!(entry.stored_size(), 120);
    }

    /// The bytes of a big-endian FAT of two records, the second compressed.
    fn big_endian_fat_bytes() -> Vec<u8> {
        build_fat_bytes(
            Endian::Big,
            &[
                FatRow {
                    name_hash: 0x1000,
                    size: 100,
                    sector_number: 1,
                    spec_flags: 0xFFFF_F7E1,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x2000,
                    size: 250,
                    sector_number: 3,
                    spec_flags: 0xFFFF_F7E2,
                    deflated_size: 120,
                },
            ],
        )
    }

    #[test]
    fn auto_detects_big_endian_fat_records() {
        let fat = Fat::parse(&mut Cursor::new(big_endian_fat_bytes())).unwrap();
        assert_eq!(fat.endian(), Endian::Big);
        assert_eq!(fat.len(), 2);
        assert_eq!(fat.entries()[1].size, 250);
        assert_eq!(fat.entries()[1].deflated_size, 120);
    }

    #[test]
    fn forced_little_endian_rejects_a_big_endian_fat() {
        let bytes = big_endian_fat_bytes();
        let err = Fat::parse_bounded(
            &mut Cursor::new(&bytes),
            Some(bytes.len() as u64),
            Some(Endian::Little),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FatError::Truncated {
                count: 0x0200_0000,
                ..
            }
        ));
    }

    #[test]
    fn falls_back_to_larger_endian_candidate_when_smaller_hashes_unsorted() {
        let records: Vec<_> = (0..0x0001_0000u32)
            .map(|i| FatRow {
                name_hash: if i == 0 { 1 } else { 0x0100 },
                size: 16,
                sector_number: i + 1,
                spec_flags: 1,
                deflated_size: 0,
            })
            .collect();
        let bytes = build_fat_bytes(Endian::Big, &records);
        let fat = Fat::parse(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(fat.endian(), Endian::Big);
        assert_eq!(fat.len(), 0x0001_0000);
    }

    /// A FAT of three variants of hash `0x2000`, with spec flags `0b0011`, `0b0111` and `0b0010`
    /// and sizes 100, 200 and 250.
    fn spec_variant_fat() -> Fat {
        let bytes = build_fat_bytes(
            Endian::Little,
            &[
                FatRow {
                    name_hash: 0x2000,
                    size: 100,
                    sector_number: 1,
                    spec_flags: 0b0011,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x2000,
                    size: 200,
                    sector_number: 2,
                    spec_flags: 0b0111,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x2000,
                    size: 250,
                    sector_number: 3,
                    spec_flags: 0b0010,
                    deflated_size: 0,
                },
            ],
        );
        Fat::parse(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn find_with_spec_mask_picks_one_matching_variant() {
        let fat = spec_variant_fat();
        let size_for = |mask| {
            fat.find_with_spec_mask(0x2000, mask)
                .map(|entry| entry.size)
        };
        assert_eq!(size_for(0b0011), Some(200));
        assert_eq!(size_for(0b0100), Some(200));
        assert_eq!(size_for(0b1000), None);
    }

    #[test]
    fn find_all_with_spec_mask_returns_every_match_in_order() {
        let fat = spec_variant_fat();
        let sizes: Vec<u32> = fat
            .find_all_with_spec_mask(0x2000, 0b0011)
            .map(|entry| entry.size)
            .collect();
        assert_eq!(sizes, [100, 200]);
    }

    #[test]
    fn rejects_unsorted_hashes() {
        let bytes = build_fat_bytes(
            Endian::Little,
            &[
                FatRow {
                    name_hash: 0x2000,
                    size: 100,
                    sector_number: 1,
                    spec_flags: 0x1,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x1000,
                    size: 100,
                    sector_number: 2,
                    spec_flags: 0x1,
                    deflated_size: 0,
                },
            ],
        );
        let err = Fat::parse(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(
            err,
            FatError::UnsortedHashes {
                endian: Endian::Little,
                index: 1,
                ..
            }
        ));
        assert!(err.to_string().contains("(little-endian)"));
    }

    #[test]
    fn rejects_negative_deflated_size() {
        let bytes = build_fat_bytes(
            Endian::Little,
            &[FatRow {
                name_hash: 0x1000,
                size: 100,
                sector_number: 1,
                spec_flags: 0x1,
                deflated_size: -5,
            }],
        );
        let err = Fat::parse(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(
            err,
            FatError::NegativeDeflatedSize {
                endian: Endian::Little,
                index: 0,
                deflated_size: -5,
                ..
            }
        ));
        assert!(err.to_string().contains("little-endian)"));
    }

    #[test]
    fn rejects_truncated_fat() {
        let mut bytes = build_fat_bytes(
            Endian::Little,
            &[FatRow {
                name_hash: 0x1000,
                size: 100,
                sector_number: 1,
                spec_flags: 0x1,
                deflated_size: 0,
            }],
        );
        bytes.pop();
        let err = Fat::parse(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(
            err,
            FatError::Truncated {
                endian: Endian::Little,
                count: 1,
                ..
            }
        ));
        assert!(err.to_string().contains("(little-endian)"));
    }

    #[test]
    fn rejects_corrupt_huge_count_without_oom() {
        let fake_cdrm = b"CDRM\x01\x00\x00\x00\x10\x00\x00\x00";
        let err = Fat::parse(&mut Cursor::new(fake_cdrm)).unwrap_err();
        assert!(matches!(
            err,
            FatError::Truncated {
                count: 0x4344_524D,
                actual: 8,
                ..
            }
        ));

        let err_bounded = Fat::parse_bounded(
            &mut Cursor::new(fake_cdrm),
            Some(fake_cdrm.len() as u64),
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err_bounded,
            FatError::Truncated {
                count: 0x4344_524D,
                actual: 8,
                ..
            }
        ));
    }

    #[test]
    fn handles_empty_fat() {
        let empty = Fat::parse(&mut Cursor::new(build_fat_bytes(Endian::Little, &[]))).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.endian(), Endian::Little);
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.header_byte_size(), 4);
        assert!(empty.find_all(0x5FF9_1900).is_empty());
    }

    #[test]
    fn header_byte_size_counts_every_record() {
        let bytes = build_fat_bytes(
            Endian::Little,
            &[
                FatRow {
                    name_hash: 0x1000,
                    size: 100,
                    sector_number: 1,
                    spec_flags: 0b0011,
                    deflated_size: 0,
                },
                FatRow {
                    name_hash: 0x1000,
                    size: 200,
                    sector_number: 2,
                    spec_flags: 0b0111,
                    deflated_size: 0,
                },
            ],
        );
        let fat = Fat::parse(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(fat.header_byte_size(), 4 + 2 * 20);
    }
}
