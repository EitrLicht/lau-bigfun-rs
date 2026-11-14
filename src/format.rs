//! Physical format specifications and geometry constants for Tomb Raider LAU bigfile archives.

use std::fmt;

/// Byte order of 32-bit integers in the bigfile Table of Contents (FAT).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Endian {
    /// Little-endian byte order (PC, PS2, PSP, Xbox).
    #[default]
    Little,
    /// Big-endian byte order (PlayStation 3, Xbox 360, Wii / GameCube).
    Big,
}

impl Endian {
    /// Canonical lowercase identifier (`"little-endian"` or `"big-endian"`).
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        }
    }

    /// Decodes a 32-bit unsigned integer from `bytes` using this byte order.
    #[inline]
    #[must_use]
    pub const fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    /// Decodes a 32-bit signed integer from `bytes` using this byte order.
    #[inline]
    #[must_use]
    pub const fn read_i32(self, bytes: [u8; 4]) -> i32 {
        self.read_u32(bytes).cast_signed()
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Base-2 logarithm of the sector size (`1 << 11 == 2048`).
pub const SECTOR_SHIFT: u32 = 11;

/// Archive sector size in bytes (2 KiB, matching DVD-ROM / Mode 1 CD-ROM sector size).
pub const SECTOR_BYTE_COUNT: u32 = 1 << SECTOR_SHIFT;

/// Number of 2 KiB sectors in a 1 MiB logical block (`512`).
pub const BLOCK_SECTOR_COUNT: u32 = 512;

/// Archive block size in bytes (1 MiB = `1,048,576` bytes), used as the volume-split alignment unit.
pub const BLOCK_BYTE_COUNT: u32 = BLOCK_SECTOR_COUNT << SECTOR_SHIFT;

/// Bitmask for extracting the intra-block byte offset (`0x000F_FFFF`).
pub const BLOCK_OFFSET_MASK: u32 = BLOCK_BYTE_COUNT - 1;

/// Byte stride of each record in the bigfile TOC (`16` bytes).
pub const RECORD_STRIDE: usize = 16;

/// Bytes of the entry count that starts the bigfile TOC (`4`).
pub const FAT_COUNT_BYTES: usize = 4;

/// Bytes of each name hash in the TOC's hash array (`4`).
pub const FAT_HASH_BYTES: usize = 4;

/// Bytes the TOC spends on each entry: its name hash plus its record (`20`).
pub const FAT_ENTRY_BYTES: usize = FAT_HASH_BYTES + RECORD_STRIDE;

/// Byte size of a TOC holding `count` entries: the entry count, then every hash, then every
/// record. Returns `None` if the size overflows `usize`.
#[inline]
#[must_use]
pub const fn fat_byte_len(count: usize) -> Option<usize> {
    match count.checked_mul(FAT_ENTRY_BYTES) {
        Some(entries_len) => entries_len.checked_add(FAT_COUNT_BYTES),
        None => None,
    }
}

/// Calculates the 64-bit logical byte offset corresponding to a 32-bit logical sector number.
#[inline]
#[must_use]
pub const fn sector_logical_offset(sector_number: u32) -> u64 {
    (sector_number as u64) << SECTOR_SHIFT
}

/// Checks if a 64-bit byte count is aligned to a 1 MiB block boundary.
#[inline]
#[must_use]
pub const fn is_block_aligned(byte_count: u64) -> bool {
    (byte_count & (BLOCK_OFFSET_MASK as u64)) == 0
}

// Compile-time geometry invariants.
const _: () = {
    assert!(SECTOR_BYTE_COUNT == 2048);
    assert!(SECTOR_BYTE_COUNT.is_power_of_two());
    assert!((1u32 << SECTOR_SHIFT) == SECTOR_BYTE_COUNT);

    assert!(BLOCK_BYTE_COUNT == 1_048_576);
    assert!(BLOCK_BYTE_COUNT.is_power_of_two());
    assert!(BLOCK_BYTE_COUNT == BLOCK_SECTOR_COUNT * SECTOR_BYTE_COUNT);
    assert!(BLOCK_OFFSET_MASK == BLOCK_BYTE_COUNT - 1);
};

/// The `0x<value:08x>` text of a 32-bit TOC value, built on the stack: lowercase, zero-padded to
/// eight digits. For a name hash this is the label
/// [`EntryFilter`](crate::filter::EntryFilter) matches, so tools that print
/// hashes with it print exactly what a filter can match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexLabel([u8; 10]);

impl HexLabel {
    /// Builds the label of `value`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = *b"0x00000000";
        let mut digit = 0;
        while digit < 8 {
            let shift = 28 - 4 * digit;
            text[2 + digit] = HEX[((value >> shift) & 0xF) as usize];
            digit += 1;
        }
        Self(text)
    }

    /// The label as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for HexLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_label_is_lowercase_zero_padded_hex() {
        for value in [0, 0x5FF9_1900, 0xABCD_EF01, u32::MAX] {
            assert_eq!(HexLabel::new(value).to_string(), format!("{value:#010x}"));
        }
    }

    #[test]
    fn is_block_aligned_detects_1mib_multiples() {
        assert!(is_block_aligned(0));
        assert!(is_block_aligned(BLOCK_BYTE_COUNT as u64));
        assert!(is_block_aligned(0x0960_0000));
        assert!(!is_block_aligned(SECTOR_BYTE_COUNT as u64));
        assert!(!is_block_aligned(0x0960_0800));
    }

    #[test]
    fn fat_byte_len_sizes_the_count_field_then_the_entries() {
        assert_eq!(fat_byte_len(0), Some(4));
        assert_eq!(fat_byte_len(2), Some(4 + 2 * 20));
    }

    #[test]
    fn fat_byte_len_reports_overflow() {
        assert_eq!(fat_byte_len(usize::MAX / FAT_ENTRY_BYTES + 1), None);
    }

    #[test]
    fn sector_logical_offset_supports_64bit_address_space() {
        assert_eq!(sector_logical_offset(0), 0);
        assert_eq!(sector_logical_offset(1), 2048);
        assert_eq!(sector_logical_offset(0x0020_0000), 0x1_0000_0000);
    }

    #[test]
    fn endian_decodes_scalars_in_selected_byte_order() {
        let bytes = [0x12, 0x34, 0x56, 0xFE];
        assert_eq!(Endian::default(), Endian::Little);
        assert_eq!(Endian::Little.read_u32(bytes), 0xFE56_3412);
        assert_eq!(Endian::Big.read_u32(bytes), 0x1234_56FE);
        assert_eq!(Endian::Little.read_i32(bytes), -27_905_006);
        assert_eq!(Endian::Big.read_i32(bytes), 0x1234_56FE);
        assert_eq!(Endian::Little.to_string(), "little-endian");
        assert_eq!(Endian::Big.to_string(), "big-endian");
    }
}
