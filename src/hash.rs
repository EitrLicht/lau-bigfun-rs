//! Tomb Raider LAU path-name hash (bigfile TOC key).
//!
//! Algorithm:
//! 1. Lowercase the filename using C-locale ASCII `tolower` (`'A'..='Z'` -> `+ 0x20`).
//! 2. Compute `CRC-32/BZIP2` over those bytes:
//!    - `init = 0xFFFF_FFFF`
//!    - `poly = 0x04C1_1DB7` (MSB-first, no input/output reflection)
//!    - `xorout = 0xFFFF_FFFF` (`!crc`)
//!
//! Canonical check value: `name_hash("123456789") == 0xFC891918`.

use thiserror::Error;

/// Generator polynomial for `CRC-32/BZIP2` (`0x04C1_1DB7`, MSB-first).
pub const CRC32_BZIP2_POLY: u32 = 0x04C1_1DB7;

/// Initial register value and final XOR mask for `CRC-32/BZIP2`.
pub const CRC32_BZIP2_INIT: u32 = 0xFFFF_FFFF;

/// Error returned when a filename contains a Unicode code point outside the Latin-1 (`<= U+00FF`) domain.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "filename contains non-Latin-1 character {ch:?} (U+{:04X}) at byte offset {byte_offset}",
    u32::from(*.ch)
)]
#[non_exhaustive]
pub struct NonLatin1CharError {
    /// The character outside Latin-1.
    pub ch: char,
    /// Its byte offset in the UTF-8 filename.
    pub byte_offset: usize,
}

/// Precomputed 256-entry MSB-first `CRC-32/BZIP2` lookup table.
const CRC32_BZIP2_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i << 24;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x8000_0000) != 0 {
                crc = (crc << 1) ^ CRC32_BZIP2_POLY;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Feeds a single byte into an MSB-first `CRC-32/BZIP2` accumulator.
#[inline]
#[must_use]
const fn crc32_bzip2_step(crc: u32, byte: u8) -> u32 {
    let idx = ((crc >> 24) ^ (byte as u32)) & 0xFF;
    (crc << 8) ^ CRC32_BZIP2_TABLE[idx as usize]
}

/// Computes the 32-bit LAU path hash over a raw Latin-1 / ASCII byte slice (case-insensitive
/// for ASCII `'A'..='Z'`).
#[inline]
#[must_use]
pub const fn name_hash_bytes(filename_bytes: &[u8]) -> u32 {
    let mut crc = CRC32_BZIP2_INIT;
    let mut i = 0;
    while i < filename_bytes.len() {
        // The engine folds case with the C-locale `tolower`, which maps only ASCII `A`..=`Z`.
        let b = filename_bytes[i].to_ascii_lowercase();
        crc = crc32_bzip2_step(crc, b);
        i += 1;
    }
    !crc
}

/// Decodes a UTF-8 `&str` into its Latin-1 byte representation (`U+0000..=U+00FF`).
fn decode_latin1_bytes(filename: &str) -> Result<Vec<u8>, NonLatin1CharError> {
    filename
        .char_indices()
        .map(|(byte_offset, ch)| {
            u8::try_from(ch).map_err(|_| NonLatin1CharError { ch, byte_offset })
        })
        .collect()
}

/// Computes the 32-bit LAU path hash of `filename` (case-insensitive for ASCII `'A'..='Z'`).
///
/// `filename` must be Latin-1/ASCII encodable (`U+0000..=U+00FF`).
///
/// # Errors
///
/// [`NonLatin1CharError`] for the first code point above `U+00FF`, rather than silently hashing
/// its multi-byte UTF-8 sequence.
#[inline]
pub fn name_hash(filename: &str) -> Result<u32, NonLatin1CharError> {
    if filename.is_ascii() {
        return Ok(name_hash_bytes(filename.as_bytes()));
    }
    let latin1 = decode_latin1_bytes(filename)?;
    Ok(name_hash_bytes(&latin1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_crc32_bzip2_check_vector() {
        assert_eq!(name_hash("123456789").unwrap(), 0xFC89_1918);
        assert_eq!(name_hash_bytes(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn test_lowercases_before_hashing() {
        assert_eq!(name_hash("ABC").unwrap(), name_hash("abc").unwrap());
        assert_eq!(
            name_hash("Foo\\Bar.DRM").unwrap(),
            name_hash("foo\\bar.drm").unwrap()
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(name_hash("").unwrap(), 0x0000_0000);
    }

    #[test]
    fn test_known_tru_paths_match_oracle() {
        assert_eq!(name_hash(r"pc-w\alister.drm").unwrap(), 0x1DE5_357F);
        assert_eq!(name_hash(r"pc-w\lara.drm").unwrap(), 0x5FF9_1900);
        assert_eq!(name_hash(r"pc-w\l1_seafloor.drm").unwrap(), 0xDCFA_360F);
        assert_eq!(
            name_hash(r"pc-w\l1_krakenstairs_b.drm").unwrap(),
            0x9591_3E62
        );
    }

    #[test]
    fn test_latin1_upper_range_hashes_raw_byte() {
        let h_latin1 = name_hash("\u{00e9}").unwrap();
        assert_eq!(h_latin1, name_hash_bytes(&[0xE9]));
    }

    #[test]
    fn test_rejects_code_point_above_u00ff() {
        let err = name_hash("pc-w\\\u{0100}.drm").unwrap_err();
        assert_eq!((err.ch, err.byte_offset), ('\u{0100}', 5));
    }

    #[test]
    fn non_latin1_error_message_shows_the_code_point() {
        let err = name_hash("pc-w\\\u{0100}.drm").unwrap_err();
        assert_eq!(
            err.to_string(),
            "filename contains non-Latin-1 character '\u{0100}' (U+0100) at byte offset 5"
        );
    }
}
