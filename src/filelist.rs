//! Filename hash dictionary for naming the entries of LAU bigfile archives.
//!
//! Archives store only path hashes, so names come from filelists the caller supplies.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::hash::{NonLatin1CharError, name_hash, trim_name};
use crate::path::sanitize_relative_path;

/// Errors that can occur when loading a filelist from disk or string.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FilelistError {
    /// The filelist file could not be read.
    #[error("failed to read filelist '{path}'")]
    Io {
        /// Path of the filelist.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },

    /// The file is larger than [`HashDictionary::load_file`] reads, which a filelist never is: an
    /// archive part passed as a filelist, for example.
    #[error("'{path}' is larger than a filelist can be ({} MiB); is it an archive?", .limit / (1024 * 1024))]
    TooLarge {
        /// Path of the file.
        path: PathBuf,
        /// The limit in bytes.
        limit: u64,
    },

    /// A line holds a name that cannot be hashed.
    #[error("invalid filename on line {line}")]
    InvalidFilename {
        /// Line number, counting from 1.
        line: usize,
        /// Why the name cannot be hashed.
        #[source]
        source: NonLatin1CharError,
    },

    /// A line holds a NUL character, which no name the game looks up can hold. A UTF-16 file
    /// without a byte order mark has one on every line, and so do UTF-32 and most binary data.
    #[error(
        "line {line} holds a NUL character, which no filename can; the filelist may be UTF-16 without a byte order mark, UTF-32, or not text"
    )]
    NulCharacter {
        /// Line number, counting from 1.
        line: usize,
    },

    /// The file starts with a UTF-16 byte order mark, but what follows is not valid UTF-16: it
    /// has an odd number of bytes or an unpaired surrogate.
    #[error("'{path}' starts with a UTF-16 byte order mark but is not valid UTF-16")]
    InvalidUtf16 {
        /// Path of the filelist.
        path: PathBuf,
    },
}

/// Largest file [`HashDictionary::load_file`] reads (64 MiB). Retail filelists are under 1 MiB, so
/// a larger file is not a filelist, and reading it whole could exhaust memory.
const MAX_FILELIST_BYTES: u64 = 64 * 1024 * 1024;

/// Where an entry unpacks to, relative to the output directory, as
/// [`HashDictionary::relative_path_or_fallback`] chooses it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RelativeOutputPath {
    /// The sanitized path the dictionary names, or `__unknown/<name_hash:08x>.bin` when it names
    /// none.
    pub path: PathBuf,
    /// `true` when the dictionary named the hash, so `path` comes from its asset path.
    pub resolved: bool,
}

/// Maps 32-bit `CRC-32/BZIP2` path hashes back to their human-readable asset paths.
#[derive(Debug, Clone, Default)]
pub struct HashDictionary {
    map: HashMap<u32, String>,
}

impl HashDictionary {
    /// Creates an empty [`HashDictionary`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses and inserts newline-delimited asset paths from `content`.
    ///
    /// A line ends at `\n`, `\r\n` or a lone `\r`. Each line loses a leading UTF-8 BOM and is
    /// trimmed with [`trim_name`], so whitespace around a name goes but `U+0085` and the no-break
    /// space (`U+00A0`) stay part of it. Blank lines and lines starting with `#` are then ignored.
    /// Returns the number of entries parsed.
    ///
    /// # Errors
    ///
    /// Fails at the first line that holds a NUL character, with [`FilelistError::NulCharacter`],
    /// or a character above `U+00FF`, with [`FilelistError::InvalidFilename`]; comment lines
    /// count for the NUL. The lines before it stay loaded.
    pub fn load_str(&mut self, content: &str) -> Result<usize, FilelistError> {
        let mut loaded = 0usize;
        for (idx, raw_line) in Self::filelist_lines(content).enumerate() {
            if raw_line.contains('\0') {
                return Err(FilelistError::NulCharacter { line: idx + 1 });
            }
            let Some(line) = Self::parse_filelist_line(raw_line) else {
                continue;
            };
            let h = name_hash(line).map_err(|source| FilelistError::InvalidFilename {
                line: idx + 1,
                source,
            })?;
            self.insert_path(h, line);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Inserts or updates a path for `hash`, reusing existing heap capacity when present.
    #[inline]
    fn insert_path(&mut self, hash: u32, line: &str) {
        use std::collections::hash_map::Entry;
        match self.map.entry(hash) {
            Entry::Occupied(mut occ) => {
                if occ.get() != line {
                    occ.get_mut().clear();
                    occ.get_mut().push_str(line);
                }
            }
            Entry::Vacant(vac) => {
                vac.insert(line.to_string());
            }
        }
    }

    /// Splits `content` into lines ending at `\n`, `\r\n` or a lone `\r`, so a file saved with
    /// classic Mac line endings is read line by line too.
    fn filelist_lines(content: &str) -> impl Iterator<Item = &str> {
        content
            .split('\n')
            .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'))
    }

    /// Strips any leading UTF-8 BOM (`U+FEFF`), trims the line with [`trim_name`], and returns
    /// `None` if it is blank or starts with `#`.
    #[inline]
    fn parse_filelist_line(raw_line: &str) -> Option<&str> {
        let line = trim_name(raw_line.strip_prefix('\u{FEFF}').unwrap_or(raw_line));
        if line.is_empty() || line.starts_with('#') {
            None
        } else {
            Some(line)
        }
    }

    /// Loads and merges newline-delimited asset paths from a file on disk: UTF-16 when it starts
    /// with a UTF-16 byte order mark, and otherwise UTF-8, with any line that isn't valid UTF-8
    /// read as Latin-1.
    ///
    /// # Errors
    ///
    /// [`FilelistError::Io`] when the file cannot be read, [`FilelistError::TooLarge`] when it is
    /// over 64 MiB, [`FilelistError::InvalidUtf16`] when it starts with a UTF-16 byte order mark
    /// but is not valid UTF-16, and otherwise fails like [`Self::load_str`].
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, FilelistError> {
        let path = path.as_ref();
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|file| file.take(MAX_FILELIST_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|source| FilelistError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() as u64 > MAX_FILELIST_BYTES {
            return Err(FilelistError::TooLarge {
                path: path.to_path_buf(),
                limit: MAX_FILELIST_BYTES,
            });
        }
        if let Some(utf16) = Self::decode_utf16_with_bom(&bytes, path) {
            return self.load_str(&utf16?);
        }
        match String::from_utf8(bytes) {
            Ok(text) => self.load_str(&text),
            Err(err) => self.load_str(&Self::decode_filelist_bytes(err.as_bytes())),
        }
    }

    /// Decodes the filelist `bytes` read from `path` as UTF-16 when they start with a UTF-16 byte
    /// order mark: `FF FE` for little-endian, as Windows PowerShell 5.1 writes with `>`, or
    /// `FE FF` for big-endian. Returns `None` for bytes without one, and
    /// [`FilelistError::InvalidUtf16`] when what follows the mark is not valid UTF-16. No UTF-8
    /// file starts with the mark, and a Latin-1 one would only if its first name began `ÿþ`.
    fn decode_utf16_with_bom(bytes: &[u8], path: &Path) -> Option<Result<String, FilelistError>> {
        let (body, from_bytes): (_, fn([u8; 2]) -> u16) = match bytes {
            [0xFF, 0xFE, body @ ..] => (body, u16::from_le_bytes),
            [0xFE, 0xFF, body @ ..] => (body, u16::from_be_bytes),
            _ => return None,
        };
        let invalid = || FilelistError::InvalidUtf16 {
            path: path.to_path_buf(),
        };
        let (units, rest) = body.as_chunks::<2>();
        if !rest.is_empty() {
            return Some(Err(invalid()));
        }
        Some(
            char::decode_utf16(units.iter().map(|&unit| from_bytes(unit)))
                .collect::<Result<String, _>>()
                .map_err(|_| invalid()),
        )
    }

    /// Decodes filelist bytes line by line after dropping a leading UTF-8 BOM: each line is read
    /// as UTF-8 when valid, otherwise as Latin-1 (one code point per byte), so lines saved in an
    /// 8-bit encoding hash the same raw bytes the archive was built from.
    fn decode_filelist_bytes(bytes: &[u8]) -> String {
        let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let mut text = String::with_capacity(body.len());
        for line in body.split_inclusive(|&b| b == b'\n' || b == b'\r') {
            match std::str::from_utf8(line) {
                Ok(utf8) => text.push_str(utf8),
                Err(_) => text.extend(line.iter().copied().map(char::from)),
            }
        }
        text
    }

    /// Returns the number of unique hashes currently in the dictionary.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the dictionary is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Looks up the asset path for `name_hash`.
    #[inline]
    #[must_use]
    pub fn get(&self, name_hash: u32) -> Option<&str> {
        self.map.get(&name_hash).map(String::as_str)
    }

    /// Returns a safe relative output path for `name_hash`, and whether the dictionary named it:
    /// - If found in the dictionary, the sanitized relative path (`pc-w/lara.drm`), resolved.
    /// - Otherwise, `__unknown/<name_hash:08x>.bin`, not resolved.
    #[must_use]
    pub fn relative_path_or_fallback(&self, name_hash: u32) -> RelativeOutputPath {
        match self.get(name_hash) {
            Some(known) => RelativeOutputPath {
                path: sanitize_relative_path(known),
                resolved: true,
            },
            None => RelativeOutputPath {
                path: PathBuf::from("__unknown").join(format!("{name_hash:08x}.bin")),
                resolved: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::hash::name_hash_bytes;
    use crate::test_support::{TempDir, assert_source_not_in_message};

    #[test]
    fn messages_leave_the_wrapped_error_to_source() {
        let dir = TempDir::new("filelist_source");
        let mut dict = HashDictionary::new();

        let read_err = dict.load_file(dir.join("missing.txt")).unwrap_err();
        let name_err = dict.load_str("pc-w\\\u{0100}.drm").unwrap_err();

        assert_source_not_in_message::<io::Error>(&read_err);
        assert_source_not_in_message::<NonLatin1CharError>(&name_err);
    }

    /// Encodes `text` as UTF-16 with `encode` (`u16::to_le_bytes` or `u16::to_be_bytes`), after
    /// the byte order mark `bom`.
    fn utf16_bytes(bom: &[u8], encode: fn(u16) -> [u8; 2], text: &str) -> Vec<u8> {
        let mut bytes = bom.to_vec();
        bytes.extend(text.encode_utf16().flat_map(encode));
        bytes
    }

    /// Writes `bytes` to `filelist.txt` in `dir` and loads it into `dict`.
    fn load_filelist_bytes(
        dict: &mut HashDictionary,
        dir: &TempDir,
        bytes: &[u8],
    ) -> Result<usize, FilelistError> {
        let path = dir.join("filelist.txt");
        fs::write(&path, bytes).unwrap();
        dict.load_file(&path)
    }

    #[test]
    fn loads_utf16_with_either_byte_order_mark() {
        let dir = TempDir::new("filelist_utf16");
        let text = "# comment\r\npc-w\\lara.drm\r\n";

        for bytes in [
            utf16_bytes(&[0xFF, 0xFE], u16::to_le_bytes, text),
            utf16_bytes(&[0xFE, 0xFF], u16::to_be_bytes, text),
        ] {
            let mut dict = HashDictionary::new();

            let loaded = load_filelist_bytes(&mut dict, &dir, &bytes);

            assert_eq!(loaded.unwrap(), 1);
            assert_eq!(dict.get(0x5FF9_1900), Some(r"pc-w\lara.drm"));
        }
    }

    #[test]
    fn rejects_utf16_without_a_byte_order_mark_at_line_one() {
        let dir = TempDir::new("filelist_utf16_no_bom");
        let bytes = utf16_bytes(&[], u16::to_le_bytes, "pc-w\\lara.drm\r\n");

        let loaded = load_filelist_bytes(&mut HashDictionary::new(), &dir, &bytes);

        assert!(
            matches!(loaded, Err(FilelistError::NulCharacter { line: 1 })),
            "{loaded:?}"
        );
    }

    #[test]
    fn rejects_utf16_that_does_not_decode() {
        let dir = TempDir::new("filelist_bad_utf16");
        let path = dir.join("filelist.txt");
        let unpaired_surrogate = [0xFF, 0xFE, 0x00, 0xD8, b'a', 0x00];
        let odd_length = [0xFF, 0xFE, b'a', 0x00, b'b'];

        for bytes in [&unpaired_surrogate[..], &odd_length] {
            let loaded = load_filelist_bytes(&mut HashDictionary::new(), &dir, bytes);

            assert!(
                matches!(&loaded, Err(FilelistError::InvalidUtf16 { path: p }) if *p == path),
                "{loaded:?}"
            );
        }
    }

    #[test]
    fn reports_a_nul_at_its_line_after_loading_the_lines_before() {
        let mut dict = HashDictionary::new();

        let err = dict.load_str("pc-w\\lara.drm\n# not\0text\n").unwrap_err();

        assert!(
            matches!(err, FilelistError::NulCharacter { line: 2 }),
            "{err:?}"
        );
        assert_eq!(dict.get(0x5FF9_1900), Some(r"pc-w\lara.drm"));
    }

    #[test]
    fn splits_lines_at_a_lone_carriage_return() {
        let mut dict = HashDictionary::new();

        assert_eq!(dict.load_str("pc-w\\a.drm\rpc-w\\b.drm\r").unwrap(), 2);
    }

    #[test]
    fn counts_lines_across_mixed_line_endings() {
        let mut dict = HashDictionary::new();

        let err = dict.load_str("a\r\nb\rc\n\r\n\u{0100}\n").unwrap_err();

        assert!(
            matches!(err, FilelistError::InvalidFilename { line: 5, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn decodes_each_carriage_return_line_in_its_own_encoding() {
        assert_eq!(
            HashDictionary::decode_filelist_bytes(b"pc-w\\a\xc3\xa9.drm\rpc-w\\b\xe9.drm"),
            "pc-w\\a\u{e9}.drm\rpc-w\\b\u{e9}.drm"
        );
    }

    #[test]
    fn loads_custom_filelist_with_bom() {
        let mut dict = HashDictionary::new();
        assert!(dict.is_empty());

        let content = "\u{FEFF}# BOM comment\r\n\r\n  # Indented comment\n\u{FEFF}  pc-w\\lara.drm  \r\npc-w\\lara.drm\npc-w\\alister.drm\n";
        assert_eq!(dict.load_str(content).unwrap(), 3);
        assert_eq!(dict.len(), 2);
        assert!(!dict.is_empty());

        dict.load_str("PC-W\\LARA.DRM\n").unwrap();
        assert_eq!(dict.get(0x5FF9_1900), Some(r"PC-W\LARA.DRM"));
        dict.load_str("pc-w\\lara.drm\n").unwrap();
        assert_eq!(dict.get(0x5FF9_1900), Some(r"pc-w\lara.drm"));
    }

    #[test]
    fn trims_padding_but_keeps_latin1_whitespace_in_a_name() {
        let mut dict = HashDictionary::new();
        let name = "\u{85}pc-w\\lara.drm\u{a0}";

        dict.load_str(&format!("\u{3000} {name}\t\u{0B}\r\n"))
            .unwrap();

        assert_eq!(dict.get(name_hash(name).unwrap()), Some(name));
    }

    #[test]
    fn named_hash_gets_its_sanitized_path_marked_resolved() {
        let mut dict = HashDictionary::new();
        dict.load_str("pc-w\\lara.drm\n").unwrap();
        let output = dict.relative_path_or_fallback(0x5FF9_1900);
        assert_eq!(output.path, PathBuf::from("pc-w/lara.drm"));
        assert!(output.resolved);
    }

    #[test]
    fn unnamed_hash_falls_back_to_the_unknown_folder() {
        let output = HashDictionary::new().relative_path_or_fallback(0xDEAD_BEEF);
        assert_eq!(output.path, PathBuf::from("__unknown/deadbeef.bin"));
        assert!(!output.resolved);
    }

    #[test]
    fn loads_latin1_encoded_filelist_file() {
        let dir = TempDir::new("latin1_filelist");
        let raw_path = b"pc-w\\caf\xe9.drm";
        let file = dir.join("latin1.txt");
        fs::write(&file, [raw_path.as_slice(), b"\n"].concat()).unwrap();

        let mut dict = HashDictionary::new();
        assert_eq!(dict.load_file(&file).unwrap(), 1);
        assert_eq!(
            dict.get(name_hash_bytes(raw_path)),
            Some("pc-w\\caf\u{e9}.drm")
        );
    }

    #[test]
    fn decode_filelist_bytes_drops_bom_before_latin1_line() {
        assert_eq!(
            HashDictionary::decode_filelist_bytes(b"\xEF\xBB\xBFpc-w\\caf\xe9.drm\n"),
            "pc-w\\caf\u{e9}.drm\n"
        );
    }

    #[test]
    fn decode_filelist_bytes_decodes_each_line_independently() {
        assert_eq!(
            HashDictionary::decode_filelist_bytes(b"pc-w\\a\xc3\xa9.drm\r\npc-w\\b\xe9.drm"),
            "pc-w\\a\u{e9}.drm\r\npc-w\\b\u{e9}.drm"
        );
    }

    #[test]
    fn reports_invalid_filename_line_number() {
        let mut dict = HashDictionary::new();
        let bad_content = "# comment\npc-w\\lara.drm\npc-w\\\u{0100}.drm\n";
        let err = dict.load_str(bad_content).unwrap_err();
        assert!(matches!(
            err,
            FilelistError::InvalidFilename { line: 3, source } if source.ch == '\u{0100}'
        ));
    }

    #[test]
    fn reports_missing_file_io_error() {
        let mut dict = HashDictionary::new();
        let missing = PathBuf::from("/nonexistent/path/to/custom_filelist.txt");
        let io_err = dict.load_file(&missing).unwrap_err();
        assert!(matches!(io_err, FilelistError::Io { path, .. } if path == missing));
    }

    #[test]
    fn too_large_error_gives_the_limit_in_mib() {
        let err = FilelistError::TooLarge {
            path: PathBuf::from("bigfile.000"),
            limit: MAX_FILELIST_BYTES,
        };
        assert_eq!(
            err.to_string(),
            "'bigfile.000' is larger than a filelist can be (64 MiB); is it an archive?"
        );
    }

    #[test]
    fn rejects_file_over_the_size_limit() {
        let dir = TempDir::new("filelist_too_large");
        let path = dir.join("bigfile.000");
        // A sparse file, so the test writes no data of this size.
        File::create(&path)
            .unwrap()
            .set_len(MAX_FILELIST_BYTES + 1)
            .unwrap();
        let err = HashDictionary::new().load_file(&path).unwrap_err();
        assert!(
            matches!(&err, FilelistError::TooLarge { path: p, limit } if *p == path && *limit == MAX_FILELIST_BYTES),
            "{err:?}"
        );
    }
}
