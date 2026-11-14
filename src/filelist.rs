//! Filename hash dictionary for naming the entries of LAU bigfile archives.
//!
//! Archives store only path hashes, so names come from filelists the caller supplies.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::hash::{NonLatin1CharError, name_hash};
use crate::path::sanitize_relative_path;

/// Errors that can occur when loading a filelist from disk or string.
#[derive(Debug, Error)]
pub enum FilelistError {
    /// The filelist file could not be read.
    #[error("failed to read filelist '{path}': {source}")]
    Io {
        /// Path of the filelist.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },

    /// A line holds a name that cannot be hashed.
    #[error("invalid filename on line {line}: {source}")]
    InvalidFilename {
        /// Line number, counting from 1.
        line: usize,
        /// Why the name cannot be hashed.
        #[source]
        source: NonLatin1CharError,
    },
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
    /// Blank lines and lines starting with `#` (after stripping any leading UTF-8 BOM and
    /// whitespace) are ignored. Returns the number of entries parsed.
    ///
    /// # Errors
    ///
    /// [`FilelistError::InvalidFilename`] at the first line holding a character above `U+00FF`.
    /// The lines before it stay loaded.
    pub fn load_str(&mut self, content: &str) -> Result<usize, FilelistError> {
        let mut loaded = 0usize;
        for (idx, raw_line) in content.lines().enumerate() {
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

    /// Strips any leading UTF-8 BOM (`U+FEFF`), trims whitespace, and returns `None` if the line
    /// is blank or starts with `#`.
    #[inline]
    fn parse_filelist_line(raw_line: &str) -> Option<&str> {
        let line = raw_line.strip_prefix('\u{FEFF}').unwrap_or(raw_line).trim();
        if line.is_empty() || line.starts_with('#') {
            None
        } else {
            Some(line)
        }
    }

    /// Loads and merges newline-delimited asset paths from a UTF-8 or Latin-1 file on disk.
    ///
    /// # Errors
    ///
    /// [`FilelistError::Io`] when the file cannot be read, and otherwise fails like
    /// [`Self::load_str`].
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, FilelistError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| FilelistError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        match String::from_utf8(bytes) {
            Ok(text) => self.load_str(&text),
            Err(err) => self.load_str(&Self::decode_filelist_bytes(err.as_bytes())),
        }
    }

    /// Decodes filelist bytes line by line after dropping a leading UTF-8 BOM: each line is read
    /// as UTF-8 when valid, otherwise as Latin-1 (one code point per byte), so lines saved in an
    /// 8-bit encoding hash the same raw bytes the archive was built from.
    fn decode_filelist_bytes(bytes: &[u8]) -> String {
        let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let mut text = String::with_capacity(body.len());
        for line in body.split_inclusive(|&b| b == b'\n') {
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
    /// - If found in the dictionary, returns the sanitized relative path (`pc-w/lara.drm`) and
    ///   `true`.
    /// - Otherwise, returns `__unknown/<name_hash:08x>.bin` and `false`.
    #[must_use]
    pub fn relative_path_or_fallback(&self, name_hash: u32) -> (PathBuf, bool) {
        if let Some(known) = self.get(name_hash) {
            (sanitize_relative_path(known), true)
        } else {
            (
                PathBuf::from("__unknown").join(format!("{name_hash:08x}.bin")),
                false,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::name_hash_bytes;
    use crate::test_support::TempDir;

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

        assert_eq!(
            dict.relative_path_or_fallback(0x5FF9_1900),
            (PathBuf::from("pc-w/lara.drm"), true)
        );
        assert_eq!(
            dict.relative_path_or_fallback(0xDEAD_BEEF),
            (PathBuf::from("__unknown/deadbeef.bin"), false)
        );
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
}
