//! Bigfile archive opening, entry location and reads for Tomb Raider LAU archives.

use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::fat::{BothFailed, Detected, Entry, FailedAttempt, Fat, FatError};
use crate::format::{Endian, HexLabel};
use crate::path::FileId;

mod discovery;
mod geometry;
mod reader;
mod set;

use discovery::DiscoveredParts;
pub use reader::EntryReader;
use reader::PositionalFileReader;
pub use set::{ArchiveSet, ResolvedEntry};

/// Errors that can occur when opening, validating, or reading from a [`Bigfile`] archive.
///
/// Variants about one record name it by its position in the FAT (`index`), its path hash
/// (`name_hash`) and, where relevant, its starting sector (`sector_number`), as in [`Entry`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BigfileError {
    /// Reading an entry's bytes from its part file failed.
    #[error("I/O error")]
    Io(#[from] io::Error),

    /// The folder that holds the archive's parts could not be listed, such as for lack of
    /// permission.
    #[error("cannot list archive folder '{path}'")]
    ArchiveDirectory {
        /// Path of the folder.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },

    /// A part file could not be opened, or its size or identity read. On Windows this includes a
    /// part that another program has open for writing.
    #[error("cannot open archive part '{path}'{}", discovery::sharing_hint(.source))]
    PartOpen {
        /// Path of the part file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },

    /// The destination rejected extracted bytes, as opposed to a failure reading the archive.
    #[error("failed to write output")]
    Write(#[source] io::Error),

    /// An output file or directory could not be created, written or moved into place. Only
    /// unpacking (feature `unpack`) returns this.
    #[error("failed to write '{path}'")]
    OutputPath {
        /// The output file or directory.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },

    /// The planned extraction is larger than [`UnpackOptions::max_output_bytes`](crate::UnpackOptions::max_output_bytes) allows.
    /// Only unpacking (feature `unpack`) returns this.
    #[error("planned output of {planned} bytes exceeds the limit of {limit} bytes")]
    OutputLimitExceeded {
        /// Bytes the extraction would write.
        planned: u64,
        /// The configured limit.
        limit: u64,
    },

    /// An unpack or extraction would write over a part file of an archive it reads, through the
    /// destination `path` (which may be a link to the part). Nothing is written. Only unpacking
    /// (feature `unpack`) returns this.
    #[error("refusing to write to '{path}': it is a part file of the archive being read")]
    OutputIsArchivePart {
        /// The destination that names the archive part.
        path: PathBuf,
    },

    /// The FAT failed to parse or validate.
    #[error(transparent)]
    Fat(#[from] FatError),

    /// The given path names no archive: no `<stem>.000` parts, `.dat` file or other archive file.
    #[error("no bigfile archive parts found at '{0}'")]
    NoPartsFound(PathBuf),

    /// [`unpack_archive_set`](crate::unpack_archive_set) was given several archives without
    /// [`UnpackOptions::spec_mask`](crate::UnpackOptions::spec_mask) and
    /// [`UnpackOptions::single_match_per_hash`](crate::UnpackOptions::single_match_per_hash),
    /// which resolving a name across archives needs. Only unpacking (feature `unpack`) returns
    /// this.
    #[error("resolving across archives requires a spec mask and single-match selection")]
    ResolutionRequiresSpecMatch,

    /// Set [`OpenOptions::endian`] to choose between the two byte orders.
    #[error(
        "archive TOC is valid as both little-endian and big-endian; choose a byte order explicitly"
    )]
    AmbiguousEndian,

    /// A segment length, given or detected, is zero or not a multiple of the 1 MiB block.
    #[error(
        "segment_length {segment_length:#x} must be non-zero and {block_size}-byte (1 MiB) aligned"
    )]
    UnalignedSegmentLength {
        /// The rejected segment length in bytes.
        segment_length: u64,
        /// The block size it must be a multiple of.
        block_size: u32,
    },

    /// A multi-part archive has no record holding data past part 0 to detect its segment length
    /// from, and [`OpenOptions::segment_length`] was not given.
    #[error(
        "cannot dynamically determine segment stride across {part_count} part files because no FAT entry holding data starts past part 0"
    )]
    UndeterminedSegmentLength {
        /// Number of part files.
        part_count: usize,
    },

    /// [`OpenOptions::segment_length`] differs from the segment length the records show, and the
    /// archive's part files and records fit the one they show but not the one given.
    #[error(
        "explicit segment_length {override_length:#010x} does not fit the archive's part files and records; they show a segment stride of {detected_length:#010x}"
    )]
    SegmentLengthMismatch {
        /// The segment length given in [`OpenOptions`].
        override_length: u64,
        /// The segment length detected from the records.
        detected_length: u64,
    },

    /// The archive's part files and records fit two segment lengths, and
    /// [`OpenOptions::segment_length`] was not given to choose: the one detected from the first
    /// record holding data past part 0, and a shorter one that starts part 1 at an empty record.
    #[error(
        "the archive fits a segment length of both {detected_length:#010x} and {other_length:#010x}; choose one explicitly"
    )]
    AmbiguousSegmentLength {
        /// The segment length detected from the first record holding data past part 0.
        detected_length: u64,
        /// The other segment length the archive fits.
        other_length: u64,
    },

    /// A part file is larger than the segment each part occupies.
    #[error(
        "part {part_index} ('{part_path}') is {physical_size} bytes ({physical_size:#x}), exceeding segment_length {segment_length:#010x}"
    )]
    PartExceedsSegmentLength {
        /// Position of the part (`0` for `.000`).
        part_index: usize,
        /// Path of the part file.
        part_path: PathBuf,
        /// Size of the part file in bytes.
        physical_size: u64,
        /// The segment length in bytes.
        segment_length: u64,
    },

    /// A record starts in a part past the last part file.
    #[error(
        "record {index} (hash {}) at sector {sector_number} references part {part_index}, but only {part_count} part(s) exist", HexLabel::new(*.name_hash)
    )]
    PartOutOfRange {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// Starting sector of the record.
        sector_number: u32,
        /// Position of the part the record would start in.
        part_index: usize,
        /// Number of part files.
        part_count: usize,
    },

    /// A record's stored bytes run past the end of its part file.
    #[error(
        "record {index} (hash {}) at sector {sector_number} overruns part {part_index} ('{part_path}'): needs {needed} bytes at offset {offset:#x}, but part is only {physical_size} bytes", HexLabel::new(*.name_hash)
    )]
    RecordOverrunsPart {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// Starting sector of the record.
        sector_number: u32,
        /// Position of the part holding the record.
        part_index: usize,
        /// Path of that part file.
        part_path: PathBuf,
        /// Byte offset of the record within the part.
        offset: u64,
        /// Stored bytes the record needs.
        needed: u32,
        /// Size of the part file in bytes.
        physical_size: u64,
    },

    /// [`Bigfile::open_entry_at`] was asked to start past the end of a record's stored bytes.
    #[error(
        "offset {offset} is past the end of record {index} (hash {}), which stores {stored_size} bytes", HexLabel::new(*.name_hash)
    )]
    OffsetPastEntryEnd {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// The requested offset into the record's stored bytes.
        offset: u64,
        /// Stored bytes the record holds.
        stored_size: u32,
    },

    /// A record with stored bytes starts inside the FAT at the start of part 0.
    #[error(
        "record {index} (hash {}) at sector {sector_number} (offset {logical_offset:#x}) overlaps the FAT header ({fat_byte_size:#x} bytes)", HexLabel::new(*.name_hash)
    )]
    RecordOverlapsFat {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// Starting sector of the record.
        sector_number: u32,
        /// Byte offset of the record in the logical archive.
        logical_offset: u64,
        /// Size of the FAT in bytes.
        fat_byte_size: u64,
    },

    /// No record starts at the beginning of a part after the first, so the segment length that
    /// places the parts is likely wrong.
    #[error(
        "part {part_index} ('{part_path}') has no entry starting at sector {expected_sector} (offset 0 of that part); segment boundary discovery may be wrong"
    )]
    MissingPartStartEntry {
        /// Position of the part.
        part_index: usize,
        /// Path of the part file.
        part_path: PathBuf,
        /// Logical sector where the part begins.
        expected_sector: u64,
    },

    /// A compressed record's zlib stream is corrupt.
    #[error("zlib decompression failed for record {index} (hash {})", HexLabel::new(*.name_hash))]
    DecompressError {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// The decoder's error.
        #[source]
        source: io::Error,
    },

    /// A compressed record's zlib stream inflates to a different size than the FAT declares.
    #[error(
        "decompressed size mismatch for record {index} (hash {}): expected {expected} bytes, got {actual}", HexLabel::new(*.name_hash)
    )]
    DecompressedSizeMismatch {
        /// Position of the record in the FAT.
        index: usize,
        /// Path hash of the record.
        name_hash: u32,
        /// Inflated size the FAT declares.
        expected: u32,
        /// Bytes the stream inflated to, or `expected + 1` for a longer stream, since inflating
        /// stops one byte past the declared size.
        actual: u64,
    },
}

/// Where an entry's stored bytes start, as [`Bigfile::locate`] finds it.
///
/// Locations order by part, then by offset, which is the order of the bytes on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub struct EntryLocation {
    /// Index of the part file holding the entry, as in [`Bigfile::part_paths`].
    pub part_index: usize,
    /// Byte offset of the entry's stored bytes within that part. Not checked against the part's
    /// size (see [`Bigfile::locate`]).
    pub offset_in_part: u64,
}

/// Configuration options for opening and validating a [`Bigfile`] archive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Explicit virtual volume segment stride in bytes (`None` = auto-detect from TOC boundaries).
    /// It must be 1 MiB-aligned, and is used even where it differs from the detected stride, as
    /// long as every part file and record fits it.
    pub segment_length: Option<u64>,
    /// Explicit TOC byte order (`None` = auto-detect from FAT and volume geometry).
    pub endian: Option<Endian>,
    /// Open exactly the given file as a single-part archive, without discovering parts from its
    /// name (`false` = gather numbered `.000`, `.001`, ... siblings and resolve `.dat` names). Some
    /// games ship numbered files that are separate archives, each with its own TOC. The file name
    /// matches regardless of case, a directory fails with [`BigfileError::NoPartsFound`], and a
    /// given `segment_length` still applies to the one part.
    pub single_part: bool,
}

/// Reader and validator for a single-part or multi-part Tomb Raider LAU bigfile.
///
/// Keeps open [`File`] handles for all physical part files (`.000`, `.001`, ...) and reads them
/// with positional I/O (`pread` / `seek_read`), which takes the offset with each read, so threads
/// share the handles without per-entry `open()`/`close()` calls or coordinated seeks.
///
/// On Windows the parts are opened sharing only reading: while a `Bigfile` is open, no other
/// handle can write to its parts or rename them, and opening fails if one already has a part open
/// for writing.
#[derive(Debug)]
pub struct Bigfile {
    /// Base directory containing the archive part files.
    dir_path: PathBuf,
    /// Archive stem name (e.g. `"bigfile"` or `"patch"`).
    stem: String,
    /// Parsed and validated File Allocation Table.
    fat: Fat,
    /// Per-part logical segment stride in bytes (`Some(stride)` for multi-part archives or when
    /// explicitly specified; `None` for unsplit single-part archives).
    segment_length: Option<u64>,
    /// Ordered list of physical part file paths (`.000`, `.001`, ...).
    part_paths: Vec<PathBuf>,
    /// Persistent open file handles for each physical part in `part_paths`.
    part_files: Vec<File>,
    /// Physical byte size of each part file in `part_paths`.
    part_sizes: Vec<u64>,
    /// Identity of each part file in `part_paths`, taken when it was opened. Empty without the
    /// `unpack` feature, which alone reads it.
    part_ids: Vec<FileId>,
}

/// The FAT bytes read from part 0 so far: the 4-byte header, then as much of the body as the
/// byte orders tried have needed, which attempts in either byte order share.
struct FatBytes {
    header: [u8; 4],
    body: Vec<u8>,
}

impl FatBytes {
    /// Reads the FAT header from `part0`, a file of `part0_size` bytes.
    fn read_header(part0: &File, part0_size: u64) -> Result<Self, BigfileError> {
        let header = Fat::read_header(&mut PositionalFileReader::new(part0, 0, part0_size))?;
        Ok(Self {
            header,
            body: Vec::new(),
        })
    }

    /// Parses the FAT in `endian` byte order, reading from `part0` only the bytes no earlier
    /// attempt has read.
    fn parse(
        &mut self,
        part0: &File,
        part0_size: u64,
        endian: Endian,
    ) -> Result<Fat, BigfileError> {
        let already_read = (self.header.len() + self.body.len()) as u64;
        let mut reader = PositionalFileReader::new(part0, already_read, part0_size);
        let fat = Fat::try_candidate(
            &mut reader,
            &mut self.body,
            self.header,
            Some(part0_size),
            endian,
        )?;
        Ok(fat)
    }
}

/// An archive's part files while its byte order is being chosen, with the FAT bytes read so far.
struct Opening {
    parts: DiscoveredParts,
    fat_bytes: FatBytes,
}

impl Opening {
    /// Reads the FAT header from part 0 of `parts`.
    fn new(parts: DiscoveredParts) -> Result<Self, BigfileError> {
        let fat_bytes = FatBytes::read_header(&parts.part_files[0], parts.part_sizes[0])?;
        Ok(Self { parts, fat_bytes })
    }
}

/// An archive opened in one byte order, with the FAT bytes read so far, which checking the other
/// byte order for ambiguity reuses.
struct Opened {
    bigfile: Bigfile,
    fat_bytes: FatBytes,
}

/// The part holding an entry and the byte range of its stored bytes in that part, checked to lie
/// within the part file.
struct StoredSpan {
    part_index: usize,
    range: Range<u64>,
}

/// Why one byte order failed while opening an archive.
enum EndianError {
    /// The FAT did not parse in that byte order.
    Fat(BigfileError),
    /// The FAT parsed, but the volume geometry under it is invalid.
    Geometry(BigfileError),
}

impl EndianError {
    fn into_error(self) -> BigfileError {
        match self {
            Self::Fat(err) | Self::Geometry(err) => err,
        }
    }

    /// The error to report when both byte orders fail: the first geometry error, since that order's
    /// FAT at least parsed, or else the preferred byte order's error. The preferred order is the
    /// one tried first.
    fn reported(both: BothFailed<Self>) -> BigfileError {
        match both {
            BothFailed {
                preferred: Self::Fat(_),
                other: Self::Geometry(err),
            } => err,
            BothFailed { preferred, .. } => preferred.into_error(),
        }
    }
}

impl Bigfile {
    /// Opens and validates a bigfile archive from either:
    /// - A directory path (e.g. `/path/to/game_dir`, discovering `bigfile.000`..`bigfile.NNN` or `bigfile.dat`), or
    /// - A specific archive file path (e.g. `/path/to/bigfile.000`, `/path/to/patch.000`, or `/path/to/BIGFILE.DAT`).
    ///
    /// Dynamically detects the TOC byte order and virtual volume segment stride.
    ///
    /// # Errors
    ///
    /// Fails like [`Self::open_with_options`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, BigfileError> {
        Self::open_with_options(path, OpenOptions::default())
    }

    /// Opens and validates a bigfile archive using the supplied [`OpenOptions`].
    ///
    /// # Errors
    ///
    /// - [`BigfileError::NoPartsFound`] when `path` names no archive.
    /// - [`BigfileError::PartOpen`] when a part file cannot be opened, or its size or identity
    ///   read, such as on Windows when another program has it open for writing.
    /// - [`BigfileError::ArchiveDirectory`] when the folder holding the parts cannot be listed.
    /// - [`BigfileError::Fat`] when the FAT cannot be read or does not parse.
    /// - [`BigfileError::AmbiguousEndian`] when no byte order is given and the archive is valid
    ///   in both.
    /// - [`BigfileError::AmbiguousSegmentLength`] when no segment length is given and the archive
    ///   fits two.
    /// - A segment or record error, such as [`BigfileError::SegmentLengthMismatch`] or
    ///   [`BigfileError::RecordOverrunsPart`], when the parts do not fit the FAT.
    ///
    /// When no byte order is given and both fail, the error is from the first one whose FAT
    /// parsed, or else from the first one tried.
    pub fn open_with_options<P: AsRef<Path>>(
        path: P,
        options: OpenOptions,
    ) -> Result<Self, BigfileError> {
        let parts = Self::discover_parts(path.as_ref(), options.single_part)?;
        let opening = Box::new(Opening::new(parts)?);
        let segment_length = options.segment_length;
        let open_as = |opening, endian| Self::open_as(opening, endian, segment_length);
        if let Some(endian) = options.endian {
            let mut bigfile = open_as(opening, endian)
                .map(|opened| opened.bigfile)
                .map_err(|failed| failed.error.into_error())?;
            bigfile.reject_ambiguous_segment_length(segment_length)?;
            return Ok(bigfile);
        }
        let Detected {
            value:
                Opened {
                    mut bigfile,
                    mut fat_bytes,
                },
            untried,
        } = Fat::try_auto_endian(opening.fat_bytes.header, opening, open_as)
            .map_err(EndianError::reported)?;
        if let Some(other) = untried {
            bigfile.reject_ambiguous(other, &mut fat_bytes, segment_length)?;
        }
        bigfile.reject_ambiguous_segment_length(segment_length)?;
        Ok(bigfile)
    }

    /// Opens the archive in `endian` byte order: parses the FAT, then validates the volume
    /// geometry under it, returning the archive with the FAT bytes read so far. On failure, hands
    /// `opening` back for the other byte order to try.
    fn open_as(
        mut opening: Box<Opening>,
        endian: Endian,
        segment_length_override: Option<u64>,
    ) -> Result<Opened, FailedAttempt<Box<Opening>, EndianError>> {
        let (part0, part0_size) = (&opening.parts.part_files[0], opening.parts.part_sizes[0]);
        let fat = match opening.fat_bytes.parse(part0, part0_size, endian) {
            Ok(fat) => fat,
            Err(err) => {
                return Err(FailedAttempt {
                    state: opening,
                    error: EndianError::Fat(err),
                });
            }
        };
        let Opening { parts, fat_bytes } = *opening;
        let mut bigfile = Self::from_parts(parts, fat);
        match bigfile.validate_volume_geometry(segment_length_override) {
            Ok(()) => Ok(Opened { bigfile, fat_bytes }),
            Err(err) => Err(FailedAttempt {
                state: Box::new(Opening {
                    parts: bigfile.into_parts(),
                    fat_bytes,
                }),
                error: EndianError::Geometry(err),
            }),
        }
    }

    /// Fails with [`BigfileError::AmbiguousEndian`] if the FAT is non-empty and the archive is
    /// also valid in the `other` byte order, parsing that FAT from `fat_bytes`. Leaves the current
    /// FAT and stride in place.
    fn reject_ambiguous(
        &mut self,
        other: Endian,
        fat_bytes: &mut FatBytes,
        segment_length_override: Option<u64>,
    ) -> Result<(), BigfileError> {
        if self.fat.is_empty() {
            return Ok(());
        }
        let Ok(other_fat) = fat_bytes.parse(&self.part_files[0], self.part_sizes[0], other) else {
            return Ok(());
        };
        let saved_fat = std::mem::replace(&mut self.fat, other_fat);
        let saved_stride = self.segment_length;
        let also_valid = self
            .validate_volume_geometry(segment_length_override)
            .is_ok();
        self.fat = saved_fat;
        self.segment_length = saved_stride;
        if also_valid {
            Err(BigfileError::AmbiguousEndian)
        } else {
            Ok(())
        }
    }

    /// An archive around `parts` with `fat`, before its volume geometry is validated.
    fn from_parts(parts: DiscoveredParts, fat: Fat) -> Self {
        Self {
            dir_path: parts.dir_path,
            stem: parts.stem,
            fat,
            segment_length: None,
            part_paths: parts.part_paths,
            part_files: parts.part_files,
            part_sizes: parts.part_sizes,
            part_ids: parts.part_ids,
        }
    }

    /// Gives back the parts of an archive whose volume geometry did not validate.
    fn into_parts(self) -> DiscoveredParts {
        DiscoveredParts {
            dir_path: self.dir_path,
            stem: self.stem,
            part_paths: self.part_paths,
            part_files: self.part_files,
            part_sizes: self.part_sizes,
            part_ids: self.part_ids,
        }
    }

    /// Directory containing the archive parts.
    #[inline]
    #[must_use]
    pub fn dir_path(&self) -> &Path {
        &self.dir_path
    }

    /// Stem name of the archive (e.g. `"bigfile"` or `"patch"`). Archives opened single-part from
    /// numbered files of one name, such as `patch.000` and `patch.001`, share a stem; their
    /// [`Self::part_paths`] tell them apart.
    #[inline]
    #[must_use]
    pub fn stem(&self) -> &str {
        &self.stem
    }

    /// Reference to the parsed [`Fat`].
    #[inline]
    #[must_use]
    pub fn fat(&self) -> &Fat {
        &self.fat
    }

    /// Detected or configured TOC byte order of the archive.
    #[inline]
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.fat.endian()
    }

    /// Slice of all [`Entry`] records in TOC order.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        self.fat.entries()
    }

    /// Returns an iterator yielding contiguous slices of entries sharing the same `name_hash`.
    #[inline]
    pub fn hash_runs(&self) -> impl Iterator<Item = &[Entry]> {
        self.fat.hash_runs()
    }

    /// Logical segment stride in bytes (`Some(stride)` for multi-part archives or when explicitly
    /// overridden; `None` for unsplit single-part archives).
    #[inline]
    #[must_use]
    pub fn segment_length(&self) -> Option<u64> {
        self.segment_length
    }

    /// Paths to each physical part file (`.000`, `.001`, ...).
    #[inline]
    #[must_use]
    pub fn part_paths(&self) -> &[PathBuf] {
        &self.part_paths
    }

    /// Physical byte size of each part file on disk.
    #[inline]
    #[must_use]
    pub fn part_sizes(&self) -> &[u64] {
        &self.part_sizes
    }

    /// Identity of each part file, taken when it was opened, so a destination can be checked
    /// against the files actually being read.
    #[cfg(feature = "unpack")]
    #[inline]
    #[must_use]
    pub(crate) fn part_ids(&self) -> &[FileId] {
        &self.part_ids
    }

    /// Returns the part holding `entry` and the byte offset within that part where its stored
    /// bytes start.
    ///
    /// The offset is not checked against the part's size. Opening the archive checked that each of
    /// its own entries fits its part, but an [`Entry`] from another archive can lie past the end.
    ///
    /// # Errors
    ///
    /// [`BigfileError::PartOutOfRange`] when `entry` would start past the last part.
    #[inline]
    pub fn locate(&self, entry: &Entry) -> Result<EntryLocation, BigfileError> {
        let logical = entry.logical_offset();
        let location = match self.segment_length {
            Some(stride) => EntryLocation {
                part_index: usize::try_from(logical / stride).unwrap_or(usize::MAX),
                offset_in_part: logical % stride,
            },
            None => EntryLocation {
                part_index: 0,
                offset_in_part: logical,
            },
        };

        if location.part_index >= self.part_paths.len() {
            return Err(BigfileError::PartOutOfRange {
                index: entry.index,
                name_hash: entry.name_hash,
                sector_number: entry.sector_number,
                part_index: location.part_index,
                part_count: self.part_paths.len(),
            });
        }

        Ok(location)
    }

    /// Returns the part holding `entry` and the byte range of its stored bytes in that part,
    /// verifying that the range lies within the part file.
    #[inline]
    fn stored_span(&self, entry: &Entry) -> Result<StoredSpan, BigfileError> {
        let EntryLocation {
            part_index,
            offset_in_part,
        } = self.locate(entry)?;
        let stored_size = entry.stored_size();
        let physical_size = self.part_sizes[part_index];
        let end = offset_in_part.saturating_add(u64::from(stored_size));
        if end > physical_size {
            return Err(BigfileError::RecordOverrunsPart {
                index: entry.index,
                name_hash: entry.name_hash,
                sector_number: entry.sector_number,
                part_index,
                part_path: self.part_paths[part_index].clone(),
                offset: offset_in_part,
                needed: stored_size,
                physical_size,
            });
        }
        Ok(StoredSpan {
            part_index,
            range: offset_in_part..end,
        })
    }

    /// Streams `entry`'s payload into `out` through the caller's reusable `chunk` buffer (at most
    /// 1 MiB), returning the number of bytes written.
    ///
    /// When `raw` is `true` or `entry` is uncompressed, copies the stored bytes; otherwise inflates
    /// them with zlib.
    ///
    /// # Errors
    ///
    /// Fails like [`Self::read_entry`], and with [`BigfileError::Write`] when `out` rejects bytes.
    /// On error, `out` may already hold part of the payload.
    pub fn read_entry_into<W: Write>(
        &self,
        entry: &Entry,
        raw: bool,
        chunk: &mut Vec<u8>,
        out: &mut W,
    ) -> Result<u64, BigfileError> {
        self.open_entry(entry, raw)?.copy_to(chunk, out)
    }

    /// Reads `entry`'s payload (raw when `raw == true`, or zlib-inflated when `raw == false`)
    /// straight into a new buffer.
    ///
    /// Inflating can allocate up to the size the TOC declares, as much as 4 GiB, so check
    /// `entry.size` first when the archive is untrusted, or stream with [`Self::open_entry`] or
    /// [`Self::read_entry_into`].
    ///
    /// # Errors
    ///
    /// Fails like [`Self::open_entry`], with [`BigfileError::Io`] when a part file read fails,
    /// and with [`BigfileError::DecompressError`] or [`BigfileError::DecompressedSizeMismatch`]
    /// when a zlib stream is corrupt or inflates to a size other than `entry.size`.
    pub fn read_entry(&self, entry: &Entry, raw: bool) -> Result<Vec<u8>, BigfileError> {
        self.open_entry(entry, raw)?.read_to_vec()
    }

    /// Opens `entry`'s payload as a stream that reads it from its part file as it goes: the
    /// stored bytes when `raw` is `true` or `entry` is uncompressed, zlib-inflated otherwise.
    ///
    /// The returned [`EntryReader`] checks the payload while it is read: a read fails where the
    /// part file ends early or the zlib stream is corrupt, and reaching the end of an inflated
    /// payload that is short or overlong fails.
    ///
    /// # Errors
    ///
    /// [`BigfileError::PartOutOfRange`] or [`BigfileError::RecordOverrunsPart`] when `entry` lies
    /// outside the archive's parts.
    pub fn open_entry(&self, entry: &Entry, raw: bool) -> Result<EntryReader<'_>, BigfileError> {
        let stored = self.stored_reader(entry, 0)?;
        Ok(EntryReader::new(*entry, raw, stored))
    }

    /// Opens `entry`'s stored bytes from `offset` to their end as a stream, never inflating them.
    /// `offset` counts stored bytes, so for a compressed entry it is a position in its zlib
    /// stream.
    ///
    /// Bytes from the middle of a zlib stream cannot be inflated on their own, so to read a
    /// compressed entry's content (see [`Entry::is_compressed`]), use [`Self::open_entry`] or
    /// [`Self::read_entry`], which inflate from the start. Starting at an offset suits
    /// uncompressed entries, whose stored bytes are their content, and raw copies of compressed
    /// ones.
    ///
    /// Readers keep no shared cursor, so several readers of one entry, on one thread or many,
    /// can each start where they need. `offset == entry.stored_size()` opens an empty reader. A
    /// read fails like one from [`Self::open_entry`] where the part file ends early.
    ///
    /// # Errors
    ///
    /// [`BigfileError::PartOutOfRange`] or [`BigfileError::RecordOverrunsPart`] when `entry` lies
    /// outside the archive's parts, and [`BigfileError::OffsetPastEntryEnd`] when `offset` is
    /// past `entry.stored_size()`.
    pub fn open_entry_at(
        &self,
        entry: &Entry,
        offset: u64,
    ) -> Result<EntryReader<'_>, BigfileError> {
        let stored = self.stored_reader(entry, offset)?;
        Ok(EntryReader::new(*entry, true, stored))
    }

    /// Reader over `entry`'s stored bytes from `offset` within them to their end.
    fn stored_reader(
        &self,
        entry: &Entry,
        offset: u64,
    ) -> Result<PositionalFileReader<'_>, BigfileError> {
        let StoredSpan { part_index, range } = self.stored_span(entry)?;
        let start = range
            .start
            .checked_add(offset)
            .filter(|&start| start <= range.end)
            .ok_or(BigfileError::OffsetPastEntryEnd {
                index: entry.index,
                name_hash: entry.name_hash,
                offset,
                stored_size: entry.stored_size(),
            })?;
        Ok(PositionalFileReader::new(
            &self.part_files[part_index],
            start,
            range.end,
        ))
    }

    /// Returns all entries matching `name_hash` (all specialisation variants).
    #[inline]
    #[must_use]
    pub fn find(&self, name_hash: u32) -> &[Entry] {
        self.fat.find_all(name_hash)
    }

    /// Finds the entry selected by the game engine's lookup order within this archive for
    /// `name_hash` and `spec_mask` (see [`Fat::find_with_spec_mask`]).
    #[inline]
    #[must_use]
    pub fn find_with_spec_mask(&self, name_hash: u32, spec_mask: u32) -> Option<&Entry> {
        self.fat.find_with_spec_mask(name_hash, spec_mask)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::format::{BLOCK_BYTE_COUNT, FAT_ENTRY_BYTES, SECTOR_BYTE_COUNT};
    use crate::test_support::{
        ArchiveRecord, FatRow, TempDir, assert_source_not_in_message, build_ambiguous_part0,
        build_part0_bytes, write_archive, write_one_empty_record, write_one_record_archives,
        write_part0, write_two_part_archive, write_two_segment_length_archive,
    };

    #[test]
    fn messages_leave_the_wrapped_error_to_source() {
        let cause = || io::Error::other("disk on fire");
        let path = PathBuf::from("bigfile.000");
        for err in [
            BigfileError::Io(cause()),
            BigfileError::ArchiveDirectory {
                path: path.clone(),
                source: cause(),
            },
            BigfileError::PartOpen {
                path: path.clone(),
                source: cause(),
            },
            BigfileError::Write(cause()),
            BigfileError::OutputPath {
                path: path.clone(),
                source: cause(),
            },
            BigfileError::DecompressError {
                index: 1,
                name_hash: 0x5FF9_1900,
                source: cause(),
            },
        ] {
            assert_source_not_in_message::<io::Error>(&err);
        }
    }

    #[cfg(not(feature = "unpack"))]
    #[test]
    fn part_identities_are_not_captured_without_unpack() {
        let dir = TempDir::new("no_part_ids");
        write_one_empty_record(dir.join("bigfile.000"));
        let bf = Bigfile::open(dir.join("bigfile.000")).unwrap();
        assert!(bf.part_ids.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn open_part_cannot_be_renamed() {
        let dir = TempDir::new("part_no_rename");
        write_one_empty_record(dir.join("bigfile.000"));
        let _bf = Bigfile::open(dir.join("bigfile.000")).unwrap();
        assert!(fs::rename(dir.join("bigfile.000"), dir.join("moved.000")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn open_part_cannot_be_opened_for_writing() {
        let dir = TempDir::new("part_no_write");
        write_one_empty_record(dir.join("bigfile.000"));
        let _bf = Bigfile::open(dir.join("bigfile.000")).unwrap();
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("bigfile.000"));
        assert!(writer.is_err());
    }

    #[test]
    fn open_finds_numbered_parts_named_in_another_case() {
        let dir = TempDir::new("part_case");
        write_one_empty_record(dir.join("BIGFILE.000"));
        let bf = Bigfile::open(dir.join("bigfile.000")).unwrap();
        assert_eq!(bf.part_paths(), [dir.join("BIGFILE.000")]);
    }

    const SINGLE_PART: OpenOptions = OpenOptions {
        segment_length: None,
        endian: None,
        single_part: true,
    };

    /// Writes each `(file name, hash)` under a new directory as a separate one-record archive.
    fn create_one_record_archives(prefix: &str, archives: &[(&str, u32)]) -> TempDir {
        let dir = TempDir::new(prefix);
        write_one_record_archives(&dir, archives);
        dir
    }

    /// Writes `patch.000` and `patch.001` as two separate archives holding `0x1000` and `0x2000`.
    fn create_separate_numbered_archives(prefix: &str) -> TempDir {
        create_one_record_archives(prefix, &[("patch.000", 0x1000), ("patch.001", 0x2000)])
    }

    #[test]
    fn single_part_opens_a_later_numbered_file_as_its_own_archive() {
        let dir = create_separate_numbered_archives("single_later");
        let bf = Bigfile::open_with_options(dir.join("patch.001"), SINGLE_PART).unwrap();
        assert_eq!(bf.part_paths(), [dir.join("patch.001")]);
        assert_eq!(bf.entries()[0].name_hash, 0x2000);
    }

    #[test]
    fn single_part_ignores_numbered_siblings() {
        let dir = create_separate_numbered_archives("single_first");
        let bf = Bigfile::open_with_options(dir.join("patch.000"), SINGLE_PART).unwrap();
        assert_eq!(bf.part_paths(), [dir.join("patch.000")]);
    }

    #[test]
    fn single_part_opens_a_dat_file_as_named() {
        let archives = [("bigfile.000", 0x1000), ("bigfile.dat", 0x2000)];
        let dir = create_one_record_archives("single_dat", &archives);
        let bf = Bigfile::open_with_options(dir.join("bigfile.dat"), SINGLE_PART).unwrap();
        assert_eq!(bf.entries()[0].name_hash, 0x2000);
    }

    #[test]
    fn single_part_finds_a_file_named_in_another_case() {
        let dir = create_one_record_archives("single_case", &[("PATCH.001", 0x2000)]);
        let bf = Bigfile::open_with_options(dir.join("patch.001"), SINGLE_PART).unwrap();
        assert_eq!(bf.part_paths(), [dir.join("PATCH.001")]);
    }

    #[test]
    fn single_part_rejects_a_missing_file() {
        let dir = create_separate_numbered_archives("single_missing");
        let err = Bigfile::open_with_options(dir.join("patch.002"), SINGLE_PART).unwrap_err();
        assert!(matches!(err, BigfileError::NoPartsFound(_)));
    }

    #[test]
    fn single_part_rejects_a_directory() {
        let dir = create_separate_numbered_archives("single_dir");
        let err = Bigfile::open_with_options(&dir, SINGLE_PART).unwrap_err();
        assert!(matches!(err, BigfileError::NoPartsFound(_)));
    }

    #[test]
    fn open_rejects_empty_directory() {
        let dir = TempDir::new("empty_dir");
        assert!(matches!(
            Bigfile::open(&dir).unwrap_err(),
            BigfileError::NoPartsFound(_)
        ));
    }

    #[test]
    fn open_rejects_unaligned_segment_length() {
        let dir = TempDir::new("unaligned_err");
        write_one_empty_record(dir.join("bigfile.000"));

        for bad_stride in [0u64, 2048, u64::from(BLOCK_BYTE_COUNT) + 2048] {
            let err = Bigfile::open_with_options(
                &dir,
                OpenOptions {
                    segment_length: Some(bad_stride),
                    endian: None,
                    single_part: false,
                },
            )
            .unwrap_err();
            assert!(matches!(
                err,
                BigfileError::UnalignedSegmentLength { segment_length, .. } if segment_length == bad_stride
            ));
        }
    }

    /// Writes to `dir` a two-part archive split every 2 MiB whose 1 MiB part 0 ends with an
    /// empty record, so counting that record would take 1 MiB as the segment length.
    fn write_empty_record_at_part0_end(dir: &Path) {
        let part0_sectors = 512;
        let records = [
            FatRow {
                name_hash: 1,
                size: 16,
                sector_number: 1,
                spec_flags: 1,
                deflated_size: 0,
            },
            FatRow {
                name_hash: 2,
                size: 0,
                sector_number: part0_sectors,
                spec_flags: 1,
                deflated_size: 0,
            },
            FatRow {
                name_hash: 3,
                size: 16,
                sector_number: 2 * part0_sectors,
                spec_flags: 1,
                deflated_size: 0,
            },
        ];
        write_part0(
            dir.join("bigfile.000"),
            Endian::Little,
            part0_sectors,
            &records,
            &[],
        );
        fs::write(dir.join("bigfile.001"), [0u8; 16]).unwrap();
    }

    #[test]
    fn open_ignores_an_empty_record_at_part0_end() {
        let dir = TempDir::new("empty_at_part0_end");
        write_empty_record_at_part0_end(&dir);

        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(bf.segment_length(), Some(2 * u64::from(BLOCK_BYTE_COUNT)));
    }

    #[test]
    fn explicit_segment_length_opens_when_an_empty_record_ends_part0() {
        let dir = TempDir::new("empty_at_part0_end_override");
        write_empty_record_at_part0_end(&dir);
        let stride = 2 * u64::from(BLOCK_BYTE_COUNT);

        let options = OpenOptions {
            segment_length: Some(stride),
            endian: None,
            single_part: false,
        };
        let bf = Bigfile::open_with_options(&dir, options).unwrap();
        assert_eq!(bf.segment_length(), Some(stride));
    }

    #[test]
    fn explicit_segment_length_the_records_do_not_fit_is_rejected() {
        let dir = TempDir::new("override_does_not_fit");
        write_empty_record_at_part0_end(&dir);
        let block = u64::from(BLOCK_BYTE_COUNT);

        let options = OpenOptions {
            segment_length: Some(block),
            endian: None,
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, options).unwrap_err();
        assert!(matches!(
            err,
            BigfileError::SegmentLengthMismatch { override_length, detected_length }
                if override_length == block && detected_length == 2 * block
        ));
    }

    #[test]
    fn open_refuses_an_archive_that_fits_two_segment_lengths() {
        let dir = TempDir::new("two_segment_lengths");
        write_two_segment_length_archive(&dir);
        let block = u64::from(BLOCK_BYTE_COUNT);

        let err = Bigfile::open(&dir).unwrap_err();

        assert!(
            matches!(
                err,
                BigfileError::AmbiguousSegmentLength { detected_length, other_length }
                    if detected_length == 3 * block && other_length == 2 * block
            ),
            "{err:?}"
        );
    }

    #[test]
    fn explicit_byte_order_still_refuses_an_archive_that_fits_two_segment_lengths() {
        let dir = TempDir::new("two_segment_lengths_endian");
        write_two_segment_length_archive(&dir);

        let options = OpenOptions {
            segment_length: None,
            endian: Some(Endian::Little),
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, options).unwrap_err();

        assert!(
            matches!(err, BigfileError::AmbiguousSegmentLength { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn explicit_segment_length_that_fits_neither_of_two_is_not_blamed_on_either() {
        let dir = TempDir::new("two_segment_lengths_misfit");
        write_two_segment_length_archive(&dir);

        let options = OpenOptions {
            segment_length: Some(u64::from(BLOCK_BYTE_COUNT)),
            endian: None,
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, options).unwrap_err();

        assert!(
            matches!(
                err,
                BigfileError::PartExceedsSegmentLength { part_index: 0, .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn explicit_segment_length_chooses_between_two_that_fit() {
        let dir = TempDir::new("two_segment_lengths_override");
        write_two_segment_length_archive(&dir);
        let stride = 2 * u64::from(BLOCK_BYTE_COUNT);

        let options = OpenOptions {
            segment_length: Some(stride),
            endian: None,
            single_part: false,
        };
        let bf = Bigfile::open_with_options(&dir, options).unwrap();

        assert_eq!(bf.segment_length(), Some(stride));
    }

    /// Writes to `dir` a two-part archive split every 2 MiB whose part 1 starts with an empty
    /// record and holds its first data one sector later, so the smallest data offset past part 0
    /// is not block-aligned.
    fn write_part1_starting_with_empty_record(dir: &Path) {
        let part0_sectors = 512;
        let records = [
            FatRow {
                name_hash: 1,
                size: 16,
                sector_number: 1,
                spec_flags: 1,
                deflated_size: 0,
            },
            FatRow {
                name_hash: 2,
                size: 0,
                sector_number: 2 * part0_sectors,
                spec_flags: 1,
                deflated_size: 0,
            },
            FatRow {
                name_hash: 3,
                size: 16,
                sector_number: 2 * part0_sectors + 1,
                spec_flags: 1,
                deflated_size: 0,
            },
        ];
        write_part0(
            dir.join("bigfile.000"),
            Endian::Little,
            part0_sectors,
            &records,
            &[],
        );
        fs::write(
            dir.join("bigfile.001"),
            vec![0u8; SECTOR_BYTE_COUNT as usize + 16],
        )
        .unwrap();
    }

    #[test]
    fn open_rejects_an_unaligned_first_data_offset() {
        let dir = TempDir::new("unaligned_first_data");
        write_part1_starting_with_empty_record(&dir);

        assert!(matches!(
            Bigfile::open(&dir).unwrap_err(),
            BigfileError::UnalignedSegmentLength { .. }
        ));
    }

    #[test]
    fn explicit_segment_length_reports_its_own_error_when_the_detected_one_does_not_fit() {
        let dir = TempDir::new("override_and_detected_misfit");
        write_part1_starting_with_empty_record(&dir);
        let block = u64::from(BLOCK_BYTE_COUNT);

        let options = OpenOptions {
            segment_length: Some(block),
            endian: None,
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, options).unwrap_err();

        assert!(
            matches!(
                err,
                BigfileError::MissingPartStartEntry {
                    part_index: 1,
                    expected_sector: 512,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn explicit_segment_length_that_fits_overrides_the_detected_one() {
        let dir = TempDir::new("override_fits");
        write_part1_starting_with_empty_record(&dir);
        let stride = 2 * u64::from(BLOCK_BYTE_COUNT);

        let options = OpenOptions {
            segment_length: Some(stride),
            endian: None,
            single_part: false,
        };
        let bf = Bigfile::open_with_options(&dir, options).unwrap();
        assert_eq!(bf.segment_length(), Some(stride));
    }

    #[test]
    fn open_validates_multipart_segment_start_invariants() {
        let dir = TempDir::new("multipart_err");
        write_one_empty_record(dir.join("bigfile.000"));
        fs::write(
            dir.join("bigfile.001"),
            vec![0u8; SECTOR_BYTE_COUNT as usize],
        )
        .unwrap();

        assert!(matches!(
            Bigfile::open(&dir).unwrap_err(),
            BigfileError::UndeterminedSegmentLength { part_count: 2 }
        ));
        assert!(matches!(
            Bigfile::open_with_options(
                &dir,
                OpenOptions {
                    segment_length: Some(u64::from(BLOCK_BYTE_COUNT)),
                    endian: None,
                    single_part: false,
                },
            )
            .unwrap_err(),
            BigfileError::MissingPartStartEntry {
                part_index: 1,
                expected_sector: 512,
                ..
            }
        ));
    }

    #[test]
    fn entry_locations_sort_in_disk_order() {
        let at = |part_index, offset_in_part| EntryLocation {
            part_index,
            offset_in_part,
        };
        let mut locations = [at(1, 0), at(0, 4096), at(0, 2048)];
        locations.sort();
        assert_eq!(locations, [at(0, 2048), at(0, 4096), at(1, 0)]);
    }

    #[test]
    fn locates_record_at_the_start_of_a_later_part() {
        let dir = TempDir::new("two_part_locate");
        let part0 = [ArchiveRecord::stored(0x1, 1, b"in part 0")];
        let part1 = [ArchiveRecord::stored(0x2, 1, b"in part 1")];
        write_two_part_archive(&dir, &part0, &part1);
        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(
            bf.locate(&bf.find(0x2)[0]).unwrap(),
            EntryLocation {
                part_index: 1,
                offset_in_part: 0
            }
        );
    }

    #[test]
    fn open_rejects_entry_referencing_nonexistent_part() {
        let dir = TempDir::new("part_oob");
        write_part0(
            dir.join("bigfile.000"),
            Endian::Little,
            2,
            &[FatRow {
                name_hash: 0x5FF9_1900,
                size: 0,
                sector_number: 512,
                spec_flags: 1,
                deflated_size: 0,
            }],
            &[],
        );

        let err = Bigfile::open_with_options(
            &dir,
            OpenOptions {
                segment_length: Some(u64::from(BLOCK_BYTE_COUNT)),
                endian: None,
                single_part: false,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BigfileError::PartOutOfRange {
                index: 0,
                part_index: 1,
                part_count: 1,
                ..
            }
        ));
    }

    /// Writes a two-sector `BIGFILE.DAT` holding one empty record at sector 1.
    fn create_monolithic_dat(prefix: &str) -> TempDir {
        let dir = TempDir::new(prefix);
        write_one_empty_record(dir.join("BIGFILE.DAT"));
        dir
    }

    #[test]
    fn opens_monolithic_dat_fallback() {
        let dir = create_monolithic_dat("monolithic_dat");

        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(bf.stem().to_ascii_lowercase(), "bigfile");
        assert_eq!(bf.endian(), Endian::Little);
        assert_eq!(bf.fat().len(), 1);
        assert_eq!(bf.part_sizes(), &[u64::from(SECTOR_BYTE_COUNT * 2)]);

        let matches = bf.find(0x5FF9_1900);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            bf.locate(&matches[0]).unwrap(),
            EntryLocation {
                part_index: 0,
                offset_in_part: u64::from(SECTOR_BYTE_COUNT)
            }
        );
        assert!(bf.read_entry(&matches[0], false).unwrap().is_empty());
    }

    /// An empty record at sector 10, past the end of the two-sector archive
    /// [`create_monolithic_dat`] writes.
    const RECORD_PAST_END: Entry = Entry {
        index: 99,
        name_hash: 0xDEAD_BEEF,
        size: 0,
        sector_number: 10,
        spec_flags: 1,
        deflated_size: 0,
    };

    fn is_record_past_end_overrun(err: &BigfileError) -> bool {
        matches!(
            err,
            BigfileError::RecordOverrunsPart {
                index: 99,
                needed: 0,
                ..
            }
        )
    }

    #[test]
    fn read_entry_rejects_record_past_the_end_of_its_part() {
        let dir = create_monolithic_dat("record_past_end");
        let bf = Bigfile::open(&dir).unwrap();
        let err = bf.read_entry(&RECORD_PAST_END, true).unwrap_err();
        assert!(is_record_past_end_overrun(&err), "{err:?}");
    }

    #[test]
    fn open_entry_at_reports_record_overrun_before_offset() {
        let dir = create_monolithic_dat("at_record_past_end");
        let bf = Bigfile::open(&dir).unwrap();
        let err = bf.open_entry_at(&RECORD_PAST_END, 1).unwrap_err();
        assert!(is_record_past_end_overrun(&err), "{err:?}");
    }

    const BIG_ENDIAN_PAYLOAD: &[u8] = b"big-endian PS3/X360 payload";

    /// Writes a single-part big-endian archive holding [`BIG_ENDIAN_PAYLOAD`] at sector 1.
    fn create_big_endian_archive(prefix: &str) -> TempDir {
        let dir = TempDir::new(prefix);
        let record = ArchiveRecord::stored(0x5FF9_1900, 0xFFFF_F7E1, BIG_ENDIAN_PAYLOAD);
        write_archive(dir.join("bigfile.000"), Endian::Big, &[record]);
        dir
    }

    #[test]
    fn auto_detects_big_endian_archive() {
        let dir = create_big_endian_archive("big_endian_auto");
        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(bf.endian(), Endian::Big);
        assert_eq!(
            bf.read_entry(&bf.entries()[0], false).unwrap(),
            BIG_ENDIAN_PAYLOAD
        );
    }

    #[test]
    fn opens_big_endian_archive_with_explicit_endian() {
        let dir = create_big_endian_archive("big_endian_explicit");
        let be_opts = OpenOptions {
            segment_length: None,
            endian: Some(Endian::Big),
            single_part: false,
        };
        let bf = Bigfile::open_with_options(&dir, be_opts).unwrap();
        assert_eq!(bf.endian(), Endian::Big);
    }

    #[test]
    fn explicit_little_endian_rejects_big_endian_archive() {
        let dir = create_big_endian_archive("big_endian_as_le");
        let le_opts = OpenOptions {
            segment_length: None,
            endian: Some(Endian::Little),
            single_part: false,
        };
        let err = Bigfile::open_with_options(&dir, le_opts).unwrap_err();
        assert!(matches!(
            err,
            BigfileError::Fat(FatError::Truncated {
                count: 0x0100_0000,
                ..
            })
        ));
    }

    #[test]
    fn falls_back_to_opposite_endian_when_volume_geometry_fails() {
        let dir = TempDir::new("tier3_endian_fallback");
        let records: Vec<_> = (0..0x0001_0000u32)
            .map(|i| {
                let hash = if i < 256 { 0 } else { 0x0000_0100 };
                FatRow {
                    name_hash: hash,
                    size: 0,
                    sector_number: 645,
                    spec_flags: 1,
                    deflated_size: 0,
                }
            })
            .collect();
        write_part0(dir.join("bigfile.000"), Endian::Big, 650, &records, &[]);

        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(bf.endian(), Endian::Big);
        assert_eq!(bf.entries().len(), 0x0001_0000);
    }

    /// An error carrying `path`, so [`EndianError::reported`] tests can tell which one it chose.
    fn named(path: &str) -> BigfileError {
        BigfileError::NoPartsFound(PathBuf::from(path))
    }

    fn names(err: &BigfileError, path: &str) -> bool {
        matches!(err, BigfileError::NoPartsFound(p) if p == Path::new(path))
    }

    #[test]
    fn reports_other_geometry_error_over_a_preferred_fat_error() {
        let err = EndianError::reported(BothFailed {
            preferred: EndianError::Fat(named("preferred")),
            other: EndianError::Geometry(named("other")),
        });
        assert!(names(&err, "other"));
    }

    #[test]
    fn reports_preferred_geometry_error_over_the_other_one() {
        let err = EndianError::reported(BothFailed {
            preferred: EndianError::Geometry(named("preferred")),
            other: EndianError::Geometry(named("other")),
        });
        assert!(names(&err, "preferred"));
    }

    #[test]
    fn reports_preferred_geometry_error_over_an_other_fat_error() {
        let err = EndianError::reported(BothFailed {
            preferred: EndianError::Geometry(named("preferred")),
            other: EndianError::Fat(named("other")),
        });
        assert!(names(&err, "preferred"));
    }

    #[test]
    fn reports_preferred_fat_error_when_both_fats_fail() {
        let err = EndianError::reported(BothFailed {
            preferred: EndianError::Fat(named("preferred")),
            other: EndianError::Fat(named("other")),
        });
        assert!(names(&err, "preferred"));
    }

    #[test]
    fn rejects_ambiguous_endian_without_explicit_override() {
        let dir = TempDir::new("ambiguous_endian");
        fs::write(dir.join("bigfile.000"), build_ambiguous_part0()).unwrap();

        assert!(matches!(
            Bigfile::open(&dir).unwrap_err(),
            BigfileError::AmbiguousEndian
        ));
        for endian in [Endian::Little, Endian::Big] {
            let opts = OpenOptions {
                segment_length: None,
                endian: Some(endian),
                single_part: false,
            };
            let bf = Bigfile::open_with_options(&dir, opts).unwrap();
            assert_eq!(bf.endian(), endian);
        }
    }

    /// A big-endian FAT of 65,536 distinct records, whose count reads as 256 in little-endian, so
    /// a little-endian attempt reads the start of the body before the big-endian one.
    #[test]
    fn fat_bytes_reads_only_the_missing_tail_for_the_second_byte_order() {
        let dir = TempDir::new("fat_bytes_tail");
        let records: Vec<_> = (0..0x0001_0000u32)
            .map(|i| FatRow {
                name_hash: i,
                size: i,
                sector_number: 0,
                spec_flags: 1,
                deflated_size: 0,
            })
            .collect();
        let path = dir.join("bigfile.000");
        fs::write(&path, build_part0_bytes(Endian::Big, 0, &records, &[])).unwrap();
        let file = File::open(&path).unwrap();
        let size = file.metadata().unwrap().len();

        let mut fat_bytes = FatBytes::read_header(&file, size).unwrap();
        let _ = fat_bytes.parse(&file, size, Endian::Little);
        assert_eq!(fat_bytes.body.len(), 256 * FAT_ENTRY_BYTES);
        let cached = fat_bytes.parse(&file, size, Endian::Big).unwrap();

        let mut fresh_reader = File::open(&path).unwrap();
        let fresh = Fat::parse_bounded(&mut fresh_reader, Some(size), Some(Endian::Big)).unwrap();
        assert_eq!(cached.entries(), fresh.entries());
    }
}
