//! Stdout error tagging, JSON report types and stderr status messages.

use std::borrow::Cow;
use std::io::{self, Write};

use lau_bigfun::HexLabel;
use serde::{Serialize, Serializer};
use thiserror::Error;

/// Error wrapper tagging I/O failures originating from `stdout` writes or flushes.
#[derive(Debug, Error)]
#[error("failed to write to stdout: {0}")]
pub(crate) struct StdoutError(#[from] pub(crate) io::Error);

impl StdoutError {
    #[inline]
    pub(crate) fn is_broken_pipe(&self) -> bool {
        self.0.kind() == io::ErrorKind::BrokenPipe
    }
}

/// Checks whether a boxed CLI error is a `BrokenPipe` originating from `stdout`.
pub(crate) fn is_stdout_broken_pipe(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<StdoutError>()
        .is_some_and(StdoutError::is_broken_pipe)
}

pub(crate) const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Text,
    Json { pretty: bool },
}

#[derive(Clone, Copy)]
pub(crate) struct HexU32(pub(crate) u32);

impl std::fmt::Display for HexU32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        HexLabel::new(self.0).fmt(f)
    }
}

impl Serialize for HexU32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

pub(crate) fn write_json_stdout<W: Write, T: Serialize + ?Sized>(
    out: &mut W,
    pretty: bool,
    value: &T,
) -> Result<(), StdoutError> {
    let res = if pretty {
        serde_json::to_writer_pretty(&mut *out, value)
    } else {
        serde_json::to_writer(&mut *out, value)
    };
    res.map_err(|e| {
        StdoutError(io::Error::new(
            e.io_error_kind().unwrap_or(io::ErrorKind::Other),
            e,
        ))
    })?;
    writeln!(out).map_err(StdoutError)?;
    out.flush().map_err(StdoutError)
}

/// Writes `entries` to `out` as one [`EntriesJsonReport`] (carrying `total_matching` when given),
/// or as one text line each through `write_line`, failing at the first entry that is an error.
pub(crate) fn write_entries<W, T, E>(
    out: &mut W,
    mode: OutputMode,
    total_matching: Option<usize>,
    entries: impl Iterator<Item = Result<T, E>>,
    mut write_line: impl FnMut(&mut W, &T) -> io::Result<()>,
) -> Result<(), Box<dyn std::error::Error>>
where
    W: Write,
    T: Serialize,
    E: Into<Box<dyn std::error::Error>>,
{
    match mode {
        OutputMode::Json { pretty } => {
            let entries = entries.collect::<Result<Vec<T>, E>>().map_err(Into::into)?;
            let report = EntriesJsonReport {
                schema: JSON_SCHEMA_VERSION,
                total_matching,
                entries,
            };
            write_json_stdout(out, pretty, &report)?;
        }
        OutputMode::Text => {
            for entry in entries {
                write_line(out, &entry.map_err(Into::into)?).map_err(StdoutError)?;
            }
            out.flush().map_err(StdoutError)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
pub(crate) struct PartJson<'a> {
    pub(crate) index: usize,
    pub(crate) path: Cow<'a, str>,
    pub(crate) size: u64,
}

#[derive(Serialize)]
pub(crate) struct SkuCountJson {
    pub(crate) sku_flags: HexU32,
    pub(crate) count: usize,
}

#[derive(Serialize)]
pub(crate) struct InfoJsonReport<'a> {
    pub(crate) schema: u32,
    pub(crate) archive: Cow<'a, str>,
    pub(crate) stem: &'a str,
    pub(crate) endian: &'static str,
    pub(crate) segment_length: Option<u64>,
    pub(crate) parts: Vec<PartJson<'a>>,
    pub(crate) total_entries: usize,
    pub(crate) unique_hashes: usize,
    pub(crate) resolved_hashes: usize,
    pub(crate) resolved_percentage: f64,
    pub(crate) compressed_entries: usize,
    pub(crate) total_stored_bytes: u64,
    pub(crate) total_logical_bytes: u64,
    pub(crate) sku_counts: Vec<SkuCountJson>,
}

#[derive(Serialize)]
pub(crate) struct EntriesJsonReport<T> {
    pub(crate) schema: u32,
    /// Entries that matched before `--limit` applied, for `list`; more than `entries` holds
    /// when the limit hid some.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) total_matching: Option<usize>,
    pub(crate) entries: Vec<T>,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct ListEntryRecord<'a> {
    pub(crate) index: usize,
    pub(crate) name_hash: HexU32,
    pub(crate) name: Option<&'a str>,
    pub(crate) size: u32,
    pub(crate) stored_size: u32,
    pub(crate) deflated_size: i32,
    pub(crate) compressed: bool,
    pub(crate) sector_number: u32,
    pub(crate) part_index: usize,
    pub(crate) offset_in_part: u64,
    pub(crate) sku_flags: HexU32,
}

#[derive(Serialize)]
pub(crate) struct ExtractJsonReport<'a> {
    pub(crate) schema: u32,
    pub(crate) index: usize,
    pub(crate) name_hash: HexU32,
    pub(crate) name: Option<&'a str>,
    pub(crate) sku_flags: HexU32,
    pub(crate) sku_mask: Option<HexU32>,
    pub(crate) variant: usize,
    pub(crate) variant_count: usize,
    pub(crate) raw: bool,
    pub(crate) bytes_written: u64,
    pub(crate) output: Cow<'a, str>,
}

#[derive(Serialize)]
pub(crate) struct UnpackJsonReport<'a> {
    pub(crate) schema: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) dry_run: bool,
    pub(crate) output: Cow<'a, str>,
    pub(crate) extracted_files: usize,
    pub(crate) extracted_bytes: u64,
    pub(crate) resolved_entries: usize,
    pub(crate) unknown_entries: usize,
    pub(crate) skipped_entries: usize,
}

#[derive(Serialize)]
pub(crate) struct HashEntryRecord<'a> {
    pub(crate) name: &'a str,
    pub(crate) name_hash: HexU32,
}

/// Operational status reporter that writes human-readable status messages to `stderr`
/// unless `--quiet` is active.
pub(crate) struct StatusReporter<W> {
    pub(crate) writer: W,
    pub(crate) quiet: bool,
}

impl<W: Write> StatusReporter<W> {
    #[inline]
    pub(crate) const fn new(writer: W, quiet: bool) -> Self {
        Self { writer, quiet }
    }

    pub(crate) fn println(&mut self, args: std::fmt::Arguments<'_>) {
        if !self.quiet {
            let _ = writeln!(self.writer, "{args}");
        }
    }
}
