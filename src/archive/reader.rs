//! Positional part-file reads and the streaming of stored or zlib-inflated entry payloads.

use std::fs::File;
use std::io::{self, Read, Take, Write};

use flate2::read::ZlibDecoder;

use super::BigfileError;
use crate::fat::{Entry, MAX_UNTRUSTED_RESERVATION};

/// Maximum bytes moved per read/write step when streaming an entry (1 MiB). Bounds each caller's
/// reusable chunk buffer regardless of entry size or a corrupt `entry.size` header, while keeping
/// reads and writes long enough to stay sequential.
const STREAM_CHUNK_BYTES: usize = 1024 * 1024;

/// Maximum input buffer (1 MiB) for reading a compressed payload from its part file, so the
/// zlib decoder reads stored bytes in long sequential steps instead of its 32 KiB default.
const COMPRESSED_READ_BYTES: usize = 1024 * 1024;

/// Reads `buf.len()` bytes at `offset` of `file` with a positional read (`pread64` on Unix,
/// `seek_read` on Windows), so concurrent readers of one handle never depend on its cursor.
#[cfg(unix)]
fn read_exact_at_os(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at_os(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// A cloned handle shares its file cursor, so seek-then-read would race between unpack workers.
#[cfg(not(any(unix, windows)))]
compile_error!("lau-bigfun needs positional file reads, which it implements for Unix and Windows");

/// Positional [`Read`] adapter over the byte range `start..end` of a [`File`] that reads through
/// [`read_exact_at_os`], so it never depends on the file cursor. (On Windows, `seek_read` still
/// moves the cursor; nothing reads it.)
///
/// It yields exactly `end - start` bytes or an error: a part file that ends early fails the read
/// with [`io::ErrorKind::UnexpectedEof`] rather than ending the range.
#[derive(Debug)]
pub(super) struct PositionalFileReader<'a> {
    file: &'a File,
    offset: u64,
    end: u64,
}

impl<'a> PositionalFileReader<'a> {
    #[inline]
    pub(super) const fn new(file: &'a File, start: u64, end: u64) -> Self {
        Self {
            file,
            offset: start,
            end,
        }
    }

    /// Bytes left in the range.
    #[inline]
    #[must_use]
    const fn remaining(&self) -> u64 {
        self.end.saturating_sub(self.offset)
    }
}

impl Read for PositionalFileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining();
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let to_read = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        read_exact_at_os(self.file, &mut buf[..to_read], self.offset)?;
        self.offset += to_read as u64;
        Ok(to_read)
    }
}

/// [`Read`] adapter that records whether its last read from the wrapped reader failed.
/// [`ZlibDecoder`] passes the wrapped reader's errors on unchanged, so this tells a part-file read
/// failure apart from a decompression error raised by the decoder itself.
#[derive(Debug)]
struct FlagReadError<R> {
    inner: R,
    failed: bool,
}

impl<R> FlagReadError<R> {
    #[inline]
    const fn new(inner: R) -> Self {
        Self {
            inner,
            failed: false,
        }
    }
}

impl<R: Read> Read for FlagReadError<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buf);
        self.failed = result.is_err();
        result
    }
}

/// Zlib-inflated bytes of a compressed entry read from `R`, capped at `entry.size + 1`.
type Inflater<R> = Take<ZlibDecoder<FlagReadError<R>>>;

/// Streamed reader over one entry's payload, opened with
/// [`Bigfile::open_entry`](super::Bigfile::open_entry): its stored bytes as they are, or
/// zlib-inflated. [`Bigfile::open_entry_at`](super::Bigfile::open_entry_at) opens one over the
/// stored bytes from an offset instead.
///
/// The single owner of raw vs. inflated reads: [`Bigfile::read_entry`](super::Bigfile::read_entry)
/// and [`Bigfile::read_entry_into`](super::Bigfile::read_entry_into) read through it too.
///
/// Each read is checked as it happens, so a damaged entry fails instead of passing as a shorter
/// or longer payload:
/// - A part-file read failure, including a part file that ends early, is returned as the
///   [`io::Error`] the part file raised, never as a decompression error.
/// - An inflated payload yields at most `entry.size` bytes. Reaching the end of a stream that
///   inflates to fewer or more bytes fails, so no more than `entry.size + 1` bytes are inflated,
///   and a corrupt zlib stream fails where it is found.
///
/// Errors in the inflated payload itself carry a [`BigfileError::DecompressError`] or
/// [`BigfileError::DecompressedSizeMismatch`], which `io::Error::downcast` recovers. A caller
/// that stops before the end skips the end-of-payload checks.
#[derive(Debug)]
pub struct EntryReader<'a> {
    entry: Entry,
    source: EntrySource<'a>,
}

/// Where an [`EntryReader`] takes its bytes from.
#[derive(Debug)]
enum EntrySource<'a> {
    Stored(PositionalFileReader<'a>),
    Inflated(Inflater<PositionalFileReader<'a>>),
}

impl<'a> EntryReader<'a> {
    /// Wraps `stored`, the stored bytes of `entry`, to read them raw when `raw` is `true` or the
    /// entry is uncompressed, and zlib-inflated otherwise.
    pub(super) fn new(entry: Entry, raw: bool, stored: PositionalFileReader<'a>) -> Self {
        if !entry.is_inflated_on_read(raw) {
            let source = EntrySource::Stored(stored);
            return Self { entry, source };
        }
        let input_len = (entry.stored_size() as usize).min(COMPRESSED_READ_BYTES);
        let decoder = ZlibDecoder::new_with_buf(FlagReadError::new(stored), vec![0; input_len]);
        let source = EntrySource::Inflated(decoder.take(u64::from(entry.size) + 1));
        Self { entry, source }
    }

    /// Most bytes left to read before the end is reached, counting the one extra byte an
    /// overlong inflated stream yields.
    #[inline]
    #[must_use]
    fn max_remaining(&self) -> u64 {
        match &self.source {
            EntrySource::Stored(stored) => stored.remaining(),
            EntrySource::Inflated(inflated) => inflated.limit(),
        }
    }

    /// Streams the payload into `out` through the reusable `chunk` buffer (see [`copy_chunked`]),
    /// returning the number of bytes written.
    pub(super) fn copy_to<W: Write>(
        mut self,
        chunk: &mut Vec<u8>,
        out: &mut W,
    ) -> Result<u64, BigfileError> {
        let expected_len = self.max_remaining();
        copy_chunked(&mut self, expected_len, chunk, out, into_bigfile_error)
    }

    /// Reads the whole payload straight into a new buffer. Stored sizes are validated against the
    /// part file at open, so they are reserved in full; an inflated size comes from the TOC, so
    /// its reservation is capped.
    pub(super) fn read_to_vec(mut self) -> Result<Vec<u8>, BigfileError> {
        let capacity = match &self.source {
            EntrySource::Stored(_) => self.max_remaining(),
            EntrySource::Inflated(_) => {
                u64::from(self.entry.size).min(MAX_UNTRUSTED_RESERVATION as u64)
            }
        };
        let mut out = Vec::with_capacity(usize::try_from(capacity).unwrap_or(0));
        self.read_to_end(&mut out).map_err(into_bigfile_error)?;
        Ok(out)
    }
}

impl Read for EntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.source {
            EntrySource::Stored(stored) => stored.read(buf),
            EntrySource::Inflated(inflated) => read_inflated(&self.entry, inflated, buf),
        }
    }
}

/// Inflates up to `buf.len()` bytes of `entry`, never past `entry.size`. Once `entry.size` bytes
/// are in, a read takes one more byte to check that the stream ends there, and an overlong stream
/// then fails on every later read. A part-file read failure is returned as it is.
fn read_inflated<R: Read>(
    entry: &Entry,
    inflated: &mut Inflater<R>,
    buf: &mut [u8],
) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let size = u64::from(entry.size);
    let inflated_len = (size + 1).saturating_sub(inflated.limit());
    if inflated_len > size {
        return Err(size_mismatch(entry, inflated_len));
    }
    let left = usize::try_from(size - inflated_len).unwrap_or(usize::MAX);
    let read_len = buf.len().min(left.max(1));
    match inflated.read(&mut buf[..read_len]) {
        Ok(0) if inflated_len == size => Ok(0),
        Ok(0) => Err(size_mismatch(entry, inflated_len)),
        Ok(_) if inflated_len == size => Err(size_mismatch(entry, size + 1)),
        Ok(n) => Ok(n),
        Err(e) if inflated.get_ref().get_ref().failed => Err(e),
        Err(e) => Err(decompress_error(entry, e)),
    }
}

/// Error for `entry`'s zlib stream failing to inflate with `source`.
fn decompress_error(entry: &Entry, source: io::Error) -> io::Error {
    let kind = source.kind();
    let error = BigfileError::DecompressError {
        index: entry.index,
        name_hash: entry.name_hash,
        source,
    };
    io::Error::new(kind, error)
}

/// Error for `entry`'s zlib stream inflating to `actual` bytes instead of `entry.size`.
fn size_mismatch(entry: &Entry, actual: u64) -> io::Error {
    let kind = if actual < u64::from(entry.size) {
        io::ErrorKind::UnexpectedEof
    } else {
        io::ErrorKind::InvalidData
    };
    let error = BigfileError::DecompressedSizeMismatch {
        index: entry.index,
        name_hash: entry.name_hash,
        expected: entry.size,
        actual,
    };
    io::Error::new(kind, error)
}

/// Recovers the [`BigfileError`] an [`EntryReader`] read error carries, or reports the error as
/// I/O when it came from the part file.
fn into_bigfile_error(error: io::Error) -> BigfileError {
    error.downcast().unwrap_or_else(BigfileError::Io)
}

/// Copies `reader` into `out` through the reusable `chunk` buffer, filling up to
/// `min(expected_len, STREAM_CHUNK_BYTES)` bytes before each write, mapping read errors with
/// `read_err` and write errors to [`BigfileError::Write`]. Returns the number of bytes copied.
fn copy_chunked<R: Read, W: Write>(
    reader: &mut R,
    expected_len: u64,
    chunk: &mut Vec<u8>,
    out: &mut W,
    read_err: impl Fn(io::Error) -> BigfileError,
) -> Result<u64, BigfileError> {
    let chunk_len =
        usize::try_from(expected_len).map_or(STREAM_CHUNK_BYTES, |len| len.min(STREAM_CHUNK_BYTES));
    if chunk.len() < chunk_len {
        chunk.resize(chunk_len, 0);
    }
    let buf = &mut chunk[..chunk_len];
    let mut copied = 0u64;
    loop {
        let filled = read_until_full(reader, buf).map_err(&read_err)?;
        out.write_all(&buf[..filled]).map_err(BigfileError::Write)?;
        copied += filled as u64;
        if filled < buf.len() || filled == 0 {
            return Ok(copied);
        }
    }
}

/// Reads from `reader` until `buf` is full or the reader reaches EOF, returning the bytes read.
/// Unlike [`Read::read_exact`], reaching EOF early is not an error.
fn read_until_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::archive::Bigfile;
    use crate::format::Endian;
    use crate::test_support::{
        ArchiveRecord, FailingWriter, TempDir, write_archive, write_two_part_archive, zlib_compress,
    };

    #[test]
    fn copy_chunked_bounds_buffer_to_stream_chunk() {
        let payload: Vec<u8> = (0..STREAM_CHUNK_BYTES + 4096)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        let (mut chunk, mut out) = (Vec::new(), Vec::new());
        let copied = copy_chunked(
            &mut payload.as_slice(),
            payload.len() as u64,
            &mut chunk,
            &mut out,
            BigfileError::Io,
        )
        .unwrap();
        assert_eq!(copied, payload.len() as u64);
        assert_eq!(out, payload);
        assert_eq!(chunk.len(), STREAM_CHUNK_BYTES);
    }

    /// [`Read`] that returns at most 1000 bytes per call, like a streaming decoder.
    struct TrickleReader<'a>(&'a [u8]);

    impl Read for TrickleReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len()).min(1000);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// [`Write`] that records the size of every `write` call.
    #[derive(Default)]
    struct WriteSizes(Vec<usize>);

    impl Write for WriteSizes {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.push(buf.len());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn copy_chunked_writes_full_chunks_from_short_reads() {
        let payload = vec![0x5Au8; 10_000];
        let mut out = WriteSizes::default();
        let copied = copy_chunked(
            &mut TrickleReader(&payload),
            payload.len() as u64,
            &mut Vec::new(),
            &mut out,
            BigfileError::Io,
        )
        .unwrap();
        assert_eq!(copied, 10_000);
        assert_eq!(out.0, vec![10_000]);
    }

    #[test]
    fn copy_chunked_reports_destination_failures_as_write_errors() {
        let err = copy_chunked(
            &mut [1u8, 2, 3].as_slice(),
            3,
            &mut Vec::new(),
            &mut FailingWriter(io::ErrorKind::BrokenPipe),
            BigfileError::Io,
        )
        .unwrap_err();
        assert!(matches!(err, BigfileError::Write(e) if e.kind() == io::ErrorKind::BrokenPipe));
    }

    /// [`Read`] over a slice that reports one `Interrupted` error before its first byte.
    struct InterruptOnceReader<'a> {
        data: &'a [u8],
        interrupted: bool,
    }

    impl Read for InterruptOnceReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.data.read(buf)
        }
    }

    #[test]
    fn flag_read_error_flags_only_the_read_that_failed() {
        let mut reader = FlagReadError::new(InterruptOnceReader {
            data: b"after",
            interrupted: false,
        });
        let mut buf = [0u8; 8];
        reader.read(&mut buf).unwrap_err();
        assert!(reader.failed);
        assert_eq!(reader.read(&mut buf).unwrap(), 5);
        assert!(!reader.failed);
    }

    #[test]
    fn inflated_read_passes_interrupted_part_read_on_for_retry() {
        let payload = b"payload read after one interrupted part-file read";
        let dir = create_payload_archive("inflated_interrupted", payload);
        let bf = Bigfile::open(&dir).unwrap();
        let zlib = bf.read_entry(&entry(&bf, ZLIB_HASH), true).unwrap();
        let part = InterruptOnceReader {
            data: &zlib,
            interrupted: false,
        };
        let mut inflated =
            ZlibDecoder::new(FlagReadError::new(part)).take(payload.len() as u64 + 1);
        let mut buf = [0u8; 128];
        let err = read_inflated(&entry(&bf, ZLIB_HASH), &mut inflated, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(carried_error(&err).is_none());
        let n = read_inflated(&entry(&bf, ZLIB_HASH), &mut inflated, &mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[test]
    fn positional_read_past_the_end_of_a_file_is_unexpected_eof() {
        let dir = TempDir::new("read_past_end");
        let path = dir.join("short.bin");
        std::fs::write(&path, [0u8; 10]).unwrap();
        let file = File::open(&path).unwrap();

        let err = read_exact_at_os(&file, &mut [0u8; 8], 6).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// [`Read`] over a slice that fails with `UnexpectedEof` once the slice runs out, like a part
    /// file that ends early.
    struct EndsEarlyReader<'a>(&'a [u8]);

    impl Read for EndsEarlyReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.0.read(buf)
        }
    }

    #[test]
    fn inflated_read_reports_a_part_ending_early_as_io() {
        let payload = patterned_payload(10_000);
        let zlib = zlib_compress(&payload);
        let mut inflated = ZlibDecoder::new(FlagReadError::new(EndsEarlyReader(&zlib[..20])))
            .take(payload.len() as u64 + 1);
        let entry = Entry {
            index: 1,
            name_hash: ZLIB_HASH,
            size: u32::try_from(payload.len()).unwrap(),
            sector_number: 1,
            spec_flags: 1,
            deflated_size: i32::try_from(zlib.len()).unwrap(),
        };
        let mut buf = [0u8; 4096];

        let err = loop {
            match read_inflated(&entry, &mut inflated, &mut buf) {
                Ok(0) => panic!("the stream ended without an error"),
                Ok(_) => {}
                Err(err) => break err,
            }
        };

        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(carried_error(&err).is_none(), "{err:?}");
    }

    /// Record holding the payload as stored bytes, at sector 1.
    const STORED_HASH: u32 = 0x1;
    /// Record holding the zlib stream, right after the stored record.
    const ZLIB_HASH: u32 = 0x2;

    /// Writes an archive in `dir` holding `stored` (record [`STORED_HASH`]) and `zlib` declaring
    /// `inflated_size` bytes (record [`ZLIB_HASH`]), so both reads start past part offset 0.
    fn write_two_record_archive(dir: &TempDir, stored: &[u8], zlib: &[u8], inflated_size: u32) {
        let records = [
            ArchiveRecord::stored(STORED_HASH, 1, stored),
            ArchiveRecord::zlib(ZLIB_HASH, 1, zlib, inflated_size),
        ];
        write_archive(dir.join("bigfile.000"), Endian::Little, &records);
    }

    /// Bytes that repeat with a period of 251, so no two nearby chunks look alike.
    fn patterned_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// Writes an archive holding `payload` both stored and zlib-compressed at its own size.
    fn create_payload_archive(prefix: &str, payload: &[u8]) -> TempDir {
        let dir = TempDir::new(prefix);
        let size = u32::try_from(payload.len()).unwrap();
        write_two_record_archive(&dir, payload, &zlib_compress(payload), size);
        dir
    }

    /// Writes an archive whose zlib record stores `zlib` but declares `inflated_size` bytes.
    fn create_zlib_archive(prefix: &str, zlib: &[u8], inflated_size: u32) -> TempDir {
        let dir = TempDir::new(prefix);
        write_two_record_archive(&dir, b"stored", zlib, inflated_size);
        dir
    }

    fn entry(bf: &Bigfile, hash: u32) -> Entry {
        bf.find(hash)[0]
    }

    /// Reads the record `hash` into a sink through [`Bigfile::read_entry_into`], inflating it when
    /// it is compressed.
    fn read_into_sink(bf: &Bigfile, hash: u32) -> Result<u64, BigfileError> {
        bf.read_entry_into(&entry(bf, hash), false, &mut Vec::new(), &mut io::sink())
    }

    /// Streams the record `hash` to its end, returning what was read and how reading ended.
    fn stream(bf: &Bigfile, hash: u32, raw: bool) -> (Vec<u8>, io::Result<usize>) {
        let mut out = Vec::new();
        let mut reader = bf.open_entry(&entry(bf, hash), raw).unwrap();
        let ended = reader.read_to_end(&mut out);
        (out, ended)
    }

    /// Reads `reader` to its end in reads of at most `step` bytes.
    fn read_in_steps(mut reader: impl Read, step: usize) -> io::Result<Vec<u8>> {
        let (mut out, mut buf) = (Vec::new(), vec![0u8; step]);
        loop {
            match reader.read(&mut buf)? {
                0 => return Ok(out),
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// The [`BigfileError`] a streamed read error carries, if any.
    fn carried_error(err: &io::Error) -> Option<&BigfileError> {
        err.get_ref()?.downcast_ref()
    }

    /// Opens the archive in `dir`, then cuts its part file `keep` bytes into record `hash`.
    ///
    /// Only on Unix: on Windows an open part cannot be written to (`open_part`), so a part never
    /// ends early once opened, and the tests that use this helper are Unix-only too.
    #[cfg(unix)]
    fn open_cut_short(dir: &TempDir, hash: u32, keep: u64) -> Bigfile {
        let bf = Bigfile::open(dir).unwrap();
        let location = bf.locate(&entry(&bf, hash)).unwrap();
        crate::test_support::truncate_file(dir.join("bigfile.000"), location.offset_in_part + keep);
        bf
    }

    #[test]
    fn reads_uncompressed_entry_spanning_multiple_chunks() {
        let payload = patterned_payload(STREAM_CHUNK_BYTES + 4096);
        let dir = create_payload_archive("multi_chunk_raw", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(
            bf.read_entry(&entry(&bf, STORED_HASH), false).unwrap(),
            payload
        );
    }

    #[test]
    fn inflates_entry_spanning_multiple_chunks() {
        let payload = patterned_payload(STREAM_CHUNK_BYTES + 4096);
        let dir = create_payload_archive("multi_chunk_zlib", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(
            bf.read_entry(&entry(&bf, ZLIB_HASH), false).unwrap(),
            payload
        );
    }

    #[test]
    fn inflated_stream_matches_read_entry() {
        let dir = create_payload_archive("stream_inflated", &patterned_payload(10_000));
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, false);
        assert_eq!(ended.unwrap(), 10_000);
        assert_eq!(
            streamed,
            bf.read_entry(&entry(&bf, ZLIB_HASH), false).unwrap()
        );
    }

    #[test]
    fn raw_stream_returns_stored_zlib_bytes() {
        let payload = patterned_payload(10_000);
        let dir = create_payload_archive("stream_raw_stored", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, true);
        ended.unwrap();
        assert_eq!(streamed, zlib_compress(&payload));
    }

    #[test]
    fn raw_stream_matches_read_entry() {
        let dir = create_payload_archive("stream_raw", &patterned_payload(10_000));
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, true);
        ended.unwrap();
        assert_eq!(
            streamed,
            bf.read_entry(&entry(&bf, ZLIB_HASH), true).unwrap()
        );
    }

    /// Read sizes from a single byte to more than the whole payload.
    const READ_STEPS: [usize; 5] = [1, 7, 4096, 65_536, 1 << 20];

    #[test]
    fn stored_stream_reads_payload_in_any_read_size() {
        let payload = patterned_payload(100_000);
        let dir = create_payload_archive("stream_steps_stored", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        for step in READ_STEPS {
            let reader = bf.open_entry(&entry(&bf, STORED_HASH), false).unwrap();
            assert_eq!(read_in_steps(reader, step).unwrap(), payload, "step {step}");
        }
    }

    #[test]
    fn inflated_stream_reads_payload_in_any_read_size() {
        let payload = patterned_payload(100_000);
        let dir = create_payload_archive("stream_steps_zlib", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        for step in READ_STEPS {
            let reader = bf.open_entry(&entry(&bf, ZLIB_HASH), false).unwrap();
            assert_eq!(read_in_steps(reader, step).unwrap(), payload, "step {step}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn stream_rejects_short_stored_payload() {
        let dir = create_payload_archive("stream_short_stored", &patterned_payload(5000));
        let bf = open_cut_short(&dir, STORED_HASH, 100);
        let (_, ended) = stream(&bf, STORED_HASH, false);
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn stream_rejects_short_zlib_stream() {
        let payload = b"only 16 bytes!!!";
        let dir = create_zlib_archive("stream_short_zlib", &zlib_compress(payload), 64);
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, false);
        assert_eq!(streamed, payload);
        assert!(matches!(
            carried_error(&ended.unwrap_err()),
            Some(BigfileError::DecompressedSizeMismatch {
                expected: 64,
                actual: 16,
                ..
            })
        ));
    }

    /// Writes an archive whose zlib record declares 64 bytes but inflates to 4096.
    fn create_overlong_zlib_archive(prefix: &str) -> TempDir {
        create_zlib_archive(prefix, &zlib_compress(&[b'A'; 4096]), 64)
    }

    fn is_overlong_mismatch(err: &BigfileError) -> bool {
        matches!(
            err,
            BigfileError::DecompressedSizeMismatch {
                expected: 64,
                actual: 65,
                ..
            }
        )
    }

    #[test]
    fn stream_stops_overlong_zlib_stream_at_declared_size() {
        let dir = create_overlong_zlib_archive("stream_overlong_zlib");
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, false);
        assert_eq!(streamed, [b'A'; 64]);
        assert!(carried_error(&ended.unwrap_err()).is_some_and(is_overlong_mismatch));
    }

    #[test]
    fn stream_keeps_failing_after_overlong_zlib_stream() {
        let dir = create_overlong_zlib_archive("stream_overlong_again");
        let bf = Bigfile::open(&dir).unwrap();
        let mut reader = bf.open_entry(&entry(&bf, ZLIB_HASH), false).unwrap();
        let mut buf = [0u8; 128];
        assert_eq!(reader.read(&mut buf).unwrap(), 64);
        for _ in 0..3 {
            let err = reader.read(&mut buf).unwrap_err();
            assert!(carried_error(&err).is_some_and(is_overlong_mismatch));
        }
    }

    #[test]
    fn stream_rejects_corrupt_zlib_stream() {
        let dir = create_zlib_archive("stream_corrupt_zlib", b"not a valid zlib stream", 64);
        let bf = Bigfile::open(&dir).unwrap();
        let (_, ended) = stream(&bf, ZLIB_HASH, false);
        assert!(matches!(
            carried_error(&ended.unwrap_err()),
            Some(BigfileError::DecompressError { index: 1, .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stream_reports_part_read_failure_as_io() {
        let dir = create_payload_archive("stream_part_failure", &patterned_payload(5000));
        let bf = open_cut_short(&dir, ZLIB_HASH, 0);
        let err = stream(&bf, ZLIB_HASH, false).1.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(carried_error(&err).is_none());
    }

    #[cfg(unix)]
    fn is_part_read_failure(err: &BigfileError) -> bool {
        matches!(err, BigfileError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof)
    }

    #[cfg(unix)]
    #[test]
    fn read_entry_reports_zlib_part_read_failure_as_io() {
        let dir = create_payload_archive("whole_part_failure", &patterned_payload(5000));
        let bf = open_cut_short(&dir, ZLIB_HASH, 0);
        let err = bf.read_entry(&entry(&bf, ZLIB_HASH), false).unwrap_err();
        assert!(is_part_read_failure(&err));
    }

    #[cfg(unix)]
    #[test]
    fn read_entry_into_reports_zlib_part_read_failure_as_io() {
        let dir = create_payload_archive("chunked_part_failure", &patterned_payload(5000));
        let bf = open_cut_short(&dir, ZLIB_HASH, 0);
        let err = read_into_sink(&bf, ZLIB_HASH).unwrap_err();
        assert!(is_part_read_failure(&err));
    }

    #[cfg(unix)]
    #[test]
    fn read_entry_reports_stored_part_read_failure_as_io() {
        let dir = create_payload_archive("whole_stored_failure", &patterned_payload(5000));
        let bf = open_cut_short(&dir, STORED_HASH, 100);
        let err = bf.read_entry(&entry(&bf, STORED_HASH), false).unwrap_err();
        assert!(is_part_read_failure(&err));
    }

    #[cfg(unix)]
    #[test]
    fn read_entry_into_reports_stored_part_read_failure_as_io() {
        let dir = create_payload_archive("chunked_stored_failure", &patterned_payload(5000));
        let bf = open_cut_short(&dir, STORED_HASH, 100);
        let err = read_into_sink(&bf, STORED_HASH).unwrap_err();
        assert!(is_part_read_failure(&err));
    }

    #[test]
    fn read_entry_rejects_overlong_zlib_stream() {
        let dir = create_overlong_zlib_archive("whole_overlong_zlib");
        let bf = Bigfile::open(&dir).unwrap();
        let err = bf.read_entry(&entry(&bf, ZLIB_HASH), false).unwrap_err();
        assert!(is_overlong_mismatch(&err));
    }

    #[test]
    fn read_entry_into_rejects_overlong_zlib_stream() {
        let dir = create_overlong_zlib_archive("chunked_overlong_zlib");
        let bf = Bigfile::open(&dir).unwrap();
        let err = read_into_sink(&bf, ZLIB_HASH).unwrap_err();
        assert!(is_overlong_mismatch(&err));
    }

    #[test]
    fn read_entry_into_rejects_short_zlib_stream() {
        let dir = create_zlib_archive(
            "chunked_short_zlib",
            &zlib_compress(b"16 bytes, short!"),
            64,
        );
        let bf = Bigfile::open(&dir).unwrap();
        let err = read_into_sink(&bf, ZLIB_HASH).unwrap_err();
        assert!(matches!(
            err,
            BigfileError::DecompressedSizeMismatch {
                index: 1,
                expected: 64,
                actual: 16,
                ..
            }
        ));
    }

    /// Reads the stored bytes of record `hash` from `offset` to the end, in reads of 4 KiB.
    fn read_from(bf: &Bigfile, hash: u32, offset: u64) -> io::Result<Vec<u8>> {
        read_in_steps(bf.open_entry_at(&entry(bf, hash), offset).unwrap(), 4096)
    }

    #[test]
    fn open_entry_at_zero_matches_raw_open_entry() {
        let dir = create_payload_archive("at_zero", &patterned_payload(10_000));
        let bf = Bigfile::open(&dir).unwrap();
        let (streamed, ended) = stream(&bf, ZLIB_HASH, true);
        ended.unwrap();
        assert_eq!(read_from(&bf, ZLIB_HASH, 0).unwrap(), streamed);
    }

    /// Record [`write_two_part_archive`] stores at the start of part 1.
    const PART1_HASH: u32 = 0x3;

    #[test]
    fn open_entry_at_reads_from_inside_an_entry_in_a_later_part() {
        let payload = patterned_payload(10_000);
        let dir = TempDir::new("at_part1");
        let part0 = [ArchiveRecord::stored(STORED_HASH, 1, b"in part 0")];
        let part1 = [ArchiveRecord::stored(PART1_HASH, 1, &payload)];
        write_two_part_archive(&dir, &part0, &part1);
        let bf = Bigfile::open(&dir).unwrap();
        assert_eq!(read_from(&bf, PART1_HASH, 4321).unwrap(), payload[4321..]);
    }

    #[test]
    fn open_entry_at_entry_end_reads_nothing() {
        let dir = create_payload_archive("at_end", &patterned_payload(5000));
        let bf = Bigfile::open(&dir).unwrap();
        assert!(read_from(&bf, STORED_HASH, 5000).unwrap().is_empty());
    }

    #[test]
    fn open_entry_at_rejects_offset_past_entry_end() {
        let dir = create_payload_archive("at_past_end", &patterned_payload(5000));
        let bf = Bigfile::open(&dir).unwrap();
        for past_end in [5001, u64::MAX] {
            let err = bf
                .open_entry_at(&entry(&bf, STORED_HASH), past_end)
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    BigfileError::OffsetPastEntryEnd {
                        index: 0,
                        name_hash: STORED_HASH,
                        offset,
                        stored_size: 5000,
                    } if offset == past_end
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn open_entry_at_returns_stored_bytes_of_compressed_entry() {
        let payload = patterned_payload(10_000);
        let dir = create_payload_archive("at_zlib", &payload);
        let bf = Bigfile::open(&dir).unwrap();
        let zlib = zlib_compress(&payload);
        let middle = zlib.len() / 2;
        let read = read_from(&bf, ZLIB_HASH, middle as u64).unwrap();
        assert_eq!(read, zlib[middle..]);
    }

    #[test]
    fn open_entry_at_serves_concurrent_readers_of_one_entry() {
        let payload = patterned_payload(STREAM_CHUNK_BYTES + 4096);
        let dir = create_payload_archive("at_threads", &payload);
        let bf = &Bigfile::open(&dir).unwrap();
        let offsets = [0, 1, 4096, 65_537, STREAM_CHUNK_BYTES, payload.len()];
        std::thread::scope(|scope| {
            let readers: Vec<_> = offsets
                .iter()
                .map(|&offset| scope.spawn(move || read_from(bf, STORED_HASH, offset as u64)))
                .collect();
            for (reader, offset) in readers.into_iter().zip(offsets) {
                let read = reader.join().unwrap().unwrap();
                assert_eq!(read, payload[offset..], "offset {offset}");
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn open_entry_at_reports_part_file_ending_early() {
        let dir = create_payload_archive("at_short", &patterned_payload(5000));
        let bf = open_cut_short(&dir, STORED_HASH, 100);
        let err = read_from(&bf, STORED_HASH, 50).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_entry_into_rejects_corrupt_zlib_stream() {
        let dir = create_zlib_archive("chunked_corrupt_zlib", b"not a valid zlib stream", 64);
        let bf = Bigfile::open(&dir).unwrap();
        let err = read_into_sink(&bf, ZLIB_HASH).unwrap_err();
        assert!(matches!(
            err,
            BigfileError::DecompressError { index: 1, .. }
        ));
    }
}
