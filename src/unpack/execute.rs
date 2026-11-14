//! Running an extraction plan: staging entries, worker threads and moving files into place.

use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::ScopedJoinHandle;

use super::plan::PlannedExtraction;
use crate::archive::{Bigfile, BigfileError};
use crate::fat::Entry;
use crate::path::parent_dir;

/// Name prefix of every [`StagingDir`], followed by the process id and an attempt number.
pub(super) const STAGING_DIR_PREFIX: &str = ".lau-bigfun-staging-";

/// Longest symbolic link chain [`follow_symlinks`] resolves, so a link rewritten into a cycle
/// mid-extraction cannot hang it.
const MAX_SYMLINK_HOPS: usize = 40;

/// Maps an I/O failure at the output `path` to an error that names it.
fn output_error(path: &Path) -> impl Fn(std::io::Error) -> BigfileError + '_ {
    move |source| BigfileError::OutputPath {
        path: path.to_path_buf(),
        source,
    }
}

/// Streams `entry` into `file`, naming `path` if the destination rejects the bytes.
fn write_entry_to_file(
    bigfile: &Bigfile,
    entry: &Entry,
    raw: bool,
    chunk: &mut Vec<u8>,
    file: &mut File,
    path: &Path,
) -> Result<u64, BigfileError> {
    bigfile
        .read_entry_into(entry, raw, chunk, file)
        .map_err(|err| match err {
            BigfileError::Write(source) => output_error(path)(source),
            other => other,
        })
}

/// Creates all unique parent directories once up front before file extraction begins.
pub(super) fn create_parent_directories(
    unique_dirs: &HashSet<PathBuf>,
) -> Result<(), BigfileError> {
    unique_dirs
        .iter()
        .try_for_each(|dir| create_output_dir(dir))
}

/// Creates the output directory `dir` and its missing ancestors, naming `dir` if that fails.
fn create_output_dir(dir: &Path) -> Result<(), BigfileError> {
    fs::create_dir_all(dir).map_err(output_error(dir))
}

/// Resolves the effective worker thread count (`0` => available CPU parallelism), bounded by task count.
fn resolve_worker_count(requested_jobs: usize, task_count: usize) -> usize {
    let threads = if requested_jobs == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        requested_jobs
    };
    threads.min(task_count.max(1))
}

/// Uniquely named hidden directory under the output directory that holds entries while they are
/// written, so final paths only ever receive complete files. Removed, with any partial files,
/// when dropped (an interrupted process can leave it behind).
struct StagingDir(PathBuf);

impl StagingDir {
    /// Creates `<out_dir>/.lau-bigfun-staging-<pid>-<n>`, using the first `n` not already taken.
    fn create(out_dir: &Path) -> std::io::Result<Self> {
        let pid = std::process::id();
        let mut attempt = 0u32;
        loop {
            let path = out_dir.join(format!("{STAGING_DIR_PREFIX}{pid}-{attempt}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) => return Err(e),
            }
        }
    }

    #[inline]
    #[must_use]
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What every worker of one extraction shares: the archives the plan reads from, the planned
/// items, whether entries are written raw, and the staging directory files are written into.
struct ExtractionJob<'a> {
    archives: &'a [Bigfile],
    items: &'a [PlannedExtraction<'a>],
    raw: bool,
    staging: &'a Path,
}

impl ExtractionJob<'_> {
    /// Streams the planned item at position `item_idx` into the staging directory through the
    /// worker's reusable `chunk` buffer, then renames it onto its destination. The position names
    /// the staged file because record indexes repeat across archives. A failed entry leaves its
    /// destination untouched, including any file already there. `item_idx` must be in the plan.
    fn extract_item(&self, item_idx: usize, chunk: &mut Vec<u8>) -> Result<u64, BigfileError> {
        let item = &self.items[item_idx];
        let archive = &self.archives[item.archive_rank];
        let staged_path = self.staging.join(item_idx.to_string());
        let dest_path = item.dest_path.as_path();
        let written = File::create(&staged_path)
            .map_err(output_error(&staged_path))
            .and_then(|mut file| {
                write_entry_to_file(archive, item.entry, self.raw, chunk, &mut file, dest_path)
            })
            .and_then(|written| {
                fs::rename(&staged_path, dest_path).map_err(output_error(dest_path))?;
                Ok(written)
            });
        if written.is_err() {
            let _ = fs::remove_file(&staged_path);
        }
        written
    }

    /// Pulls items from `next_idx` and extracts them using a worker-local reusable chunk buffer
    /// until all items are claimed or `cancelled` is set.
    fn extract_from_queue(
        &self,
        next_idx: &AtomicUsize,
        cancelled: &AtomicBool,
    ) -> Result<u64, BigfileError> {
        let mut chunk = Vec::new();
        let mut total_bytes = 0u64;
        while !cancelled.load(Ordering::Relaxed) {
            let idx = next_idx.fetch_add(1, Ordering::Relaxed);
            if idx >= self.items.len() {
                break;
            }
            total_bytes += self.extract_item(idx, &mut chunk)?;
        }
        Ok(total_bytes)
    }

    /// Extracts the items across `num_workers` threads sharing an `AtomicUsize` work index.
    fn extract_in_parallel(&self, num_workers: usize) -> Result<u64, BigfileError> {
        let next_idx = AtomicUsize::new(0);
        let cancelled = AtomicBool::new(false);
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..num_workers)
                .map(|_| {
                    s.spawn(|| {
                        let res = self.extract_from_queue(&next_idx, &cancelled);
                        if res.is_err() {
                            cancelled.store(true, Ordering::Relaxed);
                        }
                        res
                    })
                })
                .collect();
            join_workers(handles)
        })
    }
}

/// Joins every worker, returning their summed byte counts or the first error a worker returned,
/// and re-raising a worker panic.
fn join_workers(
    handles: Vec<ScopedJoinHandle<'_, Result<u64, BigfileError>>>,
) -> Result<u64, BigfileError> {
    let mut total_bytes = 0u64;
    let mut first_err = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(bytes)) => total_bytes += bytes,
            Ok(Err(err)) if first_err.is_none() => first_err = Some(err),
            Ok(Err(_)) => {}
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    first_err.map_or(Ok(total_bytes), Err)
}

/// Extracts `items` through a [`StagingDir`] under `out_dir` across `jobs` worker threads,
/// returning the total bytes written.
pub(super) fn extract_items(
    archives: &[Bigfile],
    items: &[PlannedExtraction<'_>],
    out_dir: &Path,
    raw: bool,
    jobs: usize,
) -> Result<u64, BigfileError> {
    if items.is_empty() {
        return Ok(0);
    }
    let staging = StagingDir::create(out_dir).map_err(output_error(out_dir))?;
    let job = ExtractionJob {
        archives,
        items,
        raw,
        staging: staging.path(),
    };
    let num_workers = resolve_worker_count(jobs, items.len());
    if num_workers <= 1 {
        let (next_idx, cancelled) = (AtomicUsize::new(0), AtomicBool::new(false));
        job.extract_from_queue(&next_idx, &cancelled)
    } else {
        job.extract_in_parallel(num_workers)
    }
}

/// Resolves the symbolic links at `path`, including a final link whose target does not exist yet.
fn follow_symlinks(path: &Path) -> PathBuf {
    let mut target = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        let Ok(link) = fs::read_link(&target) else {
            break;
        };
        target = target.parent().unwrap_or(Path::new("")).join(link);
    }
    target
}

/// Streams `entry`'s payload to the file `dest_path`, creating its parent directories, and returns
/// the bytes written.
///
/// A regular file is replaced through a hidden staging directory beside it, so a failed entry
/// leaves any existing file untouched. A symbolic link is followed to its target, which need not
/// exist yet. Anything else, such as a device or named pipe, is opened directly, leaving the
/// operating system to accept or reject it.
///
/// # Errors
///
/// Fails like [`Bigfile::read_entry`], and with [`BigfileError::OutputPath`] when the destination
/// or its parent directories cannot be created, written or replaced.
pub fn extract_entry(
    bigfile: &Bigfile,
    entry: &Entry,
    raw: bool,
    dest_path: &Path,
) -> Result<u64, BigfileError> {
    let replaceable = match fs::metadata(dest_path) {
        Ok(meta) => meta.is_file(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    };
    if !replaceable {
        let mut file = File::create(dest_path).map_err(output_error(dest_path))?;
        return write_entry_to_file(bigfile, entry, raw, &mut Vec::new(), &mut file, dest_path);
    }
    let target = follow_symlinks(dest_path);
    let parent = parent_dir(&target);
    create_output_dir(parent)?;
    let item = PlannedExtraction {
        archive_rank: 0,
        entry,
        dest_path: target.clone(),
    };
    extract_items(
        std::slice::from_ref(bigfile),
        std::slice::from_ref(&item),
        parent,
        raw,
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, write_shared_sector_archive};

    #[test]
    fn missing_staging_folder_names_the_staged_file() {
        let tmp = TempDir::new("error_names_staged");
        let path = tmp.join("bigfile.000");
        write_shared_sector_archive(&path, &[(0x1, 100, 0)]);
        let bf = Bigfile::open(&path).unwrap();
        let item = PlannedExtraction {
            archive_rank: 0,
            entry: &bf.entries()[0],
            dest_path: tmp.join("dest.bin"),
        };
        let staging = tmp.join("gone");
        let job = ExtractionJob {
            archives: std::slice::from_ref(&bf),
            items: std::slice::from_ref(&item),
            raw: false,
            staging: &staging,
        };

        let err = job.extract_item(0, &mut Vec::new());

        let expected = staging.join("0");
        assert!(matches!(err, Err(BigfileError::OutputPath { path, .. }) if path == expected));
    }
}
