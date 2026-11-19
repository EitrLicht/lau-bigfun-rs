//! Helpers shared by the fuzz targets.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Start of every scratch directory's name.
const SCRATCH_PREFIX: &str = "lau_bigfun_fuzz_";

/// File in each scratch directory that its fuzzing process keeps locked until it exits.
const LOCK_FILE: &str = "owner.lock";

/// Name [`LOCK_FILE`] has while it is being created and locked, before it is renamed into place.
const STAGING_LOCK_FILE: &str = "owner.staging";

/// A scratch directory and its locked [`LOCK_FILE`], which marks the directory as in use for as
/// long as the file stays open.
struct ScratchDir {
    path: PathBuf,
    _lock: File,
}

/// Returns a directory private to this fuzzing process, for targets that must read from files.
/// Every call returns the same directory.
///
/// The first call removes the directories of fuzzing processes that have ended (see
/// `remove_stale_scratch_dirs`), then claims one for this process.
///
/// # Panics
///
/// When the directory cannot be created or locked.
#[must_use]
pub fn scratch_dir() -> &'static Path {
    // Holds the lock file open for the rest of the process. Rust never drops statics, so the
    // lock is released only when the process ends and the operating system closes the file,
    // however it ends: libFuzzer exits without running destructors.
    static CLAIMED: OnceLock<ScratchDir> = OnceLock::new();
    &CLAIMED
        .get_or_init(|| {
            let temp = std::env::temp_dir();
            remove_stale_scratch_dirs(&temp);
            claim_scratch_dir(&temp)
        })
        .path
}

/// Creates a scratch directory in `temp` and locks its [`LOCK_FILE`]. The lock file is created
/// and locked as [`STAGING_LOCK_FILE`], then renamed, so no other process can find it unlocked;
/// until then the directory has no lock file, which the cleanup leaves alone. Renaming the open
/// file rather than the directory also works on Windows, which cannot rename a directory holding
/// an open file. The directory's name holds the process ID and the time, so processes with the
/// same ID in different containers sharing `temp` get different ones.
fn claim_scratch_dir(temp: &Path) -> ScratchDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let path = temp.join(format!("{SCRATCH_PREFIX}{}_{nanos}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    let staging = path.join(STAGING_LOCK_FILE);
    let lock = File::create(&staging).unwrap();
    lock.lock().unwrap();
    fs::rename(&staging, path.join(LOCK_FILE)).unwrap();
    ScratchDir { path, _lock: lock }
}

/// Removes the scratch directories in `temp` whose [`LOCK_FILE`] no process holds, because the
/// process that made them has ended.
///
/// It leaves alone what it cannot judge: a directory without a lock file, such as one made
/// before scratch directories had them, or one left by a process that ended while setting it up,
/// which holds only [`STAGING_LOCK_FILE`]. Those need removing by hand.
fn remove_stale_scratch_dirs(temp: &Path) {
    let Ok(entries) = fs::read_dir(temp) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(SCRATCH_PREFIX));
        if !ours {
            continue;
        }
        let Ok(lock) = File::open(entry.path().join(LOCK_FILE)) else {
            continue;
        };
        if lock.try_lock().is_ok() {
            // Close the lock file first: Windows cannot delete a file that is open. No other
            // process can claim the directory meanwhile, since every claim makes a new name.
            drop(lock);
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::ops::Deref;

    use super::*;

    /// A folder for one test, outside [`SCRATCH_PREFIX`]'s names, removed even if the test fails.
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "lau_bigfun_fuzz-test-{name}-{}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Deref for TestRoot {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Creates the scratch folder `name` under `root` with a lock file, and returns that file.
    fn scratch_with_lock_file(root: &Path, name: &str) -> File {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        File::create(dir.join(LOCK_FILE)).unwrap()
    }

    #[test]
    fn removes_only_scratch_dirs_whose_lock_is_free() {
        let root = TestRoot::new("cleanup");
        let held = scratch_with_lock_file(&root, &format!("{SCRATCH_PREFIX}held"));
        held.lock().unwrap();
        drop(scratch_with_lock_file(
            &root,
            &format!("{SCRATCH_PREFIX}free"),
        ));
        fs::create_dir_all(root.join(format!("{SCRATCH_PREFIX}no_lock_file"))).unwrap();
        fs::create_dir_all(root.join("unrelated")).unwrap();

        remove_stale_scratch_dirs(&root);

        let kept = ["held", "free", "no_lock_file"]
            .map(|name| root.join(format!("{SCRATCH_PREFIX}{name}")).exists());
        assert_eq!(kept, [true, false, true]);
        assert!(root.join("unrelated").exists());
    }

    #[test]
    fn scratch_dir_is_claimed_once_per_process() {
        // The directory stays: it is this test process's, and removing it would leave
        // `scratch_dir` returning a deleted path. The next process to call it cleans it up.
        assert_eq!(scratch_dir(), scratch_dir());
    }

    #[test]
    fn claimed_scratch_dir_is_locked() {
        let root = TestRoot::new("claim");
        let claimed = claim_scratch_dir(&root);
        let lock = File::open(claimed.path.join(LOCK_FILE)).unwrap();
        assert!(lock.try_lock().is_err());
    }
}
