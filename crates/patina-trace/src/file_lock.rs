//! Advisory whole-file locks, and the locked scratch files traces are written
//! through.
//!
//! The kernel releases a `flock(2)` lock when the last descriptor of the open
//! file description holding it closes, and a process that exits or dies —
//! aborted, killed, `exit`ed without unwinding — closes every descriptor it
//! has. A lock therefore never outlives its holder, which neither a sentinel
//! file removed by a destructor nor a pid in a file name can promise: the
//! destructor may never run, and the pid is reused.

use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};

/// Take an exclusive advisory lock on `file`, held until it is closed. Two opens of
/// one file contend even inside one process. With `wait` false a lock held
/// elsewhere is [`io::ErrorKind::WouldBlock`].
pub fn lock_exclusive(file: &File, wait: bool) -> io::Result<()> {
    retry_interrupted(|| {
        if wait {
            file.lock()
        } else {
            file.try_lock().map_err(lock_error)
        }
    })
}

/// Take a shared advisory lock on `file`. Other shared holders may coexist;
/// exclusive holders contend. As with [`lock_exclusive`], correctness requires
/// a filesystem with working advisory flock semantics (not all NFS mounts do).
pub fn lock_shared(file: &File, wait: bool) -> io::Result<()> {
    retry_interrupted(|| {
        if wait {
            file.lock_shared()
        } else {
            file.try_lock_shared().map_err(lock_error)
        }
    })
}

fn lock_error(error: fs::TryLockError) -> io::Error {
    // Cache eviction, campaign ownership and trace writers share this contract:
    // contention stays WouldBlock rather than becoming an ordinary I/O failure.
    match error {
        fs::TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
        fs::TryLockError::Error(error) => error,
    }
}

fn retry_interrupted(mut acquire: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    // std's Unix File locks can return Interrupted; retain our wait policy.
    loop {
        match acquire() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

/// Whether `path` names the file `file` has open. False once the name is
/// unlinked or names a different file.
#[cfg(unix)]
pub fn path_names(path: &Path, file: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let open = file.metadata()?;
    match fs::metadata(path) {
        Ok(named) => Ok(named.dev() == open.dev() && named.ino() == open.ino()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
pub fn path_names(_path: &Path, _file: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file identity is unsupported on this platform",
    ))
}

/// Create a scratch file beside `path` to write it through and rename onto it:
/// `.<name>.tmp.<random>`, a name no other writer holds, locked until the
/// returned file closes so [`remove_dead_scratch`] can tell it from one a dead
/// writer left.
pub fn create_scratch(path: &Path) -> io::Result<(PathBuf, File)> {
    let prefix = scratch_prefix(path)?;
    loop {
        let mut name = prefix.clone();
        name.push(format!(
            "{:016x}",
            RandomState::new().build_hasher().finish()
        ));
        let scratch = path.with_file_name(name);
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&scratch)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        // A sweep can lock and unlink the file between its creation and this
        // lock, leaving the lock on a name nobody else opens; draw a new name
        // then.
        match lock_exclusive(&file, false) {
            Ok(()) if path_names(&scratch, &file)? => return Ok((scratch, file)),
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
}

/// Remove the scratch files beside `path` that no writer holds: their writers
/// died before renaming them.
pub fn remove_dead_scratch(path: &Path) {
    let Ok(prefix) = scratch_prefix(path) else {
        return;
    };
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(prefix.as_encoded_bytes())
        {
            continue;
        }
        let scratch = entry.path();
        let Ok(file) = File::open(&scratch) else {
            continue;
        };
        // Unlinked while this lock is held: a writer that opened the name just
        // before sees its lock on an unlinked file and draws a new name.
        if lock_exclusive(&file, false).is_ok() && path_names(&scratch, &file).unwrap_or(false) {
            let _ = fs::remove_file(&scratch);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Class-level detector for every cache/campaign/trace lock caller: distinct
    // handles must contend, and closing the holder must release ownership.
    #[test]
    fn exclusive_contention_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("exclusive");
        let owner = File::create(&path).unwrap();
        let contender = OpenOptions::new().write(true).open(&path).unwrap();
        let reader = File::open(&path).unwrap();
        lock_exclusive(&owner, true).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        assert_eq!(
            lock_exclusive(&contender, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            lock_shared(&reader, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(owner);
        lock_exclusive(&contender, false).unwrap();
        assert_eq!(
            lock_shared(&reader, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(contender);
        lock_shared(&reader, false).unwrap();
    }

    #[test]
    fn interruptions_retry_but_other_errors_propagate() {
        let mut calls = 0;
        retry_interrupted(|| {
            calls += 1;
            if calls < 3 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(
            retry_interrupted(|| Err(io::ErrorKind::PermissionDenied.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn shared_holders_coexist_and_exclusive_holders_contend() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("shared");
        let first = File::create(&path).unwrap();
        let second = OpenOptions::new().write(true).open(&path).unwrap();
        lock_shared(&first, true).unwrap();
        lock_shared(&second, false).unwrap();
        let contender = OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            lock_exclusive(&contender, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let path = temp.path().join("exclusive");
        let writer = File::create(&path).unwrap();
        lock_exclusive(&writer, false).unwrap();
        let reader = OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            lock_shared(&reader, false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

fn scratch_prefix(path: &Path) -> io::Result<OsString> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("trace path has no file name: {}", path.display()),
        )
    })?;
    let mut prefix = OsString::from(".");
    prefix.push(file_name);
    prefix.push(".tmp.");
    Ok(prefix)
}
