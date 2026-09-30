//! Bounded cache entries with kernel-held shared leases. Catalog locks cover
//! discovery, pinning and atomic retirement; only leases survive child exec.
use super::{CliError, TARGET_DIR_LOCK, lock_target_dir};
use patina_dst_trace::{lock_exclusive, lock_shared};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub(super) const KEEP_ARTIFACTS: usize = 4;
pub(super) const KEEP_SOURCES: usize = 4;
pub(super) const KEEP_BUILDS: usize = 2;
pub(super) const BUILD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const COMPLETE: &str = ".complete";
const LEASE: &str = ".lease";
const LEGACY_GRACE: Duration = Duration::from_secs(3600);

pub(super) struct Lease {
    pub dir: PathBuf,
    file: fs::File,
}

/// Inherit ONLY a shared lease. Build/catalog locks retain OpenOptions' CLOEXEC:
/// a compiler wrapper may daemonize, and its server must not monopolize builds.
/// A clone belongs to the consuming command; clearing CLOEXEC happens only in
/// its child, never by changing descriptor flags in the multithreaded parent.
pub(super) fn inherit(command: &mut std::process::Command, lease: &Lease) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let file = lease
            .file
            .try_clone()
            .map_err(|e| CliError(format!("cloning shim cache lease: {e}")))?;
        // SAFETY: pre_exec only calls async-signal-safe fcntl on a live fd. The
        // crate's variadic declaration also preserves the Darwin arm64 ABI.
        unsafe {
            command.pre_exec(move || {
                if super::fcntl(file.as_raw_fd(), super::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (command, lease);
    Ok(())
}

fn error(path: &Path, e: io::Error) -> CliError {
    CliError(format!("shim cache {}: {e}", path.display()))
}

fn cleanup_warning(result: Result<(), CliError>) {
    if let Err(error) = result {
        eprintln!("warning: shim cache cleanup: {error}");
    }
}

/// Pin before exposing a path, while the same catalog lock excludes pruning.
/// The pruner never waits for an exclusive lease under the catalog lock.
pub(super) fn acquire(root: &Path, key: &str, keep: usize) -> Result<Lease, CliError> {
    acquire_initialized(root, key, keep, || Ok(()))
}

pub(super) fn acquire_initialized(
    root: &Path,
    key: &str,
    keep: usize,
    initialize: impl FnOnce() -> Result<(), CliError>,
) -> Result<Lease, CliError> {
    let _catalog = lock_target_dir(root)?;
    initialize()?;
    let dir = root.join(key);
    fs::create_dir_all(&dir).map_err(|e| error(&dir, e))?;
    let path = dir.join(LEASE);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| error(&path, e))?;
    lock_shared(&file, true).map_err(|e| error(&path, e))?;
    file.set_modified(SystemTime::now())
        .map_err(|e| error(&path, e))?;
    let lease = Lease { dir, file };
    cleanup_warning(prune_locked(root, keep, &|path| fs::remove_dir_all(path)));
    Ok(lease)
}

/// Remove the discoverable name BEFORE deleting any bytes. The caller holds
/// the catalog (or private workspace) lock and has excluded live readers.
fn tombstone(dir: &Path) -> Result<PathBuf, CliError> {
    let stage = tempfile::Builder::new()
        .prefix(".tombstone-")
        .tempdir_in(dir.parent().expect("cache entry has a parent"))
        .map_err(|e| error(dir, e))?;
    fs::rename(dir, stage.path()).map_err(|e| error(dir, e))?;
    Ok(stage.keep())
}

pub(super) fn retire(dir: &Path) -> Result<(), CliError> {
    let dead = tombstone(dir)?;
    cleanup_warning(fs::remove_dir_all(&dead).map_err(|e| error(&dead, e)));
    Ok(())
}

fn prune_locked(
    root: &Path,
    keep: usize,
    remove: &impl Fn(&Path) -> io::Result<()>,
) -> Result<(), CliError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| error(root, e))? {
        let entry = entry.map_err(|e| error(root, e))?;
        if !entry
            .file_type()
            .map_err(|e| error(&entry.path(), e))?
            .is_dir()
        {
            continue;
        }
        let dir = entry.path();
        // All staging/retirement runs under this catalog. Hidden directories
        // can never be cache hits or consume retention slots, even after a crash.
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            cleanup_warning(remove(&dir).map_err(|e| error(&dir, e)));
            continue;
        }
        let lease = dir.join(LEASE);
        let modified = match fs::metadata(&lease) {
            Ok(meta) => meta.modified().map_err(|e| error(&lease, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => SystemTime::UNIX_EPOCH,
            Err(e) => return Err(error(&lease, e)),
        };
        entries.push((modified, dir));
    }
    entries.sort_by(|a, b| b.cmp(a));
    for (_, dir) in entries.into_iter().skip(keep) {
        let path = dir.join(LEASE);
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| error(&path, e))?;
        match lock_exclusive(&file, false) {
            Ok(()) => {
                // A failed rename leaves a whole live entry; a failed delete
                // leaves only an undiscoverable tombstone. Both are retryable.
                match tombstone(&dir) {
                    Ok(dead) => cleanup_warning(remove(&dead).map_err(|e| error(&dead, e))),
                    Err(e) => cleanup_warning(Err(e)),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(error(&path, e)),
        }
    }
    Ok(())
}

pub(super) fn complete(dir: &Path, bundle: &str) -> Result<bool, CliError> {
    let path = dir.join(COMPLETE);
    match fs::read_to_string(&path) {
        Ok(value) => Ok(value == bundle && dir.join("Cargo.toml").is_file()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(error(&path, e)),
    }
}

/// Copy source bytes, not cache metadata. The caller writes completion LAST,
/// after copying and invalidating Cargo's local-package fingerprints.
pub(super) fn copy_sources(from: &Path, to: &Path) -> Result<(), CliError> {
    fs::create_dir_all(to).map_err(|e| error(to, e))?;
    for entry in fs::read_dir(from).map_err(|e| error(from, e))? {
        let entry = entry.map_err(|e| error(from, e))?;
        if entry.file_name() == LEASE || entry.file_name() == COMPLETE {
            continue;
        }
        let dest = to.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|e| error(&entry.path(), e))?
            .is_dir()
        {
            copy_sources(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest).map_err(|e| error(&dest, e))?;
        }
    }
    Ok(())
}

fn bytes(dir: &Path) -> Result<u64, CliError> {
    let mut size = 0;
    if !dir.exists() {
        return Ok(size);
    }
    for entry in fs::read_dir(dir).map_err(|e| error(dir, e))? {
        let entry = entry.map_err(|e| error(dir, e))?;
        let meta = entry.metadata().map_err(|e| error(&entry.path(), e))?;
        if meta.is_dir() {
            size += bytes(&entry.path())?;
        } else {
            size += meta.len();
        }
    }
    Ok(size)
}

/// Optional high-water cleanup under the private workspace's build lock. As
/// with catalog eviction, failed deletion must not turn a cache miss into a
/// failed user build; interrupted deletion stays behind an undiscoverable name.
pub(super) fn trim_build_target(work: &Path) {
    cleanup_warning((|| {
        for entry in fs::read_dir(work).map_err(|e| error(work, e))? {
            let entry = entry.map_err(|e| error(work, e))?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".tombstone-")
                && entry
                    .file_type()
                    .map_err(|e| error(&entry.path(), e))?
                    .is_dir()
            {
                cleanup_warning(
                    fs::remove_dir_all(entry.path()).map_err(|e| error(&entry.path(), e)),
                );
            }
        }
        let target = work.join("target");
        if bytes(&target)? > BUILD_BYTES {
            retire(&target)?;
        }
        Ok(())
    })());
}

// Inspect directory mtimes and file mtime/atime without reading their contents.
// Directory atimes are excluded: our own scan would refresh them indefinitely.
fn last_use(path: &Path) -> Result<SystemTime, CliError> {
    let meta = fs::symlink_metadata(path).map_err(|e| error(path, e))?;
    let mut latest = meta.modified().map_err(|e| error(path, e))?;
    if meta.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| error(path, e))? {
            latest = latest.max(last_use(&entry.map_err(|e| error(path, e))?.path())?);
        }
    } else if meta.is_file() {
        latest = latest.max(meta.accessed().map_err(|e| error(path, e))?);
    }
    Ok(latest)
}

/// Old layouts have no leases. Honor their build locks and leave recently used
/// entries alone for an hour. This grace is not a substitute for quiescent
/// migration: old-version readers/waiters cannot join the new protocol.
pub(super) fn prune_legacy(base: &Path) {
    cleanup_warning(prune_legacy_locked(base));
}

fn prune_legacy_locked(base: &Path) -> Result<(), CliError> {
    let _catalog = lock_target_dir(base)?;
    for entry in fs::read_dir(base).map_err(|e| error(base, e))? {
        let entry = entry.map_err(|e| error(base, e))?;
        if !entry
            .file_type()
            .map_err(|e| error(&entry.path(), e))?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".tombstone-") {
            cleanup_warning(fs::remove_dir_all(entry.path()).map_err(|e| error(&entry.path(), e)));
            continue;
        }
        if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let path = entry.path().join(TARGET_DIR_LOCK);
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| error(&path, e))?;
        match lock_exclusive(&file, false) {
            Ok(()) => {
                if SystemTime::now()
                    .duration_since(last_use(&entry.path())?)
                    .unwrap_or_default()
                    > LEGACY_GRACE
                {
                    cleanup_warning(retire(&entry.path()));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(error(&path, e)),
        }
    }
    Ok(())
}

/// Call only while holding the containing entry's publication/build lock.
pub(super) fn clear_partial(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(error(path, e)),
    }
}

/// Delegate clone/copy selection to std, never hard-link Cargo's mutable output.
pub(super) fn copy(from: &Path, to: &Path) -> Result<(), CliError> {
    fs::copy(from, to).map_err(|e| error(to, e))?;
    Ok(())
}

/// Tests that assert immediate lock release run in their own single-test
/// process. Unrelated libtest threads can fork while a descriptor is open; their
/// pre-exec children legitimately retain it briefly, even with CLOEXEC.
#[cfg(test)]
pub(super) fn isolated_test(name: &str) -> bool {
    if std::env::var("PATINA_SHIM_CACHE_TEST").as_deref() == Ok(name) {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("PATINA_SHIM_CACHE_TEST", name)
        .status()
        .unwrap();
    assert!(status.success(), "isolated test {name} failed: {status}");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_pins_readers_and_waiting_builders_then_reclaims_them() {
        if isolated_test(
            "shim_cache::tests::pruning_pins_readers_and_waiting_builders_then_reclaims_them",
        ) {
            return;
        }
        // Class detector: no path handoff without a lease, including waiters.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let active = acquire(root, "active", 1).unwrap();
        fs::write(active.dir.join("archive"), b"original").unwrap();
        let waiting = acquire(root, "active", 1).unwrap();
        let newer = acquire(root, "newer", 1).unwrap();
        assert_eq!(fs::read(active.dir.join("archive")).unwrap(), b"original");
        drop(active);
        let newest = acquire(root, "newest", 1).unwrap();
        assert!(waiting.dir.join("archive").exists());
        let old = waiting.dir.clone();
        drop(waiting);
        let _trigger = acquire(root, "newest", 1).unwrap();
        assert!(!old.exists());
        assert!(newer.dir.exists());
        assert!(newest.dir.exists());
    }

    #[test]
    fn interrupted_eviction_is_undiscoverable_and_failed_cleanup_is_retryable() {
        if isolated_test(
            "shim_cache::tests::interrupted_eviction_is_undiscoverable_and_failed_cleanup_is_retryable",
        ) {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let old = acquire(temp.path(), "old", 1).unwrap();
        fs::write(old.dir.join("archive"), b"old bytes").unwrap();
        let old_path = old.dir.clone();
        drop(old);
        let _catalog = lock_target_dir(temp.path()).unwrap();
        // Inject a failed recursive delete AFTER the atomic rename.
        prune_locked(temp.path(), 0, &|_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap();
        assert!(!old_path.exists());
        let dead = fs::read_dir(temp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.is_dir())
            .unwrap();
        assert_eq!(fs::read(dead.join("archive")).unwrap(), b"old bytes");
        fs::remove_file(dead.join("archive")).unwrap(); // interrupted partial delete
        let staging = temp.path().join(".abandoned.staging");
        fs::create_dir(&staging).unwrap();
        drop(_catalog);
        let fresh = acquire(temp.path(), "old", 1).unwrap();
        fs::write(fresh.dir.join("archive"), b"fresh bytes").unwrap();
        assert_eq!(fs::read(fresh.dir.join("archive")).unwrap(), b"fresh bytes");
        assert!(!dead.exists());
        assert!(!staging.exists());
    }

    #[test]
    #[cfg(unix)]
    fn consuming_subprocess_keeps_only_shared_lease_after_parent_handles_close() {
        if isolated_test(
            "shim_cache::tests::consuming_subprocess_keeps_only_shared_lease_after_parent_handles_close",
        ) {
            return;
        }
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};
        let temp = tempfile::tempdir().unwrap();
        let lease = acquire(temp.path(), "old", 1).unwrap();
        fs::write(lease.dir.join("archive"), b"pinned").unwrap();
        let build_lock = lock_target_dir(&lease.dir).unwrap();
        let old = lease.dir.clone();
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "echo READY; read reply; test -f \"$1/archive\"",
                "lease-child",
            ])
            .arg(&old)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        inherit(&mut command, &lease).unwrap();
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(build_lock);
        drop(lease);
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "READY");
        let _new = acquire(temp.path(), "new", 1).unwrap();
        assert!(old.join("archive").exists());
        let probe = fs::OpenOptions::new()
            .write(true)
            .open(old.join(TARGET_DIR_LOCK))
            .unwrap();
        lock_exclusive(&probe, false).unwrap(); // exclusive lock did NOT survive exec
        child.stdin.take().unwrap().write_all(b"finish\n").unwrap();
        assert!(child.wait().unwrap().success());
        let _new = acquire(temp.path(), "new", 1).unwrap();
        assert!(!old.exists());
    }

    #[test]
    fn copies_do_not_alias_mutable_build_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let from = temp.path().join("cargo.a");
        let to = temp.path().join("published.a");
        fs::write(&from, b"first").unwrap();
        copy(&from, &to).unwrap();
        fs::write(&from, b"other").unwrap();
        assert_eq!(fs::read(to).unwrap(), b"first");
    }

    #[test]
    fn legacy_targets_are_collected_but_locked_builds_and_unrelated_dirs_survive() {
        if isolated_test(
            "shim_cache::tests::legacy_targets_are_collected_but_locked_builds_and_unrelated_dirs_survive",
        ) {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("a".repeat(64));
        let lock = lock_target_dir(&old).unwrap();
        let unrelated = temp.path().join("builds");
        fs::create_dir(&unrelated).unwrap();
        prune_legacy(temp.path());
        assert!(old.exists());
        drop(lock);
        prune_legacy(temp.path());
        assert!(old.exists(), "recent legacy use must get its grace period");
        let ago = SystemTime::now() - LEGACY_GRACE - Duration::from_secs(60);
        for path in [old.join(TARGET_DIR_LOCK), old.clone()] {
            fs::File::open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(ago).set_accessed(ago))
                .unwrap();
        }
        let lock = lock_target_dir(&old).unwrap();
        prune_legacy(temp.path());
        assert!(old.exists(), "old but locked must survive too");
        drop(lock);
        prune_legacy(temp.path());
        assert!(!old.exists());
        assert!(unrelated.exists());
    }
}
