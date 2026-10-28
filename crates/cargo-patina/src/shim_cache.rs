//! Content-addressed shim cache entries. Each catalog has one lock, held while
//! an entry is looked up or created and while idle entries are removed.
use super::{CliError, lock_target_dir};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub(super) const COMPLETE: &str = ".complete";
/// Touched each time an entry is taken; its mtime is the entry's last use.
const USED: &str = ".used";
/// How long an entry outlives its last use. Taking an entry marks it used
/// under the catalog lock, so only an entry nobody has taken for a day goes.
const KEEP_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

fn error(path: &Path, e: io::Error) -> CliError {
    CliError(format!("shim cache {}: {e}", path.display()))
}

fn cleanup_warning(result: Result<(), CliError>) {
    if let Err(error) = result {
        eprintln!("warning: shim cache cleanup: {error}");
    }
}

/// The entry `root/key`, created if missing and marked used now.
pub(super) fn entry(root: &Path, key: &str) -> Result<PathBuf, CliError> {
    entry_initialized(root, key, || Ok(()))
}

/// [`entry`], running `initialize` first under the catalog lock.
pub(super) fn entry_initialized(
    root: &Path,
    key: &str,
    initialize: impl FnOnce() -> Result<(), CliError>,
) -> Result<PathBuf, CliError> {
    let _catalog = lock_target_dir(root)?;
    initialize()?;
    let dir = root.join(key);
    fs::create_dir_all(&dir).map_err(|e| error(&dir, e))?;
    let used = dir.join(USED);
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&used)
        .and_then(|file| file.set_modified(SystemTime::now()))
        .map_err(|e| error(&used, e))?;
    cleanup_warning(prune_idle(root, SystemTime::now()));
    Ok(dir)
}

/// Remove the discoverable name BEFORE deleting any bytes, so an interrupted
/// delete never leaves a torn entry under its key. The caller holds the lock.
pub(super) fn retire(dir: &Path) -> Result<(), CliError> {
    let stage = tempfile::Builder::new()
        .prefix(".tombstone-")
        .tempdir_in(dir.parent().expect("cache entry has a parent"))
        .map_err(|e| error(dir, e))?;
    fs::rename(dir, stage.path()).map_err(|e| error(dir, e))?;
    cleanup_warning(fs::remove_dir_all(stage.keep()).map_err(|e| error(dir, e)));
    Ok(())
}

/// Under the catalog lock: drop hidden directories (staging and tombstones,
/// which only a crashed holder of the lock leaves) and entries idle past
/// [`KEEP_IDLE`] at `now`.
fn prune_idle(root: &Path, now: SystemTime) -> Result<(), CliError> {
    for entry in fs::read_dir(root).map_err(|e| error(root, e))? {
        let entry = entry.map_err(|e| error(root, e))?;
        let dir = entry.path();
        if !entry.file_type().map_err(|e| error(&dir, e))?.is_dir() {
            continue;
        }
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            cleanup_warning(fs::remove_dir_all(&dir).map_err(|e| error(&dir, e)));
            continue;
        }
        let used = fs::metadata(dir.join(USED))
            .or_else(|_| fs::metadata(&dir))
            .and_then(|meta| meta.modified())
            .map_err(|e| error(&dir, e))?;
        if now.duration_since(used).unwrap_or_default() > KEEP_IDLE {
            cleanup_warning(retire(&dir));
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
        if cache_metadata(&entry.file_name()) {
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

/// Incremental compilation state of some packages, moved out of a Cargo target
/// dir while `cargo clean -p` removes their artifacts, and put back after.
pub(super) struct IncrementalHistory {
    kept: PathBuf,
    moved: Vec<(PathBuf, PathBuf)>,
}

impl IncrementalHistory {
    const KEPT: &str = ".incremental-kept";

    /// Move each profile's incremental directories of `packages` (named by
    /// crate, `<crate>-<hash>`) under `target`'s holding directory, after
    /// clearing whatever an interrupted earlier switch left there.
    pub(super) fn set_aside(target: &Path, packages: &[&str]) -> Result<Self, CliError> {
        let kept = target.join(Self::KEPT);
        if kept.exists() {
            fs::remove_dir_all(&kept).map_err(|e| error(&kept, e))?;
        }
        let mut moved = Vec::new();
        for profile in ["debug", "release"] {
            let incremental = target.join(profile).join("incremental");
            let Ok(entries) = fs::read_dir(&incremental) else {
                continue;
            };
            for entry in entries {
                let name = entry.map_err(|e| error(&incremental, e))?.file_name();
                let text = name.to_string_lossy();
                let owned = packages.iter().any(|package| {
                    text.strip_prefix(&package.replace('-', "_"))
                        .is_some_and(|rest| rest.starts_with('-'))
                });
                if !owned {
                    continue;
                }
                let holding = kept.join(profile);
                fs::create_dir_all(&holding).map_err(|e| error(&holding, e))?;
                let (from, to) = (incremental.join(&name), holding.join(&name));
                fs::rename(&from, &to).map_err(|e| error(&from, e))?;
                moved.push((to, from));
            }
        }
        Ok(Self { kept, moved })
    }

    /// Put the histories back. One that cannot return is dropped with a
    /// warning: rustc then compiles that crate from scratch.
    pub(super) fn restore(self) {
        for (from, to) in &self.moved {
            let returned = to
                .parent()
                .map_or(Ok(()), fs::create_dir_all)
                .and_then(|()| fs::rename(from, to));
            cleanup_warning(returned.map_err(|e| error(to, e)));
        }
        if self.kept.exists() {
            cleanup_warning(fs::remove_dir_all(&self.kept).map_err(|e| error(&self.kept, e)));
        }
    }
}

/// Whether `name` is this cache's own bookkeeping (a use or completion
/// marker), which is never part of an entry's sources.
pub(super) fn cache_metadata(name: &std::ffi::OsStr) -> bool {
    name == USED || name == COMPLETE
}

/// Whether `a` and `b` hold the same bytes: one file each, or two directories
/// with the same entries (cache metadata aside) holding the same bytes. A
/// missing side is never the same.
pub(super) fn same_tree(a: &Path, b: &Path) -> Result<bool, CliError> {
    let (meta_a, meta_b) = match (fs::metadata(a), fs::metadata(b)) {
        (Ok(meta_a), Ok(meta_b)) => (meta_a, meta_b),
        (Err(e), _) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        (_, Err(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        (Err(e), _) => return Err(error(a, e)),
        (_, Err(e)) => return Err(error(b, e)),
    };
    if meta_a.is_dir() != meta_b.is_dir() {
        return Ok(false);
    }
    if !meta_a.is_dir() {
        return Ok(meta_a.len() == meta_b.len()
            && fs::read(a).map_err(|e| error(a, e))? == fs::read(b).map_err(|e| error(b, e))?);
    }
    let names = |dir: &Path| -> Result<Vec<std::ffi::OsString>, CliError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).map_err(|e| error(dir, e))? {
            let name = entry.map_err(|e| error(dir, e))?.file_name();
            if !cache_metadata(&name) {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    };
    let entries = names(a)?;
    if entries != names(b)? {
        return Ok(false);
    }
    for name in entries {
        if !same_tree(&a.join(&name), &b.join(&name))? {
            return Ok(false);
        }
    }
    Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taking_an_entry_removes_only_entries_idle_past_a_day() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let idle = entry(root, "idle").unwrap();
        fs::write(idle.join("archive"), b"old").unwrap();
        let recent = entry(root, "recent").unwrap();
        let ago = SystemTime::now() - KEEP_IDLE - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(idle.join(USED))
            .unwrap()
            .set_modified(ago)
            .unwrap();
        fs::create_dir(root.join(".staging-abandoned")).unwrap();
        let taken = entry(root, "taken").unwrap();
        assert!(!idle.exists());
        assert!(recent.exists());
        assert!(taken.exists());
        assert!(!root.join(".staging-abandoned").exists());
        // An entry taken again is fresh, whatever its age before.
        fs::File::options()
            .write(true)
            .open(recent.join(USED))
            .unwrap()
            .set_modified(ago)
            .unwrap();
        assert_eq!(entry(root, "recent").unwrap(), recent);
        assert!(recent.exists());
    }
}
