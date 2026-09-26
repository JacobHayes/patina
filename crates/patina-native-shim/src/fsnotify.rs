//! The filesystem's notification hooks (the kernel's `include/linux/fsnotify.h`),
//! called by the `patina_*` filesystem entries once an operation took effect,
//! so an inotify watch sees what the kernel would show it, in its order.
//! Linux only.
//!
//! Three shapes of event, as the kernel reports them:
//!
//! * a directory-entry event (`IN_CREATE`, `IN_DELETE`, `IN_MOVED_FROM`,
//!   `IN_MOVED_TO`) goes to the directory's watches with the entry's name;
//! * an event on a file (`IN_ACCESS`, `IN_MODIFY`, `IN_ATTRIB` from a changed
//!   attribute, `IN_OPEN`, `IN_CLOSE_*`) goes to its directory's watches with
//!   its name (`fsnotify_parent`), then to its own without one;
//! * an event on an inode alone (`IN_ATTRIB` from a link count,
//!   `IN_MOVE_SELF`, `IN_DELETE_SELF`) goes to its own watches.
//!
//! A directory's events carry `IN_ISDIR`, but for `IN_MOVE_SELF` and
//! `IN_DELETE_SELF`. An inode whose last name goes is deleted when its last
//! reference does (`dentry_unlink_inode`): at once, or when the last
//! descriptor, `O_PATH` or working directory holding it lets go.
//!
//! Every lookup here is the kernel's own inside the call (an unrecorded
//! driver read, no latency, no fault), and nothing is computed while no watch
//! exists ([`inotify::watching`]). An open file whose last name went reports
//! to its own watches only: its former directory's watches see nothing, as
//! under `IN_EXCL_UNLINK`.

use patina_dst_abi::{Fd, FsEntryKind, FsMetadata};

use crate::thread::inotify::{
    self, IN_ATTRIB, IN_CREATE, IN_DELETE, IN_ISDIR, IN_MOVE_SELF, IN_MOVED_FROM, IN_MOVED_TO,
    Target,
};
use crate::with_context_raw as with_context;

pub(crate) use crate::thread::inotify::{IN_ACCESS, IN_MODIFY};
pub(crate) use inotify::watching;

fn lookup(path: &str) -> Option<FsMetadata> {
    with_context(|context| context.fs_metadata_unrecorded(path)).ok()
}

/// The directory holding canonical `path` and the entry's name in it; none
/// for the root.
fn split(path: &str) -> Option<(&str, &str)> {
    let index = path.rfind('/')?;
    let name = &path[index + 1..];
    if name.is_empty() {
        return None;
    }
    Some((if index == 0 { "/" } else { &path[..index] }, name))
}

fn isdir(metadata: &FsMetadata) -> u32 {
    if metadata.kind == FsEntryKind::Directory {
        IN_ISDIR
    } else {
        0
    }
}

/// A directory-entry event on the entry `path` names.
fn entry(path: &str, mask: u32, cookie: u32) {
    let Some((dir, name)) = split(path) else {
        return;
    };
    if let Some(dir) = lookup(dir) {
        inotify::notify(&[Target::Entry { dir: dir.ino, name }], mask, cookie);
    }
}

/// An event on a file at `path` (none for one whose last name went).
fn child(path: Option<&str>, metadata: &FsMetadata, mask: u32) {
    let mask = mask | isdir(metadata);
    let parent = path
        .and_then(split)
        .and_then(|(dir, name)| Some((lookup(dir)?.ino, name)));
    match parent {
        Some((dir, name)) => inotify::notify(
            &[Target::Entry { dir, name }, Target::Inode(metadata.ino)],
            mask,
            0,
        ),
        None => inotify::notify(&[Target::Inode(metadata.ino)], mask, 0),
    }
}

/// Whether a descriptor's description or the working directory holds `ino`.
fn held(ino: u64) -> bool {
    let mut handles = crate::fd_table().lock().fs_handles();
    handles.extend(crate::paths::cwd_held().map(|fd| fd.0));
    handles.into_iter().any(|handle| {
        with_context(|context| context.fs_fd_metadata_unrecorded(Fd(handle)))
            .is_ok_and(|metadata| metadata.ino == ino)
    })
}

/// `ino`'s last name went.
fn last_name_gone(ino: u64) {
    if inotify::watched(ino) {
        inotify::unlinked(ino, held(ino));
    }
}

/// `fsnotify_create`/`fsnotify_mkdir`: `path` came into existence.
pub(crate) fn created(path: &str) {
    if !watching() {
        return;
    }
    if let Some(metadata) = lookup(path) {
        entry(path, IN_CREATE | isdir(&metadata), 0);
    }
}

/// `fsnotify_link`: `source` gained the name `to` (its link count, then the
/// new entry).
pub(crate) fn linked(source: &FsMetadata, to: &str) {
    if !watching() {
        return;
    }
    inotify::notify(&[Target::Inode(source.ino)], IN_ATTRIB | isdir(source), 0);
    entry(to, IN_CREATE | isdir(source), 0);
}

/// `vfs_unlink`/`vfs_rmdir`: the entry `path` named, `before` it went, is
/// gone — a file's link count changed, the inode is deleted with its last
/// name, then the directory's entry is.
pub(crate) fn removed(path: &str, before: &FsMetadata) {
    if !watching() {
        return;
    }
    let directory = before.kind == FsEntryKind::Directory;
    if !directory {
        inotify::notify(&[Target::Inode(before.ino)], IN_ATTRIB, 0);
    }
    if directory || before.nlink <= 1 {
        last_name_gone(before.ino);
    }
    entry(path, IN_DELETE | isdir(before), 0);
}

/// `fsnotify_move`: `source` went from `from` to `to`, replacing `target`.
/// A rename between two names of one inode changed nothing.
pub(crate) fn moved(from: &str, to: &str, source: &FsMetadata, target: Option<&FsMetadata>) {
    if !watching() || target.is_some_and(|target| target.ino == source.ino) {
        return;
    }
    let cookie = inotify::next_cookie();
    entry(from, IN_MOVED_FROM | isdir(source), cookie);
    entry(to, IN_MOVED_TO | isdir(source), cookie);
    if let Some(target) = target {
        inotify::notify(&[Target::Inode(target.ino)], IN_ATTRIB | isdir(target), 0);
    }
    inotify::notify(&[Target::Inode(source.ino)], IN_MOVE_SELF, 0);
    if let Some(target) = target {
        if target.kind == FsEntryKind::Directory || target.nlink <= 1 {
            last_name_gone(target.ino);
        }
    }
}

/// `RENAME_EXCHANGE`: two moves, each with its own cookie.
pub(crate) fn exchanged(first: &str, second: &str, a: &FsMetadata, b: &FsMetadata) {
    moved(first, second, a, None);
    moved(second, first, b, None);
}

/// An event on the file at `path` (`fsnotify_change` and friends).
pub(crate) fn on_path(path: &str, mask: u32) {
    if !watching() {
        return;
    }
    if let Some(metadata) = lookup(path) {
        child(Some(path), &metadata, mask);
    }
}

/// An event on the file a driver handle is open on (`fsnotify_file`).
pub(crate) fn on_handle(handle: Fd, mask: u32) {
    if !watching() {
        return;
    }
    let Ok(metadata) = with_context(|context| context.fs_fd_metadata_unrecorded(handle)) else {
        return;
    };
    let path = with_context(|context| context.fs_fd_path_unrecorded(handle)).ok();
    child(path.as_deref(), &metadata, mask);
}

/// A reference to the filesystem let go (a description closed, the working
/// directory moved): a deleted inode nothing holds any more ends its watches.
pub(crate) fn released() {
    for ino in inotify::doomed() {
        if !held(ino) {
            inotify::settle(ino);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn a_canonical_path_splits_into_its_directory_and_name() {
        assert_eq!(split("/a"), Some(("/", "a")));
        assert_eq!(split("/a/b/c"), Some(("/a/b", "c")));
        assert_eq!(split("/"), None);
    }
}
