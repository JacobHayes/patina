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
//! exists ([`inotify::watching`]). An event on an open file whose last name
//! went still reaches that name's directory (the unhashed dentry keeps its
//! parent), but not a watch that asked for `IN_EXCL_UNLINK`.

use patina_dst_abi::{Fd, FsEntryKind, FsMetadata};

use crate::thread::inotify::{
    self, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_ISDIR, IN_MOVE_SELF,
    IN_MOVED_FROM, IN_MOVED_TO, IN_OPEN, Target,
};
use crate::with_context_raw as with_context;

pub(crate) use crate::thread::inotify::{IN_ACCESS, IN_ATTRIB, IN_MODIFY};
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

/// The directory inode holding the entry canonical `path` names, and the
/// entry's name.
fn parent(path: &str) -> Option<(u64, &str)> {
    let (dir, name) = split(path)?;
    Some((lookup(dir)?.ino, name))
}

/// A directory-entry event on the entry `path` names.
fn entry(path: &str, mask: u32, cookie: u32) {
    if let Some((dir, name)) = parent(path) {
        inotify::notify(&[Target::Entry { dir, name }], mask, cookie, false);
    }
}

/// An event on a file: its directory's watches with `name`, then its own;
/// `unlinked` when its last name went.
fn child(parent: Option<(u64, &str)>, metadata: &FsMetadata, mask: u32, unlinked: bool) {
    let mask = mask | isdir(metadata);
    let own = Target::Inode(metadata.ino);
    match parent {
        Some((dir, name)) => {
            inotify::notify(&[Target::Entry { dir, name }, own], mask, 0, unlinked);
        }
        None => inotify::notify(&[own], mask, 0, unlinked),
    }
}

/// An event on the file a driver handle is open on: where its entry is now,
/// or, for one whose last name went, where it was.
fn on_open_file(handle: Fd, mask: u32, filtered: bool) {
    if !watching() {
        return;
    }
    let Ok(metadata) = with_context(|context| context.fs_fd_metadata_unrecorded(handle)) else {
        return;
    };
    match with_context(|context| context.fs_fd_path_unrecorded(handle)) {
        Ok(path) => child(parent(&path), &metadata, mask, false),
        Err(_) => {
            let last = inotify::last_entry(metadata.ino);
            let parent = last.as_ref().map(|(dir, name)| (*dir, name.as_str()));
            child(parent, &metadata, mask, filtered);
        }
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

/// `ino`'s last name, `path`, went.
fn last_name_gone(ino: u64, path: &str) {
    if held(ino) {
        let entry = parent(path).map(|(dir, name)| (dir, name.to_owned()));
        inotify::unlinked(ino, true, entry);
    } else if inotify::watched(ino) {
        inotify::unlinked(ino, false, None);
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
    let own = [Target::Inode(source.ino)];
    inotify::notify(&own, IN_ATTRIB | isdir(source), 0, false);
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
        inotify::notify(&[Target::Inode(before.ino)], IN_ATTRIB, 0, false);
    }
    if directory || before.nlink <= 1 {
        last_name_gone(before.ino, path);
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
        let own = [Target::Inode(target.ino)];
        inotify::notify(&own, IN_ATTRIB | isdir(target), 0, false);
    }
    inotify::notify(&[Target::Inode(source.ino)], IN_MOVE_SELF, 0, false);
    if let Some(target) = target {
        if target.kind == FsEntryKind::Directory || target.nlink <= 1 {
            last_name_gone(target.ino, to);
        }
    }
}

/// `RENAME_EXCHANGE`: two moves, each with its own cookie.
pub(crate) fn exchanged(first: &str, second: &str, a: &FsMetadata, b: &FsMetadata) {
    moved(first, second, a, None);
    moved(second, first, b, None);
}

/// A changed attribute of the file at `path` (`fsnotify_change`,
/// `fsnotify_xattr`).
pub(crate) fn on_path(path: &str, mask: u32) {
    if !watching() {
        return;
    }
    if let Some(metadata) = lookup(path) {
        child(parent(path), &metadata, mask, false);
    }
}

/// A changed attribute of a node known only by inode (a FIFO's endpoint):
/// its own watches.
pub(crate) fn on_inode(ino: u64, mask: u32) {
    if watching() {
        inotify::notify(&[Target::Inode(ino)], mask, 0, false);
    }
}

/// An extended attribute of `target` changed (`fsnotify_xattr`).
pub(crate) fn xattr_changed(target: &patina_dst_abi::XattrTarget) {
    use patina_dst_abi::XattrTarget;
    match target {
        XattrTarget::Path(path) => on_path(path, IN_ATTRIB),
        XattrTarget::Fd(handle) => on_handle(*handle, IN_ATTRIB),
        XattrTarget::Inode(ino) => on_inode(*ino, IN_ATTRIB),
    }
}

/// A changed attribute of the file a driver handle is open on
/// (`fsnotify_change` through a descriptor): `IN_EXCL_UNLINK` does not
/// apply.
pub(crate) fn on_handle(handle: Fd, mask: u32) {
    on_open_file(handle, mask, false);
}

/// An access through a description (`fsnotify_file`: a read, a write, an
/// allocation, an open, a close).
pub(crate) fn on_file(handle: Fd, mask: u32) {
    on_open_file(handle, mask, true);
}

/// `fsnotify_open`.
pub(crate) fn opened(handle: Fd) {
    on_file(handle, IN_OPEN);
}

/// `fsnotify_close`: the last reference to a description went, opened with
/// write access or without; its handle is still open.
pub(crate) fn closing(handle: Fd, wrote: bool) {
    let mask = if wrote {
        IN_CLOSE_WRITE
    } else {
        IN_CLOSE_NOWRITE
    };
    on_file(handle, mask);
}

/// What setting times shows (`fsnotify_change`): both times `IN_ATTRIB`, the
/// access time alone `IN_ACCESS`, the modification time alone `IN_MODIFY`,
/// neither nothing.
pub(crate) fn times_mask(atime: bool, mtime: bool) -> u32 {
    match (atime, mtime) {
        (true, true) => IN_ATTRIB,
        (true, false) => IN_ACCESS,
        (false, true) => IN_MODIFY,
        (false, false) => 0,
    }
}

/// A reference to the filesystem let go (a description closed, the working
/// directory moved): a deleted inode nothing holds any more is gone, and its
/// watches end.
pub(crate) fn released() {
    for ino in inotify::deleted() {
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
