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
//! `IN_DELETE_SELF`.
//!
//! An event through a descriptor is reported through the name the
//! descriptor was opened through (its dentry), not whichever name the inode
//! has now: every descriptor and the working directory hold one, recorded at
//! the open ([`bound`]) and moved by a rename of that name. Unlinking or
//! renaming over a held name unhashes it: events through it still go to that
//! directory under that name, but skip the watches that asked for
//! `IN_EXCL_UNLINK`. An inode whose last name goes is deleted
//! (`dentry_unlink_inode`, `IN_DELETE_SELF`) at once when nothing held that
//! name, else when the first unhashed name holding it is let go.
//!
//! A FIFO endpoint holds the name it was opened through the same way, from
//! before its open waits for a partner. Its reads and writes reach only its
//! own watches: Ubuntu's 6.8 (from 6.8.0-108) carries the stable fix
//! "fsnotify: do not generate ACCESS/MODIFY events on child for special
//! files" (CVE-2025-68788), which stops a special file's data events
//! (`fsnotify_file`'s `IN_ACCESS`/`IN_MODIFY`) at its own watches. Upstream
//! v6.8 has no such rule. Its opens, closes and attribute changes still reach
//! the directory. A FIFO is the only special file on the volume a guest can
//! open for data (a device node there is `ENXIO`); `/dev/urandom` and its
//! directory cannot be watched.
//!
//! Every lookup here is bookkeeping inside the call (an unrecorded,
//! never-faulted driver read), and no event is computed while no watch exists
//! ([`inotify::watching`]); the names are recorded whether or not one does.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{Fd, FsEntryKind, FsMetadata};
use patina_dst_runtime::{Context, RuntimeError};

use crate::SpinMutex;
use crate::thread::inotify::{
    self, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_ISDIR, IN_MOVE_SELF,
    IN_MOVED_FROM, IN_MOVED_TO, IN_OPEN, Target,
};
use crate::with_context_raw as with_context;

pub(crate) use crate::thread::inotify::{IN_ACCESS, IN_ATTRIB, IN_MODIFY};
pub(crate) use inotify::watching;

/// What holds a name: a driver handle (a description's, the working
/// directory's), or a FIFO endpoint (a pipe end, which the filesystem does
/// not hold).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Holder {
    Handle(u64),
    Fifo(u64),
}

/// A directory inode and an entry name in it.
type Name<'a> = (u64, &'a str);

/// A name something was opened through: the kernel's dentry, as far as fs
/// notification sees it.
#[derive(Clone, Debug)]
struct Dentry {
    ino: u64,
    directory: bool,
    /// The directory inode and the name; none for the root.
    parent: Option<(u64, String)>,
    /// The name still stands; unlinked or renamed over, it is unhashed.
    hashed: bool,
    /// The holders referencing it.
    refs: usize,
}

/// Every held name. One nothing holds any more is forgotten: a later open
/// through the same name makes a new one, as the kernel's would be to
/// anything fs notification can tell.
struct Dentries {
    next: u64,
    all: BTreeMap<u64, Dentry>,
    /// The hashed ones, by name, then directory inode.
    hashed: BTreeMap<(String, u64), u64>,
    holders: BTreeMap<Holder, u64>,
    /// Inodes whose last name went while it was held.
    orphans: BTreeSet<u64>,
    /// Holders whose name an in-process crash left unknown (see
    /// [`Dentries::crashed`]).
    stale: BTreeSet<Holder>,
}

static DENTRIES: SpinMutex<Dentries> = SpinMutex::new(Dentries::new());

impl Dentries {
    const fn new() -> Self {
        Dentries {
            next: 0,
            all: BTreeMap::new(),
            hashed: BTreeMap::new(),
            holders: BTreeMap::new(),
            orphans: BTreeSet::new(),
            stale: BTreeSet::new(),
        }
    }

    /// The filesystem was rebuilt from its durable image by an in-process
    /// crash ([`crate::patina_crash`]), which renumbers every inode, may
    /// bring back a removed name and may lose a created one, while the
    /// descriptors survive. Every held name is looked up again through its
    /// descriptor, as the rebuilt image has it: the inode and the name the
    /// descriptor's node has now, hashed. A holder whose node kept no name,
    /// or a FIFO endpoint (whose node the filesystem does not hold), has no
    /// name to rebuild; it is stale, and an event through it while a watch
    /// exists stops the run by name.
    fn crashed(&mut self, context: &mut Context) {
        let holders = std::mem::take(&mut self.holders);
        self.all.clear();
        self.hashed.clear();
        self.orphans.clear();
        // Holders sharing a name share it again.
        let mut shared: BTreeMap<u64, Vec<Holder>> = BTreeMap::new();
        for (holder, id) in holders {
            shared.entry(id).or_default().push(holder);
        }
        for group in shared.into_values() {
            match group.iter().find_map(|holder| located(context, *holder)) {
                Some((ino, directory, parent)) => {
                    for holder in group {
                        self.hold(holder, ino, directory, parent.clone());
                    }
                }
                None => self.stale.extend(group),
            }
        }
    }

    /// `holder` takes the name `parent` gives `ino`: the held one standing
    /// there, or a new one.
    fn hold(&mut self, holder: Holder, ino: u64, directory: bool, parent: Option<(u64, String)>) {
        let standing = parent
            .as_ref()
            .and_then(|(dir, name)| self.hashed.get(&(name.clone(), *dir)).copied())
            .filter(|id| self.all[id].ino == ino);
        let id = standing.unwrap_or_else(|| {
            let id = self.next;
            self.next += 1;
            if let Some((dir, name)) = &parent {
                self.hashed.insert((name.clone(), *dir), id);
            }
            self.all.insert(
                id,
                Dentry {
                    ino,
                    directory,
                    parent,
                    hashed: true,
                    refs: 0,
                },
            );
            id
        });
        self.all.get_mut(&id).expect("held").refs += 1;
        self.holders.insert(holder, id);
    }

    /// `to` holds what `from` holds.
    fn share(&mut self, from: Holder, to: Holder) {
        if self.stale.contains(&from) {
            self.stale.insert(to);
        }
        if let Some(&id) = self.holders.get(&from) {
            self.all.get_mut(&id).expect("held").refs += 1;
            self.holders.insert(to, id);
        }
    }

    /// `holder` lets go of its name; answers the inode that ends with it
    /// (an unhashed name, the last of an inode with no name left).
    fn release(&mut self, holder: Holder) -> Option<u64> {
        if self.stale.remove(&holder) {
            return None;
        }
        let id = self.holders.remove(&holder)?;
        let dentry = self.all.get_mut(&id).expect("held");
        dentry.refs -= 1;
        if dentry.refs > 0 {
            return None;
        }
        let dentry = self.all.remove(&id).expect("held");
        if dentry.hashed {
            if let Some((dir, name)) = dentry.parent {
                let key = (name, dir);
                if self.hashed.get(&key) == Some(&id) {
                    self.hashed.remove(&key);
                }
            }
            return None;
        }
        self.orphans.remove(&dentry.ino).then_some(dentry.ino)
    }

    /// Whether some held name is `name`, in any directory.
    fn named(&self, name: &str) -> bool {
        self.hashed
            .range((name.to_owned(), 0)..=(name.to_owned(), u64::MAX))
            .next()
            .is_some()
    }

    /// The name `name` in `dir` went: whether something held it.
    fn unhash(&mut self, dir: u64, name: &str) -> bool {
        match self.hashed.remove(&(name.to_owned(), dir)) {
            Some(id) => {
                self.all.get_mut(&id).expect("held").hashed = false;
                true
            }
            None => false,
        }
    }

    /// The held names `from` now stand at `to`: a rename moves one, an
    /// exchange two.
    fn rename(&mut self, moves: &[(Name<'_>, Name<'_>)]) {
        let taken: Vec<Option<u64>> = moves
            .iter()
            .map(|((dir, name), _)| self.hashed.remove(&((*name).to_owned(), *dir)))
            .collect();
        for (id, (_, (dir, name))) in taken.into_iter().zip(moves) {
            if let Some(id) = id {
                self.all.get_mut(&id).expect("held").parent = Some((*dir, (*name).to_owned()));
                self.hashed.insert(((*name).to_owned(), *dir), id);
            }
        }
    }
}

/// What an event through a holder needs: the inode, whether it is a
/// directory, the name it was opened through and whether that stands.
fn dentry_of(holder: Holder) -> Option<Dentry> {
    let dentries = DENTRIES.lock();
    if dentries.stale.contains(&holder) {
        drop(dentries);
        crate::trap_fatal(
            "inotify: an event through a descriptor whose name an in-process crash \
             (patina_crash) left unknown is not modeled; failing closed",
        );
    }
    dentries
        .holders
        .get(&holder)
        .map(|id| dentries.all[id].clone())
}

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

/// The directory inode and name of `path`, when a held name could be it:
/// the lookup is skipped for a name nothing holds.
fn held_parent(path: &str) -> Option<(u64, &str)> {
    let (_, name) = split(path)?;
    if !DENTRIES.lock().named(name) {
        return None;
    }
    parent(path)
}

/// A directory-entry event on the entry `path` names.
fn entry(path: &str, mask: u32, cookie: u32) {
    if let Some((dir, name)) = parent(path) {
        inotify::notify(&[Target::Entry { dir, name }], mask, cookie, false);
    }
}

/// An event on a file: its directory's watches with `name`, then its own;
/// `unlinked` when that name went.
fn child(parent: Option<(u64, &str)>, ino: u64, mask: u32, unlinked: bool) {
    let own = Target::Inode(ino);
    match parent {
        Some((dir, name)) => {
            inotify::notify(&[Target::Entry { dir, name }, own], mask, 0, unlinked);
        }
        None => inotify::notify(&[own], mask, 0, unlinked),
    }
}

/// An event on the file `holder` holds, through the name it was opened
/// through; `filtered` for one on the open file itself (`fsnotify_file`),
/// which skips the `IN_EXCL_UNLINK` watches once that name went.
fn through(holder: Holder, mask: u32, filtered: bool) {
    if !watching() {
        return;
    }
    let Some(dentry) = dentry_of(holder) else {
        return;
    };
    let mask = if dentry.directory {
        mask | IN_ISDIR
    } else {
        mask
    };
    let parent = dentry
        .parent
        .as_ref()
        .map(|(dir, name)| (*dir, name.as_str()));
    child(parent, dentry.ino, mask, filtered && !dentry.hashed);
}

/// `ino`'s last name went, held (the first unhashed name let go deletes
/// it) or not (deleted now).
fn last_name_gone(ino: u64, held: bool) {
    if held {
        DENTRIES.lock().orphans.insert(ino);
    } else if watching() {
        inotify::settle(ino);
    }
}

/// Driver handle `handle`, open on canonical `path`, holds the name it was
/// opened through. On the context itself, for the working directory a run
/// is installed with.
pub(crate) fn bind(context: &mut Context, handle: Fd, path: &str) -> Result<(), RuntimeError> {
    let metadata = context.fs_fd_metadata_unrecorded(handle)?;
    let parent = match split(path) {
        Some((dir, name)) => Some((context.fs_metadata_unrecorded(dir)?.ino, name.to_owned())),
        None => None,
    };
    let directory = metadata.kind == FsEntryKind::Directory;
    DENTRIES
        .lock()
        .hold(Holder::Handle(handle.0), metadata.ino, directory, parent);
    Ok(())
}

/// A descriptor's inode, whether a directory, and the directory inode and
/// name its node has.
type Located = (u64, bool, Option<(u64, String)>);

/// Where descriptor `holder`'s node is now, read through it ([`Located`]);
/// none when that node has no name.
fn located(context: &mut Context, holder: Holder) -> Option<Located> {
    // A FIFO endpoint is no driver handle: nothing to look its node up
    // through.
    let Holder::Handle(handle) = holder else {
        return None;
    };
    let metadata = context.fs_fd_metadata_unrecorded(Fd(handle)).ok()?;
    let path = context.fs_fd_path_unrecorded(Fd(handle)).ok()?;
    let parent = match split(&path) {
        Some((dir, name)) => Some((
            context.fs_metadata_unrecorded(dir).ok()?.ino,
            name.to_owned(),
        )),
        None => None,
    };
    Some((
        metadata.ino,
        metadata.kind == FsEntryKind::Directory,
        parent,
    ))
}

/// After an in-process crash: the held names follow the rebuilt image
/// ([`Dentries::crashed`]).
pub(crate) fn crashed() {
    let _ = with_context(|context| {
        DENTRIES.lock().crashed(context);
        Ok(())
    });
}

/// [`bind`] from a filesystem entry.
pub(crate) fn bound(handle: Fd, path: &str) {
    let _ = with_context(|context| bind(context, handle, path));
}

/// Driver handle `duplicate` holds the name `handle` holds (`fchdir`).
pub(crate) fn shared(handle: Fd, duplicate: Fd) {
    DENTRIES
        .lock()
        .share(Holder::Handle(handle.0), Holder::Handle(duplicate.0));
}

/// `holder` let go of its name: an inode that ended with it is gone, and
/// its watches end.
fn let_go(holder: Holder) {
    let ended = DENTRIES.lock().release(holder);
    if let (Some(ino), true) = (ended, watching()) {
        inotify::settle(ino);
    }
}

/// Driver handle `handle` closed (a description's last reference, the
/// working directory moving).
pub(crate) fn unbound(handle: Fd) {
    let_go(Holder::Handle(handle.0));
}

/// FIFO endpoint `end`, on node `ino`, is being opened through canonical
/// `path`: it holds that name from before it waits for its partner, as the
/// kernel's open holds the dentry it looked up, so a rename or unlink
/// meanwhile moves or unhashes the name it holds.
pub(crate) fn fifo_bound(end: u64, ino: u64, path: &str) {
    let parent = split(path).and_then(|(dir, name)| Some((lookup(dir)?.ino, name.to_owned())));
    DENTRIES.lock().hold(Holder::Fifo(end), ino, false, parent);
}

/// FIFO endpoint `end`'s open completed (`fsnotify_open`).
pub(crate) fn fifo_opened(end: u64) {
    through(Holder::Fifo(end), IN_OPEN, true);
}

/// FIFO endpoint `end`'s open failed: the name is let go with no close
/// event, as a file that never opened has none.
pub(crate) fn fifo_abandoned(end: u64) {
    let_go(Holder::Fifo(end));
}

/// FIFO endpoint `end`'s last reference went (`fsnotify_close`), then its
/// name is let go.
pub(crate) fn fifo_closed(end: u64, wrote: bool) {
    let mask = if wrote {
        IN_CLOSE_WRITE
    } else {
        IN_CLOSE_NOWRITE
    };
    through(Holder::Fifo(end), mask, true);
    let_go(Holder::Fifo(end));
}

/// Bytes moved through FIFO endpoint `end` (`IN_ACCESS`, `IN_MODIFY`): its
/// own watches alone see it (the special-file rule of CVE-2025-68788's fix,
/// above).
pub(crate) fn fifo_moved(end: u64, mask: u32) {
    if !watching() {
        return;
    }
    if let Some(dentry) = dentry_of(Holder::Fifo(end)) {
        child(None, dentry.ino, mask, !dentry.hashed);
    }
}

/// A changed attribute of the node FIFO endpoint `end` is open on
/// (`fsnotify_change` through the descriptor).
pub(crate) fn fifo_changed(end: u64, mask: u32) {
    through(Holder::Fifo(end), mask, false);
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
    let held = held_parent(path).is_some_and(|(dir, name)| DENTRIES.lock().unhash(dir, name));
    let directory = before.kind == FsEntryKind::Directory;
    if watching() && !directory {
        inotify::notify(&[Target::Inode(before.ino)], IN_ATTRIB, 0, false);
    }
    if directory || before.nlink <= 1 {
        last_name_gone(before.ino, held);
    }
    if watching() {
        entry(path, IN_DELETE | isdir(before), 0);
    }
}

/// `fsnotify_move`'s events for `source` going from `from` to `to`,
/// replacing `target`.
fn move_events(from: &str, to: &str, source: &FsMetadata, target: Option<&FsMetadata>) {
    let cookie = inotify::next_cookie();
    entry(from, IN_MOVED_FROM | isdir(source), cookie);
    entry(to, IN_MOVED_TO | isdir(source), cookie);
    if let Some(target) = target {
        let own = [Target::Inode(target.ino)];
        inotify::notify(&own, IN_ATTRIB | isdir(target), 0, false);
    }
    inotify::notify(&[Target::Inode(source.ino)], IN_MOVE_SELF, 0, false);
}

/// `fsnotify_move`: `source` went from `from` to `to`, replacing `target`:
/// the name held at `to` is unhashed, the one held at `from` stands at `to`.
/// A rename between two names of one inode changed nothing.
pub(crate) fn moved(from: &str, to: &str, source: &FsMetadata, target: Option<&FsMetadata>) {
    if target.is_some_and(|target| target.ino == source.ino) {
        return;
    }
    let source_name = held_parent(from);
    let target_name = if source_name.is_some() {
        parent(to)
    } else {
        held_parent(to)
    };
    let mut held = false;
    if let Some(to_name) = target_name {
        let mut dentries = DENTRIES.lock();
        held = dentries.unhash(to_name.0, to_name.1);
        if let Some(from_name) = source_name {
            dentries.rename(&[(from_name, to_name)]);
        }
    }
    if watching() {
        move_events(from, to, source, target);
    }
    if let Some(target) = target
        && (target.kind == FsEntryKind::Directory || target.nlink <= 1)
    {
        last_name_gone(target.ino, held);
    }
}

/// `RENAME_EXCHANGE`: the held names swap, then two moves, each with its own
/// cookie. Exchanging two names of one inode changes nothing (`vfs_rename`
/// returns before any of it).
pub(crate) fn exchanged(first: &str, second: &str, a: &FsMetadata, b: &FsMetadata) {
    if a.ino == b.ino {
        return;
    }
    if (held_parent(first).is_some() || held_parent(second).is_some())
        && let (Some(first_name), Some(second_name)) = (parent(first), parent(second))
    {
        DENTRIES
            .lock()
            .rename(&[(first_name, second_name), (second_name, first_name)]);
    }
    if watching() {
        move_events(first, second, a, None);
        move_events(second, first, b, None);
    }
}

/// A changed attribute of the file at `path` (`fsnotify_change`,
/// `fsnotify_xattr`).
pub(crate) fn on_path(path: &str, mask: u32) {
    if !watching() {
        return;
    }
    if let Some(metadata) = lookup(path) {
        child(parent(path), metadata.ino, mask | isdir(&metadata), false);
    }
}

/// An extended attribute of `target` changed (`fsnotify_xattr`); a node
/// named by inode is the one FIFO endpoint `fifo` is open on.
pub(crate) fn xattr_changed(target: &patina_dst_abi::XattrTarget, fifo: Option<u64>) {
    use patina_dst_abi::XattrTarget;
    match (target, fifo) {
        (XattrTarget::Path(path), _) => on_path(path, IN_ATTRIB),
        (XattrTarget::Fd(handle), _) => on_handle(*handle, IN_ATTRIB),
        (XattrTarget::Inode(_), Some(end)) => fifo_changed(end, IN_ATTRIB),
        (XattrTarget::Inode(_), None) => {}
    }
}

/// A changed attribute of the file a driver handle is open on
/// (`fsnotify_change` through a descriptor): `IN_EXCL_UNLINK` does not
/// apply.
pub(crate) fn on_handle(handle: Fd, mask: u32) {
    through(Holder::Handle(handle.0), mask, false);
}

/// An access through a description (`fsnotify_file`: a read, a write, an
/// allocation, an open, a close).
pub(crate) fn on_file(handle: Fd, mask: u32) {
    through(Holder::Handle(handle.0), mask, true);
}

/// `iterate_dir` on directory handle `handle`: `IN_ACCESS`, unless the
/// directory is dead (`IS_DEADDIR`: removed, or renamed over).
pub(crate) fn dir_read(handle: Fd) {
    if watching() && dentry_of(Holder::Handle(handle.0)).is_some_and(|dentry| dentry.hashed) {
        on_file(handle, IN_ACCESS);
    }
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

#[cfg(test)]
mod tests {
    use patina_dst_abi::{Fd, FsEntryKind, OpenFlags};
    use patina_dst_fs_crash::CrashFs;
    use patina_dst_runtime::{Context, RuntimeBuilder, RuntimeConfig};

    use super::{Dentries, Holder, split};

    /// After an in-process crash the held names match the rebuilt image:
    /// its inode numbers and names, hashed; a descriptor whose node kept no
    /// name is stale; no orphan is left.
    #[test]
    fn a_crash_rebuilds_the_held_names_from_the_rebuilt_image() {
        let mut context: Context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_filesystem(CrashFs::builder().seed(1).build().unwrap())
            .build()
            .unwrap();
        let flags = OpenFlags::create_truncate_write();
        // A removed entry takes an inode number the rebuilt image does not
        // hand out again, so the survivors' numbers change.
        let first = context.fs_open("/first", flags).unwrap();
        context.fs_close(first).unwrap();
        context.fs_remove_file("/first").unwrap();
        context.fs_create_directory("/d", 0o755).unwrap();
        let file = context.fs_open("/d/f", flags).unwrap();
        let gone = context.fs_open("/d/gone", flags).unwrap();
        context.fs_sync_all().unwrap();
        context.fs_remove_file("/d/gone").unwrap();
        context.fs_sync_all().unwrap();

        let mut dentries = Dentries::new();
        let before = |context: &mut Context, fd: Fd| context.fs_fd_metadata_unrecorded(fd).unwrap();
        let dir = context.fs_metadata_unrecorded("/d").unwrap().ino;
        let (f, g) = (before(&mut context, file), before(&mut context, gone));
        dentries.hold(
            Holder::Handle(file.0),
            f.ino,
            false,
            Some((dir, "f".into())),
        );
        dentries.hold(
            Holder::Handle(gone.0),
            g.ino,
            false,
            Some((dir, "gone".into())),
        );
        assert!(dentries.unhash(dir, "gone"));
        dentries.orphans.insert(g.ino);

        context.fs_crash().unwrap();
        dentries.crashed(&mut context);

        let now = context.fs_fd_metadata_unrecorded(file).unwrap();
        let dir_now = context.fs_metadata_unrecorded("/d").unwrap();
        assert_eq!(dir_now.kind, FsEntryKind::Directory);
        assert_ne!((now.ino, dir_now.ino), (f.ino, dir), "the crash renumbered");
        let id = dentries.holders[&Holder::Handle(file.0)];
        let dentry = &dentries.all[&id];
        assert_eq!(dentry.ino, now.ino);
        assert_eq!(dentry.parent, Some((dir_now.ino, "f".to_owned())));
        assert!(dentry.hashed);
        assert_eq!(
            dentries.hashed.get(&("f".to_owned(), dir_now.ino)),
            Some(&id)
        );
        assert_eq!(dentries.hashed.len(), 1);
        assert!(!dentries.holders.contains_key(&Holder::Handle(gone.0)));
        assert!(dentries.stale.contains(&Holder::Handle(gone.0)));
        assert!(dentries.orphans.is_empty());
        // A stale holder lets go with nothing to settle.
        assert_eq!(dentries.release(Holder::Handle(gone.0)), None);
        assert!(dentries.stale.is_empty());
    }

    #[test]
    fn a_canonical_path_splits_into_its_directory_and_name() {
        assert_eq!(split("/a"), Some(("/", "a")));
        assert_eq!(split("/a/b/c"), Some(("/a/b", "c")));
        assert_eq!(split("/"), None);
    }
}
