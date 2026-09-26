//! inotify instances over the deterministic filesystem
//! (`fs/notify/inotify/inotify_user.c`, `inotify_fsnotify.c`,
//! `fs/notify/notification.c`): a descriptor (`FdKind::Inotify`) naming a
//! queue of events, and watches naming inodes by number.
//!
//! The events come from the filesystem entries themselves (`crate::fsnotify`,
//! the kernel's `include/linux/fsnotify.h` hooks), queued synchronously inside
//! the call that caused them, as the kernel queues them; this module decides
//! which watches take an event and how the queue holds it. An event is
//! reported to the watches of the directory it names an entry of (with the
//! entry's name) and of the inode it is on (without one), in that order, each
//! only when the watch asks for it. A queued event identical to the last one
//! still queued is merged into it (`inotify_merge`); past
//! `max_queued_events` one `IN_Q_OVERFLOW` event stands for everything
//! dropped. A watch ends with `IN_IGNORED`: removed, fired once under
//! `IN_ONESHOT`, or its inode gone. A read takes whole events, the name
//! NUL-padded to a multiple of the event header. Readiness is a non-empty
//! queue; every queued event is an arrival (a merged one is not).
//!
//! The model state lives with the thread runtime (a blocking read parks on
//! the scheduler); [`watching`] is the lock-free gate the filesystem entries
//! check before they compute anything.

use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::neg_errno as errno;
use crate::{EACCES, EBADF, EFAULT, ENOENT, ENOTDIR, uaccess};
use patina_dst_abi::FsEntryKind;

pub(crate) const IN_ACCESS: u32 = 0x0000_0001;
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
pub(crate) const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub(crate) const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub(crate) const IN_OPEN: u32 = 0x0000_0020;
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
pub(crate) const IN_CREATE: u32 = 0x0000_0100;
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
pub(crate) const IN_DELETE_SELF: u32 = 0x0000_0400;
pub(crate) const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_UNMOUNT: u32 = 0x0000_2000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
pub(crate) const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;

/// `IN_ALL_EVENTS`: what a watch can ask to be told.
const ALL_EVENTS: u32 = 0x0000_0fff;
/// `ALL_INOTIFY_BITS`: a mask with a bit outside it, or none inside it, is
/// `EINVAL`.
const ALL_INOTIFY_BITS: u32 = ALL_EVENTS
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
    | IN_IGNORED
    | IN_ONLYDIR
    | IN_DONT_FOLLOW
    | IN_EXCL_UNLINK
    | IN_MASK_CREATE
    | IN_MASK_ADD
    | IN_ISDIR
    | IN_ONESHOT;
/// The bits a watch keeps (`INOTIFY_USER_MASK` less the lookup-only ones).
const WATCH_BITS: u32 = ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT;

const IN_CLOEXEC: i32 = 0o2000000;
const IN_NONBLOCK: i32 = 0o4000;

/// `EMFILE`.
const EMFILE: c_int = 24;

/// `/proc/sys/fs/inotify/max_queued_events` and `max_user_instances`, the
/// kernel's defaults; the guest is the one process of its user.
const MAX_QUEUED_EVENTS: usize = 16384;
const MAX_USER_INSTANCES: usize = 128;

/// `sizeof(struct inotify_event)`: the header every event starts with.
const HEADER: usize = 16;

/// `INOTIFY_IOC_SETNEXTWD` (`_IOW('I', 0, __s32)`).
pub(crate) const INOTIFY_IOC_SETNEXTWD: u64 = 0x4004_4900;

/// Live watches across every instance: the gate the filesystem entries read
/// without the runtime lock.
static WATCHES: AtomicUsize = AtomicUsize::new(0);

/// Whether any watch exists, so a filesystem entry has an event to compute.
pub(crate) fn watching() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// One queued event (`struct inotify_event_info`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<String>,
}

impl Event {
    /// The bytes a read hands out for it: the header, then the name
    /// NUL-terminated and padded to a multiple of the header's size
    /// (`round_event_name_len`).
    fn size(&self) -> usize {
        HEADER
            + self
                .name
                .as_ref()
                .map_or(0, |name| (name.len() + 1).div_ceil(HEADER) * HEADER)
    }

    fn bytes(&self) -> Vec<u8> {
        let size = self.size();
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&self.wd.to_ne_bytes());
        bytes.extend_from_slice(&self.mask.to_ne_bytes());
        bytes.extend_from_slice(&self.cookie.to_ne_bytes());
        bytes.extend_from_slice(&((size - HEADER) as u32).to_ne_bytes());
        if let Some(name) = &self.name {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.resize(size, 0);
        bytes
    }
}

/// A watch: the inode and what it asks for (`struct inotify_inode_mark`).
#[derive(Clone, Copy, Debug)]
struct Watch {
    ino: u64,
    mask: u32,
}

/// An instance (`struct fsnotify_group` with its inotify data).
#[derive(Debug, Default)]
struct Instance {
    queue: VecDeque<Event>,
    /// The `IN_Q_OVERFLOW` event is queued (there is one per instance).
    overflowed: bool,
    watches: BTreeMap<i32, Watch>,
    by_ino: BTreeMap<u64, i32>,
    /// `idr_alloc_cyclic`'s cursor: the next descriptor tried.
    cursor: i32,
    /// Every queued event: the arrivals an edge-triggered interest fires on.
    arrivals: u64,
    waiters: VecDeque<TaskId>,
    /// A descriptor still names it. A reader blocked when the last one
    /// closed holds the file, as the kernel's `read` does, so the instance
    /// and its watches live until the last waiter leaves.
    open: bool,
}

/// Where a report goes: the watches of a directory, naming one of its
/// entries, or the watches of an inode, naming nothing.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Target<'a> {
    Entry { dir: u64, name: &'a str },
    Inode(u64),
}

/// The process's inotify instances.
#[derive(Default)]
pub(super) struct Inotify {
    instances: BTreeMap<u64, Instance>,
    next_handle: u64,
    /// `fsnotify_sync_cookie`: the last rename cookie handed out.
    cookie: u32,
    /// Inodes whose last name went while something still held them, with
    /// that name's directory and entry (the unhashed dentry an event on the
    /// open file is still reported through): their `IN_DELETE_SELF` waits
    /// for the last reference.
    deleted: BTreeMap<u64, Option<(u64, String)>>,
}

impl Instance {
    /// `fsnotify_insert_event` with `inotify_merge`: whether a waiter is
    /// owed a wakeup.
    fn enqueue(&mut self, event: Event) -> bool {
        if self.queue.len() >= MAX_QUEUED_EVENTS {
            if self.overflowed {
                return false;
            }
            self.overflowed = true;
            self.queue.push_back(Event {
                wd: -1,
                mask: IN_Q_OVERFLOW,
                cookie: 0,
                name: None,
            });
        } else {
            // `event_compare`: the cookie is not compared, and nothing merges
            // into an `IN_IGNORED`.
            if let Some(last) = self.queue.back() {
                if last.mask & IN_IGNORED == 0
                    && last.mask == event.mask
                    && last.wd == event.wd
                    && last.name == event.name
                {
                    return false;
                }
            }
            self.queue.push_back(event);
        }
        self.arrivals += 1;
        true
    }

    /// `fsnotify_destroy_mark`: the watch ends with `IN_IGNORED`; whether a
    /// waiter is owed a wakeup.
    fn destroy(&mut self, wd: i32) -> bool {
        let Some(watch) = self.watches.remove(&wd) else {
            return false;
        };
        self.by_ino.remove(&watch.ino);
        WATCHES.fetch_sub(1, Ordering::Relaxed);
        self.enqueue(Event {
            wd,
            mask: IN_IGNORED,
            cookie: 0,
            name: None,
        })
    }

    /// `idr_alloc_cyclic(…, 1, 0)`: the first free descriptor from the
    /// cursor, wrapping to 1.
    fn allocate_wd(&mut self) -> i32 {
        let mut wd = self.cursor.max(1);
        while self.watches.contains_key(&wd) {
            wd = if wd == i32::MAX { 1 } else { wd + 1 };
        }
        self.cursor = if wd == i32::MAX { 1 } else { wd + 1 };
        wd
    }

    fn queued_bytes(&self) -> usize {
        self.queue.iter().map(Event::size).sum()
    }
}

impl Inotify {
    /// Report `mask` to `targets` in every instance; answers the readers to
    /// wake. An event on an open file whose last name went (`unlinked`)
    /// skips the watches that asked for `IN_EXCL_UNLINK`.
    fn report(
        &mut self,
        targets: &[Target<'_>],
        mask: u32,
        cookie: u32,
        unlinked: bool,
    ) -> Vec<TaskId> {
        let mut wake = Vec::new();
        for instance in self.instances.values_mut() {
            let mut woken = false;
            for target in targets {
                let (ino, name) = match *target {
                    Target::Entry { dir, name } => (dir, Some(name)),
                    Target::Inode(ino) => (ino, None),
                };
                let Some(&wd) = instance.by_ino.get(&ino) else {
                    continue;
                };
                let watch = instance.watches[&wd];
                if watch.mask & mask & ALL_EVENTS == 0
                    || (unlinked && watch.mask & IN_EXCL_UNLINK != 0)
                {
                    continue;
                }
                woken |= instance.enqueue(Event {
                    wd,
                    mask,
                    cookie,
                    name: name.map(str::to_owned),
                });
                if watch.mask & IN_ONESHOT != 0 {
                    woken |= instance.destroy(wd);
                }
            }
            if woken {
                wake.extend(instance.waiters.drain(..));
            }
        }
        wake
    }

    /// `fsnotify_inoderemove`: every watch on `ino` sees `IN_DELETE_SELF`,
    /// then ends.
    fn inode_removed(&mut self, ino: u64) -> Vec<TaskId> {
        self.deleted.remove(&ino);
        let mut wake = self.report(&[Target::Inode(ino)], IN_DELETE_SELF, 0, false);
        for instance in self.instances.values_mut() {
            if let Some(&wd) = instance.by_ino.get(&ino) {
                if instance.destroy(wd) {
                    wake.extend(instance.waiters.drain(..));
                }
            }
        }
        wake
    }

    fn watched(&self, ino: u64) -> bool {
        self.instances
            .values()
            .any(|instance| instance.by_ino.contains_key(&ino))
    }

    /// Free an instance no descriptor names once no reader waits on it.
    fn release_closed(&mut self, handle: u64) {
        let done = self
            .instances
            .get(&handle)
            .is_some_and(|instance| !instance.open && instance.waiters.is_empty());
        if done {
            let instance = self.instances.remove(&handle).expect("checked above");
            WATCHES.fetch_sub(instance.watches.len(), Ordering::Relaxed);
        }
    }
}

/// Report `mask` (and `cookie`, for a rename's halves) to `targets`, waking
/// the readers whose queue took it; `unlinked` for an event on an open file
/// whose last name went.
pub(crate) fn notify(targets: &[Target<'_>], mask: u32, cookie: u32, unlinked: bool) {
    let wake = lock_state().inotify.report(targets, mask, cookie, unlinked);
    wake_all(wake);
}

/// The next rename cookie (`fsnotify_get_cookie`), never 0.
pub(crate) fn next_cookie() -> u32 {
    let mut state = lock_state();
    state.inotify.cookie = state.inotify.cookie.wrapping_add(1).max(1);
    state.inotify.cookie
}

/// Whether some watch is on `ino`.
pub(crate) fn watched(ino: u64) -> bool {
    lock_state().inotify.watched(ino)
}

/// `ino`'s last name, `entry` in its directory, is gone. Held, it lives on
/// ([`deleted`]); otherwise its watches see `IN_DELETE_SELF` and end now.
pub(crate) fn unlinked(ino: u64, held: bool, entry: Option<(u64, String)>) {
    let wake = {
        let mut state = lock_state();
        if held {
            state.inotify.deleted.insert(ino, entry);
            Vec::new()
        } else {
            state.inotify.inode_removed(ino)
        }
    };
    wake_all(wake);
}

/// The inodes whose last name went while something held them.
pub(crate) fn deleted() -> Vec<u64> {
    if !watching() {
        return Vec::new();
    }
    lock_state().inotify.deleted.keys().copied().collect()
}

/// The directory and name deleted `ino` had last.
pub(crate) fn last_entry(ino: u64) -> Option<(u64, String)> {
    lock_state().inotify.deleted.get(&ino).cloned().flatten()
}

/// The last holder of deleted `ino` let go: its watches see
/// `IN_DELETE_SELF` and end.
pub(crate) fn settle(ino: u64) {
    let wake = lock_state().inotify.inode_removed(ino);
    wake_all(wake);
}

/// `inotify_init1(flags)`: an unknown flag is `EINVAL`; past the per-user
/// instance limit `EMFILE`. The description is read-only (`O_RDONLY`), with
/// `O_NONBLOCK` from `IN_NONBLOCK`.
pub(crate) fn init1(flags: i32) -> i64 {
    if flags & !(IN_CLOEXEC | IN_NONBLOCK) != 0 {
        return errno(EINVAL);
    }
    let handle = {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return errno(error.into_posix());
        }
        if state.inotify.instances.len() >= MAX_USER_INSTANCES {
            return errno(EMFILE);
        }
        let handle = state.inotify.next_handle;
        state.inotify.next_handle += 1;
        state.inotify.instances.insert(
            handle,
            Instance {
                cursor: 1,
                open: true,
                ..Instance::default()
            },
        );
        handle
    };
    let nonblock = if flags & IN_NONBLOCK != 0 {
        O_NONBLOCK
    } else {
        0
    };
    match crate::install_fd(
        FdKind::Inotify,
        handle,
        O_READ | nonblock,
        flags & IN_CLOEXEC != 0,
    ) {
        Ok(fd) => i64::from(fd),
        Err(code) => {
            lock_state().inotify.instances.remove(&handle);
            errno(code)
        }
    }
}

/// The instance `fd` names: `EBADF` for no descriptor (`O_PATH` included),
/// `EINVAL` for one that is not an instance.
fn instance_handle(fd: c_int) -> Result<u64, c_int> {
    let resolved = crate::fdget(fd)?;
    if resolved.kind != FdKind::Inotify {
        return Err(EINVAL);
    }
    Ok(resolved.handle)
}

/// `inotify_add_watch(fd, path, mask)`, in the kernel's order: the mask
/// (`EINVAL` for a bit outside `ALL_INOTIFY_BITS` or none inside), the
/// descriptor (`EBADF`), `IN_MASK_ADD` with `IN_MASK_CREATE` and a
/// descriptor that is no instance (`EINVAL`), the path (`IN_DONT_FOLLOW`
/// stops at a trailing symlink, `IN_ONLYDIR` wants a directory), read
/// permission on what it names (`EACCES`); then the watch the instance has
/// on that inode takes the mask (`IN_MASK_ADD` adds to it; `IN_MASK_CREATE`
/// wants none, `EEXIST`), or a new one gets the next descriptor.
///
/// # Safety
/// `path`, when non-null, must point to a NUL-terminated string.
pub(crate) unsafe fn add_watch(fd: c_int, path: *const c_char, mask: u32) -> i64 {
    if mask & !ALL_INOTIFY_BITS != 0 || mask & ALL_INOTIFY_BITS == 0 {
        return errno(EINVAL);
    }
    let resolved = match crate::fdget(fd) {
        Ok(resolved) => resolved,
        Err(code) => return errno(code),
    };
    if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        return errno(EINVAL);
    }
    if resolved.kind != FdKind::Inotify {
        return errno(EINVAL);
    }
    let handle = resolved.handle;
    if path.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: the caller's contract.
    let Ok(path) = unsafe { CStr::from_ptr(path) }.to_str() else {
        return errno(EINVAL);
    };
    let flags = if mask & IN_DONT_FOLLOW != 0 {
        crate::paths::RESOLVE_NOFOLLOW
    } else {
        0
    };
    let found = match crate::paths::resolve(crate::paths::AT_FDCWD, path, flags) {
        Ok(found) => found,
        Err(code) => return errno(code),
    };
    let Some(metadata) = found.metadata else {
        return errno(ENOENT);
    };
    if mask & IN_ONLYDIR != 0 && metadata.kind != FsEntryKind::Directory {
        return errno(ENOTDIR);
    }
    // `path_permission(MAY_READ)`: the one modeled identity owns every entry.
    if metadata.mode & 0o400 == 0 {
        return errno(EACCES);
    }
    let mut state = lock_state();
    let Some(instance) = state.inotify.instances.get_mut(&handle) else {
        return errno(EBADF);
    };
    let wanted = mask & WATCH_BITS;
    if let Some(&wd) = instance.by_ino.get(&metadata.ino) {
        if mask & IN_MASK_CREATE != 0 {
            return errno(crate::EEXIST);
        }
        let watch = instance.watches.get_mut(&wd).expect("indexed watch");
        watch.mask = if mask & IN_MASK_ADD != 0 {
            watch.mask | wanted
        } else {
            wanted
        };
        return i64::from(wd);
    }
    let wd = instance.allocate_wd();
    instance.watches.insert(
        wd,
        Watch {
            ino: metadata.ino,
            mask: wanted,
        },
    );
    instance.by_ino.insert(metadata.ino, wd);
    WATCHES.fetch_add(1, Ordering::Relaxed);
    i64::from(wd)
}

/// `inotify_rm_watch(fd, wd)`: `EBADF` for no descriptor, `EINVAL` for one
/// that is no instance or a descriptor it does not watch; the watch ends
/// with `IN_IGNORED`.
pub(crate) fn rm_watch(fd: c_int, wd: i32) -> i64 {
    let handle = match instance_handle(fd) {
        Ok(handle) => handle,
        Err(code) => return errno(code),
    };
    let wake = {
        let mut state = lock_state();
        let Some(instance) = state.inotify.instances.get_mut(&handle) else {
            return errno(EBADF);
        };
        if !instance.watches.contains_key(&wd) {
            return errno(EINVAL);
        }
        if instance.destroy(wd) {
            instance.waiters.drain(..).collect()
        } else {
            Vec::new()
        }
    };
    wake_all(wake);
    0
}

/// Read an instance (`inotify_read`): whole events while they fit, each
/// copied out as it is taken (`EFAULT` for memory the guest cannot write,
/// the event taken); a first event larger than the buffer is `EINVAL`; with
/// none queued, `EAGAIN` nonblocking, else the reader waits for one.
pub(crate) fn read(handle: u64, nonblocking: bool, buf: usize, len: usize) -> isize {
    let me = current_task();
    loop {
        let mut state = lock_state();
        let Some(instance) = state.inotify.instances.get_mut(&handle) else {
            return crate::fail(EBADF) as isize;
        };
        if !instance.queue.is_empty() {
            let mut copied = 0;
            let mut failed = None;
            while let Some(event) = instance.queue.front() {
                let size = event.size();
                if size > len - copied {
                    break;
                }
                let event = instance.queue.pop_front().expect("peeked");
                if event.mask == IN_Q_OVERFLOW {
                    instance.overflowed = false;
                }
                if let Err(code) = uaccess::write_bytes(buf + copied, &event.bytes()) {
                    failed = Some(code);
                    break;
                }
                copied += size;
            }
            state.inotify.release_closed(handle);
            drop(state);
            return match (failed, copied) {
                (Some(code), _) => crate::fail(code) as isize,
                (None, 0) => crate::fail(EINVAL) as isize,
                (None, copied) => copied as isize,
            };
        }
        if nonblocking {
            return crate::fail(EWOULDBLOCK) as isize;
        }
        instance.waiters.push_back(me);
        let step = state.block(
            me,
            "inotify-read",
            Wait::new(BlockClass::Io, vec![WaiterLoc::InotifyRecv(handle)]),
        );
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return crate::fail(error.into_posix()) as isize,
        }
        lock_state().timed_out.remove(&me);
        if signals::resume() == signals::Resumed::Eintr {
            lock_state().inotify.release_closed(handle);
            return crate::fail(crate::EINTR) as isize;
        }
    }
}

/// `FIONREAD`: the bytes every queued event takes.
pub(crate) fn queued(handle: u64) -> Option<usize> {
    lock_state()
        .inotify
        .instances
        .get(&handle)
        .map(Instance::queued_bytes)
}

/// `INOTIFY_IOC_SETNEXTWD`: the next watch descriptor tried, 1 to
/// `INT_MAX` (`EINVAL` otherwise).
pub(crate) fn set_next_wd(handle: u64, next: u64) -> Result<(), c_int> {
    let next = i32::try_from(next)
        .ok()
        .filter(|next| *next >= 1)
        .ok_or(EINVAL)?;
    let mut state = lock_state();
    let instance = state.inotify.instances.get_mut(&handle).ok_or(EBADF)?;
    instance.cursor = next;
    Ok(())
}

/// An instance's readiness and its arrivals so far (`inotify_poll`).
pub(super) fn poll(state: &ThreadRuntime, handle: u64) -> (bool, u64) {
    state
        .inotify
        .instances
        .get(&handle)
        .map_or((false, 0), |instance| {
            (!instance.queue.is_empty(), instance.arrivals)
        })
}

/// Park `me` on an instance's readers, for a readiness wait.
pub(super) fn watch(state: &mut ThreadRuntime, handle: u64, me: TaskId) -> Option<WaiterLoc> {
    let instance = state.inotify.instances.get_mut(&handle)?;
    instance.waiters.push_back(me);
    Some(WaiterLoc::InotifyRecv(handle))
}

/// Unlink `me` from an instance's readers.
pub(super) fn unwatch(state: &mut ThreadRuntime, handle: u64, me: TaskId) {
    if let Some(instance) = state.inotify.instances.get_mut(&handle) {
        instance.waiters.retain(|task| *task != me);
    }
    state.inotify.release_closed(handle);
}

/// The last descriptor naming an instance closed (`inotify_release`): its
/// watches end with it, unless a blocked reader still holds it.
pub(crate) fn close(handle: u64) {
    let mut state = lock_state();
    if let Some(instance) = state.inotify.instances.get_mut(&handle) {
        instance.open = false;
    }
    state.inotify.release_closed(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(wd: i32, mask: u32, name: Option<&str>) -> Event {
        Event {
            wd,
            mask,
            cookie: 0,
            name: name.map(str::to_owned),
        }
    }

    #[test]
    fn an_event_name_is_padded_to_a_multiple_of_the_header() {
        assert_eq!(event(1, IN_MODIFY, None).size(), HEADER);
        // "new" and its NUL fit one header's worth; 15 bytes and a NUL do too.
        assert_eq!(event(1, IN_CREATE, Some("new")).size(), 2 * HEADER);
        assert_eq!(
            event(1, IN_CREATE, Some(&"x".repeat(15))).size(),
            2 * HEADER
        );
        assert_eq!(
            event(1, IN_CREATE, Some(&"x".repeat(16))).size(),
            3 * HEADER
        );
        let bytes = event(3, IN_CREATE, Some("ab")).bytes();
        assert_eq!(bytes.len(), 2 * HEADER);
        assert_eq!(&bytes[12..16], &16u32.to_ne_bytes());
        assert_eq!(&bytes[16..19], b"ab\0");
    }

    #[test]
    fn only_an_event_equal_to_the_last_queued_merges() {
        let mut instance = Instance::default();
        assert!(instance.enqueue(event(1, IN_MODIFY, Some("f"))));
        assert!(!instance.enqueue(event(1, IN_MODIFY, Some("f"))));
        assert!(instance.enqueue(event(2, IN_MODIFY, None)));
        assert!(instance.enqueue(event(1, IN_MODIFY, Some("f"))));
        assert!(instance.enqueue(event(1, IN_IGNORED, None)));
        assert!(instance.enqueue(event(1, IN_IGNORED, None)));
        assert_eq!(instance.queue.len(), 5);
        assert_eq!(instance.arrivals, 5);
    }

    #[test]
    fn a_full_queue_takes_one_overflow_event() {
        let mut instance = Instance::default();
        for index in 0..MAX_QUEUED_EVENTS {
            assert!(instance.enqueue(event(1, IN_CREATE, Some(&index.to_string()))));
        }
        assert!(instance.enqueue(event(1, IN_DELETE, Some("x"))));
        assert!(!instance.enqueue(event(1, IN_DELETE, Some("y"))));
        assert_eq!(instance.queue.len(), MAX_QUEUED_EVENTS + 1);
        assert_eq!(instance.queue.back(), Some(&event(-1, IN_Q_OVERFLOW, None)));
    }

    #[test]
    fn watch_descriptors_are_allocated_cyclically_from_the_cursor() {
        let mut instance = Instance {
            cursor: 1,
            ..Instance::default()
        };
        let watch = Watch { ino: 0, mask: 0 };
        for expected in 1..=3 {
            let wd = instance.allocate_wd();
            assert_eq!(wd, expected);
            instance.watches.insert(wd, watch);
        }
        instance.watches.remove(&1);
        // A freed descriptor is not reused until the cursor wraps.
        assert_eq!(instance.allocate_wd(), 4);
        instance.cursor = i32::MAX;
        assert_eq!(instance.allocate_wd(), i32::MAX);
        instance.watches.insert(i32::MAX, watch);
        assert_eq!(instance.allocate_wd(), 1);
    }
}
