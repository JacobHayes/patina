//! The guest descriptor table: the one place a guest file-descriptor NUMBER is
//! bound to what it names.
//!
//! A Linux process has one table of small integers, allocated lowest-free with
//! holes, each slot carrying a per-descriptor `FD_CLOEXEC` bit and a reference
//! to an open file DESCRIPTION (the kernel's `struct file`: the kind of object,
//! its status flags, its cursor). `dup`/`dup2`/`dup3`/`F_DUPFD` bind a second
//! number to the same description; `close` releases one number and frees the
//! description only when its last number goes. Every class the shim models —
//! captured stdio, deterministic-filesystem files and directories, the
//! `/dev/urandom` device, virtual sockets, in-process pipes, eventfds,
//! readiness reactors and process descriptors — is a description here, and the
//! guest number is the ONLY thing the guest sees. The class-specific tables (the
//! net module's sockets and pipe ends, the driver's handles) are keyed by the
//! description's `handle`, which no guest ever observes, so a guest number is a
//! pure function of the deterministic call sequence and is never recorded.
//!
//! This module is the data structure alone: no runtime calls, no scheduling
//! points, no locks of its own. `lib.rs` owns the single global instance behind
//! a shim spinlock and every entry that consults it; the lock order is the
//! thread runtime first, this table second, and the table lock is never held
//! across a runtime call. The unit tests below pin the allocation and refcount
//! rules the conformance probe `fd/table` checks against the host kernel.

use std::collections::BTreeMap;
use std::ffi::c_int;

/// `RLIMIT_NOFILE` as the shim reports it (`getrlimit`, `sysconf(_SC_OPEN_MAX)`)
/// and as this table enforces it: a slot at or above this number is never
/// allocated (`EMFILE`), and `F_DUPFD`/`dup2`/`dup3` refuse a number here or
/// above (`EINVAL`/`EBADF`), exactly as the kernel does at its soft limit.
pub(crate) const RLIMIT_NOFILE: usize = 1024;

/// What an open file description IS. Every match over this enum is written
/// without a wildcard arm on purpose: a builder adding a kind gets a compile
/// error at every dispatch site that has to decide what the new kind does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FdKind {
    /// The guest's standard input: EOF on every read, never a terminal.
    Stdin,
    /// Captured standard output (the capture sink the description's `handle`
    /// names, 1). `dup2(fd, 1)` redirects; `close(1)` then `open` makes number
    /// 1 an ordinary file — the Linux behavior.
    Stdout,
    /// Captured standard error (sink 2).
    Stderr,
    /// A regular file in the deterministic filesystem; `handle` is the driver
    /// `Fd`.
    File,
    /// A directory opened for reading (`O_DIRECTORY`); `handle` is the driver
    /// `Fd`.
    Dir,
    /// An `O_PATH` descriptor: names a location, opened nothing; `handle` is the
    /// driver `Fd`.
    OPath,
    /// The `/dev/urandom` device: reads draw from the deterministic entropy
    /// stream; no handle.
    Urandom,
    /// A socket of any modeled family (a socketpair end too); `handle` keys
    /// the net module's socket table.
    Socket,
    /// A pipe or FIFO endpoint; `handle` keys the pipe-end table.
    Pipe,
    /// A deterministic eventfd counter; `handle` keys the eventfd table.
    #[cfg(target_os = "linux")]
    EventFd,
    /// A virtual signal queue reader.
    #[cfg(target_os = "linux")]
    SignalFd,
    /// A virtual epoll instance; `handle` is the registry id.
    #[cfg(target_os = "linux")]
    Epoll,
    /// A POSIX message queue descriptor (`mq_open`); `handle` keys the open
    /// queue table of the IPC model.
    #[cfg(target_os = "linux")]
    MessageQueue,
    /// A timer descriptor (`timerfd_create`); `handle` keys the timer table.
    #[cfg(target_os = "linux")]
    TimerFd,
    /// A process descriptor (`pidfd_open`; 6.8's anonymous `[pidfd]` inode);
    /// `handle` is the virtual pid of the process it names, init or the
    /// guest. It has no class object: nothing is freed with it.
    #[cfg(target_os = "linux")]
    Pidfd,
    /// A virtual kqueue; `handle` is the registry id.
    #[cfg(target_os = "macos")]
    Kqueue,
}

impl FdKind {
    /// The `PATINA_FD_*` wire value `patina_fd_kind` reports to C and to the SUD
    /// rows (`include/patina_native.h`).
    pub(crate) fn wire(self) -> c_int {
        match self {
            FdKind::Stdin => 0,
            FdKind::Stdout => 1,
            FdKind::Stderr => 2,
            FdKind::File => 3,
            FdKind::Dir => 4,
            FdKind::OPath => 5,
            FdKind::Urandom => 6,
            FdKind::Socket => 7,
            FdKind::Pipe => 8,
            #[cfg(target_os = "linux")]
            FdKind::EventFd => 9,
            #[cfg(target_os = "linux")]
            FdKind::SignalFd => 12,
            #[cfg(target_os = "linux")]
            FdKind::Epoll => 10,
            #[cfg(target_os = "linux")]
            FdKind::MessageQueue => 13,
            #[cfg(target_os = "linux")]
            FdKind::TimerFd => 14,
            #[cfg(target_os = "linux")]
            FdKind::Pidfd => 15,
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => 11,
        }
    }

    /// Whether the description is a deterministic-filesystem handle (`handle`
    /// is a driver `Fd`).
    pub(crate) fn is_fs(self) -> bool {
        match self {
            FdKind::File | FdKind::Dir | FdKind::OPath => true,
            FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::Urandom
            | FdKind::Socket
            | FdKind::Pipe => false,
            #[cfg(target_os = "linux")]
            FdKind::EventFd
            | FdKind::Epoll
            | FdKind::SignalFd
            | FdKind::MessageQueue
            | FdKind::TimerFd
            | FdKind::Pidfd => false,
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => false,
        }
    }
}

/// The identity of an open file description: unique for the life of the
/// process (a monotonic counter, never reused), so a stale reference held by a
/// reactor or a mapping can never alias a later description.
pub(crate) type DescId = u64;

/// Status flags, in the shim's own `PATINA_O_*` vocabulary (`lib.rs` `O_READ`
/// etc.): the access mode, `O_APPEND`, `O_NONBLOCK`, `O_PATH`. Per description,
/// as `F_GETFL`/`F_SETFL` define them; the C and SUD layers translate to the
/// platform's spelling.
pub(crate) type Status = u32;

/// An open file description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Description {
    pub(crate) kind: FdKind,
    /// The class-specific object this description names (see [`FdKind`]).
    pub(crate) handle: u64,
    pub(crate) status: Status,
    /// Live references: one per table slot plus one per hidden retention
    /// ([`GuestFdTable::retain`]).
    refs: usize,
}

/// A descriptor slot: which description it names and its `FD_CLOEXEC` bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    desc: DescId,
    cloexec: bool,
}

/// A description whose last reference just went: the caller (outside the
/// table lock) frees the class object it named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Release {
    pub(crate) desc: DescId,
    pub(crate) kind: FdKind,
    pub(crate) handle: u64,
}

/// A resolved descriptor: what a guest number names right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) desc: DescId,
    pub(crate) kind: FdKind,
    pub(crate) handle: u64,
    pub(crate) status: Status,
    pub(crate) cloexec: bool,
}

/// Errors are POSIX errno values, as every shim entry reports them.
const EBADF: c_int = 9;
const EINVAL: c_int = 22;
const EMFILE: c_int = 24;

/// `close_range(2)` flag: set `FD_CLOEXEC` on the range instead of closing it.
pub(crate) const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
/// `close_range(2)` flag: unshare the table first — a no-op with one process.
pub(crate) const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;

pub(crate) struct GuestFdTable {
    slots: Vec<Option<Slot>>,
    descriptions: BTreeMap<DescId, Description>,
    next_desc: DescId,
    limit: usize,
}

impl GuestFdTable {
    /// A process's starting table: stdin, stdout, stderr at 0, 1, 2 — three
    /// distinct descriptions, none close-on-exec.
    pub(crate) fn new(limit: usize, stdin: Status, stdout: Status, stderr: Status) -> Self {
        let mut table = Self {
            slots: Vec::new(),
            descriptions: BTreeMap::new(),
            next_desc: 0,
            limit,
        };
        for (kind, handle, status) in [
            (FdKind::Stdin, 0, stdin),
            (FdKind::Stdout, 1, stdout),
            (FdKind::Stderr, 2, stderr),
        ] {
            table
                .install(kind, handle, status, false)
                .expect("the three standard descriptors fit any limit");
        }
        table
    }

    /// The bound no new number reaches (`EMFILE`, `F_DUPFD`'s `EINVAL`).
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// A new bound, as `setrlimit(RLIMIT_NOFILE)` sets it.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    fn slot_index(fd: c_int) -> Option<usize> {
        usize::try_from(fd).ok()
    }

    /// The lowest free number at or above `minimum`, or `EMFILE`.
    fn lowest_free(&self, minimum: usize) -> Result<usize, c_int> {
        let mut index = minimum;
        while index < self.limit {
            if self.slots.get(index).is_none_or(Option::is_none) {
                return Ok(index);
            }
            index += 1;
        }
        Err(EMFILE)
    }

    fn set_slot(&mut self, index: usize, slot: Slot) {
        if self.slots.len() <= index {
            self.slots.resize(index + 1, None);
        }
        self.slots[index] = Some(slot);
    }

    fn new_description(&mut self, kind: FdKind, handle: u64, status: Status) -> DescId {
        let desc = self.next_desc;
        self.next_desc += 1;
        self.descriptions.insert(
            desc,
            Description {
                kind,
                handle,
                status,
                refs: 0,
            },
        );
        desc
    }

    fn bind(&mut self, index: usize, desc: DescId, cloexec: bool) {
        self.descriptions
            .get_mut(&desc)
            .expect("a bound description exists")
            .refs += 1;
        self.set_slot(index, Slot { desc, cloexec });
    }

    /// Bind a fresh description to the lowest free number. The description is
    /// created only when a number is available, so a failed install leaves no
    /// orphan behind.
    pub(crate) fn install(
        &mut self,
        kind: FdKind,
        handle: u64,
        status: Status,
        cloexec: bool,
    ) -> Result<c_int, c_int> {
        let index = self.lowest_free(0)?;
        let desc = self.new_description(kind, handle, status);
        self.bind(index, desc, cloexec);
        Ok(index as c_int)
    }

    /// Bind two fresh descriptions to the two lowest free numbers, atomically:
    /// `pipe2`/`socketpair` with one free slot is `EMFILE` and creates nothing.
    pub(crate) fn install_pair(
        &mut self,
        kind: FdKind,
        first: (u64, Status),
        second: (u64, Status),
        cloexec: bool,
    ) -> Result<(c_int, c_int), c_int> {
        let a = self.lowest_free(0)?;
        let b = self.lowest_free(a + 1)?;
        let desc_a = self.new_description(kind, first.0, first.1);
        let desc_b = self.new_description(kind, second.0, second.1);
        self.bind(a, desc_a, cloexec);
        self.bind(b, desc_b, cloexec);
        Ok((a as c_int, b as c_int))
    }

    /// `EMFILE` unless `count` numbers are free: what `accept`/`socketpair`
    /// reserve before they create anything.
    pub(crate) fn ensure_free(&self, count: usize) -> Result<(), c_int> {
        let mut index = 0;
        for _ in 0..count {
            index = self.lowest_free(index)? + 1;
        }
        Ok(())
    }

    /// The two numbers [`GuestFdTable::install_pair`] would bind next.
    pub(crate) fn next_free_pair(&self) -> Result<(c_int, c_int), c_int> {
        let a = self.lowest_free(0)?;
        let b = self.lowest_free(a + 1)?;
        Ok((a as c_int, b as c_int))
    }

    /// Bind the lowest free number to the live description `desc`: a
    /// descriptor received in flight (`SCM_RIGHTS`) names the sender's open
    /// file description. `EBADF` for an id that names no live description.
    pub(crate) fn install_existing(&mut self, desc: DescId, cloexec: bool) -> Result<c_int, c_int> {
        if !self.descriptions.contains_key(&desc) {
            return Err(EBADF);
        }
        let index = self.lowest_free(0)?;
        self.bind(index, desc, cloexec);
        Ok(index as c_int)
    }

    /// What `fd` names, or `None` for an empty slot / out-of-range number.
    pub(crate) fn resolve(&self, fd: c_int) -> Option<Resolved> {
        let slot = (*self.slots.get(Self::slot_index(fd)?)?)?;
        let description = self.descriptions.get(&slot.desc)?;
        Some(Resolved {
            desc: slot.desc,
            kind: description.kind,
            handle: description.handle,
            status: description.status,
            cloexec: slot.cloexec,
        })
    }

    pub(crate) fn kind(&self, fd: c_int) -> Option<FdKind> {
        self.resolve(fd).map(|resolved| resolved.kind)
    }

    /// The description itself (for callers holding a [`DescId`], such as a
    /// mapping's retained reference).
    pub(crate) fn description(&self, desc: DescId) -> Option<&Description> {
        self.descriptions.get(&desc)
    }

    /// `dup(2)` / `F_DUPFD` / `F_DUPFD_CLOEXEC`: bind the lowest free number at
    /// or above `minimum` to `fd`'s description. `EBADF` for an empty slot;
    /// `EINVAL` for a minimum outside `[0, limit)`; `EMFILE` when nothing at or
    /// above it is free.
    pub(crate) fn dup(&mut self, fd: c_int, minimum: c_int, cloexec: bool) -> Result<c_int, c_int> {
        let resolved = self.resolve(fd).ok_or(EBADF)?;
        let minimum = usize::try_from(minimum).map_err(|_| EINVAL)?;
        if minimum >= self.limit {
            return Err(EINVAL);
        }
        let index = self.lowest_free(minimum)?;
        self.bind(index, resolved.desc, cloexec);
        Ok(index as c_int)
    }

    /// `dup3(2)` (and `dup2` after its equal-number special case): bind `newfd`
    /// to `oldfd`'s description, closing whatever `newfd` named first. The
    /// kernel checks `oldfd` (`EBADF`), then the target range (`EBADF`), then
    /// closes the old target. A closed target's last reference is returned for
    /// the caller to free once the table lock is dropped.
    pub(crate) fn dup3(
        &mut self,
        oldfd: c_int,
        newfd: c_int,
        cloexec: bool,
    ) -> Result<Option<Release>, c_int> {
        if oldfd == newfd {
            return Err(EINVAL);
        }
        let resolved = self.resolve(oldfd).ok_or(EBADF)?;
        let index = Self::slot_index(newfd).ok_or(EBADF)?;
        if index >= self.limit {
            return Err(EBADF);
        }
        let released = self.close(newfd).unwrap_or(None);
        self.bind(index, resolved.desc, cloexec);
        Ok(released)
    }

    /// Drop a reference on `desc`; the last one removes the description and
    /// hands it back for the caller to free.
    fn unref(&mut self, desc: DescId) -> Option<Release> {
        let description = self
            .descriptions
            .get_mut(&desc)
            .expect("a referenced description exists");
        description.refs -= 1;
        if description.refs > 0 {
            return None;
        }
        let description = self
            .descriptions
            .remove(&desc)
            .expect("the description was just found");
        Some(Release {
            desc,
            kind: description.kind,
            handle: description.handle,
        })
    }

    /// `close(2)`: free the number; `EBADF` for an empty slot. Returns the
    /// description's release when this was its last reference.
    pub(crate) fn close(&mut self, fd: c_int) -> Result<Option<Release>, c_int> {
        let index = Self::slot_index(fd).ok_or(EBADF)?;
        let slot = self
            .slots
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(EBADF)?;
        Ok(self.unref(slot.desc))
    }

    /// `close_range(2)`: close (or, with `CLOSE_RANGE_CLOEXEC`, mark
    /// close-on-exec) every open number in `[first, last]`. `first > last` or an
    /// unknown flag is `EINVAL`; the range is clamped to the table, so a `last`
    /// of `u32::MAX` is the idiom it is on Linux. Returns every number closed,
    /// lowest first, each with its description's release when that was its last
    /// reference.
    pub(crate) fn close_range(
        &mut self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> Result<Vec<(c_int, Option<Release>)>, c_int> {
        if first > last || flags & !(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE) != 0 {
            return Err(EINVAL);
        }
        let first = first as usize;
        let last = (last as usize).min(self.slots.len().saturating_sub(1));
        let mut closed = Vec::new();
        let mut index = first;
        while index <= last && index < self.slots.len() {
            if flags & CLOSE_RANGE_CLOEXEC != 0 {
                if let Some(slot) = &mut self.slots[index] {
                    slot.cloexec = true;
                }
            } else if let Some(slot) = self.slots[index].take() {
                let release = self.unref(slot.desc);
                closed.push((index as c_int, release));
            }
            index += 1;
        }
        Ok(closed)
    }

    /// `F_GETFD`: the slot's `FD_CLOEXEC` bit.
    pub(crate) fn cloexec(&self, fd: c_int) -> Result<bool, c_int> {
        self.resolve(fd)
            .map(|resolved| resolved.cloexec)
            .ok_or(EBADF)
    }

    /// `F_SETFD`.
    pub(crate) fn set_cloexec(&mut self, fd: c_int, cloexec: bool) -> Result<(), c_int> {
        let slot = Self::slot_index(fd)
            .and_then(|index| self.slots.get_mut(index))
            .and_then(Option::as_mut)
            .ok_or(EBADF)?;
        slot.cloexec = cloexec;
        Ok(())
    }

    /// `F_SETFL`: replace the description's settable status bits (`mask`) with
    /// `bits`, leaving the access mode and the rest untouched as the kernel
    /// does.
    pub(crate) fn set_status(
        &mut self,
        fd: c_int,
        mask: Status,
        bits: Status,
    ) -> Result<(), c_int> {
        let resolved = self.resolve(fd).ok_or(EBADF)?;
        let description = self
            .descriptions
            .get_mut(&resolved.desc)
            .expect("a resolved description exists");
        description.status = (description.status & !mask) | (bits & mask);
        Ok(())
    }

    /// A hidden reference on the live description `desc` — what a file-backed
    /// mapping holds so its write-back survives the guest closing the number.
    /// `EBADF` for an id that names no live description. Freed with
    /// [`GuestFdTable::release`].
    pub(crate) fn retain(&mut self, desc: DescId) -> Result<(), c_int> {
        self.descriptions.get_mut(&desc).ok_or(EBADF)?.refs += 1;
        Ok(())
    }

    /// Drop a hidden reference taken by [`GuestFdTable::retain`]. `EBADF` for
    /// an id that names no live description (a double release).
    pub(crate) fn release(&mut self, desc: DescId) -> Result<Option<Release>, c_int> {
        if !self.descriptions.contains_key(&desc) {
            return Err(EBADF);
        }
        Ok(self.unref(desc))
    }

    /// Every open number, lowest first — the kernel's iteration order for
    /// `/proc/self/fd` and `close_range`.
    #[cfg(test)]
    fn open_numbers(&self) -> Vec<c_int> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.map(|_| index as c_int))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const O_READ: Status = 1 << 0;
    const O_WRITE: Status = 1 << 1;
    const O_APPEND: Status = 1 << 4;
    const O_NONBLOCK: Status = 1 << 7;

    fn table() -> GuestFdTable {
        GuestFdTable::new(RLIMIT_NOFILE, O_READ, O_WRITE, O_WRITE)
    }

    #[test]
    fn a_fresh_table_holds_the_three_standard_descriptors() {
        let table = table();
        assert_eq!(table.open_numbers(), vec![0, 1, 2]);
        assert_eq!(table.kind(0), Some(FdKind::Stdin));
        assert_eq!(table.kind(1), Some(FdKind::Stdout));
        assert_eq!(table.kind(2), Some(FdKind::Stderr));
        assert_eq!(table.resolve(1).unwrap().handle, 1);
        assert_eq!(table.resolve(2).unwrap().handle, 2);
        assert_eq!(table.kind(3), None);
        assert_eq!(table.kind(-1), None);
    }

    #[test]
    fn allocation_is_lowest_free_with_holes_reused() {
        let mut table = table();
        let a = table.install(FdKind::File, 10, O_READ, false).unwrap();
        let b = table.install(FdKind::File, 11, O_READ, false).unwrap();
        let c = table.install(FdKind::File, 12, O_READ, false).unwrap();
        assert_eq!((a, b, c), (3, 4, 5));
        assert!(table.close(b).unwrap().is_some());
        // The hole at 4 is the lowest free number, so the next open takes it.
        assert_eq!(table.install(FdKind::Pipe, 20, O_READ, false), Ok(4));
        assert_eq!(table.install(FdKind::Pipe, 21, O_READ, false), Ok(6));
        // Closing stdin frees number 0 for the next allocation.
        assert!(table.close(0).unwrap().is_some());
        assert_eq!(table.install(FdKind::File, 13, O_READ, false), Ok(0));
        assert_eq!(table.kind(0), Some(FdKind::File));
    }

    #[test]
    fn dup_binds_a_second_number_to_one_description_and_refcounts_it() {
        let mut table = table();
        let fd = table.install(FdKind::File, 10, O_READ, true).unwrap();
        let dup = table.dup(fd, 0, false).unwrap();
        assert_eq!(dup, 4);
        let original = table.resolve(fd).unwrap();
        let duplicate = table.resolve(dup).unwrap();
        assert_eq!(original.desc, duplicate.desc);
        assert_eq!(duplicate.handle, 10);
        // FD_CLOEXEC is per number, never copied by dup.
        assert!(original.cloexec);
        assert!(!duplicate.cloexec);
        // The first close keeps the description alive; the last releases it.
        assert_eq!(table.close(fd), Ok(None));
        assert_eq!(table.kind(fd), None);
        assert_eq!(table.resolve(dup).unwrap().handle, 10);
        assert_eq!(
            table.close(dup),
            Ok(Some(Release {
                desc: original.desc,
                kind: FdKind::File,
                handle: 10
            }))
        );
        assert_eq!(table.close(dup), Err(EBADF));
    }

    #[test]
    fn f_dupfd_honors_the_minimum_and_the_limit() {
        let mut table = table();
        let fd = table.install(FdKind::File, 10, O_READ, false).unwrap();
        assert_eq!(table.dup(fd, 20, true).unwrap(), 20);
        assert!(table.cloexec(20).unwrap());
        assert_eq!(table.dup(fd, 20, false).unwrap(), 21);
        assert_eq!(table.dup(fd, -1, false), Err(EINVAL));
        assert_eq!(table.dup(fd, RLIMIT_NOFILE as c_int, false), Err(EINVAL));
        assert_eq!(table.dup(fd, RLIMIT_NOFILE as c_int - 1, false), Ok(1023));
        assert_eq!(
            table.dup(fd, RLIMIT_NOFILE as c_int - 1, false),
            Err(EMFILE)
        );
        assert_eq!(table.dup(4000, 0, false), Err(EBADF));
    }

    #[test]
    fn dup3_binds_a_chosen_number_and_closes_what_it_named() {
        let mut table = table();
        let file = table.install(FdKind::File, 10, O_WRITE, false).unwrap();
        // dup2(file, 1): stdout's description loses its last reference.
        let released = table.dup3(file, 1, false).unwrap();
        assert_eq!(released.map(|r| r.kind), Some(FdKind::Stdout));
        assert_eq!(table.resolve(1).unwrap().handle, 10);
        assert_eq!(
            table.resolve(1).unwrap().desc,
            table.resolve(file).unwrap().desc
        );
        // A free target releases nothing; a cloexec request lands on the target.
        assert_eq!(table.dup3(file, 40, true), Ok(None));
        assert!(table.cloexec(40).unwrap());
        assert!(!table.cloexec(1).unwrap());
        // Equal numbers are EINVAL (dup3); the kernel checks oldfd first.
        assert_eq!(table.dup3(file, file, false), Err(EINVAL));
        assert_eq!(table.dup3(4000, 5, false), Err(EBADF));
        assert_eq!(table.dup3(file, RLIMIT_NOFILE as c_int, false), Err(EBADF));
        assert_eq!(table.dup3(file, -2, false), Err(EBADF));
    }

    #[test]
    fn emfile_at_the_limit() {
        let mut table = GuestFdTable::new(5, O_READ, O_WRITE, O_WRITE);
        assert_eq!(table.install(FdKind::File, 1, O_READ, false), Ok(3));
        assert_eq!(table.install(FdKind::File, 2, O_READ, false), Ok(4));
        assert_eq!(table.install(FdKind::File, 3, O_READ, false), Err(EMFILE));
        // A pair needs two slots at once: one free slot is EMFILE with nothing
        // created.
        table.close(4).unwrap();
        assert_eq!(
            table.install_pair(FdKind::Pipe, (7, O_READ), (8, O_WRITE), false),
            Err(EMFILE)
        );
        assert_eq!(table.open_numbers(), vec![0, 1, 2, 3]);
        assert_eq!(table.descriptions.len(), 4);
        table.close(3).unwrap();
        assert_eq!(
            table.install_pair(FdKind::Pipe, (7, O_READ), (8, O_WRITE), true),
            Ok((3, 4))
        );
        assert!(table.cloexec(3).unwrap() && table.cloexec(4).unwrap());
    }

    #[test]
    fn close_range_closes_or_marks_a_clamped_range() {
        let mut table = table();
        for handle in 10..16 {
            table.install(FdKind::File, handle, O_READ, false).unwrap();
        }
        assert_eq!(table.close_range(5, 3, 0), Err(EINVAL));
        assert_eq!(table.close_range(3, 4, 0x8), Err(EINVAL));
        let closed = table.close_range(4, 6, 0).unwrap();
        assert_eq!(
            closed
                .iter()
                .map(|(number, release)| (*number, release.map(|r| r.handle)))
                .collect::<Vec<_>>(),
            vec![(4, Some(11)), (5, Some(12)), (6, Some(13))]
        );
        assert_eq!(table.open_numbers(), vec![0, 1, 2, 3, 7, 8]);
        // CLOSE_RANGE_CLOEXEC marks instead of closing, over the whole table.
        assert_eq!(
            table.close_range(7, u32::MAX, CLOSE_RANGE_CLOEXEC),
            Ok(vec![])
        );
        assert!(table.cloexec(7).unwrap() && table.cloexec(8).unwrap());
        assert!(!table.cloexec(3).unwrap());
        // A dup'd description survives until its last number in the range goes.
        let dup = table.dup(3, 0, false).unwrap();
        assert_eq!(dup, 4);
        assert_eq!(table.close_range(3, 3, 0), Ok(vec![(3, None)]));
        let closed = table.close_range(0, u32::MAX, CLOSE_RANGE_UNSHARE).unwrap();
        assert_eq!(closed.len(), 6);
        assert_eq!(
            closed
                .iter()
                .filter(|(_, release)| release.is_some())
                .count(),
            6
        );
        assert!(table.open_numbers().is_empty());
        assert_eq!(table.install(FdKind::File, 99, O_READ, false), Ok(0));
    }

    #[test]
    fn status_flags_are_per_description_and_cloexec_per_number() {
        let mut table = table();
        let fd = table.install(FdKind::Pipe, 10, O_READ, false).unwrap();
        let dup = table.dup(fd, 0, false).unwrap();
        table
            .set_status(fd, O_NONBLOCK | O_APPEND, O_NONBLOCK)
            .unwrap();
        assert_eq!(table.resolve(dup).unwrap().status, O_READ | O_NONBLOCK);
        table.set_status(dup, O_NONBLOCK | O_APPEND, 0).unwrap();
        assert_eq!(table.resolve(fd).unwrap().status, O_READ);
        table.set_cloexec(fd, true).unwrap();
        assert!(table.cloexec(fd).unwrap());
        assert!(!table.cloexec(dup).unwrap());
        assert_eq!(table.set_cloexec(4000, true), Err(EBADF));
        assert_eq!(table.set_status(4000, O_NONBLOCK, 0), Err(EBADF));
        assert_eq!(table.cloexec(-1), Err(EBADF));
    }

    #[test]
    fn a_retained_description_outlives_its_numbers() {
        let mut table = table();
        let fd = table.install(FdKind::File, 10, O_READ, false).unwrap();
        let desc = table.resolve(fd).unwrap().desc;
        table.retain(desc).unwrap();
        assert_eq!(table.close(fd), Ok(None));
        assert_eq!(table.description(desc).map(|d| d.handle), Some(10));
        // The number is free for reuse while the hidden reference lives on.
        assert_eq!(table.install(FdKind::File, 11, O_READ, false), Ok(fd));
        assert_eq!(
            table.release(desc),
            Ok(Some(Release {
                desc,
                kind: FdKind::File,
                handle: 10
            }))
        );
        assert_eq!(table.release(desc), Err(EBADF));
        assert_eq!(table.retain(desc), Err(EBADF));
    }

    #[test]
    fn description_ids_are_never_reused() {
        let mut table = table();
        let a = table.install(FdKind::File, 10, O_READ, false).unwrap();
        let first = table.resolve(a).unwrap().desc;
        table.close(a).unwrap();
        let b = table.install(FdKind::File, 10, O_READ, false).unwrap();
        assert_eq!(a, b);
        assert_ne!(table.resolve(b).unwrap().desc, first);
    }
}
