//! POSIX record locks and open-file-description locks: `fcntl`'s `F_GETLK`/
//! `F_SETLK`/`F_SETLKW` and `F_OFD_GETLK`/`F_OFD_SETLK`/`F_OFD_SETLKW`, kept
//! as Linux 6.8's `fs/locks.c` keeps them.
//!
//! A lock is a byte range `[start, end]` (`end` is `OFFSET_MAX` for a lock to
//! the end of the file) of one type on one file, held by an OWNER: the process
//! for a POSIX lock, the open file description for an OFD lock. Locks of one
//! owner never conflict with each other; locks of different owners conflict
//! where they overlap and either is a write lock, so a POSIX lock and an OFD
//! lock of the same process do conflict. A request replaces the owner's locks
//! over its range, splitting a lock it cuts through, and the owner's locks of
//! one type that touch or overlap merge into one.
//!
//! A file's locks are kept in the kernel's list order (`flc_posix`): grouped
//! by owner, the groups in the order their owners first locked (a group whose
//! last lock goes is dropped, so the owner's next lock starts a new group at
//! the end), each group sorted by start. `F_GETLK` reports the first
//! conflicting lock in that order.
//!
//! `F_SETLKW` parks the calling task on the scheduler until the lock it
//! conflicts with changes, then retries. As `__locks_insert_block` does, a
//! request that conflicts with an earlier waiter's queues behind that waiter
//! instead, so conflicting waiters take the range in the order they came: a
//! granted waiter's queue moves onto its new lock, and a waiter that parks
//! again or gives up lets its queue retry. A POSIX request whose blocker's
//! owner is (transitively) waiting on a lock of the process answers `EDEADLK`
//! (`posix_locks_deadlock`; OFD requests are never checked, and a wait on an
//! OFD lock or request is never followed). A POSIX lock is released when the
//! process closes ANY descriptor of its file (an `O_PATH` one excepted), an
//! OFD lock when its description's last reference goes.

use super::*;
use crate::LockIdentity;
use crate::fdtable::DescId;

/// The end of a lock that runs to the end of the file (`OFFSET_MAX`).
pub(crate) const OFFSET_MAX: u64 = i64::MAX as u64;

/// `MAX_DEADLK_ITERATIONS`: how far deadlock detection follows the chain of
/// waiting owners before giving up (and reporting no deadlock).
const MAX_DEADLK_ITERATIONS: usize = 10;

/// Who holds a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// A POSIX lock: the process (`current->files`), whichever thread and
    /// descriptor took it.
    Process,
    /// An OFD lock: the open file description it was taken through.
    Description(DescId),
}

/// A lock's type, or a request's (`Unlock` only ever as a request).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Type {
    Read,
    Write,
    Unlock,
}

/// A held lock, or a request for one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lock {
    pub(crate) owner: Owner,
    pub(crate) kind: Type,
    pub(crate) start: u64,
    /// Inclusive; [`OFFSET_MAX`] for a lock to the end of the file.
    pub(crate) end: u64,
}

impl Lock {
    fn overlaps(&self, other: &Lock) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// `posix_locks_conflict`: another owner's lock over part of the range,
    /// and either of the two a write lock.
    fn conflicts_with(&self, held: &Lock) -> bool {
        self.owner != held.owner
            && self.overlaps(held)
            && (self.kind == Type::Write || held.kind == Type::Write)
    }

    /// `posix_test_locks_conflict`: an `F_UNLCK` test (which only
    /// `F_OFD_GETLK` accepts) finds the caller's own lock over the range.
    fn tested_by(&self, held: &Lock) -> bool {
        if self.kind == Type::Unlock {
            self.owner == held.owner && self.overlaps(held)
        } else {
            self.conflicts_with(held)
        }
    }
}

/// A task parked in `F_SETLKW`, and the lock it waits on.
struct Waiter {
    task: TaskId,
    file: LockIdentity,
    request: Lock,
    /// The held lock the request conflicted with when it parked.
    blocker: Lock,
    /// The earlier waiter this one queued behind (its task and request),
    /// or `None` for a waiter on the held lock itself.
    behind: Option<(TaskId, Lock)>,
}

/// Every file's locks and every parked `F_SETLKW`.
#[derive(Default)]
pub(crate) struct Locks {
    files: BTreeMap<LockIdentity, Vec<Lock>>,
    waiters: Vec<Waiter>,
}

impl Locks {
    /// `F_GETLK`: the first lock, in list order, the request would conflict
    /// with.
    fn test(&self, file: LockIdentity, request: &Lock) -> Option<Lock> {
        self.files
            .get(&file)?
            .iter()
            .find(|held| request.tested_by(held))
            .copied()
    }

    /// The first lock blocking `request` (an unlock never blocks).
    fn blocker(&self, file: LockIdentity, request: &Lock) -> Option<Lock> {
        if request.kind == Type::Unlock {
            return None;
        }
        self.files
            .get(&file)?
            .iter()
            .find(|held| request.conflicts_with(held))
            .copied()
    }

    /// Whether any file holds a lock of `owner`.
    fn holds(&self, owner: Owner) -> bool {
        self.files
            .values()
            .any(|locks| locks.iter().any(|lock| lock.owner == owner))
    }

    /// Replace the owner's locks over the request's range with the request
    /// (nothing, for an unlock), merging the owner's touching locks of one
    /// type, and answer the waiters to wake: those whose blocker changed, and
    /// for a granted waiter (`requester`) the waiters queued behind it when
    /// it merged into a lock it already held. The request must not conflict.
    fn apply(
        &mut self,
        file: LockIdentity,
        request: Lock,
        requester: Option<TaskId>,
    ) -> Vec<TaskId> {
        let list = self.files.entry(file).or_default();
        let group = list.iter().position(|lock| lock.owner == request.owner);
        let survivor = survivor(list, &request);
        let mut mine = Vec::new();
        list.retain(|lock| {
            let keep = lock.owner != request.owner;
            if !keep {
                mine.push(*lock);
            }
            keep
        });
        let mut pieces = Vec::new();
        for lock in mine {
            if !lock.overlaps(&request) {
                pieces.push(lock);
                continue;
            }
            if lock.start < request.start {
                pieces.push(Lock {
                    end: request.start - 1,
                    ..lock
                });
            }
            if lock.end > request.end {
                pieces.push(Lock {
                    start: request.end + 1,
                    ..lock
                });
            }
        }
        if request.kind != Type::Unlock {
            pieces.push(request);
        }
        pieces.sort_by_key(|lock| lock.start);
        let mut merged: Vec<Lock> = Vec::new();
        for lock in pieces {
            match merged.last_mut() {
                Some(last)
                    if last.kind == lock.kind && lock.start <= last.end.saturating_add(1) =>
                {
                    last.end = last.end.max(lock.end);
                }
                _ => merged.push(lock),
            }
        }
        // The request's lock as it now stands (merged with its neighbours).
        let granted = merged
            .iter()
            .find(|lock| lock.start <= request.start && request.start <= lock.end)
            .copied();
        // The owner's group keeps its place; a new owner's goes last.
        let at = group.unwrap_or(list.len());
        list.splice(at..at, merged);
        if list.is_empty() {
            self.files.remove(&file);
        }
        let mut woken = Vec::new();
        if let (Some(task), Some(granted)) = (requester, granted) {
            if survivor.is_some() {
                // Merged into a lock already held: its queue retries
                // (`locks_delete_block`).
                woken = self.detach(task);
            } else {
                // A new lock takes over its queue (`locks_move_blocks`).
                for waiter in &mut self.waiters {
                    if waiter.behind.is_some_and(|(behind, _)| behind == task) {
                        waiter.behind = None;
                        waiter.blocker = granted;
                    }
                }
            }
        }
        // The lock the request merged into was extended in place: its
        // waiters stay parked on it.
        if let (Some(survivor), Some(granted)) = (survivor, granted) {
            for waiter in &mut self.waiters {
                if waiter.file == file && waiter.behind.is_none() && waiter.blocker == survivor {
                    waiter.blocker = granted;
                }
            }
        }
        woken.extend(self.wake_changed(file));
        woken
    }

    /// Unpark the waiters on `file` whose blocker is no longer held as it
    /// was: each retries its request (`locks_wake_up_blocks`). A waiter
    /// queued behind another stays parked.
    fn wake_changed(&mut self, file: LockIdentity) -> Vec<TaskId> {
        let held = self.files.get(&file);
        let mut woken = Vec::new();
        self.waiters.retain(|waiter| {
            let still = waiter.file != file
                || waiter.behind.is_some()
                || held.is_some_and(|locks| locks.contains(&waiter.blocker));
            if !still {
                woken.push(waiter.task);
            }
            still
        });
        woken
    }

    /// Park `task`'s `request` on `blocker`, behind the first earlier waiter
    /// there that it conflicts with, and so on down that waiter's queue
    /// (`__locks_insert_block`).
    fn enqueue(&mut self, task: TaskId, file: LockIdentity, request: Lock, blocker: Lock) {
        let mut behind = None;
        while let Some(earlier) = self.waiters.iter().find(|waiter| {
            waiter.file == file
                && match behind {
                    None => waiter.behind.is_none() && waiter.blocker == blocker,
                    Some((ahead, _)) => waiter.behind.is_some_and(|(of, _)| of == ahead),
                }
                && waiter.request.conflicts_with(&request)
        }) {
            behind = Some((earlier.task, earlier.request));
        }
        self.waiters.push(Waiter {
            task,
            file,
            request,
            blocker,
            behind,
        });
    }

    /// Free the waiters queued directly behind `task`, to retry
    /// (`__locks_wake_up_blocks` on its request).
    fn detach(&mut self, task: TaskId) -> Vec<TaskId> {
        let mut woken = Vec::new();
        self.waiters.retain(|waiter| {
            let queued = waiter.behind.is_some_and(|(behind, _)| behind == task);
            if queued {
                woken.push(waiter.task);
            }
            !queued
        });
        woken
    }

    /// Remove every lock `owner` holds on `file`.
    fn release(&mut self, file: LockIdentity, owner: Owner) -> Vec<TaskId> {
        self.apply(
            file,
            Lock {
                owner,
                kind: Type::Unlock,
                start: 0,
                end: OFFSET_MAX,
            },
            None,
        )
    }

    /// `posix_locks_deadlock`: whether granting `caller` a wait on `blocker`
    /// would close a cycle — the blocker's owner waits on a lock whose owner
    /// waits … on a lock of the caller. OFD requests are never checked.
    fn deadlock(&self, caller: Owner, blocker: Lock) -> bool {
        if caller != Owner::Process {
            return false;
        }
        let mut block = blocker;
        for _ in 0..=MAX_DEADLK_ITERATIONS {
            // `what_owner_is_waiting_for`: the newest waiter of the blocker's
            // owner in `blocked_hash`, which holds only a waiter on a POSIX
            // lock or request, then what heads its queue.
            let Some(waiter) = self.waiters.iter().rev().find(|waiter| {
                let on = waiter.behind.map_or(waiter.blocker, |(_, request)| request);
                waiter.request.owner == block.owner && on.owner == Owner::Process
            }) else {
                return false;
            };
            block = self.head(waiter);
            if block.owner == caller {
                return true;
            }
        }
        false
    }

    /// What `waiter`'s queue waits on: the held lock its first waiter parked
    /// on, or a queued-behind waiter's request while that one is awake.
    fn head(&self, waiter: &Waiter) -> Lock {
        let mut waiter = waiter;
        loop {
            let Some((task, request)) = waiter.behind else {
                return waiter.blocker;
            };
            match self.waiters.iter().find(|earlier| earlier.task == task) {
                Some(earlier) => waiter = earlier,
                None => return request,
            }
        }
    }

    fn unwait(&mut self, task: TaskId) {
        self.waiters.retain(|waiter| waiter.task != task);
    }
}

/// The owner's lock that `request` extends in place, as `posix_lock_inode`
/// merges: the first of the owner's locks, in list order, of the request's
/// type that it overlaps or touches, unless a lock of another type the
/// request wholly covers came first (then a new lock replaces that one and
/// absorbs the rest). An unlock extends nothing.
fn survivor(list: &[Lock], request: &Lock) -> Option<Lock> {
    if request.kind == Type::Unlock {
        return None;
    }
    for lock in list.iter().filter(|lock| lock.owner == request.owner) {
        if lock.kind == request.kind {
            if lock.end.saturating_add(1) < request.start {
                continue;
            }
            if lock.start > request.end.saturating_add(1) {
                return None;
            }
            return Some(*lock);
        }
        if lock.end < request.start {
            continue;
        }
        if lock.start > request.end || lock.end > request.end || lock.start >= request.start {
            return None;
        }
    }
    None
}

/// `F_GETLK`/`F_OFD_GETLK`: the lock `request` conflicts with, if any.
pub(crate) fn test(file: LockIdentity, request: Lock) -> Option<Lock> {
    lock_state().locks.test(file, &request)
}

/// `F_SETLK`/`F_SETLKW` and their OFD forms: take, change or drop the
/// owner's lock over the request's range. A conflict is `EAGAIN`, or with
/// `wait` parks the task until the blocking lock changes and retries; a POSIX
/// wait that would deadlock is `EDEADLK`.
pub(crate) fn set(file: LockIdentity, request: Lock, wait: bool) -> Result<(), c_int> {
    let me = wait.then(current_task);
    loop {
        let mut state = lock_state();
        let Some(blocker) = state.locks.blocker(file, &request) else {
            let woken = state.locks.apply(file, request, me);
            drop(state);
            wake_all(woken);
            return Ok(());
        };
        let Some(me) = me else {
            return Err(crate::EWOULDBLOCK);
        };
        // The waiters queued behind this request retry before it waits again.
        let queued = state.locks.detach(me);
        if !queued.is_empty() {
            drop(state);
            wake_all(queued);
            continue;
        }
        if state.locks.deadlock(request.owner, blocker) {
            return Err(crate::EDEADLK);
        }
        state.locks.enqueue(me, file, request, blocker);
        let step = state.block(
            me,
            "record-lock",
            Wait::new(BlockClass::Io, vec![WaiterLoc::RecordLock]),
        );
        let interrupted = match step {
            Ok(Step::Switch(picked)) => {
                switch_and_park(state, picked, me);
                None
            }
            Ok(Step::Continue) => {
                drop(state);
                None
            }
            Err(error) => Some(error.into_posix()),
        };
        {
            let mut state = lock_state();
            state.locks.unwait(me);
            state.timed_out.remove(&me);
        }
        #[cfg(target_os = "linux")]
        let interrupted = interrupted
            .or_else(|| (signals::resume() == signals::Resumed::Eintr).then_some(crate::EINTR));
        if let Some(errno) = interrupted {
            // The waiters queued behind it retry (`locks_delete_block`).
            let queued = lock_state().locks.detach(me);
            wake_all(queued);
            return Err(errno);
        }
    }
}

/// Whether the process holds a POSIX lock anywhere: only then does a close
/// have locks to release.
pub(crate) fn process_holds_locks() -> bool {
    lock_state().locks.holds(Owner::Process)
}

/// A close of any descriptor of `file` releases the process's POSIX locks on
/// it (`locks_remove_posix`).
pub(crate) fn release_process_locks(file: LockIdentity) {
    let woken = lock_state().locks.release(file, Owner::Process);
    wake_all(woken);
}

/// The last close of a description releases its OFD locks on every file
/// (`locks_remove_file`).
pub(crate) fn release_description_locks(desc: DescId) {
    let owner = Owner::Description(desc);
    let woken = {
        let mut state = lock_state();
        let files: Vec<LockIdentity> = state
            .locks
            .files
            .iter()
            .filter(|(_, locks)| locks.iter().any(|lock| lock.owner == owner))
            .map(|(file, _)| *file)
            .collect();
        let mut woken = Vec::new();
        for file in files {
            woken.extend(state.locks.release(file, owner));
        }
        woken
    };
    wake_all(woken);
}

/// Unlink a task from the waiters (a signal interrupted its wait).
pub(super) fn unwait(state: &mut ThreadRuntime, task: TaskId) {
    state.locks.unwait(task);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: LockIdentity = LockIdentity::Inode(7);

    fn lock(owner: Owner, kind: Type, start: u64, end: u64) -> Lock {
        Lock {
            owner,
            kind,
            start,
            end,
        }
    }

    fn held(locks: &Locks) -> Vec<(Owner, Type, u64, u64)> {
        locks.files.get(&FILE).map_or_else(Vec::new, |list| {
            list.iter()
                .map(|lock| (lock.owner, lock.kind, lock.start, lock.end))
                .collect()
        })
    }

    const P: Owner = Owner::Process;

    fn ofd(id: DescId) -> Owner {
        Owner::Description(id)
    }

    #[test]
    fn an_unlock_splits_a_lock_and_a_relock_merges_it_back() {
        let mut locks = Locks::default();
        locks.apply(FILE, lock(P, Type::Write, 0, OFFSET_MAX), None);
        locks.apply(FILE, lock(P, Type::Unlock, 100, 149), None);
        assert_eq!(
            held(&locks),
            [(P, Type::Write, 0, 99), (P, Type::Write, 150, OFFSET_MAX)]
        );
        locks.apply(FILE, lock(P, Type::Write, 100, 149), None);
        assert_eq!(held(&locks), [(P, Type::Write, 0, OFFSET_MAX)]);
        // Touching ranges of one type merge; of different types they split.
        locks.apply(FILE, lock(P, Type::Unlock, 0, OFFSET_MAX), None);
        locks.apply(FILE, lock(P, Type::Read, 0, 9), None);
        locks.apply(FILE, lock(P, Type::Read, 10, 19), None);
        locks.apply(FILE, lock(P, Type::Write, 5, 14), None);
        assert_eq!(
            held(&locks),
            [
                (P, Type::Read, 0, 4),
                (P, Type::Write, 5, 14),
                (P, Type::Read, 15, 19)
            ]
        );
    }

    #[test]
    fn owners_conflict_only_with_each_other_and_are_reported_in_list_order() {
        let mut locks = Locks::default();
        let (a, b) = (ofd(1), ofd(2));
        locks.apply(FILE, lock(a, Type::Read, 0, 9), None);
        locks.apply(FILE, lock(P, Type::Read, 5, 14), None);
        // Readers share; the process's own locks never block it.
        assert_eq!(locks.blocker(FILE, &lock(b, Type::Read, 0, 20)), None);
        assert_eq!(locks.blocker(FILE, &lock(P, Type::Write, 15, 20)), None);
        // A writer is blocked by the first overlapping lock in list order,
        // which is the owner that locked first.
        assert_eq!(
            locks.test(FILE, &lock(b, Type::Write, 0, OFFSET_MAX)),
            Some(lock(a, Type::Read, 0, 9))
        );
        // An owner that lets go of everything re-enters at the end.
        locks.apply(FILE, lock(a, Type::Unlock, 0, OFFSET_MAX), None);
        locks.apply(FILE, lock(a, Type::Read, 0, 9), None);
        assert_eq!(
            locks.test(FILE, &lock(b, Type::Write, 0, OFFSET_MAX)),
            Some(lock(P, Type::Read, 5, 14))
        );
        // An F_UNLCK test finds the caller's own lock.
        assert_eq!(
            locks.test(FILE, &lock(a, Type::Unlock, 3, 3)),
            Some(lock(a, Type::Read, 0, 9))
        );
    }

    #[test]
    fn a_change_to_a_blocker_wakes_its_waiters() {
        let mut locks = Locks::default();
        let a = ofd(1);
        locks.apply(FILE, lock(a, Type::Write, 0, 9), None);
        let request = lock(P, Type::Write, 0, 9);
        let blocker = locks.blocker(FILE, &request).unwrap();
        locks.enqueue(TaskId(5), FILE, request, blocker);
        // A lock elsewhere leaves the blocker as it was, and extending it in
        // place (the owner's touching lock of its type) keeps its waiters.
        assert!(
            locks
                .apply(FILE, lock(a, Type::Write, 50, 59), None)
                .is_empty()
        );
        assert!(
            locks
                .apply(FILE, lock(a, Type::Write, 10, 19), None)
                .is_empty()
        );
        assert_eq!(
            locks.apply(FILE, lock(a, Type::Unlock, 0, 4), None),
            [TaskId(5)]
        );
        assert!(locks.waiters.is_empty());
    }

    #[test]
    fn conflicting_waiters_take_the_range_in_the_order_they_came() {
        let mut locks = Locks::default();
        let (a, b, c, d) = (ofd(1), ofd(2), ofd(3), ofd(4));
        locks.apply(FILE, lock(a, Type::Write, 0, 9), None);
        let blocker = lock(a, Type::Write, 0, 9);
        // c conflicts with b, which came first, and queues behind it; d
        // conflicts only with a.
        locks.enqueue(TaskId(1), FILE, lock(b, Type::Write, 0, 4), blocker);
        locks.enqueue(TaskId(2), FILE, lock(c, Type::Write, 0, 4), blocker);
        locks.enqueue(TaskId(3), FILE, lock(d, Type::Read, 5, 9), blocker);
        assert_eq!(
            locks.apply(FILE, lock(a, Type::Unlock, 0, 9), None),
            [TaskId(1), TaskId(3)]
        );
        // b's grant moves c onto b's new lock; b's unlock wakes it.
        assert!(
            locks
                .apply(FILE, lock(b, Type::Write, 0, 4), Some(TaskId(1)))
                .is_empty()
        );
        assert_eq!(
            locks.apply(FILE, lock(b, Type::Unlock, 0, 4), None),
            [TaskId(2)]
        );
    }

    #[test]
    fn a_posix_wait_that_closes_a_cycle_is_a_deadlock() {
        let mut locks = Locks::default();
        let d = ofd(1);
        // The process holds [0, 9]; description D holds [20, 29] and waits,
        // through another thread's F_OFD_SETLKW, for the process's lock.
        locks.apply(FILE, lock(P, Type::Write, 0, 9), None);
        locks.apply(FILE, lock(d, Type::Write, 20, 29), None);
        let ofd_request = lock(d, Type::Write, 0, 9);
        let ofd_blocker = locks.blocker(FILE, &ofd_request).unwrap();
        // An OFD request is never judged a deadlock.
        assert!(!locks.deadlock(d, ofd_blocker));
        locks.enqueue(TaskId(2), FILE, ofd_request, ofd_blocker);
        // The process now waits on D's lock: D waits on the process.
        let blocker = locks.blocker(FILE, &lock(P, Type::Write, 20, 29)).unwrap();
        assert!(locks.deadlock(P, blocker));
        locks.unwait(TaskId(2));
        assert!(!locks.deadlock(P, blocker));
        // A wait on an OFD lock is never followed: D waits on X's OFD lock,
        // and X on the process.
        let x = ofd(2);
        locks.apply(FILE, lock(x, Type::Write, 40, 49), None);
        let on_x = lock(d, Type::Write, 40, 49);
        locks.enqueue(TaskId(2), FILE, on_x, locks.blocker(FILE, &on_x).unwrap());
        locks.enqueue(
            TaskId(3),
            FILE,
            lock(x, Type::Write, 0, 9),
            lock(P, Type::Write, 0, 9),
        );
        assert!(!locks.deadlock(P, blocker));
    }
}

/// `F_SETLKW` through the shim's entry, on the real scheduler.
#[cfg(all(test, target_os = "linux"))]
mod wait_tests {
    use super::*;
    use crate::thread::signals::tests::{delay, isolated, join, spawn};
    use crate::{F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW, F_SETLKW, F_UNLCK, F_WRLCK, PatinaFlock};
    use std::sync::atomic::{AtomicI32, Ordering};

    fn open() -> c_int {
        let flags = crate::O_READ | crate::O_WRITE | crate::O_CREATE;
        // SAFETY: a NUL-terminated path.
        unsafe { crate::patina_openat(crate::paths::AT_FDCWD, c"/locked".as_ptr(), flags, 0o600) }
    }

    /// `fcntl(fd, command)` on bytes 0..9; the answer and what came back.
    fn fcntl(fd: c_int, command: u32, l_type: i16) -> (c_int, PatinaFlock) {
        let mut lock = PatinaFlock {
            l_type,
            l_whence: 0,
            l_start: 0,
            l_len: 10,
            l_pid: 0,
        };
        // SAFETY: a live `struct patina_flock`.
        let r = unsafe { crate::patina_record_lock(fd, command, &mut lock) };
        (if r == 0 { 0 } else { crate::patina_errno() }, lock)
    }

    /// A waiter granted its lock after another thread closed its descriptor
    /// keeps nothing: an OFD lock goes with the description when the call
    /// returns, and a POSIX one is undone with `EBADF` (`fcntl_setlk`'s close
    /// race).
    #[test]
    fn a_wait_granted_after_its_descriptor_closed_keeps_no_lock() {
        static ANSWER: AtomicI32 = AtomicI32::new(-1);
        isolated(|| {
            let holder = open();
            for (command, answer) in [(F_OFD_SETLKW, 0), (F_SETLKW, crate::EBADF)] {
                let waiter = open();
                assert_eq!(fcntl(holder, F_OFD_SETLK, F_WRLCK).0, 0);
                let helper = spawn(move || {
                    ANSWER.store(fcntl(waiter, command, F_WRLCK).0, Ordering::SeqCst);
                });
                delay();
                assert_eq!(lock_state().locks.waiters.len(), 1, "the helper waits");
                assert_eq!(crate::patina_close(waiter), 0);
                assert_eq!(fcntl(holder, F_OFD_SETLK, F_UNLCK).0, 0);
                join(helper);
                assert_eq!(ANSWER.load(Ordering::SeqCst), answer);
                let (r, lock) = fcntl(holder, F_OFD_GETLK, F_WRLCK);
                assert_eq!((r, lock.l_type), (0, F_UNLCK), "command {command}");
            }
        });
    }
}
