//! Synchronization tables, lock kinds, and managed-thread join state.

use super::*;
use crate::hostcoll::{HostDeque, HostMap};

/// A mutex's type: what its owner's relock does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum MutexKind {
    /// `PTHREAD_MUTEX_NORMAL` (glibc's default, and its adaptive type):
    /// the owner's relock deadlocks, as glibc's does — the owner parks
    /// behind itself, and the run ends as a deadlock unless the guest has
    /// other work. Its unlock checks no owner: whoever unlocks it frees
    /// it, and unlocking it unlocked is 0.
    #[default]
    Normal,
    /// A normal mutex that is robust or priority-inheriting: its relock
    /// deadlocks as [`Self::Normal`]'s does, but an unlock by a thread
    /// that does not hold it is `EPERM`, as glibc's full unlock path
    /// answers. Decoded from glibc's flags, so only on Linux.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NormalOwned,
    /// `PTHREAD_MUTEX_ERRORCHECK`: the owner's relock is `EDEADLK`.
    ErrorCheck,
    /// `PTHREAD_MUTEX_RECURSIVE`: the owner relocks, and the mutex is
    /// free after as many unlocks as locks.
    Recursive,
}

impl MutexKind {
    /// The type in glibc's encoding, shared by a mutex attribute's
    /// `mutexkind` and a mutex's `__kind`: the low two bits, and the
    /// robust (16) and priority-inheritance (32) flags, under which a
    /// normal mutex's unlock checks its owner. The other flags
    /// (process-shared, priority protection, elision) change neither.
    #[cfg(target_os = "linux")]
    fn from_glibc(kind: c_int) -> Self {
        const ROBUST: c_int = 16;
        const PRIO_INHERIT: c_int = 32;
        match kind & 3 {
            1 => Self::Recursive,
            2 => Self::ErrorCheck,
            _ if kind & (ROBUST | PRIO_INHERIT) != 0 => Self::NormalOwned,
            _ => Self::Normal,
        }
    }

    /// The type a `pthread_mutex_init` attribute names; no attribute is
    /// the default type.
    ///
    /// # Safety
    /// Non-null `attr` must point to an initialized `pthread_mutexattr_t`.
    pub(super) unsafe fn of_attr(attr: *const c_void) -> Self {
        #[cfg(target_os = "linux")]
        {
            if attr.is_null() {
                return Self::Normal;
            }
            // SAFETY: glibc's `struct pthread_mutexattr` is one `int`,
            // `mutexkind`.
            Self::from_glibc(unsafe { attr.cast::<c_int>().read() })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = attr;
            Self::ErrorCheck
        }
    }

    /// The type of a mutex first touched without `pthread_mutex_init`:
    /// the one its static initializer wrote (glibc's
    /// `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP` and
    /// `PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP` set `__kind`).
    ///
    /// # Safety
    /// `mutex` must point to a `pthread_mutex_t`.
    pub(super) unsafe fn of_static(mutex: *const c_void) -> Self {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `__kind` is the fifth `int` of glibc's
            // `struct __pthread_mutex_s` on the 64-bit targets.
            Self::from_glibc(unsafe { mutex.cast::<c_int>().add(4).read() })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = mutex;
            Self::ErrorCheck
        }
    }
}

#[derive(Default)]
pub(super) struct MutexEntry {
    pub(super) owner: Option<TaskId>,
    /// How many times the owner holds it: 1, or more for a recursive
    /// mutex.
    count: u32,
    kind: MutexKind,
    pub(super) waiters: HostDeque<TaskId>,
}

impl MutexEntry {
    fn of_kind(kind: MutexKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Hand the mutex to `task`, held once.
    fn grant(&mut self, task: TaskId) {
        self.owner = Some(task);
        self.count = 1;
    }
}

pub(super) struct CondEntry {
    pub(super) waiters: HostDeque<(TaskId, usize)>,
    /// The clock its timed waits judge their deadline on: its attribute's
    /// (`pthread_condattr_setclock`), `CLOCK_REALTIME` by default.
    clock: ClockKind,
}

impl Default for CondEntry {
    fn default() -> Self {
        Self {
            waiters: HostDeque::default(),
            clock: ClockKind::Realtime,
        }
    }
}

impl CondEntry {
    /// The clock a `pthread_cond_init` attribute names; no attribute is
    /// `CLOCK_REALTIME`.
    ///
    /// # Safety
    /// Non-null `attr` must point to an initialized `pthread_condattr_t`.
    pub(super) unsafe fn clock_of_attr(attr: *const c_void) -> ClockKind {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: glibc's `struct pthread_condattr` is one `int`,
            // `value`: bit 0 process-shared, bit 1 the clock
            // (`CLOCK_MONOTONIC` when set; `pthread_condattr_setclock`
            // accepts only it and `CLOCK_REALTIME`).
            if !attr.is_null() && (unsafe { attr.cast::<c_int>().read() } >> 1) & 1 == 1 {
                return ClockKind::Monotonic;
            }
        }
        let _ = attr;
        ClockKind::Realtime
    }
}

/// Which side a reader/writer lock favours when both wait
/// (`nptl/pthread_rwlock_common.c`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // glibc's own names for the kinds
pub(super) enum RwLockKind {
    /// glibc's default, `PTHREAD_RWLOCK_PREFER_READER_NP`: a new reader
    /// acquires the lock whenever no writer holds it, waiting writers or
    /// not, and a releasing writer hands the lock to the waiting readers
    /// first.
    #[default]
    PreferReader,
    /// `PTHREAD_RWLOCK_PREFER_WRITER_NP`: readers are admitted as by
    /// default, but a releasing writer hands the lock to the next
    /// waiting writer first (glibc's writer-to-writer hand-over, which
    /// every kind but the default takes). Decoded from glibc's
    /// encoding, so only on Linux.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    PreferWriter,
    /// `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`: a releasing writer
    /// hands over to the next writer, and a new reader also waits while
    /// a writer holds the lock or waits for it, so readers never starve a
    /// writer.
    PreferWriterNonrecursive,
}

impl RwLockKind {
    /// The kind in glibc's encoding, shared by an attribute's `lockkind`
    /// and a lock's `__flags`.
    #[cfg(target_os = "linux")]
    fn from_glibc(kind: c_int) -> Self {
        match kind {
            0 => Self::PreferReader,
            2 => Self::PreferWriterNonrecursive,
            // glibc tests the default by equality: any other value hands
            // over writer to writer and admits readers.
            _ => Self::PreferWriter,
        }
    }

    /// The kind a `pthread_rwlock_init` attribute names; no attribute is
    /// the default kind.
    ///
    /// # Safety
    /// Non-null `attr` must point to an initialized `pthread_rwlockattr_t`.
    pub(super) unsafe fn of_attr(attr: *const c_void) -> Self {
        #[cfg(target_os = "linux")]
        {
            if attr.is_null() {
                return Self::PreferReader;
            }
            // SAFETY: glibc's `struct pthread_rwlockattr` starts with the
            // `int lockkind`.
            Self::from_glibc(unsafe { attr.cast::<c_int>().read() })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = attr;
            Self::PreferWriterNonrecursive
        }
    }

    /// The kind of a lock first touched without `pthread_rwlock_init`:
    /// the one its static initializer wrote (glibc's
    /// `PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP` sets
    /// `__flags`).
    ///
    /// # Safety
    /// `lock` must point to a `pthread_rwlock_t`.
    pub(super) unsafe fn of_static(lock: *const c_void) -> Self {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `__flags` is the `unsigned int` at byte 48 of glibc's
            // `struct __pthread_rwlock_arch_t` on the 64-bit targets.
            Self::from_glibc(unsafe { lock.cast::<u8>().add(48).cast::<c_int>().read() })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = lock;
            Self::PreferWriterNonrecursive
        }
    }
}

/// A deterministic reader/writer lock of one [`RwLockKind`]. Writers are
/// granted in strict FIFO order; blocked readers are granted together (a
/// batch wake, like a condvar broadcast). Every wake is a recorded
/// scheduler decision, so the wake order is reproducible.
#[derive(Default)]
pub(super) struct RwLockEntry {
    kind: RwLockKind,
    /// Number of tasks currently holding the read lock.
    readers: usize,
    /// The task currently holding the write lock, if any.
    writer: Option<TaskId>,
    pub(super) write_waiters: HostDeque<TaskId>,
    pub(super) read_waiters: HostDeque<TaskId>,
}

impl RwLockEntry {
    fn of_kind(kind: RwLockKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Whether a new reader acquires the lock now.
    fn admits_reader(&self) -> bool {
        self.writer.is_none()
            && (self.kind != RwLockKind::PreferWriterNonrecursive || self.write_waiters.is_empty())
    }
}

pub(super) struct ThreadEntry {
    pub(super) finished: bool,
    retval: usize,
    pub(super) joiner: Option<TaskId>,
    pub(super) detached: bool,
    // Some(false): temporarily runnable for a signal, still semantically
    // waiting. Some(true): an ordinary grant/notification arrived meanwhile.
    #[cfg(target_os = "linux")]
    pub(super) signal_resume: Option<bool>,
}

pub(super) enum LockStep {
    Acquired,
    MustBlock,
}

pub(super) enum JoinStep {
    Done(usize),
    MustBlock,
}

/// Pure state of every virtual mutex, condition variable, and managed
/// thread. Ownership transfer and wake decisions live here so they are
/// unit-testable against any [`Scheduler`] without spawning host threads.
///
/// Contended mutexes wake waiters in strict FIFO order, and an unlock hands
/// ownership directly to the next waiter so no thundering herd occurs.
#[derive(Default)]
pub(super) struct ThreadTable {
    // The synchronization tables are host-libc-backed (see `hostcoll`): the
    // lock/sync interposers register each lock lazily on first touch while
    // holding the shim spinlock, so they must never allocate through the
    // guest global allocator (a custom `#[global_allocator]` whose init takes
    // an interposed lock would re-enter and deadlock before `main`).
    pub(super) mutexes: HostMap<usize, MutexEntry>,
    pub(super) conds: HostMap<usize, CondEntry>,
    pub(super) rwlocks: HostMap<usize, RwLockEntry>,
    // Thread lifecycle only — grown by explicit `pthread_create`/join, never
    // reentrantly from an allocation, so it stays on the ordinary allocator.
    pub(super) threads: BTreeMap<TaskId, ThreadEntry>,
}

pub(super) fn refuse_nested_sync_wait(interrupted: bool) {
    if interrupted {
        fatal("signal handler blocked on a pthread wait while interrupting one: not modeled");
    }
}

impl ThreadTable {
    pub(super) fn sync_interrupted(&self, task: TaskId) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.threads
                .get(&task)
                .is_some_and(|entry| entry.signal_resume.is_some())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = task;
            false
        }
    }

    pub(super) fn register(&mut self, task: TaskId) {
        self.threads.insert(
            task,
            ThreadEntry {
                finished: false,
                retval: 0,
                joiner: None,
                detached: false,
                #[cfg(target_os = "linux")]
                signal_resume: None,
            },
        );
    }

    #[cfg(target_os = "linux")]
    pub(super) fn still_waiting(&self, task: TaskId, loc: WaiterLoc) -> bool {
        match loc {
            WaiterLoc::Mutex(key) => self
                .mutexes
                .get(&key)
                .is_some_and(|entry| entry.waiters.iter().any(|waiter| *waiter == task)),
            WaiterLoc::RwRead(key) => self
                .rwlocks
                .get(&key)
                .is_some_and(|entry| entry.read_waiters.iter().any(|waiter| *waiter == task)),
            WaiterLoc::RwWrite(key) => self
                .rwlocks
                .get(&key)
                .is_some_and(|entry| entry.write_waiters.iter().any(|waiter| *waiter == task)),
            WaiterLoc::Cond(cond, mutex) => {
                self.conds
                    .get(&cond)
                    .is_some_and(|entry| entry.waiters.iter().any(|(waiter, _)| *waiter == task))
                    || self.still_waiting(task, WaiterLoc::Mutex(mutex))
            }
            WaiterLoc::Join(target) => self
                .threads
                .get(&target)
                .is_some_and(|entry| !entry.finished && entry.joiner == Some(task)),
            _ => false,
        }
    }

    fn notify(&mut self, scheduler: &mut dyn Scheduler, task: TaskId) -> Result<(), ThreadError> {
        #[cfg(target_os = "linux")]
        if let Some(notified) = self
            .threads
            .get_mut(&task)
            .and_then(|entry| entry.signal_resume.as_mut())
        {
            *notified = true;
            return Ok(());
        }
        scheduler.wake(task)?;
        Ok(())
    }

    pub(super) fn init_mutex(&mut self, key: usize, kind: MutexKind) {
        self.mutexes.insert(key, MutexEntry::of_kind(kind));
    }

    /// The mutex at `key`; one never initialized is registered as `kind`
    /// on first touch.
    fn mutex(&mut self, key: usize, kind: MutexKind) -> &mut MutexEntry {
        self.mutexes
            .entry_or_insert_with(key, || MutexEntry::of_kind(kind))
    }

    /// Lock the mutex at `key` (`kind` if first touched here).
    pub(super) fn lock(
        &mut self,
        me: TaskId,
        key: usize,
        kind: MutexKind,
    ) -> Result<LockStep, ThreadError> {
        let interrupted = self.sync_interrupted(me);
        let entry = self.mutex(key, kind);
        match entry.owner {
            None => {
                entry.grant(me);
                Ok(LockStep::Acquired)
            }
            Some(owner) if owner == me && entry.kind == MutexKind::ErrorCheck => {
                Err(ThreadError::Posix(EDEADLK))
            }
            Some(owner) if owner == me && entry.kind == MutexKind::Recursive => {
                entry.count = entry
                    .count
                    .checked_add(1)
                    .ok_or(ThreadError::Posix(EWOULDBLOCK))?; // EAGAIN
                Ok(LockStep::Acquired)
            }
            // Another owner, or a normal mutex's owner relocking: wait.
            Some(_) => {
                refuse_nested_sync_wait(interrupted);
                entry.waiters.push_back(me);
                Ok(LockStep::MustBlock)
            }
        }
    }

    /// Try to lock the mutex at `key` (`kind` if first touched here):
    /// `EBUSY` when it is held, by the caller too unless it is recursive.
    pub(super) fn trylock(&mut self, me: TaskId, key: usize, kind: MutexKind) -> c_int {
        let entry = self.mutex(key, kind);
        match entry.owner {
            None => {
                entry.grant(me);
                0
            }
            Some(owner) if owner == me && entry.kind == MutexKind::Recursive => {
                match entry.count.checked_add(1) {
                    Some(count) => {
                        entry.count = count;
                        0
                    }
                    None => EWOULDBLOCK, // EAGAIN
                }
            }
            Some(_) => EBUSY,
        }
    }

    pub(super) fn unlock(
        &mut self,
        scheduler: &mut dyn Scheduler,
        me: TaskId,
        key: usize,
    ) -> Result<(), ThreadError> {
        let entry = self
            .mutexes
            .get_mut(&key)
            .ok_or(ThreadError::Posix(EINVAL))?;
        if entry.owner != Some(me) {
            if entry.kind != MutexKind::Normal {
                return Err(ThreadError::Posix(EPERM));
            }
            // glibc's normal unlock checks no owner: it frees a mutex
            // another thread holds, and one already unlocked stays so.
            if entry.owner.is_none() {
                return Ok(());
            }
            entry.count = 1;
        }
        entry.count -= 1;
        if entry.count > 0 {
            return Ok(());
        }
        if let Some(next) = entry.waiters.pop_front() {
            entry.grant(next);
            self.notify(scheduler, next)?;
        } else {
            entry.owner = None;
        }
        Ok(())
    }

    pub(super) fn destroy_mutex(&mut self, key: usize) -> Result<(), ThreadError> {
        if let Some(entry) = self.mutexes.get(&key) {
            if entry.owner.is_some() || !entry.waiters.is_empty() {
                return Err(ThreadError::Posix(EBUSY));
            }
            self.mutexes.remove(&key);
        }
        Ok(())
    }

    pub(super) fn init_rwlock(&mut self, key: usize, kind: RwLockKind) {
        self.rwlocks.insert(key, RwLockEntry::of_kind(kind));
    }

    /// The lock at `key`; one never initialized is registered as `kind` on
    /// first touch.
    fn rwlock(&mut self, key: usize, kind: RwLockKind) -> &mut RwLockEntry {
        self.rwlocks
            .entry_or_insert_with(key, || RwLockEntry::of_kind(kind))
    }

    /// Acquire the read lock, blocking unless the lock admits a new reader
    /// ([`RwLockEntry::admits_reader`]). The writer's own call is
    /// `EDEADLK`.
    pub(super) fn rwlock_rdlock(
        &mut self,
        me: TaskId,
        key: usize,
        kind: RwLockKind,
    ) -> Result<LockStep, ThreadError> {
        let interrupted = self.sync_interrupted(me);
        let entry = self.rwlock(key, kind);
        if entry.writer == Some(me) {
            return Err(ThreadError::Posix(EDEADLK));
        }
        if entry.admits_reader() {
            entry.readers += 1;
            Ok(LockStep::Acquired)
        } else {
            refuse_nested_sync_wait(interrupted);
            entry.read_waiters.push_back(me);
            Ok(LockStep::MustBlock)
        }
    }

    /// Acquire the write lock: exclusive, so block unless the lock is fully
    /// idle (no readers and no writer).
    pub(super) fn rwlock_wrlock(
        &mut self,
        me: TaskId,
        key: usize,
        kind: RwLockKind,
    ) -> Result<LockStep, ThreadError> {
        let interrupted = self.sync_interrupted(me);
        let entry = self.rwlock(key, kind);
        if entry.writer == Some(me) {
            return Err(ThreadError::Posix(EDEADLK));
        }
        if entry.writer.is_none() && entry.readers == 0 {
            entry.writer = Some(me);
            Ok(LockStep::Acquired)
        } else {
            refuse_nested_sync_wait(interrupted);
            entry.write_waiters.push_back(me);
            Ok(LockStep::MustBlock)
        }
    }

    /// Try the read lock: `EBUSY` unless it admits a new reader, for the
    /// writer too (glibc's non-blocking calls do not check the writer).
    pub(super) fn rwlock_tryrdlock(&mut self, key: usize, kind: RwLockKind) -> c_int {
        let entry = self.rwlock(key, kind);
        if entry.admits_reader() {
            entry.readers += 1;
            0
        } else {
            EBUSY
        }
    }

    /// Try the write lock: `EBUSY` unless the lock is idle.
    pub(super) fn rwlock_trywrlock(&mut self, me: TaskId, key: usize, kind: RwLockKind) -> c_int {
        let entry = self.rwlock(key, kind);
        if entry.writer.is_none() && entry.readers == 0 {
            entry.writer = Some(me);
            0
        } else {
            EBUSY
        }
    }

    /// Release whichever mode `me` holds, then grant the idle lock to the
    /// next waiter(s) deterministically: the preferred side first — every
    /// blocked reader together, or the first waiting writer (FIFO) — and
    /// the other side only when none of the preferred one waits.
    pub(super) fn rwlock_unlock(
        &mut self,
        scheduler: &mut dyn Scheduler,
        me: TaskId,
        key: usize,
    ) -> Result<(), ThreadError> {
        let entry = self
            .rwlocks
            .get_mut(&key)
            .ok_or(ThreadError::Posix(EINVAL))?;
        if entry.writer == Some(me) {
            entry.writer = None;
        } else if entry.readers > 0 {
            entry.readers -= 1;
            if entry.readers > 0 {
                // Other readers still hold the lock; no grant yet.
                return Ok(());
            }
        } else {
            return Err(ThreadError::Posix(EPERM));
        }
        // The lock is now idle (no writer, no readers). Grant it.
        // Every kind but the default hands a writer's release to the next
        // writer; a reader's last release finds only writers waiting.
        let readers_first = entry.kind == RwLockKind::PreferReader;
        let next_writer = if readers_first && !entry.read_waiters.is_empty() {
            None
        } else {
            entry.write_waiters.pop_front()
        };
        if let Some(next) = next_writer {
            entry.writer = Some(next);
            self.notify(scheduler, next)?;
        } else {
            // Batch-wake every blocked reader in FIFO order. Drained one at a
            // time (re-borrowing the entry each step) rather than collected
            // into a `Vec` — the collection would allocate through the guest
            // global allocator, which the sync path must never touch.
            entry.readers = entry.read_waiters.len();
            loop {
                let reader = self
                    .rwlocks
                    .get_mut(&key)
                    .and_then(|entry| entry.read_waiters.pop_front());
                match reader {
                    Some(reader) => self.notify(scheduler, reader)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    pub(super) fn destroy_rwlock(&mut self, key: usize) -> Result<(), ThreadError> {
        if let Some(entry) = self.rwlocks.get(&key) {
            if entry.writer.is_some()
                || entry.readers > 0
                || !entry.write_waiters.is_empty()
                || !entry.read_waiters.is_empty()
            {
                return Err(ThreadError::Posix(EBUSY));
            }
            self.rwlocks.remove(&key);
        }
        Ok(())
    }

    pub(super) fn init_cond(&mut self, key: usize, clock: ClockKind) {
        self.conds.insert(
            key,
            CondEntry {
                clock,
                ..CondEntry::default()
            },
        );
    }

    /// The clock the condition variable at `key` judges deadlines on.
    pub(super) fn cond_clock(&self, key: usize) -> ClockKind {
        self.conds
            .get(&key)
            .map_or(ClockKind::Realtime, |cond| cond.clock)
    }

    /// Release `mutex_key` (waking its next waiter) and enqueue `me` on the
    /// condition variable. The caller then parks `me`; a later signal or
    /// broadcast re-grants the mutex before `me` resumes, so there are no
    /// spurious wakeups.
    pub(super) fn cond_wait(
        &mut self,
        scheduler: &mut dyn Scheduler,
        me: TaskId,
        cond_key: usize,
        mutex_key: usize,
    ) -> Result<(), ThreadError> {
        refuse_nested_sync_wait(self.sync_interrupted(me));
        self.unlock(scheduler, me, mutex_key)?;
        self.conds
            .entry_or_default(cond_key)
            .waiters
            .push_back((me, mutex_key));
        Ok(())
    }

    pub(super) fn cond_signal(
        &mut self,
        scheduler: &mut dyn Scheduler,
        cond_key: usize,
    ) -> Result<(), ThreadError> {
        let woken = self
            .conds
            .get_mut(&cond_key)
            .and_then(|cond| cond.waiters.pop_front());
        if let Some((task, mutex_key)) = woken {
            let entry = self.mutexes.entry_or_default(mutex_key);
            match entry.owner {
                None => {
                    entry.grant(task);
                    self.notify(scheduler, task)?;
                }
                // A recursive mutex held more than once stays the
                // waiter's across the wait; glibc's re-lock counts it
                // again (its recursive relock), and the waiter resumes.
                Some(owner) if owner == task => {
                    entry.count += 1;
                    self.notify(scheduler, task)?;
                }
                Some(_) => entry.waiters.push_back(task),
            }
        }
        Ok(())
    }

    pub(super) fn cond_broadcast(
        &mut self,
        scheduler: &mut dyn Scheduler,
        cond_key: usize,
    ) -> Result<(), ThreadError> {
        while self
            .conds
            .get(&cond_key)
            .is_some_and(|cond| !cond.waiters.is_empty())
        {
            self.cond_signal(scheduler, cond_key)?;
        }
        Ok(())
    }

    pub(super) fn destroy_cond(&mut self, key: usize) -> Result<(), ThreadError> {
        if let Some(cond) = self.conds.get(&key) {
            if !cond.waiters.is_empty() {
                return Err(ThreadError::Posix(EBUSY));
            }
            self.conds.remove(&key);
        }
        Ok(())
    }

    /// Join `target`: its value if it has finished, else wait. A detached
    /// target is `EINVAL`, and then a join that could never end — of the
    /// caller itself, or of a thread waiting to join the caller — is
    /// `EDEADLK`, in glibc's order.
    pub(super) fn begin_join(
        &mut self,
        me: TaskId,
        target: TaskId,
    ) -> Result<JoinStep, ThreadError> {
        let interrupted = self.sync_interrupted(me);
        if self
            .threads
            .get(&target)
            .is_some_and(|entry| entry.detached)
        {
            return Err(ThreadError::Posix(EINVAL));
        }
        let joins_me = self
            .threads
            .get(&me)
            .is_some_and(|entry| !entry.finished && entry.joiner == Some(target));
        if target == me || joins_me {
            return Err(ThreadError::Posix(EDEADLK));
        }
        let entry = self
            .threads
            .get_mut(&target)
            .ok_or(ThreadError::Posix(ESRCH))?;
        if entry.detached {
            return Err(ThreadError::Posix(EINVAL));
        }
        if entry.finished {
            let retval = entry.retval;
            self.threads.remove(&target);
            return Ok(JoinStep::Done(retval));
        }
        if entry.joiner.is_some() {
            return Err(ThreadError::Posix(EINVAL));
        }
        refuse_nested_sync_wait(interrupted);
        entry.joiner = Some(me);
        Ok(JoinStep::MustBlock)
    }

    pub(super) fn take_join_result(&mut self, target: TaskId) -> usize {
        self.threads.remove(&target).map_or(0, |entry| entry.retval)
    }

    pub(super) fn detach(&mut self, target: TaskId) -> Result<(), ThreadError> {
        let entry = self
            .threads
            .get_mut(&target)
            .ok_or(ThreadError::Posix(ESRCH))?;
        if entry.detached || entry.joiner.is_some() {
            return Err(ThreadError::Posix(EINVAL));
        }
        entry.detached = true;
        if entry.finished {
            self.threads.remove(&target);
        }
        Ok(())
    }

    pub(super) fn exit(
        &mut self,
        scheduler: &mut dyn Scheduler,
        me: TaskId,
        retval: usize,
    ) -> Result<(), ThreadError> {
        let entry = self.threads.get_mut(&me).ok_or(ThreadError::Posix(ESRCH))?;
        entry.finished = true;
        entry.retval = retval;
        let joiner = entry.joiner;
        let detached = entry.detached;
        if let Some(joiner) = joiner {
            self.notify(scheduler, joiner)?;
        }
        scheduler.complete(me)?;
        if detached && joiner.is_none() {
            self.threads.remove(&me);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
