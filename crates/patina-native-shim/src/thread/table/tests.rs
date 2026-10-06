//! Managed-thread scheduler and synchronization regression tests.

use patina_dst_driver_api::SchedulerDriver;
use patina_dst_sched_det::DetScheduler;

use super::*;

/// Drives [`ThreadTable`] against the real deterministic scheduler.
struct DetAdapter {
    scheduler: DetScheduler,
}

impl DetAdapter {
    fn new(seed: u64) -> Self {
        Self {
            scheduler: DetScheduler::new(seed),
        }
    }

    /// Spawn and immediately select a task as running.
    fn spawn_running(&mut self) -> TaskId {
        let task = SchedulerDriver::spawn(&mut self.scheduler, "task").unwrap();
        self.scheduler.select(Some(task)).unwrap();
        task
    }
}

impl Scheduler for DetAdapter {
    fn spawn(&mut self, label: &str) -> Result<TaskId, String> {
        SchedulerDriver::spawn(&mut self.scheduler, label).map_err(|error| error.message)
    }

    fn yield_task(&mut self, task: TaskId) -> Result<(), String> {
        self.scheduler
            .yield_task(task)
            .map_err(|error| error.message)
    }

    fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String> {
        self.scheduler
            .park(task, reason)
            .map_err(|error| error.message)
    }

    fn park_timed(
        &mut self,
        task: TaskId,
        reason: &str,
        _clock: ClockKind,
        _deadline: u64,
    ) -> Result<(), String> {
        // The pure ThreadTable tests do not exercise the timer queue,
        // which lives in the runtime `Context`; park like the untimed op.
        self.scheduler
            .park(task, reason)
            .map_err(|error| error.message)
    }

    fn wake(&mut self, task: TaskId) -> Result<(), String> {
        self.scheduler.wake(task).map_err(|error| error.message)
    }

    fn complete(&mut self, task: TaskId) -> Result<(), String> {
        self.scheduler.complete(task).map_err(|error| error.message)
    }

    fn next(&mut self) -> Result<Option<TaskId>, String> {
        self.scheduler.next().map_err(|error| error.message)
    }
}

const MUTEX: usize = 0x1000;
const COND: usize = 0x2000;
const RWLOCK: usize = 0x3000;

// The loud path the fix must preserve: rescheduling a task the scheduler
// never registered is an error, not a silent no-op. `sched_point` reaches
// this via `reschedule` for any non-completed thread, so a foreign thread
// reaching a scheduling point still fails closed.
#[test]
fn rescheduling_an_unregistered_task_errors() {
    let mut scheduler = DetAdapter::new(1);
    assert!(scheduler.yield_task(UNMANAGED_TASK).is_err());
}

#[test]
fn uncontended_lock_and_unlock_round_trips() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let a = TaskId(1);
    assert!(matches!(
        table.lock(a, MUTEX, MutexKind::Normal).unwrap(),
        LockStep::Acquired
    ));
    assert_eq!(table.mutexes[&MUTEX].owner, Some(a));
    table.unlock(&mut scheduler, a, MUTEX).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, None);
}

#[test]
fn an_owner_relock_follows_the_mutex_kind() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let a = TaskId(1);
    let b = TaskId(2);

    table.init_mutex(MUTEX, MutexKind::ErrorCheck);
    table.lock(a, MUTEX, MutexKind::Normal).unwrap();
    assert!(matches!(
        table.lock(a, MUTEX, MutexKind::Normal),
        Err(ThreadError::Posix(EDEADLK))
    ));
    assert_eq!(table.trylock(a, MUTEX, MutexKind::Normal), EBUSY);

    // First touched here: registered with the kind the call names.
    assert!(matches!(
        table.lock(a, MUTEX + 1, MutexKind::Recursive).unwrap(),
        LockStep::Acquired
    ));
    assert!(matches!(
        table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap(),
        LockStep::Acquired
    ));
    assert_eq!(table.trylock(a, MUTEX + 1, MutexKind::Normal), 0);
    for _ in 0..2 {
        table.unlock(&mut scheduler, a, MUTEX + 1).unwrap();
        assert_eq!(table.trylock(b, MUTEX + 1, MutexKind::Normal), EBUSY);
    }
    table.unlock(&mut scheduler, a, MUTEX + 1).unwrap();
    assert_eq!(table.trylock(b, MUTEX + 1, MutexKind::Normal), 0);

    // A normal mutex's owner waits behind itself.
    table.lock(a, MUTEX + 2, MutexKind::Normal).unwrap();
    assert_eq!(table.trylock(a, MUTEX + 2, MutexKind::Normal), EBUSY);
    assert!(matches!(
        table.lock(a, MUTEX + 2, MutexKind::Normal).unwrap(),
        LockStep::MustBlock
    ));
}

#[test]
fn a_normal_mutex_unlock_checks_no_owner() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let a = scheduler.spawn("a").unwrap();
    let b = scheduler.spawn("b").unwrap();
    for task in [a, b] {
        table.register(task);
    }

    // Another thread's unlock frees it; an unlocked one stays so.
    table.lock(a, MUTEX, MutexKind::Normal).unwrap();
    table.unlock(&mut scheduler, b, MUTEX).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, None);
    table.unlock(&mut scheduler, a, MUTEX).unwrap();
    assert_eq!(table.trylock(b, MUTEX, MutexKind::Normal), 0);

    // The owner parked on its own relock resumes holding it once
    // another thread unlocks (a binary-semaphore hand-off).
    scheduler.scheduler.select(Some(a)).unwrap();
    table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap();
    assert!(matches!(
        table.lock(a, MUTEX + 1, MutexKind::Normal).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(a, "mutex").unwrap();
    table.unlock(&mut scheduler, b, MUTEX + 1).unwrap();
    assert_eq!(table.mutexes[&(MUTEX + 1)].owner, Some(a));
    assert_eq!(table.mutexes[&(MUTEX + 1)].count, 1);

    // Every other type checks the owner.
    for (key, kind) in [
        (MUTEX + 2, MutexKind::ErrorCheck),
        (MUTEX + 3, MutexKind::Recursive),
        (MUTEX + 4, MutexKind::NormalOwned),
    ] {
        table.lock(a, key, kind).unwrap();
        assert!(matches!(
            table.unlock(&mut scheduler, b, key),
            Err(ThreadError::Posix(EPERM))
        ));
        table.unlock(&mut scheduler, a, key).unwrap();
        assert!(matches!(
            table.unlock(&mut scheduler, a, key),
            Err(ThreadError::Posix(EPERM))
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn robust_and_priority_inheriting_normal_mutexes_check_the_owner() {
    assert_eq!(MutexKind::from_glibc(0), MutexKind::Normal);
    assert_eq!(MutexKind::from_glibc(3), MutexKind::Normal);
    // Priority protection (64) and elision (256) leave it unchecked.
    assert_eq!(MutexKind::from_glibc(64 | 256), MutexKind::Normal);
    assert_eq!(MutexKind::from_glibc(16), MutexKind::NormalOwned);
    assert_eq!(MutexKind::from_glibc(32 | 3), MutexKind::NormalOwned);
    assert_eq!(MutexKind::from_glibc(16 | 1), MutexKind::Recursive);
    assert_eq!(MutexKind::from_glibc(32 | 2), MutexKind::ErrorCheck);
}

#[test]
fn a_recursive_mutex_held_twice_survives_a_cond_wait() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let waiter = scheduler.spawn("waiter").unwrap();
    let signaler = scheduler.spawn("signaler").unwrap();
    table.register(waiter);
    table.register(signaler);
    table.init_mutex(MUTEX, MutexKind::Recursive);
    table.init_cond(COND, ClockKind::Realtime);

    table.lock(waiter, MUTEX, MutexKind::Recursive).unwrap();
    table.lock(waiter, MUTEX, MutexKind::Recursive).unwrap();
    scheduler.scheduler.select(Some(waiter)).unwrap();
    table
        .cond_wait(&mut scheduler, waiter, COND, MUTEX)
        .unwrap();
    // One unlock of two: the waiter still holds it.
    assert_eq!(table.mutexes[&MUTEX].owner, Some(waiter));
    scheduler.scheduler.park(waiter, "cond").unwrap();

    // The signal counts the waiter's hold again and wakes it, rather
    // than queueing it behind itself.
    scheduler.scheduler.select(Some(signaler)).unwrap();
    table.cond_signal(&mut scheduler, COND).unwrap();
    let entry = &table.mutexes[&MUTEX];
    assert_eq!((entry.owner, entry.count), (Some(waiter), 2));
    assert!(entry.waiters.is_empty());
}

#[test]
fn contended_mutex_wakes_waiters_in_fifo_order() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let a = scheduler.spawn("a").unwrap();
    let b = scheduler.spawn("b").unwrap();
    let c = scheduler.spawn("c").unwrap();
    for task in [a, b, c] {
        table.register(task);
    }

    // a takes the mutex; b then c arrive and block behind it, each
    // parking after selection so the scheduler transitions stay valid.
    scheduler.scheduler.select(Some(a)).unwrap();
    assert!(matches!(
        table.lock(a, MUTEX, MutexKind::Normal).unwrap(),
        LockStep::Acquired
    ));
    scheduler.yield_task(a).unwrap();

    scheduler.scheduler.select(Some(b)).unwrap();
    assert!(matches!(
        table.lock(b, MUTEX, MutexKind::Normal).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(b, "mutex").unwrap();

    scheduler.scheduler.select(Some(c)).unwrap();
    assert!(matches!(
        table.lock(c, MUTEX, MutexKind::Normal).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(c, "mutex").unwrap();

    // Unlocking hands ownership to the head of the FIFO queue and wakes
    // exactly that waiter.
    table.unlock(&mut scheduler, a, MUTEX).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, Some(b));
    table.unlock(&mut scheduler, b, MUTEX).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, Some(c));
    table.unlock(&mut scheduler, c, MUTEX).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, None);
}

#[test]
fn rwlock_trylock_and_deadlock_reporting() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let a = TaskId(1);
    let b = TaskId(2);

    let kind = RwLockKind::PreferReader;

    // A write hold excludes both a reader and another writer; the
    // holder's blocking re-acquire is a deadlock, its tries are busy.
    assert!(matches!(
        table.rwlock_wrlock(a, RWLOCK, kind).unwrap(),
        LockStep::Acquired
    ));
    assert_eq!(table.rwlock_trywrlock(b, RWLOCK, kind), EBUSY);
    assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), EBUSY);
    assert_eq!(table.rwlock_trywrlock(a, RWLOCK, kind), EBUSY);
    assert!(matches!(
        table.rwlock_rdlock(a, RWLOCK, kind),
        Err(ThreadError::Posix(EDEADLK))
    ));
    assert!(matches!(
        table.rwlock_wrlock(a, RWLOCK, kind),
        Err(ThreadError::Posix(EDEADLK))
    ));

    // Releasing lets multiple readers share, but a writer is then busy.
    table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
    assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), 0);
    assert_eq!(table.rwlock_tryrdlock(RWLOCK, kind), 0);
    assert_eq!(table.rwlocks[&RWLOCK].readers, 2);
    assert_eq!(table.rwlock_trywrlock(a, RWLOCK, kind), EBUSY);

    // A held rwlock cannot be destroyed; an idle one can.
    assert!(matches!(
        table.destroy_rwlock(RWLOCK),
        Err(ThreadError::Posix(EBUSY))
    ));
    table.rwlock_unlock(&mut scheduler, a, RWLOCK).unwrap();
    table.rwlock_unlock(&mut scheduler, b, RWLOCK).unwrap();
    assert!(table.destroy_rwlock(RWLOCK).is_ok());
}

/// Two readers hold the lock, a writer waits behind them, and a third
/// reader arrives: the lock's kind decides whether it barges past the
/// writer and who is granted the lock when the writer releases.
fn rwlock_preference(kind: RwLockKind) {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let r1 = scheduler.spawn("r1").unwrap();
    let r2 = scheduler.spawn("r2").unwrap();
    let w1 = scheduler.spawn("w1").unwrap();
    let r3 = scheduler.spawn("r3").unwrap();
    let w2 = scheduler.spawn("w2").unwrap();
    let r4 = scheduler.spawn("r4").unwrap();
    for task in [r1, r2, w1, r3, w2, r4] {
        table.register(task);
    }
    table.init_rwlock(RWLOCK, kind);
    let readers_barge = kind != RwLockKind::PreferWriterNonrecursive;
    let writer_first = kind != RwLockKind::PreferReader;

    // Two readers share the lock.
    for reader in [r1, r2] {
        scheduler.scheduler.select(Some(reader)).unwrap();
        assert!(matches!(
            table.rwlock_rdlock(reader, RWLOCK, kind).unwrap(),
            LockStep::Acquired
        ));
        scheduler.yield_task(reader).unwrap();
    }
    assert_eq!(table.rwlocks[&RWLOCK].readers, 2);

    // A writer arrives and blocks behind the active readers.
    scheduler.scheduler.select(Some(w1)).unwrap();
    assert!(matches!(
        table.rwlock_wrlock(w1, RWLOCK, kind).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(w1, "rwlock-write").unwrap();

    // A new reader barges past the waiting writer only when readers
    // are preferred.
    scheduler.scheduler.select(Some(r3)).unwrap();
    let step = table.rwlock_rdlock(r3, RWLOCK, kind).unwrap();
    if readers_barge {
        assert!(matches!(step, LockStep::Acquired));
        scheduler.yield_task(r3).unwrap();
        table.rwlock_unlock(&mut scheduler, r3, RWLOCK).unwrap();
    } else {
        assert!(matches!(step, LockStep::MustBlock));
        scheduler.park(r3, "rwlock-read").unwrap();
    }

    // First reader releases: one reader remains, nothing is granted.
    table.rwlock_unlock(&mut scheduler, r1, RWLOCK).unwrap();
    assert_eq!(table.rwlocks[&RWLOCK].readers, 1);
    assert_eq!(table.rwlocks[&RWLOCK].writer, None);

    // Last reader releases: the waiting writer is granted.
    table.rwlock_unlock(&mut scheduler, r2, RWLOCK).unwrap();
    assert_eq!(table.rwlocks[&RWLOCK].writer, Some(w1));
    assert_eq!(table.rwlocks[&RWLOCK].readers, 0);

    // With the writer holding it, a reader and a second writer wait.
    scheduler.scheduler.select(Some(r4)).unwrap();
    assert!(matches!(
        table.rwlock_rdlock(r4, RWLOCK, kind).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(r4, "rwlock-read").unwrap();
    scheduler.scheduler.select(Some(w2)).unwrap();
    assert!(matches!(
        table.rwlock_wrlock(w2, RWLOCK, kind).unwrap(),
        LockStep::MustBlock
    ));
    scheduler.park(w2, "rwlock-write").unwrap();

    // The writer releases to the preferred side: every blocked reader
    // at once, or the next writer.
    table.rwlock_unlock(&mut scheduler, w1, RWLOCK).unwrap();
    let entry = &table.rwlocks[&RWLOCK];
    if writer_first {
        assert_eq!(entry.writer, Some(w2));
        let waiting = if readers_barge { 1 } else { 2 };
        assert_eq!(entry.read_waiters.len(), waiting);
    } else {
        assert_eq!(entry.writer, None);
        assert_eq!(entry.readers, 1);
        assert!(entry.read_waiters.is_empty());
    }
}

#[test]
fn rwlock_prefers_readers_by_default() {
    rwlock_preference(RwLockKind::default());
}

#[test]
fn rwlock_can_hand_writer_to_writer() {
    rwlock_preference(RwLockKind::PreferWriter);
}

#[test]
fn rwlock_can_prefer_writers_over_new_readers() {
    rwlock_preference(RwLockKind::PreferWriterNonrecursive);
}

#[cfg(target_os = "linux")]
#[test]
fn rwlock_kinds_decode_as_glibc_compares_them() {
    assert_eq!(RwLockKind::from_glibc(0), RwLockKind::PreferReader);
    assert_eq!(RwLockKind::from_glibc(1), RwLockKind::PreferWriter);
    assert_eq!(
        RwLockKind::from_glibc(2),
        RwLockKind::PreferWriterNonrecursive
    );
}

#[test]
fn a_join_that_could_never_end_is_edeadlk() {
    let mut table = ThreadTable::default();
    let (a, b) = (TaskId(1), TaskId(2));
    table.register(a);
    table.register(b);
    assert!(matches!(
        table.begin_join(a, a),
        Err(ThreadError::Posix(EDEADLK))
    ));
    assert!(matches!(
        table.begin_join(a, b).unwrap(),
        JoinStep::MustBlock
    ));
    // b joining a, which waits to join b.
    assert!(matches!(
        table.begin_join(b, a),
        Err(ThreadError::Posix(EDEADLK))
    ));
    // A detached thread joining itself: not joinable, before the
    // deadlock.
    let c = TaskId(3);
    table.register(c);
    table.detach(c).unwrap();
    assert!(matches!(
        table.begin_join(c, c),
        Err(ThreadError::Posix(EINVAL))
    ));
}

#[test]
fn join_delivers_exit_value_after_target_finishes() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let main = scheduler.spawn_running();
    let worker = SchedulerDriver::spawn(&mut scheduler.scheduler, "worker").unwrap();
    table.register(worker);

    assert!(matches!(
        table.begin_join(main, worker).unwrap(),
        JoinStep::MustBlock
    ));
    // The joiner parks; hand the baton to the worker.
    scheduler.park(main, "join").unwrap();
    scheduler.scheduler.select(Some(worker)).unwrap();

    table.exit(&mut scheduler, worker, 42).unwrap();
    // The worker's exit re-runs the joiner.
    assert_eq!(scheduler.next().unwrap(), Some(main));
    assert_eq!(table.take_join_result(worker), 42);
}

#[test]
fn cond_wait_reacquires_mutex_on_signal_without_spurious_wakeups() {
    let mut table = ThreadTable::default();
    let mut scheduler = DetAdapter::new(1);
    let waiter = scheduler.spawn("waiter").unwrap();
    let signaler = scheduler.spawn("signaler").unwrap();
    table.register(waiter);
    table.register(signaler);
    table.init_mutex(MUTEX, MutexKind::Normal);
    table.init_cond(COND, ClockKind::Realtime);

    // The waiter owns the mutex, then waits on the condition.
    assert!(matches!(
        table.lock(waiter, MUTEX, MutexKind::Normal).unwrap(),
        LockStep::Acquired
    ));
    scheduler.scheduler.select(Some(waiter)).unwrap();
    table
        .cond_wait(&mut scheduler, waiter, COND, MUTEX)
        .unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, None);
    scheduler.scheduler.park(waiter, "cond").unwrap();

    // A signal with the mutex free grants it back to the waiter.
    scheduler.scheduler.select(Some(signaler)).unwrap();
    table.cond_signal(&mut scheduler, COND).unwrap();
    assert_eq!(table.mutexes[&MUTEX].owner, Some(waiter));
    assert!(table.conds[&COND].waiters.is_empty());

    // A second signal with no waiter is a no-op (no spurious wakeup).
    table.cond_signal(&mut scheduler, COND).unwrap();
}

#[test]
fn all_threads_parked_is_an_explicit_deadlock() {
    // Two managed tasks that each block waiting on the other deadlock;
    // the scheduler reports it rather than hanging.
    let mut scheduler = DetAdapter::new(1);
    let a = scheduler.spawn_running();
    let b = SchedulerDriver::spawn(&mut scheduler.scheduler, "b").unwrap();
    scheduler.park(a, "wait-b").unwrap();
    assert_eq!(scheduler.next().unwrap(), Some(b));
    scheduler.park(b, "wait-a").unwrap();
    assert!(scheduler.next().is_err());
}
