//! Managed-thread identity and pipe-channel regression tests.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

#[test]
fn endpoint_handles_wrap_and_skip_live_keys() {
    // Live keys straddle the wrap and hold the bottom of the range.
    let live = [c_int::MAX, c_int::MIN, 0, 1];
    let allocate = |next: &mut c_int| {
        handle_allocator::next_free_handle(next, |handle| live.contains(&handle))
    };
    let mut next = c_int::MAX - 1;
    let pipe_ends = [allocate(&mut next), allocate(&mut next)];

    // The second end wraps past both live keys around `c_int::MAX`.
    assert_eq!(pipe_ends, [c_int::MAX - 1, c_int::MIN + 1]);
    assert_eq!(next, c_int::MIN + 2);

    // Fast-forward to the low keys rather than spending billions of
    // allocations traversing the c_int range.
    next = 0;
    assert_eq!(allocate(&mut next), 2);
    assert_eq!(next, 3);
}

// The `--yield-points` teardown fix must keep "task completed" a state
// distinct from "thread never registered": a completed thread's
// post-finish scheduling points are silently skipped, but a foreign or
// pre-registration thread must still fail loudly. Run on a fresh host
// thread so the thread-locals start at their defaults.
#[test]
fn completed_sentinel_is_distinct_from_never_registered() {
    std::thread::spawn(|| {
        // Never-registered defaults: no task, not completed.
        assert_eq!(current_task(), UNMANAGED_TASK);
        assert!(!task_completed());
        // sched_point on a never-registered thread does NOT take the
        // completed no-op path (it would fall through to the loud
        // reschedule when the subsystem is active).
        mark_task_completed();
        // Completing marks the sentinel WITHOUT aliasing the unregistered
        // task id, so the two states remain distinguishable.
        assert!(task_completed());
        assert_eq!(current_task(), UNMANAGED_TASK);
        // A completed thread takes no scheduling point.
        assert!(sched_point().is_ok());
    })
    .join()
    .unwrap();
}

// The main-thread teardown fix: once the process enters its post-`main`
// teardown window (the `exit` interposer calls `note_main_returned`), the
// ROOT task — which never runs `thread_finish` and so has no per-thread
// completion sentinel — takes NO scheduling point, exactly like a
// completed worker's post-teardown, so its `--yield-points` thread-local
// destructors record zero trailing yields. `MAIN_RETURNED` is process-wide
// (no other test sets it, and none relies on the global `sched_point`
// taking its reschedule path); this test restores it so the teardown state
// never leaks into sibling tests.
#[test]
fn main_returned_silences_the_root_task_scheduling_point() {
    note_main_returned();
    assert!(main_returned());
    // A scheduling point in the teardown window is a no-op, on any thread —
    // never a reschedule against a torn-down scheduler.
    std::thread::spawn(|| assert!(sched_point().is_ok()))
        .join()
        .unwrap();
    MAIN_RETURNED.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(!main_returned());
}

// Pure pipe-channel semantics (the scheduler-integrated parking is covered
// end-to-end by the pipe tests in cargo-patina/tests/native_abi.rs):
// bounded capacity, partial reads, and EOF only after drain.
#[test]
fn pipe_channel_transfers_bytes_with_bounded_capacity_and_eof() {
    let mut channel = PipeChannel::new(4);
    let mut dst = [0u8; 8];
    // Empty + writer open → WouldBlock (the reader parks).
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // Bounded capacity: a write fills it, and the next (atomic, below
    // PIPE_BUF) waits for room for all of it.
    assert_eq!(channel.try_write(b"abcd"), PipeWrite::Wrote(4));
    assert_eq!(channel.try_write(b"ef"), PipeWrite::WouldBlock);
    // A short read frees space for the writer's remaining bytes.
    assert_eq!(channel.try_read(&mut dst[..2]), PipeRead::Read(2));
    assert_eq!(&dst[..2], b"ab");
    assert_eq!(channel.try_write(b"ef"), PipeWrite::Wrote(2));
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(4));
    assert_eq!(&dst[..4], b"cdef");
    // Drained but writer still open → WouldBlock, not EOF.
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // Buffered bytes are delivered before EOF even after the writer closes.
    channel.try_write(b"hi");
    channel.write_refs = 0;
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
    assert_eq!(&dst[..2], b"hi");
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
}

// A FIFO channel is born with NO ends, and every "closed" answer is
// derived from the reference counts rather than latched — which is what
// lets a FIFO's reader or writer side come BACK when it is opened again.
// RED before FIFOs were modeled: `PipeChannel` had no such constructor
// and the two closed flags were one-way latches.
#[test]
fn fifo_channel_starts_endless_and_derives_closedness_from_its_refs() {
    let mut channel = PipeChannel::new_fifo(4, 7);
    assert_eq!(channel.fifo_ino, Some(7));
    assert_eq!((channel.read_refs, channel.write_refs), (0, 0));
    assert_eq!((channel.read_opens, channel.write_opens), (0, 0));
    // No writer: a read is end-of-file, not a park.
    let mut dst = [0u8; 8];
    assert!(channel.read_closed() && channel.write_closed());
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
    // No reader: a write is a broken pipe.
    assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);

    // One opener of each side, as `fifo_open` registers them.
    channel.read_refs += 1;
    channel.write_refs += 1;
    assert!(!channel.read_closed() && !channel.write_closed());
    assert_eq!(channel.try_write(b"hi"), PipeWrite::Wrote(2));
    // Drained with a live writer is a park, not end-of-file.
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(2));
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
    // The last writer leaves: end-of-file. A NEW writer revives the
    // channel, which a latched flag could not express.
    channel.write_refs -= 1;
    assert_eq!(channel.try_read(&mut dst), PipeRead::Eof);
    channel.write_refs += 1;
    assert_eq!(channel.try_read(&mut dst), PipeRead::WouldBlock);
}

// `pipe_write`: a write of at most PIPE_BUF bytes is atomic — it waits
// for room for all of it rather than landing in part — while a longer
// one takes what fits.
#[test]
fn pipe_channel_writes_up_to_pipe_buf_atomically() {
    let mut channel = PipeChannel::new(PIPE_BUF + 8);
    let small = [7u8; 16];
    assert_eq!(
        channel.try_write(&[0; PIPE_BUF]),
        PipeWrite::Wrote(PIPE_BUF)
    );
    assert_eq!(channel.try_write(&small), PipeWrite::WouldBlock);
    assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
    let mut dst = [0u8; PIPE_BUF + 8];
    assert_eq!(channel.try_read(&mut dst), PipeRead::Read(PIPE_BUF + 8));
    assert_eq!(channel.try_write(&small[..8]), PipeWrite::Wrote(8));
    assert_eq!(
        channel.try_write(&[1; PIPE_BUF + 1]),
        PipeWrite::Wrote(PIPE_BUF)
    );
}

// Writing to a channel whose reader closed is a broken pipe surfaced as an
// errno (EPIPE) — never a signal.
#[test]
fn pipe_channel_write_to_closed_reader_is_broken_pipe() {
    let mut channel = PipeChannel::new(4);
    channel.read_refs = 0;
    assert_eq!(channel.try_write(b"x"), PipeWrite::BrokenPipe);
}

/// A scheduler for pure wait-state tests: any transition is a test failure.
struct NoTransitions;

impl Scheduler for NoTransitions {
    fn spawn(&mut self, _: &str) -> Result<TaskId, String> {
        Err("unexpected spawn".into())
    }
    fn yield_task(&mut self, _: TaskId) -> Result<(), String> {
        Err("unexpected yield".into())
    }
    fn park(&mut self, _: TaskId, _: &str) -> Result<(), String> {
        Err("unexpected park".into())
    }
    fn park_timed(&mut self, _: TaskId, _: &str, _: ClockKind, _: u64) -> Result<(), String> {
        Err("unexpected timed park".into())
    }
    fn wake(&mut self, task: TaskId) -> Result<(), String> {
        Err(format!("unexpected wake of task {}", task.0))
    }
    fn complete(&mut self, _: TaskId) -> Result<(), String> {
        Err("unexpected complete".into())
    }
    fn next(&mut self) -> Result<Option<TaskId>, String> {
        Err("unexpected pick".into())
    }
}

// Class pairing: timer settlement unlinks a wait through its one registration
// (`ThreadRuntime::register_wait`) on every platform, so it reaches every
// queue the wait has moved to. A condition waiter a signal moved onto its held
// mutex's queue is the case a per-queue scan misses: the owner's unlock would
// grant, and wake, a task its timer already woke.
#[test]
fn an_expired_condition_waiter_leaves_the_held_mutex_queue_a_signal_moved_it_to() {
    const MUTEX: usize = 0x1000;
    const COND: usize = 0x2000;
    let (owner, waiter) = (TaskId(1), TaskId(2));
    let mut state = ThreadRuntime::new();
    state.table.register(owner);
    state.table.register(waiter);
    state.table.init_mutex(MUTEX, MutexKind::Normal);
    state.table.init_cond(COND, ClockKind::Monotonic);
    // The waiter's `pthread_cond_timedwait`: it released the mutex and waits
    // on the condition, registered as `block_timed` registers it.
    assert!(matches!(
        state
            .table
            .lock(
                waiter,
                MUTEX,
                MutexKind::Normal,
                &mut Wait::new(BlockClass::Sync, vec![])
            )
            .unwrap(),
        LockStep::Acquired
    ));
    let mut wait = Wait::new(BlockClass::Sync, vec![]);
    state
        .table
        .cond_wait(&mut NoTransitions, waiter, COND, MUTEX, &mut wait)
        .unwrap();
    state.register_wait(
        waiter,
        "cond-timedwait",
        wait,
        Some((ClockKind::Monotonic, 1)),
    );
    // The owner takes the mutex and signals: the waiter moves to its queue.
    assert!(matches!(
        state
            .table
            .lock(
                owner,
                MUTEX,
                MutexKind::Normal,
                &mut Wait::new(BlockClass::Sync, vec![])
            )
            .unwrap(),
        LockStep::Acquired
    ));
    state.table.cond_signal(&mut NoTransitions, COND).unwrap();
    assert!(
        state.table.mutexes[&MUTEX]
            .waiters
            .iter()
            .any(|task| *task == waiter)
    );
    // The timer expires the wait.
    state.mark_timed_out(waiter);
    assert!(state.timed_out.contains(&waiter));
    assert!(
        !state.table.mutexes[&MUTEX]
            .waiters
            .iter()
            .any(|task| *task == waiter)
    );
    assert!(state.table.conds[&COND].waiters.is_empty());
    // The owner's unlock grants nobody (a grant would wake the waiter).
    state
        .table
        .unlock(&mut NoTransitions, owner, MUTEX)
        .unwrap();
    assert_eq!(state.table.mutexes[&MUTEX].owner, None);
}

// Class pairing: a wait registration has one removal path,
// `ThreadRuntime::remove_wait`, which a resume (`switch_and_park` through
// `resumed`), an expiry and thread exit (`thread_finish` through
// `finish_wait`) all take, on every platform; none may outlive its wait.
#[test]
fn a_wait_registration_ends_with_its_wait_and_with_its_thread() {
    const WORD: usize = 0x3000;
    let task = TaskId(1);
    let mut state = ThreadRuntime::new();
    // A normal wake: `FUTEX_WAKE` unqueues the waiter, which resumes.
    let mut wait = Wait::new(BlockClass::TimedFutex, vec![]);
    let waiter = FutexWaiter::multiplexed(task, false, u32::MAX);
    state.queue_futex_waiter(WORD, waiter, &mut wait);
    state.register_wait(task, "futex-wait", wait, Some((ClockKind::Monotonic, 1)));
    assert_eq!(state.take_futex_waiters(WORD, 1, |_| true).len(), 1);
    assert!(!state.resumed(task), "a futex wait is no pthread wait");
    assert!(!state.has_wait(task));
    // Thread exit drops a registration the thread left, and its queue entry.
    let mut wait = Wait::new(BlockClass::TimedFutex, vec![]);
    let waiter = FutexWaiter::multiplexed(task, false, u32::MAX);
    state.queue_futex_waiter(WORD, waiter, &mut wait);
    state.register_wait(task, "futex-wait", wait, None);
    state.finish_wait(task);
    assert!(!state.has_wait(task));
    assert!(!state.futexes.contains_key(&WORD));
}

// Class pairing: a queue entry can only come from `Wait::enqueue`, which
// records the queue in the wait `block`/`block_timed` registers, so ending
// the wait (`remove_wait`: a wake, resume, expiry or exit) empties every queue
// the task joined. One waiter on several kinds of queue at once, each entered
// the only way there is; the kqueue `EVFILT_USER` list is the case that once
// sat outside the registration (macOS, guest-archive builds).
#[test]
fn ending_a_wait_empties_every_queue_it_entered() {
    const WORD: usize = 0x4000;
    const MUTEX: usize = 0x5000;
    const RWLOCK: usize = 0x6000;
    let (owner, waiter, target) = (TaskId(1), TaskId(2), TaskId(3));
    let mut state = ThreadRuntime::new();
    for task in [owner, waiter, target] {
        state.table.register(task);
    }
    let mut wait = Wait::new(BlockClass::Sync, vec![]);
    // A futex word.
    let futex = FutexWaiter::multiplexed(waiter, false, u32::MAX);
    state.queue_futex_waiter(WORD, futex, &mut wait);
    // A held mutex and a write-held rwlock.
    state.table.init_mutex(MUTEX, MutexKind::Normal);
    let mut held = Wait::new(BlockClass::Sync, vec![]);
    assert!(matches!(
        state
            .table
            .lock(owner, MUTEX, MutexKind::Normal, &mut held)
            .unwrap(),
        LockStep::Acquired
    ));
    assert!(matches!(
        state
            .table
            .lock(waiter, MUTEX, MutexKind::Normal, &mut wait)
            .unwrap(),
        LockStep::MustBlock
    ));
    let kind = RwLockKind::default();
    assert!(matches!(
        state
            .table
            .rwlock_wrlock(owner, RWLOCK, kind, &mut held)
            .unwrap(),
        LockStep::Acquired
    ));
    assert!(matches!(
        state
            .table
            .rwlock_rdlock(waiter, RWLOCK, kind, &mut wait)
            .unwrap(),
        LockStep::MustBlock
    ));
    // A thread's join slot.
    assert!(matches!(
        state.table.begin_join(waiter, target, &mut wait).unwrap(),
        JoinStep::MustBlock
    ));
    // A pipe's readers.
    state.net.pipe_channels.insert(7, pipe::PipeChannel::new(1));
    let channel = state.net.pipe_channels.get_mut(&7).unwrap();
    wait.enqueue(&mut channel.recv_waiters, waiter, WaiterLoc::PipeRecv(7));
    state.register_wait(waiter, "many", wait, None);
    assert!(state.remove_wait(waiter).is_some());
    assert!(!state.futexes.contains_key(&WORD));
    assert!(state.table.mutexes[&MUTEX].waiters.is_empty());
    assert!(state.table.rwlocks[&RWLOCK].read_waiters.is_empty());
    assert_eq!(*state.table.threads[&target].joiner, None);
    assert!(state.net.pipe_channels[&7].recv_waiters.is_empty());
}
