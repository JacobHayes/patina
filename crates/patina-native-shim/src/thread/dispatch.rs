//! Darwin dispatch semaphore entry points.

#[cfg(target_os = "macos")]
use super::*;

// ------------------------------------------------------------------
// libdispatch semaphores (macOS std thread `Parker`).
//
// Rust `std`'s Darwin thread `Parker` blocks on a libdispatch semaphore, so
// `thread::park`/`park_timeout` and everything layered on them — `mpsc`/
// `mpmc` `recv`/`recv_timeout`, blocking channel and `Once` paths — reach
// `dispatch_semaphore_wait`. The C layer interposes `dispatch_time`,
// `dispatch_semaphore_create`/`wait`/`signal`, and `dispatch_release` and
// forwards them here so the wait routes through `DetScheduler` and the
// virtual clock exactly like the pthread/futex primitives. Without this the
// Parker would block a real host thread outside the scheduler and read host
// time — a silent determinism escape that shared the shim baton's own
// `dispatch_semaphore_*` audit allowance.
//
// Deterministic tie-break (signal vs. deadline at the same virtual instant):
// a signal is only applied by a *runnable* unparker, which the scheduler
// runs before any clock advance; the deadline fires only through the
// deadlock rescue, which advances virtual time solely when no task can make
// progress. So a pending signal always wins a same-instant tie, and which
// path removed the waiter — never a clock comparison — decides the outcome,
// matching `patina_cond_timedwait`. Wakeup cause and order are recorded as
// ordinary scheduler park/wake and timer-rescue operations, so replay is
// exact.
#[cfg(target_os = "macos")]
const DISPATCH_TIME_NOW: u64 = 0;
#[cfg(target_os = "macos")]
const DISPATCH_TIME_FOREVER: u64 = u64::MAX;
/// Non-zero sentinel returned when a timed wait reaches its deadline; std
/// only tests `dispatch_semaphore_wait(...) != 0`.
#[cfg(target_os = "macos")]
const DISPATCH_TIMED_OUT: isize = -1;

#[unsafe(no_mangle)]
/// Reduce `dispatch_time(when, delta)` to the relative monotonic token that
/// [`patina_dispatch_semaphore_wait`] consumes. std only ever calls it as
/// `dispatch_time(DISPATCH_TIME_NOW, nanos)` for `park_timeout`, so a
/// `NOW`-relative non-negative nanosecond delta is returned verbatim (the
/// wait resolves it against the virtual monotonic clock); `FOREVER` and a
/// non-positive delta pass through as their sentinels.
///
/// # Safety
/// C ABI entry point; no pointers are dereferenced.
#[cfg(target_os = "macos")]
pub extern "C" fn patina_dispatch_time(when: u64, delta: i64) -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if when == DISPATCH_TIME_FOREVER {
        return DISPATCH_TIME_FOREVER;
    }
    if delta <= 0 {
        return DISPATCH_TIME_NOW;
    }
    // Clamp away from the `FOREVER` sentinel so a real deadline is never
    // mistaken for an infinite wait.
    (delta as u64).min(DISPATCH_TIME_FOREVER - 1)
}

#[unsafe(no_mangle)]
/// Allocate a modeled dispatch semaphore and return its opaque handle. Pure
/// local allocation — no scheduling point, mirroring the non-blocking
/// `dispatch_semaphore_create`.
///
/// # Safety
/// C ABI entry point; the returned pointer is an opaque token, never
/// dereferenced by the shim or by std.
#[cfg(target_os = "macos")]
pub extern "C" fn patina_dispatch_semaphore_create(value: isize) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut state = lock_state();
    let handle = state.next_dispatch_handle;
    state.next_dispatch_handle = handle.wrapping_add(1).max(1);
    state.dispatch.insert(
        handle,
        DispatchSem {
            count: value,
            waiters: WaitQueue::new(),
        },
    );
    handle as *mut c_void
}

#[unsafe(no_mangle)]
/// Release a modeled dispatch semaphore (its `Parker`'s `Drop`). Handles are
/// never reused, so simply dropping the table entry is safe.
///
/// # Safety
/// C ABI entry point; `object` is an opaque handle from
/// [`patina_dispatch_semaphore_create`].
#[cfg(target_os = "macos")]
pub extern "C" fn patina_dispatch_release(object: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    lock_state().dispatch.remove(&(object as usize));
}

#[unsafe(no_mangle)]
/// Wait on a modeled dispatch semaphore, routing any block through the
/// deterministic scheduler and virtual clock. Returns `0` when acquired (or
/// signalled) and a non-zero sentinel when a timed wait reaches its
/// deadline.
///
/// # Safety
/// C ABI entry point; `sem` is an opaque handle from
/// [`patina_dispatch_semaphore_create`].
#[cfg(target_os = "macos")]
pub extern "C" fn patina_dispatch_semaphore_wait(sem: *mut c_void, timeout: u64) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let key = sem as usize;
    if sched_point().is_err() {
        fatal("scheduler error entering dispatch_semaphore_wait");
    }
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        fatal(&format!("activating the thread runtime failed: {error:?}"));
    }
    // `ensure_active` may have just registered this host thread as the main
    // managed task, so read the current task after it.
    let me = current_task();
    let count_after = {
        let entry = state.dispatch.entry(key).or_default();
        entry.count -= 1;
        entry.count
    };
    if count_after >= 0 {
        // The token was available; no block.
        return 0;
    }
    if timeout == DISPATCH_TIME_NOW {
        // Non-blocking poll: undo the decrement and report timed out.
        if let Some(entry) = state.dispatch.get_mut(&key) {
            entry.count += 1;
        }
        return DISPATCH_TIMED_OUT;
    }
    let mut wait = Wait::new(BlockClass::Sync, vec![]);
    let sem = state
        .dispatch
        .get_mut(&key)
        .expect("semaphore was just decremented");
    wait.enqueue(&mut sem.waiters, me, WaiterLoc::Dispatch(key));
    if timeout == DISPATCH_TIME_FOREVER {
        match state.block(me, "dispatch-sem-wait", wait) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => {
                fatal("dispatch semaphore wait parked without transferring the baton")
            }
            Err(ThreadError::Fatal(message)) => fatal(&message),
            Err(ThreadError::Posix(errno)) => fatal(&format!(
                "dispatch semaphore wait failed with errno {errno}"
            )),
        }
        // Resumed only by a signal, which removed us from the waiters.
        0
    } else {
        let now = match with_context_raw(|context| context.now(ClockKind::Monotonic)) {
            Ok(now) => now,
            Err(_) => fatal("dispatch semaphore timed wait could not read the virtual clock"),
        };
        let deadline = now.saturating_add(timeout);
        match state.block_timed(
            me,
            "dispatch-sem-timedwait",
            wait,
            ClockKind::Monotonic,
            deadline,
        ) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(ThreadError::Fatal(message)) => fatal(&message),
            Err(ThreadError::Posix(errno)) => fatal(&format!(
                "dispatch semaphore timed wait failed with errno {errno}"
            )),
        }
        // A timer wake left us in `timed_out` (and restored the count); a
        // signal wake removed us from the waiters and kept the decrement.
        if lock_state().timed_out.remove(&me) {
            DISPATCH_TIMED_OUT
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
/// Signal a modeled dispatch semaphore, waking one waiter if the increment
/// leaves a non-positive count (i.e. a task was blocked). Returns `1` when a
/// task was woken, `0` otherwise; std ignores the value.
///
/// # Safety
/// C ABI entry point; `sem` is an opaque handle from
/// [`patina_dispatch_semaphore_create`].
#[cfg(target_os = "macos")]
pub extern "C" fn patina_dispatch_semaphore_signal(sem: *mut c_void) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let key = sem as usize;
    if sched_point().is_err() {
        fatal("scheduler error entering dispatch_semaphore_signal");
    }
    let mut state = lock_state();
    let woke = {
        let entry = state.dispatch.entry(key).or_default();
        entry.count += 1;
        if entry.count <= 0 {
            entry.waiters.pop_front()
        } else {
            None
        }
    };
    match woke {
        Some(task) => {
            if let Err(message) = RealScheduler.wake(task) {
                fatal(&message);
            }
            1
        }
        None => 0,
    }
}
