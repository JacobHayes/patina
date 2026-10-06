//! Linux futex wait and wake entry points.

use super::*;

// ------------------------------------------------------------------
// Linux futex routing. Rust std on Linux lowers Mutex/Condvar/thread
// parking to raw SYS_futex through libc's `syscall` wrapper rather than the
// pthread primitives the shim interposes, so the interposed `syscall` routes
// FUTEX_WAIT/FUTEX_WAKE here. A wait parks the calling managed task on the
// futex word's address through the baton (like a cond wait); a wake releases
// up to N of them. macOS is unaffected — std uses pthread there. The address
// is only read/parked while this task holds the baton, so the value check
// and the park are atomic and no wakeup is lost. A timed wait parks with
// its deadline on the virtual-clock timer queue: a FUTEX_WAKE that arrives
// first wins, otherwise the deadlock rescue fires the deadline, purges the
// waiter from the futex word's queue, and the wait returns ETIMEDOUT —
// exactly the cond_timedwait discipline.

/// FUTEX_WAIT: if the word at `addr` still equals `expected`, park the
/// calling task on that address; otherwise return `EWOULDBLOCK` so the
/// caller re-checks. Returns 0 when woken by a FUTEX_WAKE.
///
/// # Safety
/// `addr` must be the address of a live, aligned 4-byte futex word.
#[unsafe(no_mangle)]
pub extern "C" fn patina_futex_wait(addr: usize, expected: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    futex_wait(addr, expected, false, u32::MAX)
}

/// [`patina_futex_wait`], noting whether the wait is private
/// (`FUTEX_PRIVATE_FLAG`) and its bitset: the dispatcher's `futex` row.
pub(crate) fn futex_wait(addr: usize, expected: u32, private: bool, bitset: u32) -> c_int {
    let mut restart = true;
    while restart {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return super::fail(error.into_posix());
        }
        let me = current_task();
        // SAFETY: `addr` is the guest's futex word per this function's contract;
        // only the baton holder runs, so this read races with nothing.
        let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if current != expected {
            return super::fail(EWOULDBLOCK);
        }

        state.queue_futex_waiter(addr, FutexWaiter::multiplexed(me, private, bitset));
        match state.block(
            me,
            "futex-wait",
            Wait::new(BlockClass::Futex, vec![WaiterLoc::Futex(addr)]),
        ) {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => fatal("futex wait parked without transferring the baton"),
            Err(error) => return error.into_posix(),
        }
        #[cfg(target_os = "linux")]
        match signals::resume() {
            signals::Resumed::Eintr => return super::fail(super::EINTR),
            signals::Resumed::Restart => restart = true,
            signals::Resumed::Normal => restart = false,
        }
        #[cfg(not(target_os = "linux"))]
        {
            restart = false;
        }
    }
    0
}

/// Timed `FUTEX_WAIT`/`FUTEX_WAIT_BITSET`: like [`patina_futex_wait`] but
/// with a deadline on the virtual-clock timer queue. `absolute` is 0 for a
/// relative `FUTEX_WAIT` timeout (added to the current `clock` time) and
/// nonzero for an absolute `FUTEX_WAIT_BITSET` deadline. `clock_id` is
/// `PATINA_CLOCK_MONOTONIC` unless `FUTEX_CLOCK_REALTIME` was set. Returns 0
/// when woken by a `FUTEX_WAKE`, `-1`/`ETIMEDOUT` when the timer fires, and
/// `-1`/`EWOULDBLOCK` if the word no longer holds `expected`. The value
/// check, clock read, and park all run under the baton, so the check and the
/// park stay atomic exactly like the untimed path.
///
/// # Safety
/// `addr` must be the address of a live, aligned 4-byte futex word.
#[unsafe(no_mangle)]
pub extern "C" fn patina_futex_wait_timed(
    addr: usize,
    expected: u32,
    clock_id: u32,
    absolute: c_int,
    timeout_nanos: u64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    futex_wait_timed(
        addr,
        expected,
        clock_id,
        absolute,
        timeout_nanos,
        false,
        u32::MAX,
    )
}

/// [`patina_futex_wait_timed`], noting whether the wait is private and
/// its bitset.
pub(crate) fn futex_wait_timed(
    addr: usize,
    expected: u32,
    clock_id: u32,
    absolute: c_int,
    timeout_nanos: u64,
    private: bool,
    bitset: u32,
) -> c_int {
    let clock = match clock_id {
        0 => ClockKind::Realtime,
        1 => ClockKind::Monotonic,
        _ => return super::fail(EINVAL),
    };
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return super::fail(error.into_posix());
    }
    let me = current_task();
    // SAFETY: `addr` is the guest's futex word per this function's contract;
    // only the baton holder runs, so this read races with nothing.
    let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
    if current != expected {
        return super::fail(EWOULDBLOCK);
    }

    // A relative timeout is anchored to the current virtual time; both reads
    // and the subsequent park happen without releasing the baton.
    let deadline = if absolute != 0 {
        timeout_nanos
    } else {
        match with_context_raw(|context| context.now(clock)) {
            Ok(now) => now.saturating_add(timeout_nanos),
            Err(errno) => return super::fail(errno),
        }
    };
    state.queue_futex_waiter(addr, FutexWaiter::multiplexed(me, private, bitset));
    match state.block_timed(
        me,
        "futex-wait",
        Wait::new(BlockClass::TimedFutex, vec![WaiterLoc::Futex(addr)]),
        clock,
        deadline,
    ) {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return error.into_posix(),
    }
    // Whether the deadline ended the wait is read before a pending
    // handler runs, which could itself wait and take the flag.
    #[cfg(target_os = "linux")]
    let timed_out = {
        let mut timed_out = false;
        let resumed = signals::resume_with(|_| timed_out = lock_state().timed_out.remove(&me));
        if resumed == signals::Resumed::Eintr {
            return super::fail(super::EINTR);
        }
        timed_out
    };
    #[cfg(not(target_os = "linux"))]
    let timed_out = lock_state().timed_out.remove(&me);
    if timed_out { super::fail(ETIMEDOUT) } else { 0 }
}

/// FUTEX_WAKE: wake up to `count` tasks (all if `count < 0`) parked on
/// `addr`. Returns the number woken.
///
/// # Safety
/// C ABI entry point.
#[unsafe(no_mangle)]
pub extern "C" fn patina_futex_wake(addr: usize, count: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    futex_wake(addr, count, true)
}

/// A kernel-side wake by the word's shared key (a dead robust owner's,
/// `handle_futex_death`): up to `count` waiters, skipping those that wait
/// privately, whose key it does not match.
#[cfg(target_os = "linux")]
pub(crate) fn futex_wake_shared(addr: usize, count: c_int) -> c_int {
    futex_wake(addr, count, false)
}

/// Wake up to `count` waiters on `addr` (all if negative), in queue
/// order; private waiters too unless `private` is false.
fn futex_wake(addr: usize, count: c_int, private: bool) -> c_int {
    let mut state = lock_state();
    let limit = usize::try_from(count).unwrap_or(usize::MAX);
    let woken = state.take_futex_waiters(addr, limit, |waiter| private || !waiter.private);
    state.wake_futex_waiters(&woken);
    c_int::try_from(woken.len()).unwrap_or(c_int::MAX)
}
