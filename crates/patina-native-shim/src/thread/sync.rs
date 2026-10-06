//! Managed mutex, rwlock, and condition-variable entry points.

use super::*;

/// Run the deterministic body of a mutex/cond boundary op after taking a
/// scheduling point. The shim's own synchronization never routes here (it
/// uses [`SpinMutex`] and the baton), so these always take the managed path.
macro_rules! managed_op {
    ($body:block) => {{
        if let Err(errno) = sched_point() {
            return errno;
        }
        $body
    }};
}

#[unsafe(no_mangle)]
/// # Safety
/// `mutex` must reference a valid `pthread_mutex_t`.
pub unsafe extern "C" fn patina_mutex_init(mutex: *mut c_void, attr: *const c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: a null or initialized attribute, per the pthread contract.
    let kind = unsafe { MutexKind::of_attr(attr) };
    managed_op!({
        let mut state = lock_state();
        state.table.init_mutex(mutex as usize, kind);
        0
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `mutex` must reference a valid `pthread_mutex_t`.
pub unsafe extern "C" fn patina_mutex_lock(mutex: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let key = mutex as usize;
        // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
        let kind = unsafe { MutexKind::of_static(mutex) };
        let me = current_task();
        let mut state = lock_state();
        match state.begin_lock(me, key, kind) {
            Ok(Step::Continue) => 0,
            Ok(Step::Switch(picked)) => {
                switch_and_park(state, picked, me);
                0
            }
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `mutex` must reference a valid `pthread_mutex_t`.
pub unsafe extern "C" fn patina_mutex_trylock(mutex: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
        let kind = unsafe { MutexKind::of_static(mutex) };
        let me = current_task();
        let mut state = lock_state();
        state.table.trylock(me, mutex as usize, kind)
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `mutex` must reference a valid `pthread_mutex_t`.
pub unsafe extern "C" fn patina_mutex_unlock(mutex: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let me = current_task();
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        match state.table.unlock(&mut scheduler, me, mutex as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `mutex` must reference a valid `pthread_mutex_t`.
pub unsafe extern "C" fn patina_mutex_destroy(mutex: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let mut state = lock_state();
        match state.table.destroy_mutex(mutex as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// `os_unfair_lock` (macOS) routed through the deterministic scheduler using
/// the shared mutex table, keyed on the lock's address. `os_unfair_lock` is a
/// bare `u32` with no init call, so the table lazily registers it on first
/// lock/trylock (the `or_default` path) exactly as it does for a
/// never-`pthread_mutex_init`'d word.
///
/// The real primitive is non-recursive and traps on misuse: a recursive lock
/// by the current owner (`EDEADLK` here) and an unlock by a non-owner or of a
/// never-locked word (`EPERM`/`EINVAL` here) both abort loudly and
/// deterministically rather than returning silently — these functions have no
/// error channel, so a soft failure would be an invisible escape. A scheduler
/// fault at the entry point cannot be surfaced through the `void`/`bool` ABI
/// either, so it is ignored: the scheduling point (and any baton handoff) has
/// already happened inside `sched_point`, and the real primitive has no such
/// failure mode.
///
/// # Safety
/// `lock` must reference a valid `os_unfair_lock`.
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn patina_os_unfair_lock_lock(lock: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Run the lock natively — never through the deterministic model — for an
    // allocator-internal `os_unfair_lock` in either of the two windows where
    // one appears: (1) the bootstrap window, where a custom global allocator's
    // own eager init takes its `malloc_mutex`; (2) reentrantly while this
    // thread already holds a shim spinlock, which happens only when the shim's
    // scheduler-path allocation re-enters the (now-initialized) allocator. Both
    // are allocator-internal, single-owner locks that must not route through
    // the scheduler (it would trip the non-recursive guard or deadlock on the
    // held spinlock). See `SHIM_BOOTSTRAP` and `SPIN_DEPTH`.
    //
    // The spinlock test comes FIRST because the window test aborts on a
    // stored init error: shim-internal reentrancy must never be the call that
    // triggers a fail-closed abort, or the shim's own diagnostic write could
    // abort from inside its allocator's deallocation.
    if super::in_shim_critical() || super::in_shim_bootstrap() {
        // SAFETY: the resolved real `os_unfair_lock_lock`; `lock` is a valid
        // `os_unfair_lock` per the caller's contract.
        unsafe { (super::hostapi::get().host_os_unfair_lock_lock)(lock) };
        return;
    }
    let _ = sched_point();
    let key = lock as usize;
    let me = current_task();
    let mut state = lock_state();
    match state.begin_lock(me, key, MutexKind::ErrorCheck) {
        Ok(Step::Continue) => {}
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Err(ThreadError::Fatal(message)) => {
            drop(state);
            fatal(&message);
        }
        Err(ThreadError::Posix(_)) => {
            drop(state);
            fatal(
                "os_unfair_lock_lock: recursive lock of an os_unfair_lock already held by the \
                 current task",
            );
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `os_unfair_lock`.
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn patina_os_unfair_lock_trylock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
    // The real `os_unfair_lock_trylock` returns a C `bool`.
    if super::in_shim_critical() || super::in_shim_bootstrap() {
        // SAFETY: the resolved real `os_unfair_lock_trylock`; valid `lock`.
        return c_int::from(unsafe { (super::hostapi::get().host_os_unfair_lock_trylock)(lock) });
    }
    let _ = sched_point();
    let me = current_task();
    let mut state = lock_state();
    // Acquired -> 1. Held by another task (EBUSY) or already owned by this
    // task (EDEADLK) -> 0: the real single-cmpxchg trylock simply fails to
    // acquire when the word is non-zero, without trapping.
    c_int::from(
        state
            .table
            .trylock(me, lock as usize, MutexKind::ErrorCheck)
            == 0,
    )
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `os_unfair_lock` the caller holds.
#[cfg(target_os = "macos")]
pub unsafe extern "C" fn patina_os_unfair_lock_unlock(lock: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Allocator-internal lock: run natively (see `patina_os_unfair_lock_lock`).
    // A lock taken natively (bootstrap, or reentrant under a held spinlock) is
    // released natively too; the allocator's lock/unlock pair is balanced
    // within the same window, so none spans a transition.
    if super::in_shim_critical() || super::in_shim_bootstrap() {
        // SAFETY: the resolved real `os_unfair_lock_unlock`; valid `lock`.
        unsafe { (super::hostapi::get().host_os_unfair_lock_unlock)(lock) };
        return;
    }
    let _ = sched_point();
    let me = current_task();
    let mut state = lock_state();
    let mut scheduler = RealScheduler;
    match state.table.unlock(&mut scheduler, me, lock as usize) {
        Ok(()) => {}
        Err(ThreadError::Fatal(message)) => {
            drop(state);
            fatal(&message);
        }
        Err(ThreadError::Posix(_)) => {
            drop(state);
            fatal(
                "os_unfair_lock_unlock: unlock of an os_unfair_lock not owned by the current \
                 task",
            );
        }
    }
}

#[unsafe(no_mangle)]
/// Deterministic `pthread_rwlock_*`. Reader/writer contention routes through
/// the scheduler exactly like the mutex/cond interposition: the lock's kind
/// (from its attribute or static initializer; glibc's default prefers
/// readers) decides the grant order, writers are FIFO, and blocked readers
/// are woken together. std's own `RwLock` does not
/// lower to these symbols on the supported toolchains (it uses the queue-based
/// parking `RwLock`), so this serves C guests and any std that does.
///
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_init(lock: *mut c_void, attr: *const c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: a null or initialized attribute, per the pthread contract.
    let kind = unsafe { RwLockKind::of_attr(attr) };
    managed_op!({
        let mut state = lock_state();
        state.table.init_rwlock(lock as usize, kind);
        0
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_rdlock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let key = lock as usize;
        // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
        let kind = unsafe { RwLockKind::of_static(lock) };
        let me = current_task();
        let mut state = lock_state();
        match state.begin_rdlock(me, key, kind) {
            Ok(Step::Continue) => 0,
            Ok(Step::Switch(picked)) => {
                switch_and_park(state, picked, me);
                0
            }
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_wrlock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let key = lock as usize;
        // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
        let kind = unsafe { RwLockKind::of_static(lock) };
        let me = current_task();
        let mut state = lock_state();
        match state.begin_wrlock(me, key, kind) {
            Ok(Step::Continue) => 0,
            Ok(Step::Switch(picked)) => {
                switch_and_park(state, picked, me);
                0
            }
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_tryrdlock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
        let kind = unsafe { RwLockKind::of_static(lock) };
        let mut state = lock_state();
        state.table.rwlock_tryrdlock(lock as usize, kind)
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_trywrlock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        // SAFETY: a valid `pthread_rwlock_t`, per this function's contract.
        let kind = unsafe { RwLockKind::of_static(lock) };
        let me = current_task();
        let mut state = lock_state();
        state.table.rwlock_trywrlock(me, lock as usize, kind)
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t` the caller holds.
pub unsafe extern "C" fn patina_rwlock_unlock(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let me = current_task();
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        match state.table.rwlock_unlock(&mut scheduler, me, lock as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `lock` must reference a valid `pthread_rwlock_t`.
pub unsafe extern "C" fn patina_rwlock_destroy(lock: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let mut state = lock_state();
        match state.table.destroy_rwlock(lock as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `cond` must reference a valid `pthread_cond_t`.
pub unsafe extern "C" fn patina_cond_init(cond: *mut c_void, attr: *const c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: a null or initialized attribute, per the pthread contract.
    let clock = unsafe { CondEntry::clock_of_attr(attr) };
    managed_op!({
        let mut state = lock_state();
        state.table.init_cond(cond as usize, clock);
        0
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `cond` and `mutex` must reference valid pthread objects, and the caller
/// must own `mutex`.
pub unsafe extern "C" fn patina_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let me = current_task();
        let mut state = lock_state();
        match state.begin_cond_wait(me, cond as usize, mutex as usize) {
            Ok(Step::Switch(picked)) => {
                switch_and_park(state, picked, me);
                0
            }
            Ok(Step::Continue) => fatal("cond wait parked without transferring the baton"),
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

/// A C `struct timespec` for the supported 64-bit targets. `time_t` and
/// `long` are both 64-bit on macOS and Linux aarch64/x86_64.
#[repr(C)]
pub(crate) struct CTimespec {
    pub(crate) tv_sec: i64,
    pub(crate) tv_nsec: i64,
}

/// Convert an absolute `struct timespec` deadline to nanoseconds: `EINVAL`
/// for a `tv_nsec` outside a second, `EOVERFLOW` past `u64`. A deadline
/// before the epoch is already past, as glibc's futex wait judges it, so
/// it is the epoch.
///
/// # Safety
/// `ptr` must point to a valid `struct timespec`.
unsafe fn timespec_nanos(ptr: *const c_void) -> Result<u64, c_int> {
    // SAFETY: guaranteed by this function's contract.
    let time = unsafe { &*ptr.cast::<CTimespec>() };
    if time.tv_nsec < 0 || time.tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    if time.tv_sec < 0 {
        return Ok(0);
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|nanos| nanos.checked_add(time.tv_nsec as u64))
        .ok_or(EOVERFLOW)
}

#[unsafe(no_mangle)]
/// Timed condition wait. Like [`patina_cond_wait`], but parks with the
/// wait's absolute deadline, on the condition's clock, registered on the
/// virtual-clock timer queue. A signal before the deadline returns 0 (the
/// waiter owns the mutex, exactly like the untimed path); reaching the
/// deadline re-acquires the mutex and returns `ETIMEDOUT`. Whether the wake
/// was a signal or the timer is decided by which path removed the waiter —
/// never by comparing clocks — so it is deterministic. A deadline already
/// reached parks nothing: the mutex is released and re-acquired, and the
/// wait is `ETIMEDOUT` at once, however busy the other tasks are.
///
/// # Safety
/// `cond` and `mutex` must reference valid pthread objects the caller owns,
/// and `abstime` a valid `struct timespec`.
pub unsafe extern "C" fn patina_cond_timedwait(
    cond: *mut c_void,
    mutex: *mut c_void,
    abstime: *const c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if abstime.is_null() {
        return EINVAL;
    }
    // SAFETY: `abstime` was checked non-null and is a `struct timespec`.
    let deadline = match unsafe { timespec_nanos(abstime) } {
        Ok(deadline) => deadline,
        Err(errno) => return errno,
    };
    if let Err(errno) = sched_point() {
        return errno;
    }
    let cond_key = cond as usize;
    let mutex_key = mutex as usize;
    let me = current_task();
    let mut state = lock_state();
    let mut scheduler = RealScheduler;
    let clock = state.table.cond_clock(cond_key);
    let past = with_context_raw(|context| {
        let due = context.monotonic_deadline(clock, deadline)?;
        Ok(due <= context.monotonic_now_unrecorded()?)
    });
    match past {
        Ok(false) => {}
        Ok(true) => {
            if let Err(error) = state.table.unlock(&mut scheduler, me, mutex_key) {
                return c_int::from(error.into_posix());
            }
            // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
            let kind = unsafe { MutexKind::of_static(mutex) };
            match state.begin_lock(me, mutex_key, kind) {
                Ok(Step::Continue) => drop(state),
                Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
                Err(error) => return c_int::from(error.into_posix()),
            }
            return ETIMEDOUT;
        }
        Err(errno) => return errno,
    }
    // Release the mutex and enqueue on the condition, exactly as cond_wait.
    if let Err(error) = state
        .table
        .cond_wait(&mut scheduler, me, cond_key, mutex_key)
    {
        return c_int::from(error.into_posix());
    }
    match state.block_timed(
        me,
        "cond-timedwait",
        Wait::new(BlockClass::Sync, vec![WaiterLoc::Cond(cond_key, mutex_key)]),
        clock,
        deadline,
    ) {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return c_int::from(error.into_posix()),
    }
    // Resumed. A timer wake left `me` in `timed_out` and holding no mutex; a
    // signal wake removed `me` from the condition and re-granted the mutex.
    let mut state = lock_state();
    if state.timed_out.remove(&me) {
        // SAFETY: a valid `pthread_mutex_t`, per this function's contract.
        let kind = unsafe { MutexKind::of_static(mutex) };
        match state.begin_lock(me, mutex_key, kind) {
            Ok(Step::Continue) => drop(state),
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Err(error) => return c_int::from(error.into_posix()),
        }
        ETIMEDOUT
    } else {
        drop(state);
        0
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// `cond` must reference a valid `pthread_cond_t`.
pub unsafe extern "C" fn patina_cond_signal(cond: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        match state.table.cond_signal(&mut scheduler, cond as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `cond` must reference a valid `pthread_cond_t`.
pub unsafe extern "C" fn patina_cond_broadcast(cond: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let mut state = lock_state();
        let mut scheduler = RealScheduler;
        match state.table.cond_broadcast(&mut scheduler, cond as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}

#[unsafe(no_mangle)]
/// # Safety
/// `cond` must reference a valid `pthread_cond_t`.
pub unsafe extern "C" fn patina_cond_destroy(cond: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    managed_op!({
        let mut state = lock_state();
        match state.table.destroy_cond(cond as usize) {
            Ok(()) => 0,
            Err(error) => c_int::from(error.into_posix()),
        }
    })
}
