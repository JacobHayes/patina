//! SUD rows — readiness: the epoll frontend (`epoll_create*`/`epoll_ctl`/
//! `epoll_*wait*`), `eventfd*`, and `poll`/`ppoll` over the same reactor core.

use super::*;

// ---- Readiness reactor (epoll) + eventfd ----

pub(super) fn sys_epoll_create1(flags: u64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_epoll_create1(flags as c_int) })
}

/// Legacy `epoll_create(size)` (x86_64-only syscall). The `size` hint has been
/// ignored since Linux 2.6.8, but the kernel still rejects `size <= 0` with
/// `-EINVAL` before creating the instance with no flags. Everything else is
/// `epoll_create1(0)`.
pub(super) fn sys_epoll_create(size: u64) -> i64 {
    if size as i32 <= 0 {
        return -EINVAL;
    }
    sys_epoll_create1(0)
}

pub(super) fn sys_epoll_ctl(epfd: i64, op: i64, fd: i64, event: u64) -> i64 {
    // SAFETY: `event` is a guest `struct epoll_event` for ADD/MOD (NULL for DEL,
    // which the entry tolerates).
    ret_i32(unsafe {
        patina_epoll_ctl(
            epfd as c_int,
            op as c_int,
            fd as c_int,
            event as *const c_void,
        )
    })
}

pub(super) fn sys_epoll_wait(epfd: i64, events: u64, maxevents: i64, timeout_ms: i64) -> i64 {
    // SAFETY: `events` is the guest event buffer for `maxevents` entries.
    ret_i32(unsafe {
        patina_epoll_wait(
            epfd as c_int,
            events as *mut c_void,
            maxevents as c_int,
            timeout_ms as c_int,
        )
    })
}

pub(super) fn sys_epoll_pwait(
    epfd: i64,
    events: u64,
    maxevents: i64,
    timeout_ms: i64,
    sigmask: u64,
) -> i64 {
    // Patina delivers no ambient signals, so a NULL mask is the plain wait; a
    // real mask swap has no deterministic meaning. Mirror the C epoll_pwait
    // interposer's deny EXACTLY — the same recorded diagnostic and -ENOSYS.
    if sigmask != 0 {
        return sud_deny("patina: epoll_pwait with a signal mask is not modeled; failing closed\n");
    }
    sys_epoll_wait(epfd, events, maxevents, timeout_ms)
}

pub(super) fn sys_epoll_pwait2(
    epfd: i64,
    events: u64,
    maxevents: i64,
    timeout: u64,
    sigmask: u64,
) -> i64 {
    if sigmask != 0 {
        return -EINVAL;
    }
    // epoll_pwait2 takes an absolute `struct timespec *timeout` (NULL == block
    // forever). Convert to the millisecond timeout the reactor entry takes.
    let timeout_ms: i64 = if timeout == 0 {
        -1
    } else {
        // SAFETY: `timeout` is a guest `struct timespec`.
        let ts = unsafe { (timeout as *const Timespec).read() };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 {
            return -EINVAL;
        }
        let ms = ts.tv_sec.saturating_mul(1000) + ts.tv_nsec / 1_000_000;
        ms.min(c_int::MAX as i64)
    };
    sys_epoll_wait(epfd, events, maxevents, timeout_ms)
}

pub(super) fn sys_eventfd2(initval: u64, flags: i64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_eventfd(initval as u32, flags as c_int) })
}

/// The size of a Linux `struct pollfd` (`int fd; short events; short revents;`).
pub(super) const POLLFD_SIZE: usize = 8;

/// The shared `poll`/`ppoll` core, mirroring the C `poll` interposer
/// (patina_posix.c). `timeout` is normalized to nanoseconds: `Some(0)` = return
/// immediately, `Some(n>0)` = wait `n` ns of VIRTUAL time, `None` = the "infinite"
/// timeout (poll's `-1` / ppoll's NULL). The C model:
///  - with descriptors (`nfds != 0`): a non-zero timeout is an unmodeled real
///    wait → `-ENOSYS`; a zero timeout requires every `events` to be empty (a
///    non-empty event set is an unmodeled real readiness query → `-ENOSYS`),
///    clearing each `revents` and returning 0.
///  - with no descriptors (`nfds == 0`): sleep for a strictly-positive timeout
///    (advancing virtual time), then return 0. An infinite/zero timeout returns 0
///    immediately (no event can ever arrive on an empty set, so a real kernel's
///    forever-block is deterministically an instant no-op here).
pub(super) fn poll_core(fds: u64, nfds: u64, timeout: Option<u64>) -> i64 {
    let zero_timeout = timeout == Some(0);
    if nfds != 0 {
        if !zero_timeout {
            // A real wait on descriptors has no deterministic model.
            return -ENOSYS;
        }
        if fds == 0 {
            return -EFAULT;
        }
        for i in 0..nfds as usize {
            let entry = (fds as *mut u8).wrapping_add(i * POLLFD_SIZE);
            // events/revents are `short` at offsets 4 and 6 of the pollfd.
            // SAFETY: `fds` is the guest's array of `nfds` pollfd entries.
            let events = unsafe { (entry.add(4) as *const u16).read_unaligned() };
            if events != 0 {
                // A real readiness query is unmodeled.
                return -ENOSYS;
            }
            // SAFETY: as above; clear the result field.
            unsafe { (entry.add(6) as *mut u16).write_unaligned(0) };
        }
        return 0;
    }
    // No descriptors: a strictly-positive timeout advances virtual time; an
    // infinite or zero timeout returns 0 immediately.
    match timeout {
        Some(nanos) if nanos > 0 => {
            let mut now: u64 = 0;
            // SAFETY: local storage.
            let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut now) };
            if rc != 0 {
                return ret_i32(rc);
            }
            let deadline = now.saturating_add(nanos);
            // SAFETY: no pointers.
            ret_i32(unsafe { patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) })
        }
        _ => 0,
    }
}

/// Legacy `poll(2)` (x86_64-only syscall). `timeout` is an `int` of milliseconds:
/// negative is the infinite timeout, otherwise it scales to nanoseconds for
/// [`poll_core`].
pub(super) fn sys_poll(fds: u64, nfds: u64, timeout_ms: i64) -> i64 {
    let timeout = if timeout_ms < 0 {
        None
    } else {
        Some((timeout_ms as u64).saturating_mul(1_000_000))
    };
    poll_core(fds, nfds, timeout)
}

/// `ppoll(2)`. The `int`-milliseconds timeout of `poll` becomes a relative
/// `struct timespec *` (NULL = infinite); a signal mask is inert in a signal-free
/// deterministic world (no ambient signals exist to block), so it is ignored and
/// the call routes through the same [`poll_core`]. `ppoll_time64` (x86_64 414) is
/// deliberately NOT routed — 64-bit callers never use it — so it stays fail-closed.
pub(super) fn sys_ppoll(fds: u64, nfds: u64, timeout: u64, _sigmask: u64, _sigsetsize: u64) -> i64 {
    let timeout = if timeout == 0 {
        None
    } else {
        // SAFETY: `timeout` is a guest `struct timespec`.
        let ts = unsafe { (timeout as *const Timespec).read() };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
            return -EINVAL;
        }
        Some(
            (ts.tv_sec as u64)
                .saturating_mul(NANOS_PER_SEC)
                .saturating_add(ts.tv_nsec as u64),
        )
    };
    poll_core(fds, nfds, timeout)
}
