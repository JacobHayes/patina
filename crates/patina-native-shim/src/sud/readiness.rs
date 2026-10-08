//! SUD rows — readiness: the epoll frontend (`epoll_create1`/`epoll_ctl`/
//! `epoll_pwait*`), `eventfd2`, `ppoll` and `pselect6` over the same reactor
//! core. The x86_64-only forms live in `x86_64.rs` or alias these rows.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---- Readiness reactor (epoll) + eventfd ----

pub(super) fn sys_epoll_create1(flags: u64) -> i64 {
    ret_i32(crate::thread::epoll::patina_epoll_create1(flags as c_int))
}

pub(super) fn sys_epoll_ctl(epfd: i64, op: i64, fd: i64, event: u64) -> i64 {
    // SAFETY: `event` is a guest `struct epoll_event` for ADD/MOD (NULL for DEL,
    // which the entry tolerates).
    ret_i32(unsafe {
        crate::thread::epoll::patina_epoll_ctl(
            epfd as c_int,
            op as c_int,
            fd as c_int,
            (event as *const c_void).cast(),
        )
    })
}

pub(super) fn sys_epoll_pwait(
    epfd: i64,
    events: u64,
    maxevents: i64,
    timeout_ms: i64,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    if sigmask != 0 && sigsetsize != 8 {
        return -EINVAL;
    }

    // SAFETY: the event buffer and optional signal mask are guest pointers;
    // the entry copies them through `uaccess`.
    unsafe {
        crate::thread::readiness::patina_epoll_wait_masked(
            epfd as i32,
            events as *mut c_void,
            maxevents as i32,
            timeout_ms as i32,
            sigmask as *const u64,
        )
    }
}

pub(super) fn sys_epoll_pwait2(
    epfd: i64,
    events: u64,
    maxevents: i64,
    timeout: u64,
    sigmask: u64,
    sigsetsize: u64,
) -> i64 {
    // epoll_pwait2 takes a relative `struct timespec *timeout` (NULL == block
    // forever), copied in and judged before the mask's size
    // (`do_epoll_pwait`'s `set_user_sigmask`). Convert to the millisecond
    // timeout the reactor entry takes.
    let timeout_ms: i64 = if timeout == 0 {
        -1
    } else {
        let Ok(ts) = crate::uaccess::read::<Timespec>(timeout as usize) else {
            return -EFAULT;
        };
        if ts.tv_sec < 0 || !(0..NANOS_PER_SEC as i64).contains(&ts.tv_nsec) {
            return -EINVAL;
        }
        let ms = ts
            .tv_sec
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec + 999_999) / 1_000_000);
        ms.min(c_int::MAX as i64)
    };
    if sigmask != 0 && sigsetsize != 8 {
        return -EINVAL;
    }
    sys_epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, sigsetsize)
}

pub(super) fn sys_eventfd2(initval: u64, flags: i64) -> i64 {
    ret_i32(crate::thread::patina_eventfd(
        initval as u32,
        flags as c_int,
    ))
}

/// The unslept time a `ppoll`/`pselect6` writes back to its non-NULL
/// timeout once the wait answered (or was interrupted): none for a zero
/// timeout, and a copy that fails is ignored, the answer standing
/// (`poll_select_finish`: a timeout in read-only memory must not turn a
/// completed wait into a fault).
fn write_back_timeout(timeout: u64, requested: Option<u64>, remaining: u64, rc: i64) {
    if timeout == 0 || requested == Some(0) || !(rc >= 0 || rc == -EINTR) {
        return;
    }
    let left = Timespec {
        tv_sec: (remaining / NANOS_PER_SEC) as i64,
        tv_nsec: (remaining % NANOS_PER_SEC) as i64,
    };
    let _ = crate::uaccess::write(timeout as usize, &left);
}

/// `ppoll(2)` uses a temporary task mask and a relative timespec. Unlike
/// libc's wrapper, the raw row writes the unslept timeout back to the guest.
pub(super) fn sys_ppoll(fds: u64, nfds: u64, timeout: u64, sigmask: u64, sigsetsize: u64) -> i64 {
    // 6.8's order: the timeout, then the mask's size (`set_user_sigmask`,
    // whose copy-in `patina_poll` does before the descriptors).
    let timeout_ptr = timeout;
    let timeout = if timeout == 0 {
        None
    } else {
        let Ok(ts) = crate::uaccess::read::<Timespec>(timeout as usize) else {
            return -EFAULT;
        };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
            return -EINVAL;
        }
        Some(
            (ts.tv_sec as u64)
                .saturating_mul(NANOS_PER_SEC)
                .saturating_add(ts.tv_nsec as u64),
        )
    };
    if sigmask != 0 && sigsetsize != 8 {
        return -EINVAL;
    }
    let mut remaining = timeout.unwrap_or(0);
    // SAFETY: `fds` and `sigmask` are guest pointers checked and copied by
    // `patina_poll`; `remaining` is local storage.
    let rc = unsafe {
        crate::thread::readiness::patina_poll(
            fds as *mut _,
            nfds as usize,
            timeout.map_or(-1, |n| n.min(i64::MAX as u64) as i64),
            sigmask as *const u64,
            &mut remaining,
        )
    };
    write_back_timeout(timeout_ptr, timeout, remaining, rc);
    rc
}

/// select writes its timeval back; the raw pselect6 row writes its timespec
/// back too (glibc preserves the caller's pselect timeout in its wrapper).
pub(super) fn sys_select(
    nfds: u64,
    read: u64,
    write: u64,
    except: u64,
    timeout: u64,
    sigarg: Option<u64>,
) -> i64 {
    let Some(sigarg) = sigarg else {
        // The `select` row: the shared entry normalizes its timeval.
        // SAFETY: the sets and the timeval are the guest's, copied through
        // `uaccess`.
        return unsafe {
            crate::thread::readiness::patina_select_timeval(
                nfds as i32,
                read as *mut u64,
                write as *mut u64,
                except as *mut u64,
                timeout as usize,
            )
        };
    };
    // 6.8's order: the (set, size) argpack is copied in
    // (`get_sigset_argpack`), then the timeout, then the size is judged
    // (`set_user_sigmask`, whose copy-in `patina_select` does before the
    // sets).
    let pair = if sigarg == 0 {
        [0, 0]
    } else {
        match crate::uaccess::read::<[u64; 2]>(sigarg as usize) {
            Ok(pair) => pair,
            Err(_) => return -EFAULT,
        }
    };
    let nanos = if timeout == 0 {
        -1
    } else {
        match read_timespec_nanos(timeout as *const Timespec) {
            Ok(n) => n.min(i64::MAX as u64) as i64,
            Err(e) => return e,
        }
    };
    if pair[0] != 0 && pair[1] != 8 {
        return -EINVAL;
    }
    let mask = pair[0] as *const u64;
    let mut remaining = nanos.max(0) as u64;
    // SAFETY: the sets and mask are guest pointers checked and copied by
    // `patina_select`; `remaining` is local storage.
    let rc = unsafe {
        crate::thread::readiness::patina_select(
            nfds as i32,
            read as *mut u64,
            write as *mut u64,
            except as *mut u64,
            nanos,
            mask,
            &mut remaining,
        )
    };
    write_back_timeout(timeout, (nanos >= 0).then_some(nanos as u64), remaining, rc);
    rc
}
