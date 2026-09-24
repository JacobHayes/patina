//! SUD rows — readiness: the epoll frontend (`epoll_create1`/`epoll_ctl`/
//! `epoll_pwait*`), `eventfd2`, `ppoll` and `pselect6` over the same reactor
//! core. The x86_64-only forms live in `x86_64.rs` or alias these rows.

use super::*;

// ---- Readiness reactor (epoll) + eventfd ----

pub(super) fn sys_epoll_create1(flags: u64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_epoll_create1(flags as c_int) })
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
    if sigmask != 0 && sigsetsize != 8 {
        return -EINVAL;
    }
    // epoll_pwait2 takes a relative `struct timespec *timeout` (NULL == block
    // forever). Convert to the millisecond timeout the reactor entry takes.
    let timeout_ms: i64 = if timeout == 0 {
        -1
    } else {
        // SAFETY: `timeout` is a guest `struct timespec`.
        let ts = unsafe { (timeout as *const Timespec).read() };
        if ts.tv_sec < 0 || !(0..NANOS_PER_SEC as i64).contains(&ts.tv_nsec) {
            return -EINVAL;
        }
        let ms = ts
            .tv_sec
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec + 999_999) / 1_000_000);
        ms.min(c_int::MAX as i64)
    };
    sys_epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, sigsetsize)
}

pub(super) fn sys_eventfd2(initval: u64, flags: i64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_eventfd(initval as u32, flags as c_int) })
}

/// `ppoll(2)` uses a temporary task mask and a relative timespec. Unlike
/// libc's wrapper, the raw row writes the unslept timeout back to the guest.
pub(super) fn sys_ppoll(fds: u64, nfds: u64, timeout: u64, sigmask: u64, sigsetsize: u64) -> i64 {
    if sigmask != 0 && sigsetsize != 8 {
        return -EINVAL;
    }
    let timeout_ptr = timeout as *mut Timespec;
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
    let mut remaining = timeout.unwrap_or(0);
    let rc = unsafe {
        crate::thread::readiness::patina_poll(
            fds as *mut _,
            nfds as usize,
            timeout.map_or(-1, |n| n.min(i64::MAX as u64) as i64),
            sigmask as *const u64,
            &mut remaining,
        )
    };
    if !timeout_ptr.is_null() && (rc >= 0 || rc == -4) {
        unsafe {
            timeout_ptr.write(Timespec {
                tv_sec: (remaining / NANOS_PER_SEC) as i64,
                tv_nsec: (remaining % NANOS_PER_SEC) as i64,
            });
        }
    }
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
    let nanos = if timeout == 0 {
        -1
    } else if sigarg.is_some() {
        match read_timespec_nanos(timeout as *const Timespec) {
            Ok(n) => n.min(i64::MAX as u64) as i64,
            Err(e) => return e,
        }
    } else {
        let tv = unsafe { &*(timeout as *const Timeval) };
        if tv.tv_sec < 0 || !(0..1_000_000).contains(&tv.tv_usec) {
            return -EINVAL;
        }
        tv.tv_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(tv.tv_usec * 1000)
    };
    let mask = if let Some(arg) = sigarg.filter(|arg| *arg != 0) {
        let pair = unsafe { &*(arg as *const [u64; 2]) };
        if pair[0] != 0 && pair[1] != 8 {
            return -EINVAL;
        }
        pair[0] as *const u64
    } else {
        std::ptr::null()
    };
    let mut remaining = nanos.max(0) as u64;
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
    if timeout != 0 && (rc >= 0 || rc == -4) {
        unsafe {
            if sigarg.is_some() {
                (timeout as *mut Timespec).write(Timespec {
                    tv_sec: (remaining / 1_000_000_000) as i64,
                    tv_nsec: (remaining % 1_000_000_000) as i64,
                });
            } else {
                (timeout as *mut Timeval).write(Timeval {
                    tv_sec: (remaining / 1_000_000_000) as i64,
                    tv_usec: ((remaining % 1_000_000_000) / 1000) as i64,
                });
            }
        }
    }
    rc
}
