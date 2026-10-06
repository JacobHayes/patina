//! Linux readiness and fixed fortify entries.
use crate::posix::{cancel, error, model_result};
use crate::thread::{epoll, readiness};
use core::ffi::c_int;

const _: () = {
    assert!(core::mem::offset_of!(libc::epoll_event, events) == 0);
    #[cfg(target_arch = "x86_64")]
    {
        assert!(size_of::<libc::epoll_event>() == 12);
        assert!(core::mem::offset_of!(libc::epoll_event, u64) == 4);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        assert!(size_of::<libc::epoll_event>() == 16);
        assert!(core::mem::offset_of!(libc::epoll_event, u64) == 8);
    }
};

#[unsafe(no_mangle)]
pub extern "C" fn epoll_create1(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(epoll::patina_epoll_create1(flags))
}
/// # Safety
/// `event` has the epoll_ctl buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut libc::epoll_event,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { model_result(epoll::patina_epoll_ctl(epfd, op, fd, event.cast())) }
}
/// # Safety
/// `events` is writable for `maxevents` records.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"epoll_wait");
    unsafe {
        model_result(epoll::patina_epoll_wait(
            epfd,
            events.cast(),
            maxevents,
            timeout,
        ))
    }
}
/// # Safety
/// The event and optional mask buffers follow epoll_pwait's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_pwait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"epoll_pwait");
    unsafe {
        crate::posix::signal_result(readiness::patina_epoll_wait_masked(
            epfd,
            events.cast(),
            maxevents,
            timeout,
            sigmask.cast(),
        ))
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn eventfd(initval: libc::c_uint, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::thread::patina_eventfd(initval, flags))
}
unsafe fn timeout_nanos(ts: *const libc::timespec) -> i64 {
    unsafe {
        if ts.is_null() {
            return -1;
        }
        if (*ts).tv_sec < 0 || (*ts).tv_nsec < 0 || (*ts).tv_nsec >= 1_000_000_000 {
            return -2;
        }
        if (*ts).tv_sec > i64::MAX / 1_000_000_000 {
            return i64::MAX;
        }
        let base = (*ts).tv_sec * 1_000_000_000;
        if (*ts).tv_nsec > i64::MAX - base {
            i64::MAX
        } else {
            base + (*ts).tv_nsec
        }
    }
}
/// # Safety
/// Buffers follow ppoll's contract; timeout is null or readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ppoll(
    fds: *mut libc::pollfd,
    count: libc::nfds_t,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"ppoll");
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        crate::posix::signal_result(readiness::patina_poll(
            fds.cast(),
            count as usize,
            nanos,
            mask.cast(),
            core::ptr::null_mut(),
        ))
    }
}
/// # Safety
/// Sets and optional timeout follow select's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    nfds: c_int,
    read: *mut libc::fd_set,
    write: *mut libc::fd_set,
    except: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"select");
    unsafe {
        crate::posix::signal_result(readiness::patina_select_timeval(
            nfds,
            read.cast(),
            write.cast(),
            except.cast(),
            timeout as usize,
        ))
    }
}
/// # Safety
/// Buffers follow pselect's contract; timeout is null or readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    read: *mut libc::fd_set,
    write: *mut libc::fd_set,
    except: *mut libc::fd_set,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pselect");
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        crate::posix::signal_result(readiness::patina_select(
            nfds,
            read.cast(),
            write.cast(),
            except.cast(),
            nanos,
            mask.cast(),
            core::ptr::null_mut(),
        ))
    }
}
/// # Safety
/// Poll records must be writable within `fdslen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __poll_chk(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout: c_int,
    fdslen: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__poll_chk");
    if fdslen / size_of::<libc::pollfd>() < nfds as usize {
        crate::posix::chk_fail();
    }
    unsafe {
        crate::posix::signal_result(readiness::patina_poll(
            fds.cast(),
            nfds as usize,
            if timeout < 0 {
                -1
            } else {
                i64::from(timeout) * 1_000_000
            },
            core::ptr::null(),
            core::ptr::null_mut(),
        ))
    }
}
/// # Safety
/// Poll records must be writable within `fdslen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __ppoll_chk(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
    fdslen: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__ppoll_chk");
    if fdslen / size_of::<libc::pollfd>() < nfds as usize {
        crate::posix::chk_fail();
    }
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        crate::posix::signal_result(readiness::patina_poll(
            fds.cast(),
            nfds as usize,
            nanos,
            mask.cast(),
            core::ptr::null_mut(),
        ))
    }
}

core::arch::global_asm!(
    ".globl patina_route_epoll_create1",
    ".hidden patina_route_epoll_create1",
    ".set patina_route_epoll_create1, epoll_create1",
    ".globl patina_route_epoll_ctl",
    ".hidden patina_route_epoll_ctl",
    ".set patina_route_epoll_ctl, epoll_ctl",
    ".globl patina_route_epoll_wait",
    ".hidden patina_route_epoll_wait",
    ".set patina_route_epoll_wait, epoll_wait",
    ".globl patina_route_epoll_pwait",
    ".hidden patina_route_epoll_pwait",
    ".set patina_route_epoll_pwait, epoll_pwait",
    ".globl patina_route_eventfd",
    ".hidden patina_route_eventfd",
    ".set patina_route_eventfd, eventfd",
    ".globl patina_route_ppoll",
    ".hidden patina_route_ppoll",
    ".set patina_route_ppoll, ppoll",
    ".globl patina_route_select",
    ".hidden patina_route_select",
    ".set patina_route_select, select",
    ".globl patina_route_pselect",
    ".hidden patina_route_pselect",
    ".set patina_route_pselect, pselect",
    ".globl patina_route___poll_chk",
    ".hidden patina_route___poll_chk",
    ".set patina_route___poll_chk, __poll_chk",
    ".globl patina_route___ppoll_chk",
    ".hidden patina_route___ppoll_chk",
    ".set patina_route___ppoll_chk, __ppoll_chk",
);
