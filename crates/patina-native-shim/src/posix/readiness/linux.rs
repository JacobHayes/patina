//! Linux readiness and fixed fortify entries.
#![deny(clippy::undocumented_unsafe_blocks)]

use crate::abi;
use crate::posix::{cancel, error};
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
extern "C" fn epoll_create1(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abi::libc_result(epoll::create1(flags), -1)
}
/// # Safety
/// `event` has the epoll_ctl buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut libc::epoll_event,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller provides epoll_ctl's event buffer; the core reads via uaccess.
    abi::libc_result(unsafe { epoll::ctl_core(epfd, op, fd, event.cast()) }, -1)
}
/// # Safety
/// `events` is writable for `maxevents` records.
#[unsafe(no_mangle)]
unsafe extern "C" fn epoll_wait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"epoll_wait");
    // SAFETY: the caller provides `maxevents` writable records; the core copies by uaccess.
    abi::libc_result(
        unsafe { epoll::wait_core(epfd, events.cast(), maxevents, timeout) },
        -1,
    )
}
/// # Safety
/// The event and optional mask buffers follow epoll_pwait's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn epoll_pwait(
    epfd: c_int,
    events: *mut libc::epoll_event,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"epoll_pwait");
    // SAFETY: event and optional mask buffers follow epoll_pwait's caller contract.
    abi::libc_delivered(
        unsafe {
            readiness::epoll_wait_masked_core(
                epfd,
                events.cast(),
                maxevents,
                timeout,
                sigmask.cast(),
            )
        },
        -1,
    ) as c_int
}
#[unsafe(no_mangle)]
extern "C" fn eventfd(initval: libc::c_uint, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    abi::libc_result(crate::thread::create(initval, flags), -1)
}
unsafe fn timeout_nanos(ts: *const libc::timespec) -> i64 {
    // SAFETY: null is returned above; the caller guarantees a readable timespec otherwise.
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
unsafe extern "C" fn ppoll(
    fds: *mut libc::pollfd,
    count: libc::nfds_t,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"ppoll");
    // SAFETY: fds and mask follow ppoll's caller contract; timeout was checked above.
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        abi::libc_delivered(
            readiness::poll_core(
                fds.cast(),
                count as usize,
                nanos,
                mask.cast(),
                core::ptr::null_mut(),
            ),
            -1,
        ) as c_int
    }
}
/// # Safety
/// Sets and optional timeout follow select's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn select(
    nfds: c_int,
    read: *mut libc::fd_set,
    write: *mut libc::fd_set,
    except: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"select");
    // SAFETY: fd sets and timeval follow select's caller contract; the core uses uaccess.
    unsafe {
        abi::libc_delivered(
            readiness::select_timeval_core(
                nfds,
                read.cast(),
                write.cast(),
                except.cast(),
                timeout as usize,
            ),
            -1,
        ) as c_int
    }
}
/// # Safety
/// Buffers follow pselect's contract; timeout is null or readable.
#[unsafe(no_mangle)]
unsafe extern "C" fn pselect(
    nfds: c_int,
    read: *mut libc::fd_set,
    write: *mut libc::fd_set,
    except: *mut libc::fd_set,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pselect");
    // SAFETY: fd sets, timeout and mask follow pselect's caller contract; the core uses uaccess.
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        abi::libc_delivered(
            readiness::select_core(
                nfds,
                read.cast(),
                write.cast(),
                except.cast(),
                nanos,
                mask.cast(),
                core::ptr::null_mut(),
            ),
            -1,
        ) as c_int
    }
}
/// # Safety
/// Poll records must be writable within `fdslen` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn __poll_chk(
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
    // SAFETY: fortify validated the record count; poll_core uses uaccess for records.
    unsafe {
        abi::libc_delivered(
            readiness::poll_core(
                fds.cast(),
                nfds as usize,
                if timeout < 0 {
                    -1
                } else {
                    i64::from(timeout) * 1_000_000
                },
                core::ptr::null(),
                core::ptr::null_mut(),
            ),
            -1,
        ) as c_int
    }
}
/// # Safety
/// Poll records must be writable within `fdslen` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn __ppoll_chk(
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
    // SAFETY: fortify validated the record count; timeout and mask follow ppoll's contract.
    unsafe {
        let nanos = timeout_nanos(timeout);
        if nanos == -2 {
            return error(libc::EINVAL);
        }
        abi::libc_delivered(
            readiness::poll_core(
                fds.cast(),
                nfds as usize,
                nanos,
                mask.cast(),
                core::ptr::null_mut(),
            ),
            -1,
        ) as c_int
    }
}
