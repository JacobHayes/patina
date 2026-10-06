//! Darwin kevent adapters; allocation remains owned by libc.
use crate::posix::{error, model_result};
use crate::thread::kqueue;
use core::ffi::c_int;

// Patina's neutral event is the native kevent layout. Existing reactor code
// writes this layout; these assertions replace readiness.c's header checks.
const _: () = {
    assert!(size_of::<libc::kevent>() == 32);
    assert!(core::mem::offset_of!(libc::kevent, ident) == 0);
    assert!(core::mem::offset_of!(libc::kevent, filter) == 8);
    assert!(core::mem::offset_of!(libc::kevent, flags) == 10);
    assert!(core::mem::offset_of!(libc::kevent, fflags) == 12);
    assert!(core::mem::offset_of!(libc::kevent, data) == 16);
    assert!(core::mem::offset_of!(libc::kevent, udata) == 24);
};
#[unsafe(no_mangle)]
pub extern "C" fn kqueue() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(kqueue::patina_kqueue())
}
unsafe fn mode(timeout: *const libc::timespec) -> (c_int, u64) {
    unsafe {
        if timeout.is_null() {
            return (1, 0);
        }
        if (*timeout).tv_sec == 0 && (*timeout).tv_nsec == 0 {
            return (0, 0);
        }
        (
            2,
            ((*timeout).tv_sec as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add((*timeout).tv_nsec as u64),
        )
    }
}
/// # Safety
/// Changelist, eventlist and timeout follow kevent's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kevent(
    kq: c_int,
    changelist: *const libc::kevent,
    nchanges: c_int,
    eventlist: *mut libc::kevent,
    nevents: c_int,
    timeout: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if crate::patina_fd_kind(kq) != 11 {
            return error(libc::EBADF);
        }
        if (nchanges > 0 && changelist.is_null())
            || (!timeout.is_null() && ((*timeout).tv_sec < 0 || (*timeout).tv_nsec < 0))
        {
            return error(libc::EINVAL);
        }
        let mut nout = 0;
        for index in 0..nchanges {
            let change = changelist.add(index as usize);
            let rc = kqueue::patina_kqueue_apply(
                kq,
                (*change).ident as u64,
                (*change).filter,
                (*change).flags,
                (*change).fflags,
                (*change).data as i64,
                (*change).udata as usize,
            );
            if (*change).flags & libc::EV_RECEIPT != 0 || rc != 0 {
                if !eventlist.is_null() && nout < nevents {
                    // Buffers may alias. Capture identity before overwriting.
                    let ident = (*change).ident;
                    let filter = (*change).filter;
                    let udata = (*change).udata;
                    let event = eventlist.add(nout as usize);
                    nout += 1;
                    (*event).ident = ident;
                    (*event).filter = filter;
                    (*event).flags = libc::EV_ERROR;
                    (*event).fflags = 0;
                    (*event).data = rc as libc::intptr_t;
                    (*event).udata = udata;
                } else if rc != 0 {
                    return error(rc);
                }
            }
        }
        if nout > 0 {
            return nout;
        }
        let (mode, nanos) = mode(timeout);
        model_result(kqueue::patina_kevent_gather(
            kq,
            eventlist.cast(),
            nevents.max(0),
            mode,
            nanos,
        ))
    }
}
/// # Safety
/// Changelist, eventlist and timeout follow kevent64's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kevent64(
    kq: c_int,
    changelist: *const libc::kevent64_s,
    nchanges: c_int,
    eventlist: *mut libc::kevent64_s,
    nevents: c_int,
    _flags: libc::c_uint,
    timeout: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if crate::patina_fd_kind(kq) != 11 {
            return error(libc::EBADF);
        }
        if (nchanges > 0 && changelist.is_null())
            || (!timeout.is_null() && ((*timeout).tv_sec < 0 || (*timeout).tv_nsec < 0))
        {
            return error(libc::EINVAL);
        }
        let mut nout = 0;
        for index in 0..nchanges {
            let change = changelist.add(index as usize);
            let rc = kqueue::patina_kqueue_apply(
                kq,
                (*change).ident,
                (*change).filter,
                (*change).flags,
                (*change).fflags,
                (*change).data,
                (*change).udata as usize,
            );
            if (*change).flags & libc::EV_RECEIPT != 0 || rc != 0 {
                if !eventlist.is_null() && nout < nevents {
                    let ident = (*change).ident;
                    let filter = (*change).filter;
                    let udata = (*change).udata;
                    let event = eventlist.add(nout as usize);
                    nout += 1;
                    (*event).ident = ident;
                    (*event).filter = filter;
                    (*event).flags = libc::EV_ERROR;
                    (*event).fflags = 0;
                    (*event).data = i64::from(rc);
                    (*event).udata = udata;
                    (*event).ext = [0; 2];
                } else if rc != 0 {
                    return error(rc);
                }
            }
        }
        if nout > 0 {
            return nout;
        }
        let (mode, nanos) = mode(timeout);
        let capacity = nevents.max(0);
        let scratch = if capacity > 0 {
            libc::calloc(capacity as usize, size_of::<libc::kevent>()).cast::<libc::kevent>()
        } else {
            core::ptr::null_mut()
        };
        if capacity > 0 && scratch.is_null() {
            return error(libc::ENOMEM);
        }
        let count = kqueue::patina_kevent_gather(kq, scratch.cast(), capacity, mode, nanos);
        if count < 0 {
            libc::free(scratch.cast());
            return error(crate::patina_errno());
        }
        for index in 0..count as usize {
            let event = eventlist.add(index);
            let source = scratch.add(index);
            (*event).ident = (*source).ident as u64;
            (*event).filter = (*source).filter;
            (*event).flags = (*source).flags;
            (*event).fflags = (*source).fflags;
            (*event).data = (*source).data as i64;
            (*event).udata = (*source).udata as u64;
            (*event).ext = [0; 2];
        }
        libc::free(scratch.cast());
        count
    }
}
