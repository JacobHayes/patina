//! Timer libc doors. Linux shares the raw models; Darwin refuses scheduled
//! signals until it has a virtual delivery model (never a host interval timer).
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use crate::thread::timers;
use core::ffi::{c_int, c_uint};

#[unsafe(no_mangle)]
extern "C" fn setitimer(
    which: c_int,
    new: *const libc::itimerval,
    old: *mut libc::itimerval,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        super::signal_result(timers::setitimer(which, new.cast(), old.cast()))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (which, new, old);
        crate::trap_fatal("Darwin setitimer is not modeled")
    }
}

#[unsafe(no_mangle)]
extern "C" fn getitimer(which: c_int, out: *mut libc::itimerval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        super::signal_result(timers::getitimer(which, out.cast()))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (which, out);
        crate::trap_fatal("Darwin getitimer is not modeled")
    }
}

#[unsafe(no_mangle)]
extern "C" fn alarm(seconds: c_uint) -> c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        super::signal_result(timers::alarm(seconds)) as c_uint
    }
    #[cfg(target_os = "macos")]
    {
        let _ = seconds;
        crate::trap_fatal("Darwin alarm is not modeled")
    }
}

#[unsafe(no_mangle)]
extern "C" fn ualarm(micros: c_uint, interval: c_uint) -> c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        crate::abi::libc_delivered(timers::ualarm(micros, interval), c_uint::MAX)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (micros, interval);
        crate::trap_fatal("Darwin ualarm is not modeled")
    }
}

#[cfg(target_os = "linux")]
mod linux;
