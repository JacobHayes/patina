//! Linux libc timer_t adaptation and static-archive spellings.
use crate::posix::signal_result;
use crate::thread::timers;
use core::ffi::c_int;

const _: () = {
    assert!(core::mem::size_of::<libc::itimerval>() == core::mem::size_of::<timers::Itimerval>());
    assert!(core::mem::size_of::<libc::itimerspec>() == core::mem::size_of::<timers::Itimerspec>());
    assert!(core::mem::size_of::<libc::sigevent>() == core::mem::size_of::<timers::Sigevent>());
    assert!(core::mem::size_of::<libc::timer_t>() == core::mem::size_of::<usize>());
};

fn timer_id(timer: libc::timer_t) -> Result<i32, crate::abi::Errno> {
    i32::try_from(timer as usize).map_err(|_| crate::abi::Errno::new(crate::EINVAL))
}
fn timer_result(timer: libc::timer_t, operation: impl FnOnce(i32) -> i64) -> c_int {
    crate::abi::libc_delivered(
        timer_id(timer).and_then(|id| crate::abi::from_neg(operation(id))),
        -1,
    ) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn timer_create(
    clock: libc::clockid_t,
    event: *const libc::sigevent,
    out: *mut libc::timer_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::libc_timer_create(clock, event.cast(), out as usize))
}

#[unsafe(no_mangle)]
extern "C" fn timer_settime(
    timer: libc::timer_t,
    flags: c_int,
    new: *const libc::itimerspec,
    old: *mut libc::itimerspec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| {
        timers::timer_settime(id, flags, new.cast(), old.cast())
    })
}

#[unsafe(no_mangle)]
extern "C" fn timer_gettime(timer: libc::timer_t, out: *mut libc::itimerspec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| timers::timer_gettime(id, out.cast()))
}

#[unsafe(no_mangle)]
extern "C" fn timer_delete(timer: libc::timer_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, timers::timer_delete)
}

#[unsafe(no_mangle)]
extern "C" fn timer_getoverrun(timer: libc::timer_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, timers::timer_getoverrun)
}

#[unsafe(no_mangle)]
extern "C" fn timerfd_create(clock: libc::clockid_t, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::timerfd_create(clock, flags))
}

#[unsafe(no_mangle)]
extern "C" fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new: *const libc::itimerspec,
    old: *mut libc::itimerspec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::timerfd_settime(
        fd,
        flags,
        new as usize,
        old as usize,
    ))
}

#[unsafe(no_mangle)]
extern "C" fn timerfd_gettime(fd: c_int, out: *mut libc::itimerspec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::timerfd_gettime(fd, out as usize))
}

#[unsafe(no_mangle)]
extern "C" fn __setitimer(
    which: c_int,
    new: *const libc::itimerval,
    old: *mut libc::itimerval,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::setitimer(which, new.cast(), old.cast()))
}

#[unsafe(no_mangle)]
extern "C" fn __getitimer(which: c_int, out: *mut libc::itimerval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::getitimer(which, out.cast()))
}

#[unsafe(no_mangle)]
extern "C" fn __timerfd_settime(
    fd: c_int,
    flags: c_int,
    new: *const libc::itimerspec,
    old: *mut libc::itimerspec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::timerfd_settime(
        fd,
        flags,
        new as usize,
        old as usize,
    ))
}

#[unsafe(no_mangle)]
extern "C" fn __timerfd_gettime(fd: c_int, out: *mut libc::itimerspec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::timerfd_gettime(fd, out as usize))
}

#[unsafe(no_mangle)]
extern "C" fn ___timer_create(
    clock: libc::clockid_t,
    event: *const libc::sigevent,
    out: *mut libc::timer_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signal_result(timers::libc_timer_create(clock, event.cast(), out as usize))
}

#[unsafe(no_mangle)]
extern "C" fn ___timer_delete(timer: libc::timer_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, timers::timer_delete)
}

#[unsafe(no_mangle)]
extern "C" fn ___timer_getoverrun(timer: libc::timer_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, timers::timer_getoverrun)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn ___timer_settime_new(
    timer: libc::timer_t,
    flags: c_int,
    new: *const libc::itimerspec,
    old: *mut libc::itimerspec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| {
        timers::timer_settime(id, flags, new.cast(), old.cast())
    })
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn ___timer_gettime_new(timer: libc::timer_t, out: *mut libc::itimerspec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| timers::timer_gettime(id, out.cast()))
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
extern "C" fn ___timer_settime64(
    timer: libc::timer_t,
    flags: c_int,
    new: *const libc::itimerspec,
    old: *mut libc::itimerspec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| {
        timers::timer_settime(id, flags, new.cast(), old.cast())
    })
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
extern "C" fn ___timer_gettime64(timer: libc::timer_t, out: *mut libc::itimerspec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    timer_result(timer, |id| timers::timer_gettime(id, out.cast()))
}
