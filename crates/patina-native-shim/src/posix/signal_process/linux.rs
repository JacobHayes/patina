//! Linux libc signal layouts, diagnostics and process-descriptor adapters.
use super::{dispatch, process_trap};
use crate::thread::signals::{self, Action, Info};
use core::ffi::{c_char, c_int};
use core::ptr;

// Same libc synchronization contract as glibc's _sigintr.
static mut SIGINTR: u64 = 0;

unsafe fn clear_internal_signals(
    set: *const libc::sigset_t,
    copy: *mut libc::sigset_t,
) -> *const libc::sigset_t {
    if set.is_null() {
        return ptr::null();
    }
    let internal = (1u64 << 31) | (1u64 << 32);
    let word = unsafe { set.cast::<u64>().read_unaligned() };
    if word & internal == 0 {
        return set;
    }
    unsafe {
        ptr::copy_nonoverlapping(set, copy, 1);
        copy.cast::<u64>().write_unaligned(word & !internal);
    }
    copy
}

/// # Safety
/// act and old follow libc's optional action input/output contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(
    sig: c_int,
    act: *const libc::sigaction,
    old: *mut libc::sigaction,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if signals::patina_signal_reserved(sig) != 0 {
        return crate::posix::error(libc::EINVAL);
    }
    let mut prior = Action::default();
    let next = if act.is_null() {
        None
    } else {
        Some(unsafe {
            Action {
                handler: (*act).sa_sigaction,
                flags: (*act).sa_flags as u32 as u64,
                restorer: (*act).sa_restorer.map_or(0, |restorer| restorer as usize),
                mask: ptr::addr_of!((*act).sa_mask).cast::<u64>().read_unaligned(),
            }
        })
    };
    let rc = unsafe {
        signals::patina_signal_action_libc(
            sig,
            next.as_ref().map_or(ptr::null(), |next| next),
            &mut prior,
        )
    };
    if !old.is_null() && rc == 0 {
        unsafe {
            ptr::write_bytes(old, 0, 1);
            (*old).sa_sigaction = prior.handler;
            (*old).sa_flags = prior.flags as c_int;
            (*old).sa_restorer = if prior.restorer == 0 {
                None
            } else {
                Some(core::mem::transmute::<usize, extern "C" fn()>(
                    prior.restorer,
                ))
            };
            ptr::addr_of_mut!((*old).sa_mask)
                .cast::<u64>()
                .write_unaligned(prior.mask);
        }
    }
    crate::posix::signal_result(rc)
}

#[unsafe(no_mangle)]
pub extern "C" fn signal(sig: c_int, handler: libc::sighandler_t) -> libc::sighandler_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if handler == libc::SIG_ERR
        || !(1..=64).contains(&sig)
        || signals::patina_signal_reserved(sig) != 0
    {
        crate::posix::error(libc::EINVAL);
        return libc::SIG_ERR;
    }
    let bit = 1u64 << (sig - 1);
    let next = Action {
        handler,
        flags: if unsafe { SIGINTR } & bit != 0 {
            0
        } else {
            libc::SA_RESTART as u64
        },
        restorer: 0,
        mask: bit,
    };
    let mut old = Action::default();
    if crate::posix::signal_result(unsafe {
        signals::patina_signal_action_libc(sig, &next, &mut old)
    }) < 0
    {
        return libc::SIG_ERR;
    }
    old.handler
}

/// # Safety
/// set and old follow libc's optional signal-mask input/output contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const libc::sigset_t,
    old: *mut libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut copy = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let set = unsafe { clear_internal_signals(set, copy.as_mut_ptr()) };
    let rc = unsafe { signals::patina_signal_mask(how, set.cast(), old.cast(), size_of::<u64>()) };
    signals::deliver();
    (-rc) as c_int
}

/// # Safety
/// set and old follow libc's optional signal-mask input/output contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const libc::sigset_t,
    old: *mut libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut copy = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let set = unsafe { clear_internal_signals(set, copy.as_mut_ptr()) };
    crate::posix::signal_result(unsafe {
        signals::patina_signal_mask(how, set.cast(), old.cast(), size_of::<u64>())
    })
}

/// # Safety
/// set follows libc's output contract; only its first eight bytes are written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut libc::sigset_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::signal_result(unsafe {
        signals::patina_signal_pending(set.cast(), size_of::<u64>())
    })
}

const _: () = {
    assert!(size_of::<signals::Stack>() == size_of::<libc::stack_t>());
    assert!(
        core::mem::offset_of!(signals::Stack, base) == core::mem::offset_of!(libc::stack_t, ss_sp)
    );
    assert!(
        core::mem::offset_of!(signals::Stack, flags)
            == core::mem::offset_of!(libc::stack_t, ss_flags)
    );
    assert!(
        core::mem::offset_of!(signals::Stack, size)
            == core::mem::offset_of!(libc::stack_t, ss_size)
    );
};

/// # Safety
/// stack and old follow libc's alternate-stack input/output contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaltstack(
    stack: *const libc::stack_t,
    old: *mut libc::stack_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::signal_result(unsafe {
        signals::patina_signal_altstack(stack.cast(), old.cast())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn pause() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"pause");
    crate::posix::signal_result(unsafe {
        signals::patina_signal_wait(
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            size_of::<u64>(),
            signals::WaitMode::Pause,
        )
    })
}

/// # Safety
/// set follows libc's sigsuspend mask contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigsuspend(set: *const libc::sigset_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"sigsuspend");
    crate::posix::signal_result(unsafe {
        signals::patina_signal_wait(
            set.cast(),
            ptr::null_mut(),
            ptr::null(),
            size_of::<u64>(),
            signals::WaitMode::Suspend,
        )
    })
}

unsafe fn timedwait(
    set: *const libc::sigset_t,
    info: *mut libc::siginfo_t,
    timeout: *const libc::timespec,
) -> c_int {
    let rc = crate::posix::signal_result(unsafe {
        signals::patina_signal_wait(
            set.cast(),
            info.cast(),
            timeout.cast(),
            size_of::<u64>(),
            signals::WaitMode::Dequeue,
        )
    });
    if rc > 0 && !info.is_null() && unsafe { (*info).si_code } == libc::SI_TKILL {
        unsafe {
            (*info).si_code = libc::SI_USER;
        }
    }
    rc
}

/// # Safety
/// set, info and timeout follow libc's signal-wait contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigtimedwait(
    set: *const libc::sigset_t,
    info: *mut libc::siginfo_t,
    timeout: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"sigtimedwait");
    unsafe { timedwait(set, info, timeout) }
}
/// # Safety
/// set and info follow libc's signal-wait contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwaitinfo(
    set: *const libc::sigset_t,
    info: *mut libc::siginfo_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"sigwaitinfo");
    unsafe { timedwait(set, info, ptr::null()) }
}
/// # Safety
/// set follows libc's input mask contract; sig is a writable c_int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwait(set: *const libc::sigset_t, sig: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"sigwait");
    loop {
        let rc = unsafe {
            signals::patina_signal_wait(
                set.cast(),
                ptr::null_mut(),
                ptr::null(),
                size_of::<u64>(),
                signals::WaitMode::Dequeue,
            )
        };
        signals::deliver();
        if rc == -i64::from(libc::EINTR) {
            continue;
        }
        if rc < 0 {
            return (-rc) as c_int;
        }
        unsafe {
            sig.write(rc as c_int);
        }
        return 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sigqueue(pid: libc::pid_t, sig: c_int, value: libc::sigval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut info = Info { words: [0; 16] };
    info.words[0] = u64::from(sig as u32);
    info.words[1] = u64::from(libc::SI_QUEUE as u32);
    info.words[2] = u64::from(crate::patina_pid() as u32) | (u64::from(crate::patina_uid()) << 32);
    info.words[3] = value.sival_ptr as u64;
    unsafe {
        dispatch(
            libc::SYS_rt_sigqueueinfo,
            [pid as u64, sig as u64, ptr::addr_of!(info) as u64, 0, 0, 0],
        )
    }
}

fn description(sig: c_int) -> Option<&'static core::ffi::CStr> {
    const DESCRIPTIONS: [&core::ffi::CStr; 31] = [
        c"Hangup",
        c"Interrupt",
        c"Quit",
        c"Illegal instruction",
        c"Trace/breakpoint trap",
        c"Aborted",
        c"Bus error",
        c"Floating point exception",
        c"Killed",
        c"User defined signal 1",
        c"Segmentation fault",
        c"User defined signal 2",
        c"Broken pipe",
        c"Alarm clock",
        c"Terminated",
        c"Stack fault",
        c"Child exited",
        c"Continued",
        c"Stopped (signal)",
        c"Stopped",
        c"Stopped (tty input)",
        c"Stopped (tty output)",
        c"Urgent I/O condition",
        c"CPU time limit exceeded",
        c"File size limit exceeded",
        c"Virtual timer expired",
        c"Profiling timer expired",
        c"Window changed",
        c"I/O possible",
        c"Power failure",
        c"Bad system call",
    ];
    if !(1..=31).contains(&sig) {
        None
    } else {
        Some(DESCRIPTIONS[sig as usize - 1])
    }
}

fn append(out: &mut [c_char], mut at: usize, text: &[u8]) -> usize {
    for &byte in text {
        if at + 1 >= out.len() {
            break;
        }
        out[at] = byte as c_char;
        at += 1;
    }
    out[at] = 0;
    at
}
fn numbered(out: &mut [c_char], text: &[u8], number: c_int) {
    let mut digits = [0; 12];
    let mut count = 0;
    let mut value = i64::from(number);
    let negative = value < 0;
    if negative {
        value = -value;
    }
    loop {
        digits[count] = (i64::from(b'0') + value % 10) as c_char;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut at = append(out, 0, text);
    if negative {
        at = append(out, at, b"-");
    }
    while count > 0 && at + 1 < out.len() {
        count -= 1;
        out[at] = digits[count];
        at += 1;
    }
    out[at] = 0;
}
thread_local! {
    static SIGNAL_BUFFER: core::cell::UnsafeCell<[c_char; 32]> = const { core::cell::UnsafeCell::new([0; 32]) };
}

#[unsafe(no_mangle)]
pub extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Some(description) = description(sig) {
        return description.as_ptr().cast_mut();
    }
    SIGNAL_BUFFER.with(|buffer| unsafe {
        let out = &mut *buffer.get();
        if (34..=64).contains(&sig) {
            numbered(out, b"Real-time signal ", sig - 34);
        } else {
            numbered(out, b"Unknown signal ", sig);
        }
        out.as_mut_ptr()
    })
}

/// # Safety
/// prefix is null or a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psignal(sig: c_int, prefix: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut unknown = [0; 32];
    let description = if let Some(description) = description(sig) {
        description.as_ptr()
    } else {
        numbered(&mut unknown, b"Unknown signal ", sig);
        unknown.as_ptr()
    };
    let fd = super::super::stdio::sentinel_fd(unsafe { super::super::stdio::STDERR });
    if fd < 0 {
        super::super::stdio::trap(c"psignal")
    }
    let mut parts = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; 4];
    let mut count = 0;
    if !prefix.is_null() && unsafe { prefix.read() } != 0 {
        parts[count] = libc::iovec {
            iov_base: prefix.cast_mut().cast(),
            iov_len: unsafe { libc::strlen(prefix) },
        };
        count += 1;
        parts[count] = libc::iovec {
            iov_base: c": ".as_ptr().cast_mut().cast(),
            iov_len: 2,
        };
        count += 1;
    }
    parts[count] = libc::iovec {
        iov_base: description.cast_mut().cast(),
        iov_len: unsafe { libc::strlen(description) },
    };
    count += 1;
    parts[count] = libc::iovec {
        iov_base: c"\n".as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    count += 1;
    unsafe {
        crate::iov::patina_writev(fd, parts.as_ptr().cast(), count as i64, 0);
    }
}

// abort deliberately remains in C: patina_abort observes caller ownership
// before entering its own guard; another first-statement guard changes guest
// panic=abort into an internal panic and loses healthy trace finalization.

#[unsafe(no_mangle)]
pub extern "C" fn pthread_kill(thread: libc::pthread_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    signals::patina_pthread_kill(thread as usize, sig)
}
#[unsafe(no_mangle)]
pub extern "C" fn killpg(group: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if group < 0 {
        return crate::posix::error(libc::EINVAL);
    }
    unsafe {
        dispatch(
            libc::SYS_kill,
            [(-(i64::from(group))) as u64, sig as u64, 0, 0, 0, 0],
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn siginterrupt(sig: c_int, interrupt: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if signals::patina_signal_reserved(sig) != 0 {
        return crate::posix::error(libc::EINVAL);
    }
    let mut act = Action::default();
    if crate::posix::signal_result(unsafe {
        signals::patina_signal_action_libc(sig, ptr::null(), &mut act)
    }) < 0
    {
        return -1;
    }
    let bit = 1u64 << (sig - 1);
    unsafe {
        if interrupt != 0 {
            SIGINTR |= bit;
            act.flags &= !(libc::SA_RESTART as u64);
        } else {
            SIGINTR &= !bit;
            act.flags |= libc::SA_RESTART as u64;
        }
    }
    crate::posix::signal_result(unsafe {
        signals::patina_signal_action_libc(sig, &act, ptr::null_mut())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tgkill(tgid: libc::pid_t, tid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_tgkill,
            [tgid as u64, tid as u64, sig as u64, 0, 0, 0],
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn tkill(tid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { dispatch(libc::SYS_tkill, [tid as u64, sig as u64, 0, 0, 0, 0]) }
}

#[unsafe(no_mangle)]
pub extern "C" fn pidfd_open(pid: libc::pid_t, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_pidfd_open,
            [pid as i64 as u64, flags as u64, 0, 0, 0, 0],
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_pidfd_getfd,
            [
                pidfd as i64 as u64,
                targetfd as i64 as u64,
                flags as u64,
                0,
                0,
                0,
            ],
        )
    }
}
/// # Safety
/// info is null or a readable siginfo_t.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pidfd_send_signal(
    pidfd: c_int,
    sig: c_int,
    info: *mut libc::siginfo_t,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_pidfd_send_signal,
            [
                pidfd as i64 as u64,
                sig as i64 as u64,
                info as u64,
                flags as u64,
                0,
                0,
            ],
        )
    }
}
/// # Safety
/// iov follows libc's vlen-element input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_madvise(
    pidfd: c_int,
    iov: *const libc::iovec,
    vlen: usize,
    advice: c_int,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_process_madvise,
            [
                pidfd as i64 as u64,
                iov as u64,
                vlen as u64,
                advice as i64 as u64,
                flags as u64,
                0,
            ],
        ) as isize
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn process_mrelease(pidfd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_process_mrelease,
            [pidfd as i64 as u64, flags as u64, 0, 0, 0, 0],
        )
    }
}
/// # Safety
/// local and remote follow libc's iovec input contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_vm_readv(
    pid: libc::pid_t,
    local: *const libc::iovec,
    liovcnt: libc::c_ulong,
    remote: *const libc::iovec,
    riovcnt: libc::c_ulong,
    flags: libc::c_ulong,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_process_vm_readv,
            [
                pid as i64 as u64,
                local as u64,
                liovcnt,
                remote as u64,
                riovcnt,
                flags,
            ],
        ) as isize
    }
}
/// # Safety
/// local and remote follow libc's iovec input contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_vm_writev(
    pid: libc::pid_t,
    local: *const libc::iovec,
    liovcnt: libc::c_ulong,
    remote: *const libc::iovec,
    riovcnt: libc::c_ulong,
    flags: libc::c_ulong,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        dispatch(
            libc::SYS_process_vm_writev,
            [
                pid as i64 as u64,
                local as u64,
                liovcnt,
                remote as u64,
                riovcnt,
                flags,
            ],
        ) as isize
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pidfd_getpid(_pidfd: c_int) -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"pidfd_getpid")
}
/// # Safety
/// Pointers follow libc's pidfd_spawnp argument contracts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pidfd_spawnp(
    _pidfd: *mut c_int,
    _file: *const c_char,
    _file_actions: *const libc::posix_spawn_file_actions_t,
    _attrp: *const libc::posix_spawnattr_t,
    _argv: *const *mut c_char,
    _envp: *const *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"pidfd_spawnp")
}
/// # Safety
/// acts and path follow libc's spawn file actions contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    _acts: *mut libc::posix_spawn_file_actions_t,
    _path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_addchdir_np")
}
/// # Safety
/// acts and path follow libc's spawn file actions contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir(
    _acts: *mut libc::posix_spawn_file_actions_t,
    _path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"posix_spawn_file_actions_addchdir")
}
/// # Safety
/// infop follows libc's waitid output contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitid(
    idtype: libc::idtype_t,
    id: libc::id_t,
    infop: *mut libc::siginfo_t,
    options: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"waitid");
    unsafe {
        dispatch(
            libc::SYS_waitid,
            [idtype as u64, id as u64, infop as u64, options as u64, 0, 0],
        )
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn __libc_current_sigrtmax() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    64
}
/// # Safety
/// mask follows libc's signalfd input mask contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signalfd(fd: c_int, mask: *const libc::sigset_t, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::signal_result(unsafe {
        signals::fd::patina_signalfd(fd, mask.cast(), size_of::<u64>(), flags)
    })
}

core::arch::global_asm!(
    ".globl patina_route_sigaction",
    ".hidden patina_route_sigaction",
    ".set patina_route_sigaction, sigaction",
    ".globl patina_route_signal",
    ".hidden patina_route_signal",
    ".set patina_route_signal, signal",
    ".globl patina_route_pthread_sigmask",
    ".hidden patina_route_pthread_sigmask",
    ".set patina_route_pthread_sigmask, pthread_sigmask",
    ".globl patina_route_sigprocmask",
    ".hidden patina_route_sigprocmask",
    ".set patina_route_sigprocmask, sigprocmask",
    ".globl patina_route_sigpending",
    ".hidden patina_route_sigpending",
    ".set patina_route_sigpending, sigpending",
    ".globl patina_route_sigaltstack",
    ".hidden patina_route_sigaltstack",
    ".set patina_route_sigaltstack, sigaltstack",
    ".globl patina_route_pause",
    ".hidden patina_route_pause",
    ".set patina_route_pause, pause",
    ".globl patina_route_sigsuspend",
    ".hidden patina_route_sigsuspend",
    ".set patina_route_sigsuspend, sigsuspend",
    ".globl patina_route_sigtimedwait",
    ".hidden patina_route_sigtimedwait",
    ".set patina_route_sigtimedwait, sigtimedwait",
    ".globl patina_route_sigwaitinfo",
    ".hidden patina_route_sigwaitinfo",
    ".set patina_route_sigwaitinfo, sigwaitinfo",
    ".globl patina_route_sigwait",
    ".hidden patina_route_sigwait",
    ".set patina_route_sigwait, sigwait",
    ".globl patina_route_sigqueue",
    ".hidden patina_route_sigqueue",
    ".set patina_route_sigqueue, sigqueue",
    ".globl patina_route_strsignal",
    ".hidden patina_route_strsignal",
    ".set patina_route_strsignal, strsignal",
    ".globl patina_route_psignal",
    ".hidden patina_route_psignal",
    ".set patina_route_psignal, psignal",
    ".globl patina_route_pthread_kill",
    ".hidden patina_route_pthread_kill",
    ".set patina_route_pthread_kill, pthread_kill",
    ".globl patina_route_killpg",
    ".hidden patina_route_killpg",
    ".set patina_route_killpg, killpg",
    ".globl patina_route_siginterrupt",
    ".hidden patina_route_siginterrupt",
    ".set patina_route_siginterrupt, siginterrupt",
    ".globl patina_route_tgkill",
    ".hidden patina_route_tgkill",
    ".set patina_route_tgkill, tgkill",
    ".globl patina_route_tkill",
    ".hidden patina_route_tkill",
    ".set patina_route_tkill, tkill",
    ".globl patina_route_pidfd_open",
    ".hidden patina_route_pidfd_open",
    ".set patina_route_pidfd_open, pidfd_open",
    ".globl patina_route_pidfd_getfd",
    ".hidden patina_route_pidfd_getfd",
    ".set patina_route_pidfd_getfd, pidfd_getfd",
    ".globl patina_route_pidfd_send_signal",
    ".hidden patina_route_pidfd_send_signal",
    ".set patina_route_pidfd_send_signal, pidfd_send_signal",
    ".globl patina_route_process_madvise",
    ".hidden patina_route_process_madvise",
    ".set patina_route_process_madvise, process_madvise",
    ".globl patina_route_process_mrelease",
    ".hidden patina_route_process_mrelease",
    ".set patina_route_process_mrelease, process_mrelease",
    ".globl patina_route_process_vm_readv",
    ".hidden patina_route_process_vm_readv",
    ".set patina_route_process_vm_readv, process_vm_readv",
    ".globl patina_route_process_vm_writev",
    ".hidden patina_route_process_vm_writev",
    ".set patina_route_process_vm_writev, process_vm_writev",
    ".globl patina_route_pidfd_getpid",
    ".hidden patina_route_pidfd_getpid",
    ".set patina_route_pidfd_getpid, pidfd_getpid",
    ".globl patina_route_pidfd_spawnp",
    ".hidden patina_route_pidfd_spawnp",
    ".set patina_route_pidfd_spawnp, pidfd_spawnp",
    ".globl patina_route_posix_spawn_file_actions_addchdir_np",
    ".hidden patina_route_posix_spawn_file_actions_addchdir_np",
    ".set patina_route_posix_spawn_file_actions_addchdir_np, posix_spawn_file_actions_addchdir_np",
    ".globl patina_route_posix_spawn_file_actions_addchdir",
    ".hidden patina_route_posix_spawn_file_actions_addchdir",
    ".set patina_route_posix_spawn_file_actions_addchdir, posix_spawn_file_actions_addchdir",
    ".globl patina_route_waitid",
    ".hidden patina_route_waitid",
    ".set patina_route_waitid, waitid",
    ".globl patina_route___libc_current_sigrtmax",
    ".hidden patina_route___libc_current_sigrtmax",
    ".set patina_route___libc_current_sigrtmax, __libc_current_sigrtmax",
    ".globl patina_route_signalfd",
    ".hidden patina_route_signalfd",
    ".set patina_route_signalfd, signalfd",
);
