//! Linux libc signal layouts, diagnostics and process-descriptor adapters.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::process_trap;
use crate::sud::Word;
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
    // SAFETY: callers supply a readable sigset_t; unaligned access matches its word representation.
    let word = unsafe { set.cast::<u64>().read_unaligned() };
    if word & internal == 0 {
        return set;
    }
    // SAFETY: callers supply readable `set` and writable scratch storage of one sigset_t.
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
        // SAFETY: the unsafe entry contract makes a non-null `act` readable for this call.
        Some(unsafe {
            Action {
                handler: (*act).sa_sigaction,
                flags: (*act).sa_flags as u32 as u64,
                restorer: (*act).sa_restorer.map_or(0, |restorer| restorer as usize),
                mask: ptr::addr_of!((*act).sa_mask).cast::<u64>().read_unaligned(),
            }
        })
    };
    // SAFETY: `next` is either null or a live local Action; `prior` is writable local storage.
    let rc = unsafe {
        signals::patina_signal_action_libc(
            sig,
            next.as_ref().map_or(ptr::null(), |next| next),
            &mut prior,
        )
    };
    if !old.is_null() && rc == 0 {
        // SAFETY: the unsafe entry contract makes non-null `old` writable for this call.
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
        // SAFETY: guest entries are serialized by the deterministic task baton while `_sigintr` is accessed.
        flags: if unsafe { SIGINTR } & bit != 0 {
            0
        } else {
            libc::SA_RESTART as u64
        },
        restorer: 0,
        mask: bit,
    };
    let mut old = Action::default();
    // SAFETY: both Action pointers refer to live local values for this synchronous model call.
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
    // SAFETY: the unsafe entry contract supplies a readable `set`; `copy` is writable scratch storage.
    let set = unsafe { clear_internal_signals(set, copy.as_mut_ptr()) };
    // SAFETY: the unsafe entry contract covers `set` and `old`, and the call reads/writes at most one word.
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
    // SAFETY: the unsafe entry contract supplies a readable `set`; `copy` is writable scratch storage.
    let set = unsafe { clear_internal_signals(set, copy.as_mut_ptr()) };
    // SAFETY: the unsafe entry contract covers `set` and `old`, and the call reads/writes at most one word.
    crate::posix::signal_result(unsafe {
        signals::patina_signal_mask(how, set.cast(), old.cast(), size_of::<u64>())
    })
}

/// # Safety
/// set follows libc's output contract; only its first eight bytes are written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut libc::sigset_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the unsafe entry contract supplies writable `set` storage for one word.
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
    // SAFETY: the unsafe entry contract covers optional input and output stack pointers.
    crate::posix::signal_result(unsafe {
        signals::patina_signal_altstack(stack.cast(), old.cast())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn pause() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"pause");
    // SAFETY: pause passes null for every pointer operand to the signal wait model.
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
    // SAFETY: the unsafe entry contract supplies the readable mask when `set` is non-null.
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
    // SAFETY: this unsafe helper's caller supplies the optional signal set, info, and timeout buffers.
    let rc = crate::posix::signal_result(unsafe {
        signals::patina_signal_wait(
            set.cast(),
            info.cast(),
            timeout.cast(),
            size_of::<u64>(),
            signals::WaitMode::Dequeue,
        )
    });
    // SAFETY: a positive result fills non-null `info` under the helper's caller contract.
    if rc > 0 && !info.is_null() && unsafe { (*info).si_code } == libc::SI_TKILL {
        // SAFETY: the same successful dequeue grants writable access to the returned siginfo_t.
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
    // SAFETY: this entry's unsafe contract satisfies timedwait's pointer requirements.
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
    // SAFETY: this entry's unsafe contract satisfies timedwait's set/info requirements; timeout is null.
    unsafe { timedwait(set, info, ptr::null()) }
}
/// # Safety
/// set follows libc's input mask contract; sig is a writable c_int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwait(set: *const libc::sigset_t, sig: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::posix::cancel(c"sigwait");
    loop {
        // SAFETY: the unsafe entry contract supplies the readable mask; output pointers are null here.
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
        // SAFETY: the unsafe entry contract supplies writable storage for the selected signal number.
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
    // SAFETY: `info` is a live local buffer for the synchronous syscall dispatch.
    unsafe {
        crate::sud::forward(
            libc::SYS_rt_sigqueueinfo,
            &[pid.word(), sig.word(), ptr::addr_of!(info).word()],
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
    SIGNAL_BUFFER.with(|buffer| {
        // SAFETY: the thread-local closure gives exclusive access to this thread's signal buffer.
        unsafe {
            let out = &mut *buffer.get();
            if (34..=64).contains(&sig) {
                numbered(out, b"Real-time signal ", sig - 34);
            } else {
                numbered(out, b"Unknown signal ", sig);
            }
            out.as_mut_ptr()
        }
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
    // SAFETY: STDERR is the initialized thread-local sentinel stream slot used by this door.
    let fd = super::super::stdio::sentinel_fd(unsafe { super::super::stdio::STDERR });
    if fd < 0 {
        super::super::stdio::trap(c"psignal")
    }
    let mut parts = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; 4];
    let mut count = 0;
    // SAFETY: the unsafe entry contract makes a non-null prefix readable as a C string.
    if !prefix.is_null() && unsafe { prefix.read() } != 0 {
        parts[count] = libc::iovec {
            iov_base: prefix.cast_mut().cast(),
            // SAFETY: the unsafe entry contract makes the prefix NUL-terminated and readable.
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
        // SAFETY: description is a static or local NUL-terminated C string built above.
        iov_len: unsafe { libc::strlen(description) },
    };
    count += 1;
    parts[count] = libc::iovec {
        iov_base: c"\n".as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    count += 1;
    // SAFETY: each iovec points to live readable bytes and `count` is within the four-element array.
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
    // SAFETY: killpg forwards scalar identifiers only; the negated group keeps the prior u64 encoding.
    unsafe {
        crate::sud::forward(
            libc::SYS_kill,
            &[((-(i64::from(group))) as u64).word(), sig.word()],
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
    // SAFETY: null input plus a live local output Action satisfy the model's pointer contract.
    if crate::posix::signal_result(unsafe {
        signals::patina_signal_action_libc(sig, ptr::null(), &mut act)
    }) < 0
    {
        return -1;
    }
    let bit = 1u64 << (sig - 1);
    // SAFETY: signal entries are serialized by the deterministic task baton while `_sigintr` is accessed.
    unsafe {
        if interrupt != 0 {
            SIGINTR |= bit;
            act.flags &= !(libc::SA_RESTART as u64);
        } else {
            SIGINTR &= !bit;
            act.flags |= libc::SA_RESTART as u64;
        }
    }
    // SAFETY: the live local Action is readable for the update; the output pointer is null.
    crate::posix::signal_result(unsafe {
        signals::patina_signal_action_libc(sig, &act, ptr::null_mut())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tgkill(tgid: libc::pid_t, tid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: tgkill forwards only scalar process, thread, and signal numbers.
    unsafe { crate::sud::forward(libc::SYS_tgkill, &[tgid.word(), tid.word(), sig.word()]) }
}
#[unsafe(no_mangle)]
pub extern "C" fn tkill(tid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: tkill forwards only scalar thread and signal numbers.
    unsafe { crate::sud::forward(libc::SYS_tkill, &[tid.word(), sig.word()]) }
}

#[unsafe(no_mangle)]
pub extern "C" fn pidfd_open(pid: libc::pid_t, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: pidfd_open forwards only scalar arguments.
    unsafe { crate::sud::forward(libc::SYS_pidfd_open, &[pid.word(), flags.word()]) }
}
#[unsafe(no_mangle)]
pub extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: pidfd_getfd forwards only scalar descriptor and flag values.
    unsafe {
        crate::sud::forward(
            libc::SYS_pidfd_getfd,
            &[pidfd.word(), targetfd.word(), flags.word()],
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
    // SAFETY: `info` obeys this unsafe entry's readable siginfo contract when the row reads it.
    unsafe {
        crate::sud::forward(
            libc::SYS_pidfd_send_signal,
            &[pidfd.word(), sig.word(), info.word(), flags.word()],
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
    // SAFETY: `iov` obeys this unsafe entry's vlen-element input contract when the row reads it.
    unsafe {
        crate::sud::forward(
            libc::SYS_process_madvise,
            &[
                pidfd.word(),
                iov.word(),
                vlen.word(),
                advice.word(),
                flags.word(),
            ],
        ) as isize
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn process_mrelease(pidfd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: process_mrelease forwards only scalar descriptor and flag values.
    unsafe { crate::sud::forward(libc::SYS_process_mrelease, &[pidfd.word(), flags.word()]) }
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
    // SAFETY: the unsafe entry contract supplies both iovec arrays for their element counts.
    unsafe {
        crate::sud::forward(
            libc::SYS_process_vm_readv,
            &[
                pid.word(),
                local.word(),
                liovcnt.word(),
                remote.word(),
                riovcnt.word(),
                flags.word(),
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
    // SAFETY: the unsafe entry contract supplies both iovec arrays for their element counts.
    unsafe {
        crate::sud::forward(
            libc::SYS_process_vm_writev,
            &[
                pid.word(),
                local.word(),
                liovcnt.word(),
                remote.word(),
                riovcnt.word(),
                flags.word(),
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
    // SAFETY: the unsafe entry contract supplies a writable siginfo output when non-null.
    unsafe {
        crate::sud::forward(
            libc::SYS_waitid,
            &[idtype.word(), id.word(), infop.word(), options.word()],
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
    // SAFETY: the unsafe entry contract supplies a readable mask when the model reads it.
    crate::posix::signal_result(unsafe {
        signals::fd::patina_signalfd(fd, mask.cast(), size_of::<u64>(), flags)
    })
}
