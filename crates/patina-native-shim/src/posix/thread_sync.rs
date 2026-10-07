//! pthread lifecycle and synchronization adapters over the deterministic
//! scheduler (`src/thread/`), and pthread_once's state. pthread objects are
//! identified by their storage address; the created pthread_t is the real host
//! handle, so the uninterposed pthread_self, pthread_equal and *_np helpers
//! remain consistent. pthread returns error numbers directly, not via errno.
//!
//! Linux keeps the frames glibc's forced unwind crosses in
//! `c/posix/thread_sync.c`: the thread body, pthread_exit, the acting
//! cancellation doors and pthread_once, which calls the once helpers here.
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

/// pthread_atfork: the fork/exec process surface is a deterministic-runtime
/// non-goal (denied by the audit, and a managed guest never forks), so a
/// registered handler could never run. Rust std and libc startup still
/// reference this symbol, and as a host import it would taint the run's
/// determinism claim: ignore the registration and succeed.
#[unsafe(no_mangle)]
pub extern "C" fn pthread_atfork(
    _prepare: Option<extern "C" fn()>,
    _parent: Option<extern "C" fn()>,
    _child: Option<extern "C" fn()>,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}

/// Every guest/std thread creation, through the scheduler. The shim reaches
/// the real host creator through a private vehicle (`spawn_host_thread`), so
/// it never recurses here; glibc ships `__wrap_pthread_create` in libgcc's
/// split-stack support on x86, so the shim must not use `--wrap` instead.
///
/// # Safety
/// As pthread_create's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_thread_create(thread.cast(), attr.cast(), start_routine, arg) }
}

/// # Safety
/// As pthread_join's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_thread_join(thread as *mut c_void, retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_thread_detach(thread as *mut c_void) }
}

/// macOS: thread exit is not modeled and fails closed by name.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_thread_exit(retval) }
}

/// macOS: cancellation is not modeled, and a cancel fails closed.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub extern "C" fn pthread_cancel(_thread: libc::pthread_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    libc::ENOSYS
}

/// A thread's name (`comm`) is modeled per thread: the executable's by
/// default, inherited by a new thread, and changed by these and
/// `prctl(PR_SET_NAME)`.
///
/// # Safety
/// As pthread_getname_np's.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_getname_np(
    thread: libc::pthread_t,
    name: *mut core::ffi::c_char,
    len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::thread::sched::patina_thread_getname(thread as usize, name, len) }
}

/// # Safety
/// As pthread_setname_np's.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setname_np(
    thread: libc::pthread_t,
    name: *const core::ffi::c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::thread::sched::patina_thread_setname(thread as usize, name) }
}

/// # Safety
/// As pthread_mutex_init's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_mutex_init(mutex.cast(), attr.cast()) }
}

/// # Safety
/// As pthread_mutex_lock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_mutex_lock(mutex.cast()) }
}

/// # Safety
/// As pthread_mutex_trylock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_mutex_trylock(mutex.cast()) }
}

/// # Safety
/// As pthread_mutex_unlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_mutex_unlock(mutex.cast()) }
}

/// # Safety
/// As pthread_mutex_destroy's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_mutex_destroy(mutex.cast()) }
}

/// # Safety
/// As pthread_cond_init's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut libc::pthread_cond_t,
    attr: *const libc::pthread_condattr_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_cond_init(cond.cast(), attr.cast()) }
}

/// # Safety
/// As pthread_cond_wait's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"pthread_cond_wait");
    unsafe { crate::patina_cond_wait(cond.cast(), mutex.cast()) }
}

/// # Safety
/// As pthread_cond_timedwait's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    abstime: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"pthread_cond_timedwait");
    unsafe { crate::patina_cond_timedwait(cond.cast(), mutex.cast(), abstime.cast()) }
}

/// Rust std lowers `Condvar::wait_timeout` on Darwin to this relative-deadline
/// variant: the deadline against the interposed virtual CLOCK_REALTIME, then
/// the ordinary timed wait, so timeouts stay on the virtual-clock timer queue.
///
/// # Safety
/// As pthread_cond_timedwait_relative_np's.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_timedwait_relative_np(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    reltime: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    const NANOS: u64 = 1_000_000_000;
    if reltime.is_null() {
        return libc::EINVAL;
    }
    let reltime = unsafe { reltime.read() };
    if reltime.tv_sec < 0 || !(0..NANOS as libc::c_long).contains(&reltime.tv_nsec) {
        return libc::EINVAL;
    }
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { super::time::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
        return super::get_errno();
    }
    let now = (now.tv_sec as u64)
        .wrapping_mul(NANOS)
        .wrapping_add(now.tv_nsec as u64);
    let relative = (reltime.tv_sec as u64)
        .wrapping_mul(NANOS)
        .wrapping_add(reltime.tv_nsec as u64);
    let Some(deadline) = now.checked_add(relative) else {
        return libc::EINVAL;
    };
    let abstime = libc::timespec {
        tv_sec: (deadline / NANOS) as libc::time_t,
        tv_nsec: (deadline % NANOS) as libc::c_long,
    };
    unsafe { crate::patina_cond_timedwait(cond.cast(), mutex.cast(), (&raw const abstime).cast()) }
}

/// # Safety
/// As pthread_cond_signal's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut libc::pthread_cond_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_cond_signal(cond.cast()) }
}

/// # Safety
/// As pthread_cond_broadcast's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut libc::pthread_cond_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_cond_broadcast(cond.cast()) }
}

/// # Safety
/// As pthread_cond_destroy's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut libc::pthread_cond_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_cond_destroy(cond.cast()) }
}

// pthread_rwlock_* routes reader/writer contention through the scheduler (the
// lock's kind from the attribute or static initializer, as glibc keeps three:
// readers preferred by default, writer-to-writer hand-over for
// PREFER_WRITER_NP, to which PREFER_WRITER_NONRECURSIVE_NP adds new readers
// waiting behind a waiting writer; FIFO among writers; blocked readers woken
// together). Rust std's RwLock does not reach these; C guests do.

/// # Safety
/// As pthread_rwlock_init's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(
    lock: *mut libc::pthread_rwlock_t,
    attr: *const libc::pthread_rwlockattr_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_init(lock.cast(), attr.cast()) }
}

/// # Safety
/// As pthread_rwlock_destroy's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_destroy(lock.cast()) }
}

/// # Safety
/// As pthread_rwlock_rdlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_rdlock(lock.cast()) }
}

/// # Safety
/// As pthread_rwlock_tryrdlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_tryrdlock(lock.cast()) }
}

/// # Safety
/// As pthread_rwlock_wrlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_wrlock(lock.cast()) }
}

/// # Safety
/// As pthread_rwlock_trywrlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_trywrlock(lock.cast()) }
}

/// # Safety
/// As pthread_rwlock_unlock's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { crate::patina_rwlock_unlock(lock.cast()) }
}

// pthread_once: run `init_routine` exactly once across all managed threads,
// concurrent callers blocking until the first completes (aws-lc's lazy library
// init reaches it). The control's layout is not portable (glibc's is a bare
// zeroed int; Darwin's carries a signature word), so state lives in a registry
// keyed on the control's address, guarded by a mutex and condvar that route
// through the scheduler. Exactly one thread moves an entry to running, runs
// the init with the guard released, then wakes any waiters.

const FRESH: c_int = 0;
const RUNNING: c_int = 1;
const DONE: c_int = 2;

struct Once {
    key: usize,
    state: c_int,
    next: *mut Once,
}

struct Shared<T>(UnsafeCell<T>);
// SAFETY: the guard mutex serializes the registry; the mutex and condvar are
// scheduler-model objects identified by address.
unsafe impl<T> Sync for Shared<T> {}

static GUARD: Shared<libc::pthread_mutex_t> =
    Shared(UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER));
static WAKE: Shared<libc::pthread_cond_t> = Shared(UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER));
static REGISTRY: Shared<*mut Once> = Shared(UnsafeCell::new(null_mut()));

fn guard() -> *mut c_void {
    GUARD.0.get().cast()
}

/// Find or register `control`, wait out a running init, and claim a fresh
/// one: the entry whose init the caller runs, null once done, or ENOMEM.
unsafe fn once_begin(control: usize) -> Result<*mut Once, c_int> {
    unsafe {
        crate::patina_mutex_lock(guard());
        let mut entry = *REGISTRY.0.get();
        while !entry.is_null() && (*entry).key != control {
            entry = (*entry).next;
        }
        if entry.is_null() {
            // libc's allocator, as every C-compatible shim allocation.
            entry = libc::malloc(size_of::<Once>()).cast();
            if entry.is_null() {
                crate::patina_mutex_unlock(guard());
                return Err(libc::ENOMEM);
            }
            entry.write(Once {
                key: control,
                state: FRESH,
                next: *REGISTRY.0.get(),
            });
            *REGISTRY.0.get() = entry;
        }
        // The model's wait, not pthread_cond_wait's: glibc's pthread_once
        // waits without being a cancellation point.
        loop {
            if (*entry).state != RUNNING {
                break;
            }
            crate::patina_cond_wait(WAKE.0.get().cast(), guard());
        }
        let claimed = if (*entry).state == DONE {
            null_mut()
        } else {
            (*entry).state = RUNNING;
            entry
        };
        crate::patina_mutex_unlock(guard());
        Ok(claimed)
    }
}

unsafe fn once_settle(entry: *mut Once, state: c_int) {
    unsafe {
        crate::patina_mutex_lock(guard());
        (*entry).state = state;
        crate::patina_cond_broadcast(WAKE.0.get().cast());
        crate::patina_mutex_unlock(guard());
    }
}

/// The C pthread_once's claim: 0 with `*entry` the claimed entry (null once
/// done), or ENOMEM.
///
/// # Safety
/// `entry` names writable storage.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_once_begin(
    control: *mut libc::pthread_once_t,
    entry: *mut *mut c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match unsafe { once_begin(control as usize) } {
        Ok(claimed) => {
            unsafe { entry.write(claimed.cast()) };
            0
        }
        Err(errno) => errno,
    }
}

/// The init routine returned: the control is done.
///
/// # Safety
/// `entry` is one [`patina_once_begin`] claimed.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_once_done(entry: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { once_settle(entry.cast(), DONE) }
}

/// An init routine that never returns (it calls pthread_exit, or a
/// cancellation acts in it) leaves the control fresh again and wakes the
/// callers waiting on it, one of which then runs the init: glibc's
/// clear_once_control, the cleanup record the C caller keeps around the
/// routine (nptl pthread_once.c), run as the unwind leaves its frame.
///
/// # Safety
/// `entry` is one [`patina_once_begin`] claimed.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_once_reset(entry: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { once_settle(entry.cast(), FRESH) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".hidden patina_once_begin",
    ".hidden patina_once_done",
    ".hidden patina_once_reset",
);

/// macOS: no forced unwind reaches the init routine (pthread_exit and
/// cancellation fail closed), so the whole door is Rust.
///
/// # Safety
/// As pthread_once's.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(
    control: *mut libc::pthread_once_t,
    init_routine: extern "C" fn(),
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match unsafe { once_begin(control as usize) } {
        Err(errno) => errno,
        Ok(entry) if entry.is_null() => 0,
        Ok(entry) => {
            {
                let _guest = crate::panic_boundary::PanicScope::suspend();
                init_routine();
            }
            unsafe { once_settle(entry, DONE) };
            0
        }
    }
}

/// The x86_64 thread-pointer rows' glibc wrappers (glibc declares neither in a
/// header). Both enter the one model (`src/sud/thread_pointer.rs`), which
/// refuses by name whatever would move the thread pointer. `modify_ldt`'s row
/// answers an int in a zero-extended register, errors included, and glibc's
/// wrapper hands that int back as it is (-22 for EINVAL, errno untouched):
/// `signal_result` does the same, since such a value is never negative.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
pub extern "C" fn arch_prctl(code: c_int, addr: libc::c_ulong) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_arch_prctl,
            code as i64 as u64,
            addr,
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// # Safety
/// `ptr` follows modify_ldt's contract; the model copies through uaccess.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn modify_ldt(
    func: c_int,
    ptr: *mut c_void,
    bytecount: libc::c_ulong,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::signal_result(unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_modify_ldt,
            func as i64 as u64,
            ptr as u64,
            bytecount,
            0,
            0,
            0,
            0,
        )
    })
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_pthread_atfork",
    ".hidden patina_route_pthread_atfork",
    ".set patina_route_pthread_atfork, pthread_atfork",
    ".globl patina_route_pthread_create",
    ".hidden patina_route_pthread_create",
    ".set patina_route_pthread_create, pthread_create",
    ".globl patina_route_pthread_join",
    ".hidden patina_route_pthread_join",
    ".set patina_route_pthread_join, pthread_join",
    ".globl patina_route_pthread_detach",
    ".hidden patina_route_pthread_detach",
    ".set patina_route_pthread_detach, pthread_detach",
    ".globl patina_route_pthread_getname_np",
    ".hidden patina_route_pthread_getname_np",
    ".set patina_route_pthread_getname_np, pthread_getname_np",
    ".globl patina_route_pthread_setname_np",
    ".hidden patina_route_pthread_setname_np",
    ".set patina_route_pthread_setname_np, pthread_setname_np",
    ".globl patina_route_pthread_mutex_init",
    ".hidden patina_route_pthread_mutex_init",
    ".set patina_route_pthread_mutex_init, pthread_mutex_init",
    ".globl patina_route_pthread_mutex_lock",
    ".hidden patina_route_pthread_mutex_lock",
    ".set patina_route_pthread_mutex_lock, pthread_mutex_lock",
    ".globl patina_route_pthread_mutex_trylock",
    ".hidden patina_route_pthread_mutex_trylock",
    ".set patina_route_pthread_mutex_trylock, pthread_mutex_trylock",
    ".globl patina_route_pthread_mutex_unlock",
    ".hidden patina_route_pthread_mutex_unlock",
    ".set patina_route_pthread_mutex_unlock, pthread_mutex_unlock",
    ".globl patina_route_pthread_mutex_destroy",
    ".hidden patina_route_pthread_mutex_destroy",
    ".set patina_route_pthread_mutex_destroy, pthread_mutex_destroy",
    ".globl patina_route_pthread_cond_init",
    ".hidden patina_route_pthread_cond_init",
    ".set patina_route_pthread_cond_init, pthread_cond_init",
    ".globl patina_route_pthread_cond_wait",
    ".hidden patina_route_pthread_cond_wait",
    ".set patina_route_pthread_cond_wait, pthread_cond_wait",
    ".globl patina_route_pthread_cond_timedwait",
    ".hidden patina_route_pthread_cond_timedwait",
    ".set patina_route_pthread_cond_timedwait, pthread_cond_timedwait",
    ".globl patina_route_pthread_cond_signal",
    ".hidden patina_route_pthread_cond_signal",
    ".set patina_route_pthread_cond_signal, pthread_cond_signal",
    ".globl patina_route_pthread_cond_broadcast",
    ".hidden patina_route_pthread_cond_broadcast",
    ".set patina_route_pthread_cond_broadcast, pthread_cond_broadcast",
    ".globl patina_route_pthread_cond_destroy",
    ".hidden patina_route_pthread_cond_destroy",
    ".set patina_route_pthread_cond_destroy, pthread_cond_destroy",
    ".globl patina_route_pthread_rwlock_init",
    ".hidden patina_route_pthread_rwlock_init",
    ".set patina_route_pthread_rwlock_init, pthread_rwlock_init",
    ".globl patina_route_pthread_rwlock_destroy",
    ".hidden patina_route_pthread_rwlock_destroy",
    ".set patina_route_pthread_rwlock_destroy, pthread_rwlock_destroy",
    ".globl patina_route_pthread_rwlock_rdlock",
    ".hidden patina_route_pthread_rwlock_rdlock",
    ".set patina_route_pthread_rwlock_rdlock, pthread_rwlock_rdlock",
    ".globl patina_route_pthread_rwlock_tryrdlock",
    ".hidden patina_route_pthread_rwlock_tryrdlock",
    ".set patina_route_pthread_rwlock_tryrdlock, pthread_rwlock_tryrdlock",
    ".globl patina_route_pthread_rwlock_wrlock",
    ".hidden patina_route_pthread_rwlock_wrlock",
    ".set patina_route_pthread_rwlock_wrlock, pthread_rwlock_wrlock",
    ".globl patina_route_pthread_rwlock_trywrlock",
    ".hidden patina_route_pthread_rwlock_trywrlock",
    ".set patina_route_pthread_rwlock_trywrlock, pthread_rwlock_trywrlock",
    ".globl patina_route_pthread_rwlock_unlock",
    ".hidden patina_route_pthread_rwlock_unlock",
    ".set patina_route_pthread_rwlock_unlock, pthread_rwlock_unlock",
);
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".globl patina_route_arch_prctl",
    ".hidden patina_route_arch_prctl",
    ".set patina_route_arch_prctl, arch_prctl",
    ".globl patina_route_modify_ldt",
    ".hidden patina_route_modify_ldt",
    ".set patina_route_modify_ldt, modify_ldt",
);
