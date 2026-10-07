//! Linux startup before the constructors, for the C `__libc_start_main` door
//! (`c/posix/init.c`), and the glibc cleanup records its main wrapper and
//! pthread_once keep in their own frames.
//!
//! The executable's strong `__libc_start_main` runs before glibc gets control,
//! so it sees the natural main-return path that glibc's hidden `exit` alias
//! hides from the `exit` interposer. Everything here runs before the
//! constructors: no guest allocator has initialized, so nothing here allocates
//! through Rust's global allocator, and host vehicles are resolved through the
//! private `__real_dlsym` resolver, never interposed names.
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::traps;

/// The program's argv[0], which glibc's dlerror and assertion messages name.
#[unsafe(no_mangle)]
pub(crate) static patina_program_path: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

type LibcStartMain = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *mut *mut c_char,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> c_int;
type Rlimit = unsafe extern "C" fn(c_int, *mut libc::rlimit) -> c_int;

/// Whether the startup environment names `name` (environ is still the
/// kernel's here: the constructor's scrub runs later).
pub(super) unsafe fn env_has(envp: *const *const c_char, name: &[u8]) -> bool {
    let mut entry = envp;
    unsafe {
        while !(*entry).is_null() {
            let text = core::ffi::CStr::from_ptr(*entry).to_bytes();
            if text.len() > name.len() && text.starts_with(name) && text[name.len()] == b'=' {
                return true;
            }
            entry = entry.add(1);
        }
    }
    false
}

/// Prepare the process for guest code, in this order: the saved host envp,
/// panic containment, the program name, syscall-user-dispatch, the counter
/// trap, the fault front handler, transparent huge pages off and the host's
/// descriptor budget. Answers glibc's own `__libc_start_main`.
///
/// # Safety
/// The kernel's argc/argv, from the C door; `sud_probe` 0 only in the
/// acceptance object that exercises the unavailable-kernel branch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_start_prepare(
    argc: c_int,
    argv: *mut *mut c_char,
    sud_probe: c_int,
) -> LibcStartMain {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let envp = unsafe { argv.add(argc as usize + 1) };
    unsafe { crate::posix_env::save_host(envp) };
    // The POSIX link supplies host aliases; install panic containment before
    // any guest constructors, independently of whether Context is deferred.
    crate::panic_boundary::install();
    let program = if argc > 0 {
        unsafe { *argv }
    } else {
        null_mut()
    };
    patina_program_path.store(program, Ordering::Relaxed);
    // The main thread's name is the basename of argv[0], which the supervisor
    // fixes to a machine-independent name: never the host binary's path,
    // which the kernel would name it after (AT_EXECFN).
    unsafe { crate::thread::sched::patina_note_program_name(program) };
    let envp = envp.cast_const().cast();
    unsafe {
        traps::sud_init(envp, sud_probe != 0);
        traps::tsc_init(envp);
        traps::fault_front_init(envp);
    }
    // The virtual kernel runs the process with transparent huge pages off
    // (what PR_GET_THP_DISABLE answers), so page residency is page-exact on
    // every host. Fail closed: a guest told THP is off must not run with it on.
    let prctl = crate::sud::arming::prctl().or_else(traps::resolve_prctl);
    if !prctl.is_some_and(|prctl| unsafe { prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0 }) {
        crate::trap_fatal("could not disable transparent huge pages (PR_SET_THP_DISABLE)");
    }
    // Every mapped file and System V segment of the guest is one host memfd,
    // beside the shim's own descriptors, so the host's soft RLIMIT_NOFILE is
    // the budget of guest mappings. Raise it to the hard limit (process-local:
    // the guest's RLIMIT_NOFILE is the virtual table's). A memfd the host still
    // refuses is a named fatal, never a guest errno.
    let resolve = |name: &core::ffi::CStr| {
        let address = crate::hostapi::symbol(name);
        // SAFETY: glibc's getrlimit/setrlimit share this signature.
        (!address.is_null())
            .then(|| unsafe { core::mem::transmute::<*mut c_void, Rlimit>(address) })
    };
    let mut descriptors = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let (Some(get), Some(set)) = (resolve(c"getrlimit"), resolve(c"setrlimit")) else {
        crate::trap_fatal("could not read the host's RLIMIT_NOFILE");
    };
    if unsafe { get(libc::RLIMIT_NOFILE as c_int, &mut descriptors) } != 0 {
        crate::trap_fatal("could not read the host's RLIMIT_NOFILE");
    }
    descriptors.rlim_cur = descriptors.rlim_max;
    if unsafe { set(libc::RLIMIT_NOFILE as c_int, &mut descriptors) } != 0 {
        crate::trap_fatal("could not raise the host's soft RLIMIT_NOFILE to its hard limit");
    }
    let real = crate::hostapi::symbol(c"__libc_start_main");
    if real.is_null() {
        // Defensive and effectively unreachable: glibc always exports it, and
        // this layer is only linked with -Wl,--wrap=dlsym. Fail closed loudly
        // rather than run the guest unwrapped, which would silently
        // reintroduce the nondeterministic teardown yields the door removes.
        crate::patina_host_abort();
    }
    // SAFETY: glibc's __libc_start_main.
    unsafe { core::mem::transmute::<*mut c_void, LibcStartMain>(real) }
}

type CleanupPush =
    unsafe extern "C" fn(*mut c_void, unsafe extern "C" fn(*mut c_void), *mut c_void);
type CleanupPop = unsafe extern "C" fn(*mut c_void, c_int);

/// glibc's old-style cleanup records, resolved once: a record pushed in a
/// frame runs when glibc's forced unwind (pthread_exit, a cancellation acting)
/// leaves that frame. The record's storage is the C caller's.
fn cleanup_vehicles() -> (CleanupPush, CleanupPop) {
    static VEHICLES: [core::sync::atomic::AtomicUsize; 2] =
        [const { core::sync::atomic::AtomicUsize::new(0) }; 2];
    let [push, pop] = [&VEHICLES[0], &VEHICLES[1]].map(|slot| slot.load(Ordering::Relaxed));
    let (push, pop) = if push == 0 || pop == 0 {
        let push = crate::hostapi::symbol(c"_pthread_cleanup_push") as usize;
        let pop = crate::hostapi::symbol(c"_pthread_cleanup_pop") as usize;
        if push == 0 || pop == 0 {
            crate::trap_fatal("could not resolve glibc's _pthread_cleanup_push/_pop");
        }
        VEHICLES[0].store(push, Ordering::Relaxed);
        VEHICLES[1].store(pop, Ordering::Relaxed);
        (push, pop)
    } else {
        (push, pop)
    };
    // SAFETY: glibc's _pthread_cleanup_push/_pop.
    unsafe {
        (
            core::mem::transmute::<usize, CleanupPush>(push),
            core::mem::transmute::<usize, CleanupPop>(pop),
        )
    }
}

/// Push a cleanup record whose storage is the calling C frame's.
///
/// # Safety
/// `buffer` is a `struct _pthread_cleanup_buffer` in the caller's frame,
/// popped before that frame returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cleanup_push(
    buffer: *mut c_void,
    routine: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { (cleanup_vehicles().0)(buffer, routine, arg) }
}

/// # Safety
/// `buffer` is the innermost record [`patina_cleanup_push`] pushed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cleanup_pop(buffer: *mut c_void, execute: c_int) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { (cleanup_vehicles().1)(buffer, execute) }
}

/// The main wrapper's record: the main thread's pthread_exit unwinds out of
/// `main` into glibc's __libc_start_call_main, running the cleanup handlers of
/// every frame it leaves; this one, the outermost, runs last and tells the
/// model the main thread has ended (glibc then runs its pthread_key
/// destructors and retires it, or ends the process with exit(0) when it is
/// the last thread).
#[unsafe(no_mangle)]
pub extern "C" fn patina_main_exited(_unused: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_main_thread_exited();
}

core::arch::global_asm!(
    ".hidden patina_program_path",
    ".hidden patina_start_prepare",
    ".hidden patina_cleanup_push",
    ".hidden patina_cleanup_pop",
    ".hidden patina_main_exited",
);
