//! Managed host-thread startup, completion, joining, and exit.

use super::*;

struct ThreadStart {
    task: TaskId,
    routine: StartRoutine,
    arg: *mut c_void,
}

/// Everything a managed thread does before its guest routine runs, on the
/// new host thread: take the task, arm the per-thread traps, take the
/// host registrations over, register the completion, then wait for the
/// baton. Answers the guest routine and its argument.
fn thread_prelude(raw: *mut c_void) -> (StartRoutine, *mut c_void) {
    // SAFETY: `raw` is the `Box<ThreadStart>` leaked in patina_thread_create.
    let start = unsafe { Box::from_raw(raw.cast::<ThreadStart>()) };
    let ThreadStart { task, routine, arg } = *start;
    set_current_task(task);
    // The shim's signal handlers build their frames on a private stack
    // of each managed thread's, armed before any trap can be taken on it.
    #[cfg(target_os = "linux")]
    if signals::front_installed() {
        signals::arm_signal_stack();
    }
    // Arm syscall-user-dispatch on this managed thread. The SUD config does
    // not survive clone(2), so every thread must re-arm; this is the second
    // (and only other) arming site besides the main thread in
    // `__libc_start_main`. A no-op when SUD was not armed for this run
    // (non-SUD kernel or standalone binary).
    #[cfg(target_os = "linux")]
    crate::sud::arming::arm_sud();
    // The timestamp-counter setting is per-thread too, so it arms at the same
    // two sites. A no-op when the trap was not armed for this run.
    #[cfg(target_os = "linux")]
    crate::sud::arming::arm_tsc();
    // glibc's start_thread registered this thread with the host kernel
    // before calling here: take the registrations over before the guest
    // runs on it, and register the task's completion as this thread's
    // first thread-local destructor. Then let the creator return: until
    // now it waits, so no guest code runs beside this off-baton setup and
    // a query of this thread's registrations answers the same every run.
    #[cfg(target_os = "linux")]
    {
        registrations::adopt(task);
        EXIT_RECORD.with(|cell| cell.set(finish_after_destructors(task)));
        creation_settled().signal();
    }
    // Park on this task's baton semaphore until it is first scheduled.
    let sem = lock_state().task_sem(task);
    sem.wait();
    #[cfg(target_os = "linux")]
    {
        let mask = lock_state().signals.mask(task);
        signals::set_segv(mask);
        signals::install_mask(mask);
    }
    (routine, arg)
}

/// The host start routine where the C layer is not linked (the shim's own
/// unit tests, and macOS, where no `pthread_exit` reaches the model): the
/// prelude, the guest routine, then the completion.
extern "C" fn thread_trampoline(raw: *mut c_void) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (routine, arg) = thread_prelude(raw);
    let ret = {
        let _guest = crate::panic_boundary::PanicScope::suspend();
        routine(arg)
    };
    // On Linux the task completes from glibc's thread-local destructor
    // pass (`finish_after_destructors`), once the guest's own destructors
    // ran on it.
    #[cfg(target_os = "linux")]
    thread_returned(ret);
    #[cfg(not(target_os = "linux"))]
    thread_finish(current_task(), ret as usize, 0);
    ret
}

// The C layer's host start routine (`c/posix/thread_sync.c`), which calls
// the guest routine from C: the one frame glibc's forced unwind
// (`pthread_exit`, cancellation) crosses between the guest's frames and
// `start_thread` is then C, never a Rust frame, which could not be
// unwound. Weak: a link without the C layer leaves it unresolved, and
// `thread_trampoline` serves.
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".weak patina_thread_body",
    ".pushsection .data.rel.ro.patina_thread_body,\"aw\"",
    ".balign 8",
    ".globl patina_thread_body_address",
    ".hidden patina_thread_body_address",
    "patina_thread_body_address:",
    ".quad patina_thread_body",
    ".popsection",
);
#[cfg(target_os = "linux")]
unsafe extern "C" {
    static patina_thread_body_address: usize;
}

/// The host start routine of a managed thread: the C body where the C
/// layer is linked, else [`thread_trampoline`].
fn host_start_routine() -> StartRoutine {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a plain data word the link filled in: the C body's
        // address, or 0.
        let body = unsafe { std::ptr::read_volatile(&raw const patina_thread_body_address) };
        if body != 0 {
            // SAFETY: the C body has the start routine's signature.
            return unsafe { std::mem::transmute::<usize, StartRoutine>(body) };
        }
    }
    thread_trampoline
}

#[unsafe(no_mangle)]
/// The C body's prelude: [`thread_prelude`], answering the guest routine
/// and writing its argument.
///
/// # Safety
/// `raw` must be the payload `patina_thread_create` handed the host
/// thread, and `arg` writable.
#[cfg(target_os = "linux")]
pub unsafe extern "C" fn patina_thread_prelude(
    raw: *mut c_void,
    arg: *mut *mut c_void,
) -> StartRoutine {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (routine, argument) = thread_prelude(raw);
    // SAFETY: writable, per this function's contract.
    unsafe { arg.write(argument) };
    routine
}

thread_local! {
    /// The completion record of the managed thread running on this host
    /// thread, from its prelude until the completion consumes it.
    #[cfg(target_os = "linux")]
    static EXIT_RECORD: Cell<*mut ThreadExit> = const { Cell::new(core::ptr::null_mut()) };
}

/// Hand the completion the value the thread ends with.
#[cfg(target_os = "linux")]
fn thread_returned(value: *mut c_void) {
    let record = EXIT_RECORD.with(Cell::get);
    if record.is_null() {
        fatal("a managed thread ended with no completion registered");
    }
    // SAFETY: the record `finish_after_destructors` leaked; its
    // destructor, which frees it and clears the cell, has not run yet.
    unsafe { (*record).retval = value as usize };
}

#[unsafe(no_mangle)]
/// The C body's epilogue once the guest routine returned: its value is
/// the thread's.
#[cfg(target_os = "linux")]
pub extern "C" fn patina_thread_returned(value: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    thread_returned(value);
}

#[unsafe(no_mangle)]
/// `pthread_exit(value)` on the calling thread, the model's half: the
/// value becomes the thread's, which its completion hands a joiner. It
/// returns glibc's `pthread_exit` for the C interposer to call: glibc's
/// forced unwind then runs the cleanup handlers and `start_thread` the
/// thread-local and `pthread_key` destructors, and the thread completes
/// from its destructor pass as a returning one does. From the guest's own
/// frames the unwind crosses only the guest's and C ones.
///
/// On the main thread the value is the one a thread joining the main
/// thread answers; the unwind ends in the `__libc_start_main` wrapper's
/// cleanup record ([`patina_main_thread_exited`]). A `pthread_exit`
/// inside a guest signal handler (a cancellation acting there included,
/// which comes here too) is a named fatal: its unwind would cross the
/// shim's Rust delivery frames beneath the handler (a Rust frame cannot
/// be unwound: the process would abort where glibc ends the thread).
#[cfg(target_os = "linux")]
pub extern "C" fn patina_thread_exiting(
    value: *mut c_void,
) -> unsafe extern "C" fn(*mut c_void) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if lock_state().signals.in_handler(current_task()) {
        fatal(
            "pthread_exit, or a cancellation acting, inside a signal handler is not \
             modeled: glibc's unwind would cross the shim's signal-delivery frames beneath \
             the handler",
        );
    }
    let me = current_task();
    if !EXIT_RECORD.with(Cell::get).is_null() {
        thread_returned(value);
    } else if me == MAIN_TASK {
        MAIN_EXIT_VALUE.store(value as usize, std::sync::atomic::Ordering::SeqCst);
    } else {
        fatal("pthread_exit on a thread the runtime does not run is not modeled");
    }
    lock_state().cancels.exiting(me);
    crate::hostapi::get().host_pthread_exit
}

/// Posted by a new thread once its host registrations are taken over and
/// its completion is registered; `patina_thread_create` waits for it.
/// Creations are serialized (only the baton holder creates, and it holds
/// the baton while it waits), so one semaphore serves every creation.
#[cfg(target_os = "linux")]
fn creation_settled() -> &'static baton::Semaphore {
    static SETTLED: OnceLock<baton::Semaphore> = OnceLock::new();
    SETTLED.get_or_init(baton::Semaphore::new)
}

/// A managed thread's completion, waiting for its return value.
#[cfg(target_os = "linux")]
struct ThreadExit {
    task: TaskId,
    retval: usize,
}

/// Register `task`'s completion ([`thread_finish`]) as the calling
/// thread's first thread-local destructor. glibc runs them last-registered
/// first once the start routine returns, so the task completes after every
/// destructor the guest registered (C++ `thread_local`, Rust's
/// thread-locals), which therefore run on the live task, as natively they
/// run before the kernel's exit: the robust-list walk and the
/// clear-child-tid wake that a join waits for. Answers the record the
/// trampoline fills in with the return value.
#[cfg(target_os = "linux")]
fn finish_after_destructors(task: TaskId) -> *mut ThreadExit {
    unsafe extern "C" fn complete(record: *mut c_void) {
        let _panic_scope = crate::panic_boundary::PanicScope::enter();
        // SAFETY: the record leaked below, consumed exactly once here.
        let ThreadExit { task, retval } = *unsafe { Box::from_raw(record.cast::<ThreadExit>()) };
        EXIT_RECORD.with(|cell| cell.set(core::ptr::null_mut()));
        thread_returns(task, retval);
    }
    unsafe extern "C" {
        static __dso_handle: u8;
    }
    let record = Box::into_raw(Box::new(ThreadExit { task, retval: 0 }));
    // SAFETY: glibc's real `__cxa_thread_atexit_impl` with a destructor
    // that takes the record, and this image's DSO handle.
    let rc = unsafe {
        (crate::hostapi::get().host_cxa_thread_atexit_impl)(
            complete,
            record.cast(),
            (&raw const __dso_handle).cast_mut().cast(),
        )
    };
    if rc != 0 {
        fatal("registering a managed thread's completion failed (__cxa_thread_atexit_impl)");
    }
    record
}

/// Set once the main thread left through `pthread_exit` (glibc's setjmp
/// branch in `__libc_start_call_main`): the process then ends when its last
/// thread does, through the `exit(0)` glibc's `start_thread` calls, where a
/// main thread's raw `exit` leaves the process to end with its last
/// thread's kernel exit.
#[cfg(target_os = "linux")]
static MAIN_EXITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The value the main thread's `pthread_exit` gave, which a thread joining
/// the main thread answers.
#[cfg(target_os = "linux")]
static MAIN_EXIT_VALUE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A managed thread's completion once its start routine returned or it
/// left through `pthread_exit`. After the main thread's `pthread_exit` the
/// last thread does not complete: it stays the running task through
/// glibc's `exit(0)`, as the main thread does through a return from
/// `main`.
#[cfg(target_os = "linux")]
fn thread_returns(task: TaskId, retval: usize) {
    if MAIN_EXITED.load(std::sync::atomic::Ordering::SeqCst) {
        let last = {
            let state = lock_state();
            state.signals.task_count() == 1 && state.signals.has_task(task)
        };
        if last {
            last_thread_exits();
            return;
        }
    }
    thread_finish(task, retval, 0);
}

#[unsafe(no_mangle)]
/// The main thread's `pthread_exit`, once the guest's cleanup handlers
/// ran on it (the C `__libc_start_main` wrapper's cleanup record, the
/// outermost of the main thread's, calls this). With another thread
/// running, the main task completes as a leader's raw `exit` completes it
/// and hands the baton on; glibc then runs its `pthread_key` destructors
/// and retires the host thread. Alone, it is the last thread, and glibc's
/// `exit(0)` follows on it.
#[cfg(target_os = "linux")]
pub extern "C" fn patina_main_thread_exited() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    MAIN_EXITED.store(true, std::sync::atomic::Ordering::SeqCst);
    let others = {
        let state = lock_state();
        state.active && state.signals.task_count() > 1
    };
    if others {
        thread_finish(
            current_task(),
            MAIN_EXIT_VALUE.load(std::sync::atomic::Ordering::SeqCst),
            0,
        );
    } else {
        last_thread_exits();
    }
}

/// The last thread after the main thread's `pthread_exit`: glibc calls
/// `exit(0)` from the host thread that ends last, so the run's teardown
/// begins (the atexit hook's canary expects the flag) with status 0, and
/// this thread waits for every other host thread to have left glibc's
/// count, which makes it the one whose `exit(0)` runs the atexit
/// handlers, whatever the host's timing of their own teardown.
#[cfg(target_os = "linux")]
fn last_thread_exits() {
    note_main_returned();
    crate::patina_note_guest_exit_status(0);
    let count = crate::hostapi::symbol(c"__nptl_nthreads")
        .cast::<std::sync::atomic::AtomicU32>()
        .cast_const();
    if count.is_null() {
        fatal(
            "glibc's thread count (__nptl_nthreads) is not visible, so the thread that \
             calls exit(0) after the main thread's pthread_exit cannot be chosen",
        );
    }
    // The wait is for host teardown the model does not see (the other
    // host threads' pthread_key destructors, freeres and kernel exit, all
    // after their tasks completed), so no virtual clock can bound it, and
    // how long it takes decides nothing the run records. A thread wedged
    // on the model instead (a destructor waiting on a modeled lock after
    // its task completed) is already a named stop, since a completed task
    // cannot park; one wedged on the host is what the wall-clock bound
    // turns from a hang into a named stop.
    let pause = [0i64, 100_000];
    for _ in 0..100_000 {
        // SAFETY: glibc's `unsigned int __nptl_nthreads`, which it updates
        // atomically.
        if unsafe { (*count).load(std::sync::atomic::Ordering::Acquire) } <= 1 {
            return;
        }
        // SAFETY: the host's `nanosleep` on a local request.
        unsafe {
            crate::sud_host_syscall(
                crate::registry::Syscall::N_nanosleep.number() as std::ffi::c_long,
                pause.as_ptr() as std::ffi::c_long,
                0,
                0,
                0,
                0,
                0,
            )
        };
    }
    fatal(
        "a host thread outlived the guest's last thread by 10 s (wall clock) after the main \
         thread's pthread_exit, wedged in its teardown outside the model: glibc would run \
         exit(0) on whichever thread leaves last",
    );
}

pub(crate) fn thread_finish(task: TaskId, retval: usize, exit_status: i32) {
    #[cfg(not(target_os = "linux"))]
    let _ = exit_status;
    // The kernel's exit order: the robust list, then clear-child-tid.
    #[cfg(target_os = "linux")]
    registrations::exit(task);
    #[cfg(target_os = "linux")]
    signals::clear_tid(task);
    #[cfg(target_os = "linux")]
    signals::release_signal_stack();
    #[cfg(target_os = "linux")]
    crate::sud::task_exited(tid_of(task));
    let mut state = lock_state();
    let mut scheduler = RealScheduler;
    if let Err(ThreadError::Fatal(message)) = state.table.exit(&mut scheduler, task, retval) {
        fatal(&message);
    }
    state.finish_wait(task);
    #[cfg(target_os = "linux")]
    state.signals.finish(task);
    #[cfg(target_os = "linux")]
    state.sched.finish(task);
    #[cfg(target_os = "linux")]
    state.cancels.finish(task);
    // Detached handles remain targetable while live, then disappear with
    // their ThreadEntry; completed joinable handles remain until reaped.
    if !state.table.threads.contains_key(&task) {
        state.handles.retain(|_, owner| *owner != task);
    }
    // The task is gone from the scheduler; mark this host thread completed so
    // instrumented teardown (TLS destructors under `--yield-points`) takes no
    // scheduling point rather than rescheduling a task that no longer exists.
    mark_task_completed();
    let next = match state.next_task() {
        Ok(next) => next,
        Err(error) => fatal(&format!(
            "picking the next task after completion failed ({})",
            c_int::from(error.into_posix())
        )),
    };
    #[cfg(target_os = "linux")]
    if state.signals.is_empty() {
        drop(state);
        signals::patina_raw_exit_group(exit_status);
    }
    // The completed task never runs again; hand the baton to the next task
    // (if any) and let this host thread return out of the trampoline and
    // exit. When no task remains the program is ending.
    if let Some(next) = next {
        let next_sem = state.task_sem(next);
        drop(state);
        next_sem.signal();
    }
}

#[unsafe(no_mangle)]
/// Create a managed thread. `pthread_create` semantics: register a task,
/// spawn a real host thread that parks until it receives the baton, and hand
/// the caller the real `pthread_t`.
///
/// # Safety
/// `thread_out` must be writable, and `start`/`arg` must form a valid
/// thread entry point per the C ABI.
pub unsafe extern "C" fn patina_thread_create(
    thread_out: *mut *mut c_void,
    attr: *const c_void,
    start: Option<StartRoutine>,
    arg: *mut c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(start) = start else {
        return EINVAL;
    };
    if thread_out.is_null() {
        return EINVAL;
    }
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return c_int::from(error.into_posix());
    }
    let task = match RealScheduler.spawn("thread") {
        Ok(task) => task,
        Err(message) => fatal(&message),
    };
    state.table.register(task);
    #[cfg(target_os = "linux")]
    state.signals.spawn(task, Some(current_task()));
    #[cfg(target_os = "linux")]
    state.sched.spawn(task, current_task());
    // A new thread inherits its creator's memory policy.
    #[cfg(target_os = "linux")]
    crate::numa::spawned(deterministic_thread_id(), tid_of(task));
    // And its locked shadow-stack features.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    crate::sud::thread_pointer_spawned(deterministic_thread_id(), tid_of(task));
    // And its per-task credential state.
    #[cfg(target_os = "linux")]
    crate::sud::task_spawned(deterministic_thread_id(), tid_of(task));
    // The semaphore must exist before the host thread parks on it.
    state.sems.insert(task, Arc::new(baton::Semaphore::new()));
    #[cfg(target_os = "linux")]
    creation_settled();
    let payload = Box::into_raw(Box::new(ThreadStart {
        task,
        routine: start,
        arg,
    }));
    let mut handle: *mut c_void = core::ptr::null_mut();
    // SAFETY: `spawn_host_thread` creates a real, non-interposed host OS
    // thread; `payload` is consumed exactly once by the trampoline.
    let rc = unsafe { spawn_host_thread(&mut handle, attr, host_start_routine(), payload.cast()) };
    if rc != 0 {
        // SAFETY: the trampoline never ran, so `payload` is still owned.
        drop(unsafe { Box::from_raw(payload) });
        fatal(&format!("host thread creation failed with code {rc}"));
    }
    state.handles.insert(handle as usize, task);
    crate::watchdog::start();
    drop(state);
    // The new thread takes over its host registrations off the baton;
    // wait for that before the guest can ask about them.
    #[cfg(target_os = "linux")]
    creation_settled().wait();
    // SAFETY: `thread_out` is non-null and writable per the pthread contract.
    unsafe { thread_out.write(handle) };
    0
}

#[unsafe(no_mangle)]
/// Join a managed thread, blocking the caller until the target completes.
///
/// # Safety
/// `handle` must be a `pthread_t` from [`patina_thread_create`] and
/// `retval_out` must be null or writable.
pub unsafe extern "C" fn patina_thread_join(
    handle: *mut c_void,
    retval_out: *mut *mut c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let key = handle as usize;
    // A thread joining itself, the main thread before the thread runtime
    // is active too (the table below refuses a managed one): `EINVAL`
    // once it detached itself, else `EDEADLK`, glibc's order.
    // SAFETY: the real glibc `pthread_self`, resolved through the
    // host-alias table.
    #[cfg(target_os = "linux")]
    if key == unsafe { (crate::hostapi::get().host_pthread_self)() } {
        let me = current_task();
        let state = lock_state();
        if state
            .table
            .threads
            .get(&me)
            .is_some_and(|entry| entry.detached)
        {
            return EINVAL;
        }
        state.refuse_deadlocked_join(me);
        return EDEADLK;
    }
    let me = current_task();
    let mut state = lock_state();
    let Some(&target) = state.handles.get(&key) else {
        return ESRCH;
    };
    let retval = match state.begin_join(me, target) {
        Ok(JoinResolve::Ready(retval)) => {
            state.handles.remove(&key);
            // Release the state lock before the host reap below so the
            // worker's exit never contends with a lock this thread holds.
            drop(state);
            retval
        }
        Ok(JoinResolve::Blocked(Step::Switch(picked))) => {
            switch_and_park(state, picked, me);
            let mut state = lock_state();
            state.handles.remove(&key);
            state.table.take_join_result(target)
        }
        Ok(JoinResolve::Blocked(Step::Continue)) => {
            fatal("join parked without transferring the baton")
        }
        Err(error) => {
            let error = c_int::from(error.into_posix());
            #[cfg(target_os = "linux")]
            if error == EDEADLK {
                state.refuse_deadlocked_join(me);
            }
            return error;
        }
    };
    // The managed join is complete (the worker's task has exited the
    // scheduler). Now REAP the real host thread so the worker fully unwinds
    // before we return: std drops the worker's `Arc<thread::Inner>` in a
    // thread-local destructor as the host thread exits, and if that drop
    // races the joiner's own `Arc<Inner>` drop (std's `JoinInner` cleanup,
    // which runs right after this returns), whichever is the LAST reference
    // takes the acquire-fence + destructor slow path — so under
    // `--yield-points` the joiner records a host-timing-dependent number of
    // scheduling points (the op-742/12623 x86 divergence on Linux; the
    // ±2-yield main-tls record/replay divergence under load on Darwin).
    // Joining here forces the worker to drop its reference first, so the
    // joiner's drop is deterministically the last reference on every run and
    // every host thread that reaches this. The worker's own teardown runs on
    // a task-completed-silenced thread, so it records nothing; the join adds
    // no instrumented guest edges.
    // SAFETY: `handle` is the real joinable host `pthread_t` returned by
    // `patina_thread_create`; the state lock is released above so the worker's
    // exit cannot deadlock against a lock this thread holds.
    let _ = unsafe { (crate::hostapi::get().host_pthread_join)(handle, core::ptr::null_mut()) };
    if !retval_out.is_null() {
        // SAFETY: `retval_out` was checked non-null and is writable.
        unsafe { retval_out.write(retval as *mut c_void) };
    }
    0
}

#[unsafe(no_mangle)]
/// Detach a managed thread so it is never joined.
///
/// # Safety
/// `handle` must be a `pthread_t` from [`patina_thread_create`].
pub unsafe extern "C" fn patina_thread_detach(handle: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let key = handle as usize;
    let mut state = lock_state();
    let Some(&target) = state.handles.get(&key) else {
        return ESRCH;
    };
    match state.table.detach(target) {
        Ok(()) => {
            if !state.table.threads.contains_key(&target) {
                state.handles.remove(&key);
            }
            drop(state);
            // Reap the host vehicle too; its pthread identity remains valid
            // until completion, exactly as the modeled detached handle does.
            let rc = unsafe { (crate::hostapi::get().host_pthread_detach)(handle) };
            if rc != 0 {
                fatal("host pthread_detach failed");
            }
            0
        }
        Err(error) => c_int::from(error.into_posix()),
    }
}

#[unsafe(no_mangle)]
/// `pthread_exit` where the model does not reach it, fail-closed: on macOS
/// (whose libsystem ends a thread without an unwind the model could
/// follow) and through the prefixed C ABI. On Linux the C interposer goes
/// through [`patina_thread_exiting`] instead.
///
/// # Safety
/// C ABI entry point; the argument is an opaque pointer.
pub unsafe extern "C" fn patina_thread_exit(_retval: *mut c_void) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fatal(
        "pthread_exit is not supported by Patina's deterministic thread runtime; \
         return from the thread body instead",
    )
}
