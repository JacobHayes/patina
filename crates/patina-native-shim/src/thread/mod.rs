//! Deterministic managed-thread scheduler and shared runtime state.

#[cfg(target_os = "linux")]
pub(crate) mod cancel;
#[cfg(target_os = "linux")]
pub(crate) mod futex2;
#[cfg(target_os = "linux")]
pub(crate) mod inotify;
#[cfg(target_os = "linux")]
pub(crate) mod ipc;
pub(crate) mod locks;
pub(crate) mod net;
#[cfg(target_os = "linux")]
pub(crate) mod pty;
#[cfg(target_os = "linux")]
pub(crate) mod readiness;
#[cfg(target_os = "linux")]
pub(crate) mod registrations;
#[cfg(target_os = "linux")]
pub(crate) mod sched;
#[cfg(target_os = "linux")]
pub(crate) mod signals;
#[cfg(target_os = "macos")]
#[path = "signals_darwin.rs"]
pub(crate) mod signals;
#[cfg(target_os = "linux")]
pub(crate) mod timers;
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_char;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use patina_dst_abi::ClockKind;

#[cfg(any(target_os = "linux", patina_posix_exports))]
use super::fdtable::DescId;
use super::fdtable::FdKind;
use super::{
    EBADF, EBUSY, EDEADLK, EINVAL, EISCONN, ENOTCONN, ENXIO, EOPNOTSUPP, EOVERFLOW, EPERM, EPIPE,
    ESRCH, ETIMEDOUT, EWOULDBLOCK, O_NONBLOCK, O_READ, O_WRITE, PATINA_ENTRY_FIFO,
    PATINA_ENTRY_SOCKET, PATINA_FS_PIPEFS, PATINA_FS_SOCKFS, PatinaMetadata, PatinaTimestamp,
    SpinGuard, SpinMutex, TaskId, fail, fd_table, fs_time_unrecorded, host_write_all, install_fd,
    patina_close, set_errno, with_context, with_context_msg, with_context_raw,
};
#[cfg(target_os = "linux")]
use super::{EINTR, PATINA_FS_VOLUME};
#[cfg(target_os = "macos")]
use crate::{hostapi, in_shim_bootstrap, in_shim_critical};

#[cfg(target_os = "macos")]
mod dispatch;
#[cfg(target_os = "linux")]
#[path = "reactor/epoll.rs"]
pub(crate) mod epoll;
#[cfg(target_os = "linux")]
mod eventfd;
mod futex;
#[cfg(target_os = "macos")]
#[path = "reactor/kqueue.rs"]
pub(crate) mod kqueue;
mod lifecycle;
mod net_state;
mod pipe;
mod posix_error;
mod reactor;
mod state_lock;
mod sync;
mod table;
mod wait_queue;
#[cfg(all(test, target_os = "linux"))]
use state_lock::unsettled_state;
use state_lock::{EXPIRIES_PENDING, StateGuard, lock_state};
pub(crate) use state_lock::{in_state_section, note_expiries, watchdog_observe};
use table::*;
use wait_queue::{Covered, WaitQueue};

#[cfg(target_os = "linux")]
use epoll::EpollSlot;
#[cfg(target_os = "linux")]
pub(crate) use epoll::{epoll_close, epoll_target, forget_description};
#[cfg(target_os = "macos")]
use kqueue::KqueueSlot;
#[cfg(target_os = "macos")]
pub(crate) use kqueue::{kqueue_close, kqueue_forget_number};

#[cfg(target_os = "macos")]
pub use dispatch::*;
#[cfg(target_os = "linux")]
pub(crate) use eventfd::{EventFd, create, eventfd_close, eventfd_read, eventfd_write};
pub use futex::*;
pub use lifecycle::*;
pub use net_state::*;
pub use pipe::*;
#[cfg(all(target_os = "macos", patina_posix_exports))]
use reactor::PatinaKevent;
#[cfg(any(target_os = "linux", patina_posix_exports))]
use reactor::{ReadyDir, fd_poll, register_readiness_waiters};
use reactor::{WaiterLoc, unregister_waiters};
pub use sync::*;

/// Where a guest number lands in this module's class tables. Every extern
/// entry below resolves its guest number ONCE through the descriptor table
/// and works on the handle from then on; the class tables never see a guest
/// number. `EBADF` for an empty slot.
fn class_entry(guest_fd: c_int) -> Result<super::fdtable::Resolved, c_int> {
    super::resolve_fd(guest_fd)
}

/// A guest number's socket handle and its `O_NONBLOCK`: `ENOTSOCK` for any
/// other kind of description.
fn socket_entry(guest_fd: c_int) -> Result<(c_int, bool), c_int> {
    let resolved = class_entry(guest_fd)?;
    match resolved.kind {
        FdKind::Socket => Ok((resolved.handle as c_int, resolved.status & O_NONBLOCK != 0)),
        FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::File
        | FdKind::Dir
        | FdKind::OPath
        | FdKind::Urandom
        | FdKind::Pipe => Err(super::ENOTSOCK),
        #[cfg(target_os = "linux")]
        FdKind::EventFd
        | FdKind::Epoll
        | FdKind::SignalFd
        | FdKind::MessageQueue
        | FdKind::TimerFd
        | FdKind::Inotify
        | FdKind::Pidfd
        | FdKind::LandlockRuleset
        | FdKind::Userfaultfd
        | FdKind::Namespace
        | FdKind::NamespacePath
        | FdKind::PtyMaster
        | FdKind::PtySlave => Err(super::ENOTSOCK),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => Err(super::ENOTSOCK),
    }
}

/// A guest number's pipe-endpoint handle and its `O_NONBLOCK`: `EBADF` for
/// anything that is not a pipe/FIFO endpoint.
fn pipe_entry(guest_fd: c_int) -> Result<(c_int, bool), c_int> {
    let resolved = class_entry(guest_fd)?;
    match resolved.kind {
        FdKind::Pipe => Ok((resolved.handle as c_int, resolved.status & O_NONBLOCK != 0)),
        FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::File
        | FdKind::Dir
        | FdKind::OPath
        | FdKind::Urandom
        | FdKind::Socket => Err(super::EBADF),
        #[cfg(target_os = "linux")]
        FdKind::EventFd
        | FdKind::Epoll
        | FdKind::SignalFd
        | FdKind::MessageQueue
        | FdKind::TimerFd
        | FdKind::Inotify
        | FdKind::Pidfd
        | FdKind::LandlockRuleset
        | FdKind::Userfaultfd
        | FdKind::Namespace
        | FdKind::NamespacePath
        | FdKind::PtyMaster
        | FdKind::PtySlave => Err(super::EBADF),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => Err(super::EBADF),
    }
}

mod handle_allocator {
    #![deny(clippy::undocumented_unsafe_blocks)]

    use super::{ThreadRuntime, c_int, fatal};

    /// Mint the next class handle. Handles are internal identities (never a
    /// guest number) shared by every class table in this module, so a handle
    /// is a socket XOR a pipe end XOR an eventfd; the descriptor table's kind
    /// says which. The socket table includes embryos queued for `accept`.
    pub(super) fn next_handle(state: &mut ThreadRuntime) -> c_int {
        let net = &mut state.net;
        let (next, sockets, pipe_ends) = (&mut net.next_handle, &net.sockets.table, &net.pipe_ends);
        #[cfg(target_os = "linux")]
        let eventfds = &net.eventfds;
        next_free_handle(next, |handle| {
            sockets.contains_key(&handle) || pipe_ends.contains_key(&handle) || {
                #[cfg(target_os = "linux")]
                {
                    eventfds.contains_key(&handle)
                }
                #[cfg(target_os = "macos")]
                {
                    false
                }
            }
        })
    }

    pub(super) fn next_free_handle(
        next: &mut c_int,
        mut is_live: impl FnMut(c_int) -> bool,
    ) -> c_int {
        let start = *next;
        loop {
            let handle = *next;
            *next = handle.wrapping_add(1);
            if !is_live(handle) {
                return handle;
            }
            if *next == start {
                fatal("endpoint handle space exhausted");
            }
        }
    }
}

use handle_allocator::next_handle;

/// A guest thread body: `void *start_routine(void *arg)`.
type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;

// Host thread creation: the shim interposes `pthread_create` with a strong
// def, so to spawn a real OS thread it reaches the host creator through a
// *distinct*, non-interposed path. On macOS that is
// `pthread_create_suspended_np` plus a mach `thread_resume` (the created
// thread parks on the baton immediately, so the brief suspend/resume is only
// used to avoid the interposed name). glibc has no suspended variant, so on
// Linux the shim resolves the genuine glibc `pthread_create` through the
// host-alias table's `dlsym(RTLD_NEXT, ...)` primitive — the same mechanism
// that reaches the real `read`/`write`/`sem_*`. `RTLD_NEXT` returns the libc
// definition after the main executable, so the resolved vehicle is never this
// shim's own interposer and the call cannot recurse. No `--wrap` and no named
// import: `pthread_create` stays off the guest import table like the rest.
/// Create a real, non-interposed host OS thread running `start(arg)` and
/// write its `pthread_t` into `handle`. The thread's trampoline parks on the
/// baton before executing any guest code. The creation vehicle is reached
/// through the resolved host-alias table, so `pthread_create_suspended_np`,
/// `pthread_mach_thread_np`, and `thread_resume` never appear in the guest
/// binary's import table (see the top-level host-alias doctrine).
///
/// # Safety
/// `handle` must be writable and `start`/`arg` a valid thread entry point.
#[cfg(target_os = "macos")]
pub(super) unsafe fn spawn_host_thread(
    handle: *mut *mut c_void,
    attr: *const c_void,
    start: StartRoutine,
    arg: *mut c_void,
) -> c_int {
    let api = crate::hostapi::get();
    // SAFETY: forwarded from this function's contract to the resolved host
    // `pthread_create_suspended_np`. `StartRoutine` here and the table's
    // matching type share the `extern "C" fn(*mut c_void) -> *mut c_void`
    // ABI, so the resolved pointer is called with its true signature.
    let rc = unsafe { (api.pthread_create_suspended_np)(handle, attr, start, arg) };
    if rc != 0 {
        return rc;
    }
    // SAFETY: `*handle` is the freshly created (suspended) host thread.
    unsafe { (api.thread_resume)((api.pthread_mach_thread_np)(handle.read())) };
    0
}

/// # Safety
/// `handle` must be writable and `start`/`arg` a valid thread entry point.
#[cfg(target_os = "linux")]
pub(super) unsafe fn spawn_host_thread(
    handle: *mut *mut c_void,
    attr: *const c_void,
    start: StartRoutine,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the real glibc `pthread_create` resolved through
    // `dlsym(RTLD_NEXT, ...)` (never this shim's strong-def interposer);
    // forwarded from this function's contract.
    unsafe { (crate::hostapi::get().host_pthread_create)(handle, attr, start, arg) }
}

thread_local! {
    /// The managed task this host thread runs, if any.
    static CURRENT_TASK: Cell<Option<TaskId>> = const { Cell::new(None) };
    /// Set once this host thread's task has completed (`thread_finish`), so
    /// any instrumented teardown it runs afterward — pthread TLS destructors
    /// under `--yield-points` execute std generic code monomorphized into the
    /// guest crate, which carries the yield hook — takes no scheduling point
    /// instead of rescheduling a task the scheduler has already removed. This
    /// is deliberately a *distinct* state from "never registered": a foreign
    /// or pre-registration thread that reaches a scheduling point still fails
    /// loudly through the unchanged `reschedule` path, never silently proceeds
    /// unscheduled.
    static TASK_COMPLETED: Cell<bool> = const { Cell::new(false) };
    /// The guest pc of the in-flight `--yield-points` guard hit, captured by
    /// [`yield_point_from`] so a replay divergence can name the instrumented
    /// site that took the extra scheduling point; 0 outside a guard hit.
    static YIELD_SITE: Cell<usize> = const { Cell::new(0) };
}

fn set_current_task(task: TaskId) {
    CURRENT_TASK.with(|cell| cell.set(Some(task)));
}

/// Mark this host thread's task as completed. Idempotent.
fn mark_task_completed() {
    TASK_COMPLETED.with(|cell| cell.set(true));
}

/// Whether this host thread has already finished its managed task and is now
/// in post-completion teardown.
fn task_completed() -> bool {
    TASK_COMPLETED.with(Cell::get)
}

/// Set once the guest's `main` has returned (or the guest called `exit`), so
/// the process is unwinding through the `exit` interposer. Unlike
/// [`task_completed`] (per host thread, set for a *worker* at `thread_finish`),
/// this is process-wide and covers the ROOT (main) task, which never runs
/// `thread_finish` and so has no completion sentinel of its own. glibc drives
/// the guest's thread-local destructors from inside `exit()` — under
/// `--yield-points` those are instrumented std code that hits the yield hook —
/// BEFORE the atexit-registered `patina_shutdown` runs `deactivate()`. Those
/// teardown yields sit outside the deterministic body, and whether a given
/// yield-guard edge fires before or after the runtime detaches is governed by
/// host teardown ordering (glibc TLS-dtor vs atexit ordering, plus a
/// still-exiting worker host thread), not the seed — so recording them lets a
/// record run and a replay run disagree on a trailing `TaskYield`. Setting
/// this at the `exit` boundary (never via `atexit`, which glibc runs *after*
/// the TLS destructors) lets `sched_point` silence them deterministically.
static MAIN_RETURNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark the process as having entered post-`main` teardown. Idempotent.
/// Called only by the `exit` interposer at the main-return/`exit` boundary.
pub(crate) fn note_main_returned() {
    MAIN_RETURNED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Whether the process has entered post-`main` teardown.
pub(crate) fn main_returned() -> bool {
    MAIN_RETURNED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The task of a host thread the runtime does not run (a foreign thread,
/// or the main thread of an embedding without the POSIX startup
/// constructor); the scheduler never issues task id 0.
const UNMANAGED_TASK: TaskId = TaskId(0);

/// The main thread's task. The scheduler numbers tasks from 1 and
/// [`ThreadRuntime::ensure_active`] spawns the main thread's first, so the
/// startup constructor can claim this identity for the main thread before
/// the thread runtime activates. Everything that records a thread's
/// identity before activation — a mutex or write-lock owner, a waiter —
/// then names the same task after it: activation (the first
/// `pthread_create`, but also a pipe, an eventfd, a FIFO open, a futex
/// wait or any signal-state call) never changes who the main thread is.
const MAIN_TASK: TaskId = TaskId(1);

/// Claim [`MAIN_TASK`] for the calling thread. Called once, by the POSIX
/// startup constructor, which the loader runs on the main thread.
pub(crate) fn claim_main_thread() {
    set_current_task(MAIN_TASK);
}

fn current_task() -> TaskId {
    CURRENT_TASK.with(Cell::get).unwrap_or(UNMANAGED_TASK)
}

/// How far thread ids sit above task ids: the main thread is
/// [`MAIN_TASK`], and its id is the guest's pid.
const TID_OFFSET: u64 = crate::registry::IDENTITY_PID as u64 - 1;

/// The thread id of `task`: the guest's pid for the main thread (and for
/// the unmanaged main thread before the thread subsystem activates).
pub(crate) fn tid_of(task: TaskId) -> c_int {
    if task == UNMANAGED_TASK {
        crate::registry::IDENTITY_PID as c_int
    } else {
        c_int::try_from(task.0 + TID_OFFSET).unwrap_or(c_int::MAX)
    }
}

/// The task a thread id names, if it is one a task could have (the
/// thread ids below the guest's pid belong to no thread of the guest).
#[cfg(target_os = "linux")]
pub(crate) fn task_of(tid: c_int) -> Option<TaskId> {
    u64::try_from(tid)
        .ok()
        .filter(|tid| *tid > TID_OFFSET)
        .map(|tid| TaskId(tid - TID_OFFSET))
}

pub(crate) fn deterministic_thread_id() -> c_int {
    tid_of(current_task())
}

/// The calling thread's tid (the main thread's is the pid).
#[cfg(target_os = "linux")]
pub(crate) fn current_tid() -> i32 {
    deterministic_thread_id()
}

/// Whether `tid` names a live thread of the guest: the main thread (whose
/// tid is the pid) before the thread subsystem activates, any task the
/// signal state holds after.
#[cfg(target_os = "linux")]
pub(crate) fn live_tid(tid: i32) -> bool {
    let state = lock_state();
    live_tid_locked(&state, tid)
}

/// [`live_tid`] under the runtime lock the caller holds.
#[cfg(target_os = "linux")]
fn live_tid_locked(state: &ThreadRuntime, tid: i32) -> bool {
    if state.signals.is_empty() {
        return tid == crate::registry::IDENTITY_PID as i32;
    }
    task_of(tid).is_some_and(|task| state.signals.has_task(task))
}

/// The live threads of the virtual process.
#[cfg(target_os = "linux")]
pub(crate) fn live_threads() -> usize {
    lock_state().signals.task_count().max(1)
}

/// Detach the thread subsystem from the runtime at shutdown. Later boundary
/// calls (for example `Mutex`/`Condvar` destructors as the program unwinds)
/// then take no scheduling point and never touch the removed context.
pub(crate) fn deactivate() {
    let mut state = lock_state();
    state.active = false;
}

fn fatal(message: &str) -> ! {
    // Like `trap_fatal`: `host_abort()` skips the shutdown flush, so the guest's
    // captured output goes out first — a probe that dies here (a deadlock,
    // an unmodeled flag) still leaves its event stream for the conformance
    // differ, which is what lets the testbed declare the death at an exact
    // event instead of writing the whole probe off.
    let _ = super::flush_before_refusal();
    let text = format!("patina native shim fatal: {message}\n");
    let _ = host_write_all(2, text.as_bytes());
    crate::host_abort();
}

/// A recoverable POSIX error code or a fatal determinism violation.
#[derive(Debug)]
enum ThreadError {
    Posix(c_int),
    Fatal(String),
}

impl ThreadError {
    fn into_posix(self) -> posix_error::PosixErrno {
        match self {
            Self::Posix(code) => posix_error::PosixErrno::new(code),
            Self::Fatal(message) => fatal(&message),
        }
    }
}

impl From<String> for ThreadError {
    fn from(message: String) -> Self {
        Self::Fatal(message)
    }
}

/// The scheduler transitions the thread runtime needs. Implemented for the
/// real runtime [`Context`](super::Context) and, in tests, for a bare
/// [`DetScheduler`](patina_dst_sched_det).
trait Scheduler {
    fn spawn(&mut self, label: &str) -> Result<TaskId, String>;
    fn yield_task(&mut self, task: TaskId) -> Result<(), String>;
    fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String>;
    fn park_timed(
        &mut self,
        task: TaskId,
        reason: &str,
        clock: ClockKind,
        deadline: u64,
    ) -> Result<(), String>;
    fn wake(&mut self, task: TaskId) -> Result<(), String>;
    fn complete(&mut self, task: TaskId) -> Result<(), String>;
    fn next(&mut self) -> Result<Option<TaskId>, String>;
}

/// Routes scheduler transitions through the installed runtime context so
/// they are recorded and replayed like every other boundary operation.
struct RealScheduler;

impl Scheduler for RealScheduler {
    fn spawn(&mut self, label: &str) -> Result<TaskId, String> {
        with_context_msg(|context| context.task_spawn(label))
    }

    fn yield_task(&mut self, task: TaskId) -> Result<(), String> {
        with_context_msg(|context| context.task_yield(task))
    }

    fn park(&mut self, task: TaskId, reason: &str) -> Result<(), String> {
        with_context_msg(|context| context.task_park(task, reason))
    }

    fn park_timed(
        &mut self,
        task: TaskId,
        reason: &str,
        clock: ClockKind,
        deadline: u64,
    ) -> Result<(), String> {
        with_context_msg(|context| context.task_park_timed(task, reason, clock, deadline))
    }

    fn wake(&mut self, task: TaskId) -> Result<(), String> {
        // Every native wake funnels here. A timer expiry the native wait state
        // has not settled means the waker chose from queues that may still
        // hold the expired waiter: refuse by name rather than wake it twice.
        if EXPIRIES_PENDING.load(Ordering::Acquire) {
            return Err(format!(
                "a wake of task {} met timer expiries the native wait state has not settled: \
                 a section advanced virtual time and then woke without settling",
                task.0
            ));
        }
        with_context_msg(|context| context.task_wake(task))
    }

    fn complete(&mut self, task: TaskId) -> Result<(), String> {
        with_context_msg(|context| context.task_complete(task))
    }

    fn next(&mut self) -> Result<Option<TaskId>, String> {
        with_context_msg(super::Context::scheduler_next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockClass {
    Io,
    Futex,
    TimedFutex,
    Sleep,
    #[cfg(any(target_os = "linux", patina_posix_exports))]
    Readiness,
    Sync,
    #[cfg(target_os = "linux")]
    Pause,
    #[cfg(target_os = "linux")]
    SigSuspend,
    #[cfg(target_os = "linux")]
    SigWait,
    #[cfg(target_os = "linux")]
    SignalfdRead,
    /// A System V IPC wait: never restarted after a handler (`EINTR`).
    #[cfg(target_os = "linux")]
    Ipc,
}

#[derive(Clone)]
struct Wait {
    class: BlockClass,
    locs: Vec<WaiterLoc>,
    #[cfg(target_os = "linux")]
    wanted: u64,
}
impl Wait {
    fn new(class: BlockClass, locs: Vec<WaiterLoc>) -> Self {
        Self {
            class,
            locs,
            #[cfg(target_os = "linux")]
            wanted: 0,
        }
    }
    #[cfg(target_os = "linux")]
    fn signals(mut self, wanted: u64) -> Self {
        self.wanted = wanted;
        self
    }
}

/// The scheduling result of a boundary or blocking operation.
enum Step {
    /// Keep running on this thread.
    Continue,
    /// Transfer the baton to the given task and wait to be resumed.
    Switch(TaskId),
}

enum JoinResolve {
    Ready(usize),
    Blocked(Step),
}

/// Per-managed-thread blocking primitive. The execution baton is handed to a
/// task by signaling its semaphore; a task parks by waiting on its own. The
/// backing host OS semaphore (a libdispatch semaphore on macOS, a POSIX
/// `sem_t` on Linux) is a pure blocking primitive that carries no
/// deterministic decision — every scheduling choice is made by
/// [`DetScheduler`](patina_dst_sched_det).
///
/// On macOS the baton uses the *canonical* Darwin primitive — a libdispatch
/// semaphore, the same one Rust std's thread [`Parker`] uses — rather than a
/// distinct one chosen to dodge the symbol namespace. That is only safe
/// because of the host-alias doctrine: the shim interposes
/// `dispatch_semaphore_*` with public strong defs (so a *guest* `Parker`
/// routes through the deterministic scheduler), while the baton reaches the
/// *real* libdispatch entry points through the host-alias table
/// (`dlsym(RTLD_NEXT, ...)`), so it never recurses into its own interposer.
/// The vehicle names therefore never appear in the guest import table (only
/// `dlsym` does), so no `--allow` is needed and a guest importing
/// `dispatch_semaphore_wait` still fails the audit. Matching the native
/// primitive is also a robustness win: the baton exercises this shim-vs-guest
/// discrimination on every context switch, so a doctrine regression deadlocks
/// immediately instead of lying dormant.
#[cfg(target_os = "macos")]
mod baton {
    use std::ffi::c_void;

    use crate::hostapi;

    // `<dispatch/time.h>`: `DISPATCH_TIME_FOREVER == ~0ull`. The baton never
    // times out — a park blocks until the baton is handed back by a signal.
    const DISPATCH_TIME_FOREVER: u64 = u64::MAX;

    /// The per-task execution baton: a real libdispatch counting semaphore
    /// (created with value 0, so the first wait blocks until the baton is
    /// first handed over). This is the *canonical* Darwin primitive — the
    /// same one Rust std's `Parker` uses — chosen deliberately to match the
    /// native implementation. The doctrine makes reusing it safe: the shim
    /// reaches the REAL libdispatch entry points through the host-alias table
    /// (`dlsym(RTLD_NEXT, ...)`), while the shim's own public
    /// `dispatch_semaphore_*` strong-def interposers capture *guest* parking
    /// and route it through the deterministic scheduler. Because the baton
    /// exercises that shim-vs-guest discrimination on every context switch, a
    /// doctrine regression (the baton accidentally binding the interposer)
    /// deadlocks immediately instead of lying dormant.
    pub(super) struct Semaphore(*mut c_void);

    // SAFETY: libdispatch semaphores are thread-safe objects.
    unsafe impl Send for Semaphore {}
    // SAFETY: as above.
    unsafe impl Sync for Semaphore {}

    impl Semaphore {
        pub(super) fn new() -> Self {
            // Initial value 0: the first wait blocks until the baton is handed
            // over, exactly matching the previous Mach-semaphore baton.
            let handle = unsafe { (hostapi::get().dispatch_semaphore_create)(0) };
            assert!(!handle.is_null(), "dispatch_semaphore_create failed");
            Self(handle)
        }

        pub(super) fn wait(&self) {
            // SAFETY: `self.0` is a live dispatch semaphore for this object's
            // lifetime. `DISPATCH_TIME_FOREVER` blocks until signalled and
            // never times out (libdispatch absorbs interrupts internally), so
            // the wait returns only when the baton is handed to this task —
            // the same "block until handed the baton" contract the Mach
            // `semaphore_wait` EINTR loop provided.
            unsafe { (hostapi::get().dispatch_semaphore_wait)(self.0, DISPATCH_TIME_FOREVER) };
        }

        pub(super) fn signal(&self) {
            // SAFETY: as above; hands the baton to the task waiting on `self`.
            unsafe { (hostapi::get().dispatch_semaphore_signal)(self.0) };
        }
    }

    impl Drop for Semaphore {
        fn drop(&mut self) {
            // A baton at rest has value 0 (its created value), so releasing is
            // sound (libdispatch traps a release below the created value). In
            // practice managed-task batons live for the process — the runtime's
            // `sems` map is never pruned — so this is defensive lifecycle
            // correctness mirroring a native libdispatch client, not a hot path.
            // SAFETY: `self.0` is a live dispatch object with no waiters.
            unsafe { (hostapi::get().dispatch_release)(self.0) };
        }
    }
}

#[cfg(target_os = "linux")]
mod baton {
    use crate::hostapi;

    // `sem_t` is opaque; glibc's is 32 bytes. Over-allocate and align so the
    // backing storage is valid on any supported layout.
    #[repr(C, align(16))]
    struct SemStorage([u8; 64]);

    pub(super) struct Semaphore(*mut SemStorage);

    // SAFETY: POSIX semaphores are thread-safe; the storage is heap-pinned.
    unsafe impl Send for Semaphore {}
    // SAFETY: as above.
    unsafe impl Sync for Semaphore {}

    impl Semaphore {
        pub(super) fn new() -> Self {
            let storage = Box::into_raw(Box::new(SemStorage([0; 64])));
            // SAFETY: `storage` is a fresh, correctly aligned `sem_t` slot.
            // `sem_init` is reached through the resolved host-alias table, so
            // `sem_init`/`sem_wait`/`sem_post` never appear in the guest
            // binary's import table (see the top-level host-alias doctrine):
            // the shim's use is invisible to the symbol namespace, so even a
            // guest that itself uses POSIX semaphores could be interposed
            // without colliding with the baton.
            let rc = unsafe { (hostapi::get().sem_init)(storage.cast(), 0, 0) };
            assert!(rc == 0, "sem_init failed");
            Self(storage)
        }

        pub(super) fn wait(&self) {
            let wait = hostapi::get().sem_wait;
            // SAFETY: `self.0` is a live semaphore; retry on EINTR.
            while unsafe { wait(self.0.cast()) } != 0 {}
        }

        pub(super) fn signal(&self) {
            // SAFETY: as above.
            unsafe { (hostapi::get().sem_post)(self.0.cast()) };
        }
    }
    // Intentionally not `Drop`: managed-thread semaphores live for the
    // process, so the pinned storage is deliberately leaked.
}

/// Release the state lock, hand the baton to `picked` by signaling its
/// semaphore, then park on `me`'s semaphore until it is handed back.
fn handoff(state: StateGuard, picked: TaskId, me: TaskId) {
    let picked_sem = state.task_sem(picked);
    let my_sem = state.task_sem(me);
    drop(state);
    picked_sem.signal();
    my_sem.wait();
}

fn switch_and_park(state: StateGuard, picked: TaskId, me: TaskId) {
    handoff(state, picked, me);
    #[cfg(target_os = "linux")]
    {
        while let Some(blocked) = signals::take_sync_resume(me) {
            // Pthread waits retain their semantic registration while a
            // handler runs. Grants mark completion, not another wake.
            signals::deliver();
            let mut state = lock_state();
            let notified = state
                .table
                .threads
                .get_mut(&me)
                .unwrap()
                .signal_resume
                .take()
                .unwrap_or_else(|| fatal("signal-woken pthread waiter lost resume state"));
            if notified {
                state.remove_wait(me);
                return;
            }
            let wait = Wait::new(blocked.class, blocked.locs);
            let step = match blocked.deadline {
                Some((clock, deadline)) => {
                    state.block_timed(me, blocked.reason, wait, clock, deadline)
                }
                None => state.block(me, blocked.reason, wait),
            };
            match step {
                Ok(Step::Switch(next)) => handoff(state, next, me),
                Ok(Step::Continue) => return,
                Err(error) => fatal(&format!(
                    "resuming pthread wait failed: {}",
                    c_int::from(error.into_posix())
                )),
            }
        }
    }
    let sync = lock_state().resumed(me);
    #[cfg(target_os = "linux")]
    if sync {
        signals::deliver();
    }
    #[cfg(target_os = "macos")]
    let _ = sync;
}

/// Baton-guarded state shared by every managed host thread. Only the current
/// baton holder touches it, so the spinlock is essentially uncontended.
struct ThreadRuntime {
    table: ThreadTable,
    #[cfg(target_os = "linux")]
    signals: signals::SignalRuntime,
    /// System V IPC objects and their waiters.
    #[cfg(target_os = "linux")]
    ipc: ipc::Ipc,
    /// The pseudoterminal pairs and their waiters.
    #[cfg(target_os = "linux")]
    ptys: pty::Ptys,
    /// Record and OFD locks, and the tasks waiting on them.
    locks: locks::Locks,
    /// Per-thread scheduling attributes and persona.
    #[cfg(target_os = "linux")]
    sched: sched::SchedRuntime,
    /// Per-thread kernel registrations (the robust-futex list head).
    #[cfg(target_os = "linux")]
    registrations: registrations::RegistrationRuntime,
    /// The interval timers, POSIX timers and timer descriptors.
    #[cfg(target_os = "linux")]
    timers: timers::Timers,
    /// Every thread's cancellation state.
    #[cfg(target_os = "linux")]
    cancels: cancel::Cancels,
    /// The inotify instances and their watches.
    #[cfg(target_os = "linux")]
    inotify: inotify::Inotify,
    /// Real host `pthread_t` bits mapped to the managed task they run.
    handles: BTreeMap<usize, TaskId>,
    /// Per-task baton semaphores.
    sems: BTreeMap<TaskId, Arc<baton::Semaphore>>,
    /// Virtual datagram sockets delegating to the runtime's `SimNet`.
    net: NetState,
    /// Tasks parked on a Linux futex word, keyed by the word's address.
    /// Rust std on Linux lowers `Mutex`/`Condvar`/thread parking to raw
    /// `SYS_futex` through libc's `syscall` wrapper rather than pthread, so
    /// the interposed `syscall` routes those waits/wakes here.
    futexes: BTreeMap<usize, WaitQueue<VecDeque<FutexWaiter>>>,
    /// The futex2 index a wake unqueued, per woken task: the highest, as
    /// `futex_unqueue_multiple` reports it. The task takes it on resume.
    #[cfg(target_os = "linux")]
    futex_woken: BTreeMap<TaskId, u32>,
    /// Timed waiters (`cond_timedwait`, timed futex waits) whose deadline
    /// fired: the runtime's timer expiry woke them, and this shim purged them
    /// from their primitive's waiter list. On resume they return `ETIMEDOUT`
    /// instead of the signalled `0`. Populated by
    /// [`ThreadRuntime::settle_expired`] from the runtime's expired set.
    timed_out: std::collections::BTreeSet<TaskId>,
    /// macOS: each blocked task's wait locations, the registration timer
    /// settlement unlinks it through (on Linux the signal model's `blocked`
    /// registration is the same record, see [`ThreadRuntime::register_wait`]).
    #[cfg(target_os = "macos")]
    waits: BTreeMap<TaskId, Vec<WaiterLoc>>,
    /// libdispatch semaphores modeled deterministically, keyed by the opaque
    /// handle the interposed `dispatch_semaphore_create` hands out. std's
    /// Darwin thread `Parker` (and everything built on it: `mpsc`/`mpmc`
    /// `recv`/`recv_timeout`, `Once`, ...) blocks here through the interposed
    /// `dispatch_semaphore_wait` so it stays on the scheduler + virtual clock.
    #[cfg(target_os = "macos")]
    dispatch: BTreeMap<usize, DispatchSem>,
    /// Monotonic allocator for dispatch-semaphore handles. Starts at one so
    /// the pointer std stores is never null (it asserts non-null).
    #[cfg(target_os = "macos")]
    next_dispatch_handle: usize,
    active: bool,
}

/// A libdispatch counting semaphore modeled for the deterministic scheduler.
/// `count` follows dispatch semantics: `wait` decrements and blocks when the
/// result is negative, `signal` increments and wakes one waiter when the
/// result is not positive. A negative `count` equals the number of blocked
/// waiters, so a timed-out waiter restores one to `count` when it leaves.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct DispatchSem {
    count: isize,
    waiters: WaitQueue<VecDeque<TaskId>>,
}

/// One waiter queued on a futex word (the kernel's `futex_q`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FutexWaiter {
    task: TaskId,
    /// The waiter's bitset: a wake whose bitset shares no bit with it
    /// passes it by (`FUTEX_BITSET_MATCH_ANY` but for `futex_wait` and
    /// `FUTEX_WAIT_BITSET`).
    bitset: u32,
    /// Whether it waits by the word's private key (`FUTEX_PRIVATE_FLAG`,
    /// `FUTEX2_PRIVATE`), which a wake by the shared key (a dead robust
    /// owner's, a shared futex2 wake) does not match, nor a private
    /// futex2 wake a shared waiter.
    private: bool,
    /// Its index in its futex2 wait (`futex_waitv`'s vector; 0 for
    /// `futex_wait`), which a wake reports to it; `None` for a
    /// multiplexed `futex` wait.
    slot: Option<u32>,
}

impl FutexWaiter {
    /// A multiplexed `futex` row's waiter (`FUTEX_WAIT`,
    /// `FUTEX_WAIT_BITSET`).
    fn multiplexed(task: TaskId, private: bool, bitset: u32) -> Self {
        FutexWaiter {
            task,
            bitset,
            private,
            slot: None,
        }
    }
}

impl ThreadRuntime {
    /// Queue a waiter on the futex word at `addr` (`futex_queue`), as part
    /// of its task's `wait`.
    fn queue_futex_waiter(&mut self, addr: usize, waiter: FutexWaiter, wait: &mut Wait) {
        let queue = self.futexes.entry(addr).or_default();
        wait.enqueue(queue, waiter, WaiterLoc::Futex(addr));
    }

    /// Queue a requeued waiter on `addr`, whose wait was relocated there.
    #[cfg(target_os = "linux")]
    fn requeue_futex_waiter(&mut self, addr: usize, waiter: FutexWaiter) {
        self.futexes
            .entry(addr)
            .or_default()
            .requeue(waiter, Covered::Relocated);
    }

    /// Unqueue, in queue order, up to `limit` of the waiters on `addr`
    /// that `matches` accepts.
    fn take_futex_waiters(
        &mut self,
        addr: usize,
        limit: usize,
        matches: impl Fn(&FutexWaiter) -> bool,
    ) -> Vec<FutexWaiter> {
        let mut taken = Vec::new();
        if let Some(queue) = self.futexes.get_mut(&addr) {
            queue.retain(|waiter| {
                let take = taken.len() < limit && matches(waiter);
                if take {
                    taken.push(*waiter);
                }
                !take
            });
            if queue.is_empty() {
                self.futexes.remove(&addr);
            }
        }
        taken
    }

    /// Wake the tasks of unqueued waiters (`futex_wake_mark`), each
    /// once: it leaves every other queue it waits on, and a futex2
    /// waiter learns the highest index unqueued.
    fn wake_futex_waiters(&mut self, woken: &[FutexWaiter]) {
        let mut tasks = Vec::new();
        for waiter in woken {
            #[cfg(target_os = "linux")]
            if let Some(slot) = waiter.slot {
                let highest = self.futex_woken.entry(waiter.task).or_insert(slot);
                *highest = (*highest).max(slot);
            }
            if !tasks.contains(&waiter.task) {
                tasks.push(waiter.task);
            }
        }
        let mut scheduler = RealScheduler;
        for task in tasks {
            self.remove_wait(task);
            if let Err(message) = scheduler.wake(task) {
                fatal(&message);
            }
        }
    }

    fn task_sem(&self, task: TaskId) -> Arc<baton::Semaphore> {
        Arc::clone(
            self.sems
                .get(&task)
                .expect("every managed task has a baton semaphore"),
        )
    }

    /// Register the main thread as the first managed task, [`MAIN_TASK`],
    /// and give it the baton the first time the thread subsystem is used.
    fn ensure_active(&mut self) -> Result<(), ThreadError> {
        if self.active {
            return Ok(());
        }
        let mut scheduler = RealScheduler;
        let main = scheduler.spawn("main")?;
        if main != MAIN_TASK {
            return Err(ThreadError::Fatal(format!(
                "the scheduler numbered the main task {main:?}, not {MAIN_TASK:?}"
            )));
        }
        let selected = scheduler.next()?;
        if selected != Some(main) {
            return Err(ThreadError::Fatal(format!(
                "scheduler selected {selected:?} instead of the main task {main:?}"
            )));
        }
        self.table.register(main);
        #[cfg(target_os = "linux")]
        self.signals.spawn(main, None);
        self.handles
            .insert(crate::watchdog::host_thread_self(), main);
        self.sems.insert(main, Arc::new(baton::Semaphore::new()));
        self.active = true;
        set_current_task(main);
        Ok(())
    }

    /// Pick the next task. On Linux the process's timers come first: what
    /// virtual time reached fires, and while every task waits idle time
    /// advances to a timer ahead of every parked deadline, whose expiry may
    /// wake one (`timers`). The pick may run the deadlock rescue, which
    /// wakes the tasks whose own deadlines came due; they are settled
    /// (unlinked from every wait) before the timers that came due with
    /// them fire, so an expiry never wakes a task the rescue already woke.
    fn next_task(&mut self) -> Result<Option<TaskId>, ThreadError> {
        #[cfg(target_os = "linux")]
        for task in self.idle_timers()? {
            RealScheduler.wake(task)?;
        }
        let next = RealScheduler.next()?;
        // The pick may have run the deadlock rescue, and the park before it a
        // registration-time expiry: settle both before this section goes on.
        self.settle_expired();
        #[cfg(target_os = "linux")]
        for task in self.fire_timers().map_err(ThreadError::Posix)? {
            RealScheduler.wake(task)?;
        }
        Ok(next)
    }

    fn reschedule(&mut self, me: TaskId) -> Result<Option<TaskId>, ThreadError> {
        let mut scheduler = RealScheduler;
        scheduler.yield_task(me)?;
        Ok(scheduler.next()?)
    }

    fn begin_lock(&mut self, me: TaskId, key: usize, kind: MutexKind) -> Result<Step, ThreadError> {
        let mut wait = Wait::new(BlockClass::Sync, vec![]);
        match self.table.lock(me, key, kind, &mut wait)? {
            LockStep::Acquired => Ok(Step::Continue),
            LockStep::MustBlock => self.block(me, "mutex-contended", wait),
        }
    }

    fn begin_rdlock(
        &mut self,
        me: TaskId,
        key: usize,
        kind: RwLockKind,
    ) -> Result<Step, ThreadError> {
        let mut wait = Wait::new(BlockClass::Sync, vec![]);
        match self.table.rwlock_rdlock(me, key, kind, &mut wait)? {
            LockStep::Acquired => Ok(Step::Continue),
            LockStep::MustBlock => self.block(me, "rwlock-read-contended", wait),
        }
    }

    fn begin_wrlock(
        &mut self,
        me: TaskId,
        key: usize,
        kind: RwLockKind,
    ) -> Result<Step, ThreadError> {
        let mut wait = Wait::new(BlockClass::Sync, vec![]);
        match self.table.rwlock_wrlock(me, key, kind, &mut wait)? {
            LockStep::Acquired => Ok(Step::Continue),
            LockStep::MustBlock => self.block(me, "rwlock-write-contended", wait),
        }
    }

    fn begin_cond_wait(
        &mut self,
        me: TaskId,
        cond_key: usize,
        mutex_key: usize,
    ) -> Result<Step, ThreadError> {
        let mut scheduler = RealScheduler;
        let mut wait = Wait::new(BlockClass::Sync, vec![]);
        self.table
            .cond_wait(&mut scheduler, me, cond_key, mutex_key, &mut wait)?;
        self.block(me, "cond-wait", wait)
    }

    fn begin_join(&mut self, me: TaskId, target: TaskId) -> Result<JoinResolve, ThreadError> {
        let mut wait = Wait::new(BlockClass::Sync, vec![]);
        match self.table.begin_join(me, target, &mut wait)? {
            JoinStep::Done(retval) => Ok(JoinResolve::Ready(retval)),
            JoinStep::MustBlock => Ok(JoinResolve::Blocked(self.block(me, "join", wait)?)),
        }
    }

    fn block(&mut self, me: TaskId, reason: &'static str, wait: Wait) -> Result<Step, ThreadError> {
        if wait.class == BlockClass::Sync {
            refuse_nested_sync_wait(self.table.sync_interrupted(me));
        }
        #[cfg(target_os = "linux")]
        self.refuse_unmodeled_cancellation(me, reason, &wait);
        // A wait before the first thread (a normal mutex's owner relocking
        // it) parks the main task, so the scheduler must know it.
        self.ensure_active()?;
        self.register_wait(me, reason, wait, None);
        // Handing the baton to itself: the wait ends at once.
        #[cfg(target_os = "linux")]
        if self.interrupt_before_park(me) {
            return Ok(Step::Switch(me));
        }
        let mut scheduler = RealScheduler;
        scheduler.park(me, reason)?;
        let next = self.next_task()?;
        match next {
            Some(next) => Ok(Step::Switch(next)),
            None => Err(ThreadError::Fatal(
                "scheduler returned no runnable task after parking".into(),
            )),
        }
    }

    /// Park `me` with a virtual-clock deadline, hand off the baton, and
    /// report whether another task took over. Unlike [`Self::block`] this can
    /// return [`Step::Continue`]: if `me`'s own timer is the earliest and no
    /// other task is runnable, the deadlock-rescue advances virtual time and
    /// re-selects `me` in the same `scheduler.next()`, so `me` keeps running.
    fn block_timed(
        &mut self,
        me: TaskId,
        reason: &'static str,
        wait: Wait,
        clock: ClockKind,
        deadline: u64,
    ) -> Result<Step, ThreadError> {
        if wait.class == BlockClass::Sync {
            refuse_nested_sync_wait(self.table.sync_interrupted(me));
        }
        #[cfg(target_os = "linux")]
        self.refuse_unmodeled_cancellation(me, reason, &wait);
        // As in `block`: the main task may wait before the first thread.
        self.ensure_active()?;
        let mut scheduler = RealScheduler;
        self.register_wait(me, reason, wait, Some((clock, deadline)));
        #[cfg(target_os = "linux")]
        if self.interrupt_before_park(me) {
            return Ok(Step::Continue);
        }
        scheduler.park_timed(me, reason, clock, deadline)?;
        let next = self.next_task()?;
        match next {
            Some(picked) if picked == me => Ok(Step::Continue),
            Some(picked) => Ok(Step::Switch(picked)),
            None => Err(ThreadError::Fatal(
                "scheduler returned no runnable task after timed park".into(),
            )),
        }
    }
}

/// Take a guard-driven scheduling point, remembering the instrumented call
/// site for the divergence diagnostic. On the failure path `sched_point`
/// aborts with the site still set, which is exactly when
/// [`yield_site_context`] reads it.
pub(crate) fn yield_point_from(site: usize) {
    YIELD_SITE.with(|cell| cell.set(site));
    let _ = sched_point();
    YIELD_SITE.with(|cell| cell.set(0));
}

/// Divergence-diagnostic context: where the in-flight scheduling point came
/// from. ASLR makes a raw pc unusable offline, so the site is also reported
/// relative to the shim's own `patina_yield_point` in the same executable
/// image — a delta that is stable across runs of one binary. Symbolize by
/// adding the delta to `nm <binary> | grep patina_yield_point`.
pub(crate) fn yield_site_context() -> String {
    let site = YIELD_SITE.with(Cell::get);
    if site == 0 {
        return "; the divergent scheduling point came from an interposed boundary call, not a \
--yield-points guard"
            .into();
    }
    let anchor = crate::patina_yield_point as *const () as usize;
    let delta = site.wrapping_sub(anchor) as isize;
    let sign = if delta < 0 { '-' } else { '+' };
    format!(
        "; divergent yield point: guest pc {site:#x} = patina_yield_point{sign}{:#x}",
        delta.unsigned_abs()
    )
}

/// Take a deterministic scheduling point at a boundary call. A no-op until
/// the thread subsystem activates, so single-threaded programs are
/// unaffected.
pub(crate) fn sched_point() -> Result<(), c_int> {
    // A thread whose task already completed is running teardown code only; it
    // must not take a scheduling point. Checked before locking and keyed on
    // the completed sentinel alone, so a never-registered thread falls through
    // to the unchanged (loud) reschedule path below rather than being silenced.
    //
    // `main_returned()` extends the identical treatment to the ROOT (main)
    // task once the process is unwinding through the `exit` interposer: the
    // main task never runs `thread_finish`, so without this its instrumented
    // thread-local destructors (under `--yield-points`) would record trailing,
    // host-teardown-ordering-dependent `TaskYield`s and diverge record from
    // replay. The deterministic contract: the root task records exactly ZERO
    // teardown yields on every platform. This is a silence (no op recorded or
    // consumed), never a replay-tolerance relaxation; a NON-yield scheduler op
    // arriving past the flag is still caught loudly (see `with_context_msg`).
    if task_completed() || main_returned() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    signals::deliver();
    let mut state = lock_state();
    if !state.active {
        return Ok(());
    }
    let me = current_task();
    match state.reschedule(me) {
        Ok(Some(picked)) if picked == me => Ok(()),
        Ok(Some(picked)) => {
            switch_and_park(state, picked, me);
            #[cfg(target_os = "linux")]
            signals::deliver();
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(ThreadError::Posix(errno)) => Err(errno),
        Err(ThreadError::Fatal(message)) => fatal(&message),
    }
}

/// Sleep until an absolute virtual deadline through a timed park, so other
/// managed tasks run while this one sleeps and the clock advances only via
/// the rescue. Returns `None` when the thread subsystem is inactive (no
/// managed threads yet), so the caller performs a plain clock jump identical
/// to the historical single-threaded behavior; otherwise `Some(0)` once the
/// deadline is reached (a timed sleep has no distinct timeout return).
/// An interrupted sleep copies the time it had left out to a non-null
/// `remaining` (`nanosleep_copyout`): `EFAULT` where it cannot, instead
/// of `EINTR`.
/// # Safety
/// None beyond the ABI: `remaining` is copied to through `uaccess`.
pub(crate) unsafe fn managed_sleep(
    clock: ClockKind,
    deadline: u64,
    remaining: *mut i64,
) -> Option<c_int> {
    let me = current_task();
    let mut state = lock_state();
    // A cancel that arrived since the sleep's entry acts now, as the
    // sleep returns: glibc's thread, asynchronously cancellable inside
    // the sleep, ended at once, before any virtual time passed.
    #[cfg(target_os = "linux")]
    if state.cancel_ends_sleep(me) {
        return Some(0);
    }
    if !state.active {
        return None;
    }
    match state.block_timed(
        me,
        "sleep",
        Wait::new(BlockClass::Sleep, vec![]),
        clock,
        deadline,
    ) {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return Some(c_int::from(error.into_posix())),
    }
    // A bare sleep is on no waiter list; clear a defensive timer flag anyway.
    lock_state().timed_out.remove(&me);
    #[cfg(target_os = "linux")]
    {
        let mut unwritable = false;
        let mut finished = false;
        let resumed = signals::resume_with(|resumed| {
            if resumed != signals::Resumed::Normal && !remaining.is_null() {
                // Snapshot at interruption, not after a handler that may
                // itself advance virtual time. A clock failure must never
                // invent rem=0.
                let now = with_context_raw(|context| context.now(clock))
                    .unwrap_or_else(|_| fatal("reading interrupted sleep clock failed"));
                let rem = deadline.saturating_sub(now);
                // `do_nanosleep`: a sleep with no time left finished,
                // whatever interrupted it, and copies nothing out.
                if rem == 0 {
                    finished = true;
                    return;
                }
                let left = [(rem / 1_000_000_000) as i64, (rem % 1_000_000_000) as i64];
                unwritable = crate::uaccess::write(remaining as usize, &left).is_err();
            }
        });
        if unwritable {
            return Some(super::EFAULT);
        }
        if finished {
            return Some(0);
        }
        if resumed == signals::Resumed::Eintr {
            return Some(super::EINTR);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = remaining;
    Some(0)
}

#[cfg(test)]
mod tests;
