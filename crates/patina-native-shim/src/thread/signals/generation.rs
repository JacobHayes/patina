//! Signal generation, thread exits, tid clearing, and temporary masks.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::abi::{Errno, SysResult};

#[derive(Clone, Copy)]
pub(crate) enum GenerationTarget {
    Process { pid: i32 },
    Thread { tgid: Option<i32>, tid: i32 },
}
#[derive(Clone, Copy)]
pub(crate) enum GenerationInfo {
    User,
    Thread,
    Queued(*const Info),
}

/// glibc's `abort` (stdlib/abort.c) through the virtual kernel: unblock
/// SIGABRT and raise it, so an installed handler runs even when the caller
/// blocked the signal; if the handler returns, restore `SIG_DFL` and raise it
/// again. The default action then finalizes the trace and ends the run by
/// SIGABRT. Returns only if neither raise ended the run (the caller falls
/// back to finalizing and the host abort).
pub(crate) fn abort_through_kernel() {
    const SIGABRT: i32 = 6;
    let sigabrt = bit(SIGABRT);
    // SAFETY: a valid one-word set and no old-set output.
    unsafe { patina_signal_mask(SIG_UNBLOCK, &sigabrt, std::ptr::null_mut(), SIGSET_BYTES) };
    let raise = || {
        refresh_handler_mask();
        let target = GenerationTarget::Thread {
            tgid: Some(crate::registry::IDENTITY_PID as i32),
            tid: current_tid(),
        };
        // SAFETY: a thread-directed kill of the caller carries no pointer.
        unsafe { generate_signal(target, SIGABRT, GenerationInfo::Thread) };
        deliver();
    };
    raise();
    let default = Action {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: u64::MAX,
    };
    // SAFETY: a valid action and no old-action output.
    unsafe { patina_signal_action_libc(SIGABRT, &default, std::ptr::null_mut()) };
    raise();
}

/// The one generation entry owns target and queued-info validation. Doors only
/// marshal; a thread with tid zero can never become process-directed. As in
/// 6.8, the target is found first (`ESRCH`) and the signal judged on it
/// (`check_kill_permission`: an invalid one `EINVAL`, then the permission).
pub(crate) unsafe fn generate_signal(
    target: GenerationTarget,
    sig: i32,
    info: GenerationInfo,
) -> i64 {
    assert!(
        !crate::in_shim_critical(),
        "signal generation under the runtime lock"
    );
    let valid = (0..=SIGNAL_MAX).contains(&sig);
    let queued = matches!(info, GenerationInfo::Queued(_));
    let info = match info {
        GenerationInfo::User => Info::new(sig as u8, SI_USER),
        GenerationInfo::Thread => Info::new(sig as u8, SI_TKILL),
        GenerationInfo::Queued(ptr) => match crate::uaccess::read::<Info>(ptr as usize) {
            Ok(info) => info,
            Err(_) => return -i64::from(EFAULT),
        },
    };
    // `do_rt_sigqueueinfo`/`do_rt_tgsigqueueinfo`: a caller may forge a
    // kernel or `tkill` code only to itself, judged by its own thread id.
    let forged = queued && (info.code() >= 0 || info.code() == SI_TKILL);
    let target = match target {
        GenerationTarget::Process { pid } => {
            if forged && pid != current_tid() {
                return -i64::from(EPERM);
            }
            // A queued signal names one process; `kill` also names groups.
            // Every signal reaching another process here comes from user
            // space (a kernel code to another pid was refused as forged), so
            // `check_kill_permission` judges it by the target's credential.
            match crate::identity::signal_target(pid, !queued) {
                Some(_) if !valid => return -i64::from(EINVAL),
                Some(process) if !crate::identity::may_signal(process, sig) => {
                    return -i64::from(EPERM);
                }
                Some(crate::identity::Process::Guest) => SignalTarget::Process,
                // Init has no handlers, and the kernel drops what a member
                // of its namespace sends it by default.
                Some(crate::identity::Process::Init) => return 0,
                None => return -i64::from(ESRCH),
            }
        }
        GenerationTarget::Thread { tgid, tid } => {
            if tid <= 0 || tgid.is_some_and(|pid| pid <= 0) {
                return -i64::from(EINVAL);
            }
            if forged && tid != current_tid() {
                return -i64::from(EPERM);
            }
            let init = crate::registry::INIT_PID as i32;
            let guest = crate::registry::IDENTITY_PID as i32;
            if tid == init {
                // Init's one thread, reached by `tkill` or with its own tgid,
                // under the permission check; past it init drops the signal.
                return if tgid.is_some_and(|pid| pid != init) {
                    -i64::from(ESRCH)
                } else if !valid {
                    -i64::from(EINVAL)
                } else if crate::identity::may_signal(crate::identity::Process::Init, sig) {
                    0
                } else {
                    -i64::from(EPERM)
                };
            }
            match task_of(tid) {
                Some(task) if tgid.is_none_or(|pid| pid == guest) => SignalTarget::Task(task),
                _ => return -i64::from(ESRCH),
            }
        }
    };
    activate();
    let mut state = lock_state();
    if let SignalTarget::Task(task) = target
        && !state.signals.tasks.contains_key(&task)
    {
        return -i64::from(ESRCH);
    }
    if !valid {
        return -i64::from(EINVAL);
    }
    if sig == 0 {
        return 0;
    }
    let wakes = state.generate_locked(target, info);
    drop(state);
    for task in wakes {
        RealScheduler
            .wake(task)
            .unwrap_or_else(|error| fatal(&error));
    }
    0
}

impl ThreadRuntime {
    /// Generate `info` for `target` under the runtime lock the caller holds:
    /// queue it (unless discarded), record the generation, count signalfd
    /// arrivals, and answer the tasks to wake once the lock is released.
    pub(in crate::thread) fn generate_locked(
        &mut self,
        target: SignalTarget,
        info: Info,
    ) -> Vec<TaskId> {
        // No modeled kernel operation raises SIGSYS (seccomp enforcement is
        // refused). Explicit sends and timer notifications must not reach the
        // host containment handler or silently disappear, regardless of the
        // guest disposition. Keep this check at the shared generation funnel.
        if info.signo() == SIGSYS {
            fatal("guest SIGSYS generation is not modeled; SIGSYS is reserved for containment");
        }
        let (instance, wake) = self.signals.enqueue(info.signo(), target, info);
        with_context_raw(|context| {
            context.signal_generated(
                instance.seq,
                instance.sig,
                target,
                info.code(),
                info.value(),
            )
        })
        .unwrap_or_else(|errno| fatal(&format!("recording signal generation failed ({errno})")));
        for fd in self.signals.signalfds.values_mut() {
            if fd.mask & bit(instance.sig) != 0 {
                fd.arrivals += 1;
            }
        }
        self.prepare_signal_wakes(instance, wake)
    }

    /// `dequeue_signal`: take the next pending signal in `eligible` (for
    /// delivery, only one the process-wide target rule sends this task), and
    /// let the timers rearm on its dequeue — `ITIMER_REAL` on `SIGALRM`, a
    /// periodic POSIX timer on its own `SI_TIMER` record.
    pub(super) fn dequeue_signal(
        &mut self,
        task: TaskId,
        eligible: u64,
        delivery: bool,
    ) -> Option<Instance> {
        let mut instance = if delivery {
            self.signals.dequeue_delivery(task, eligible)
        } else {
            self.signals.dequeue(task, eligible)
        }?;
        self.timers.dequeued(&mut instance.info);
        Some(instance)
    }
}

#[unsafe(no_mangle)]
/// Register the guest word without replacing glibc's host clear-child-tid.
/// # Safety
/// A non-null address must remain writable until the calling task exits.
pub unsafe extern "C" fn patina_set_tid_address(address: *mut i32) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = activate();
    lock_state()
        .signals
        .tasks
        .get_mut(&me)
        .unwrap()
        .clear_child_tid = (!address.is_null()).then_some(address as usize);
    i64::from(tid_of(me))
}

pub(in crate::thread) fn clear_tid(task: TaskId) {
    let address = lock_state()
        .signals
        .tasks
        .get_mut(&task)
        .unwrap()
        .clear_child_tid
        .take();
    if let Some(address) = address {
        // The guest keeps this word alive through exit, as for set_tid_address(2).
        // SAFETY: the registered clear_child_tid contract keeps this address writable.
        unsafe {
            (address as *mut i32).write_volatile(0);
        }
        patina_futex_wake(address, 1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_raw_exit_group(status: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_guest_exit_status(status & 255);
    if crate::shutdown_run() != 0 {
        fatal("exit_group finalization failed");
    }
    note_main_returned();
    host(SYS_EXIT_GROUP, [(status & 255) as u64, 0, 0, 0, 0, 0]);
    fatal("host exit_group returned")
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_raw_exit(status: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = activate();
    thread_finish(me, (status & 255) as usize, status & 255);
    host(SYS_EXIT, [(status & 255) as u64, 0, 0, 0, 0, 0]);
    fatal("host exit returned")
}

#[unsafe(no_mangle)]
/// Whether `sig` is one of glibc's reserved signals, SIGCANCEL and
/// SIGSETXID (`internal-signals.h`), which its libc face refuses to act on:
/// the one predicate the Rust and C wrappers share.
pub extern "C" fn patina_signal_reserved(sig: i32) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    i32::from(matches!(sig, GLIBC_SIGCANCEL | GLIBC_SIGSETXID))
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_pthread_kill(handle: usize, sig: i32) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !(0..=SIGNAL_MAX).contains(&sig) || patina_signal_reserved(sig) != 0 {
        return EINVAL;
    }
    activate();
    refresh_handler_mask();
    // SAFETY: hostapi initialization installs a callable pthread_self entry.
    let task = if handle == unsafe { (crate::hostapi::get().host_pthread_self)() } {
        Some(current_task())
    } else {
        lock_state().handles.get(&handle).copied()
    };
    let Some(task) = task else {
        return ESRCH;
    };
    // SAFETY: this thread-targeted signal carries no guest siginfo pointer.
    let rc = unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(crate::registry::IDENTITY_PID as i32),
                tid: tid_of(task),
            },
            sig,
            GenerationInfo::Thread,
        )
    };
    deliver();
    -rc as i32
}

/// Run a typed wait under the temporary mask supplied by the caller.
///
/// # Safety
/// A non-null `mask` points to the optional guest mask described by the wait API.
pub(in crate::thread) unsafe fn with_temporary_mask<T>(
    mask: *const u64,
    body: impl FnOnce() -> SysResult<T>,
) -> SysResult<T> {
    match temporary_mask(mask) {
        Ok(mask) => with_mask(mask, body),
        Err(errno) => Err(errno),
    }
}

/// The temporary mask a wait names, copied in as `set_user_sigmask` copies
/// it (`None`: the wait names none): a wait whose own arguments the kernel
/// judges after it (`ppoll`, `pselect6`) copies it in first.
pub(in crate::thread) fn temporary_mask(mask: *const u64) -> SysResult<Option<u64>> {
    if mask.is_null() {
        return Ok(None);
    }
    crate::uaccess::read::<u64>(mask as usize)
        .map(Some)
        .map_err(|_| Errno::new(EFAULT))
}

/// [`with_temporary_mask`] with the mask already copied in.
pub(in crate::thread) fn with_mask<T>(
    requested: Option<u64>,
    body: impl FnOnce() -> SysResult<T>,
) -> SysResult<T> {
    let Some(requested) = requested else {
        return body();
    };
    let me = activate();
    let old = with_segv(read_mask());
    let temporary = host_mask(requested);
    // The wait's SIGSEGV block is the temporary mask's, until it returns.
    let mut scope = Scoped::new();
    scope.open();
    set_segv(requested);
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = with_segv(temporary);
    install_mask(temporary);
    let pending = lock_state().signals.has_deliverable(me);
    let rc = if pending {
        deliver_saving(old);
        Err(Errno::new(EINTR))
    } else {
        body()
    };
    scope.close();
    if crate::panic_boundary::exit_owned() {
        // The trap's exit delivers under the temporary mask, has the first
        // frame save `old`, and restores it.
        file_temporary_mask(old, requested);
        return rc;
    }
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
    install_mask(old);
    rc
}
