//! Darwin's synchronous self-signal seam. Generation is a recorded operation
//! targeting the baton holder, never process-directed or host-time scheduled.
//! Host registrations remain the disposition store on Darwin. Kernel delivery
//! is only a vehicle for an unblocked, one-argument handler (including its
//! mask, alternate stack and reset/nodefer flags), or a default fatal action.
//! Deferred delivery and host siginfo are refused, not leaked into the guest.

use patina_dst_abi::SignalTarget;
use std::sync::atomic::{AtomicU64, Ordering};

// XNU bsd/sys/signalvar.h, sigprop: these defaults ignore the signal. A managed
// process is never stopped, so SIGCONT's continue side effect is inert.
fn ignored_by_default(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGURG | libc::SIGCONT | libc::SIGCHLD | libc::SIGIO | libc::SIGWINCH | libc::SIGINFO
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_raise(sig: i32) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abort_if_init_failed();
    // Darwin has signals 1..31, unlike Linux's 1..64. Zero only probes self.
    if !(0..32).contains(&sig) {
        return crate::fail(libc::EINVAL);
    }
    let mut state = super::lock_state();
    if let Err(error) = state.ensure_active() {
        return crate::fail(error.into_posix().into());
    }
    let task = super::current_task();
    drop(state);
    if sig == 0 {
        return 0;
    }
    if sig == libc::SIGSYS {
        crate::trap_fatal(
            "guest SIGSYS generation is not modeled; SIGSYS is reserved for containment",
        );
    }
    let host = crate::hostapi::get();
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut mask: libc::sigset_t = 0;
    if unsafe { (host.host_sigaction)(sig, std::ptr::null(), &mut action) } != 0
        || unsafe { (host.host_pthread_sigmask)(libc::SIG_SETMASK, std::ptr::null(), &mut mask) }
            != 0
    {
        crate::trap_fatal("Darwin self-signal state query failed");
    }
    let ignored = action.sa_sigaction == libc::SIG_IGN
        || (action.sa_sigaction == libc::SIG_DFL && ignored_by_default(sig));
    if mask & (1u32 << (sig - 1)) != 0 {
        crate::trap_fatal("Darwin deferred self-signal delivery is not modeled");
    }
    if !ignored {
        if action.sa_flags & libc::SA_SIGINFO != 0 {
            crate::trap_fatal("Darwin self-signal SA_SIGINFO delivery is not modeled");
        }
        if action.sa_sigaction == libc::SIG_DFL
            && matches!(
                sig,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            )
        {
            crate::trap_fatal("Darwin default signal stop is not modeled");
        }
    }
    // No scheduling handoff between validating the disposition and delivering.
    // A handler may enter modeled operations once ownership is suspended below.
    static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    if crate::with_context_raw(|context| {
        context.signal_generated(
            sequence,
            sig as u8,
            SignalTarget::Task(task),
            0x10001, // Darwin <sys/signal.h>: SI_USER (not exposed by libc).
            0,
        )
    })
    .is_err()
    {
        crate::trap_fatal("recording Darwin self-signal generation failed");
    }
    if ignored {
        return 0;
    }
    if action.sa_sigaction == libc::SIG_DFL && crate::shutdown_run() != 0 {
        crate::trap_fatal("Darwin default signal finalization failed");
    }
    let _guest = crate::panic_boundary::PanicScope::suspend();
    // Never libc raise (which can fall back to process-directed kill). The
    // checked current-thread vehicle completes unblocked delivery before return.
    let rc =
        unsafe { (host.host_pthread_kill)((host.host_pthread_self)() as libc::pthread_t, sig) };
    if rc != 0 {
        crate::trap_fatal("Darwin self-signal delivery vehicle failed");
    }
    0
}
