//! SIGSEGV under the timestamp-counter trap (x86_64 Linux). While the trap is
//! armed the host SIGSEGV disposition is the trap's handler
//! (`patina_tsc_sigsegv`, `c/posix/init.c`) and the guest's own SIGSEGV
//! action is virtual. The handler answers a counter read itself and asks
//! [`patina_signal_fault`] what every other SIGSEGV does: what the kernel's
//! `force_sig_fault` would do with the guest's action. A guest handler runs
//! from the trap's own frame, which the kernel built for the fault, so its
//! siginfo is the kernel's (`si_code`, `si_addr`, `si_pkey`) and its
//! ucontext is the faulting context: a return retries the instruction, an
//! edited context is what resumes, and `siglongjmp` leaves as it would. The
//! trap's host action carries the guest's `SA_ONSTACK` ([`mirror_onstack`]),
//! so the kernel puts that frame on the stack the guest asked for (a
//! guard-page fault included).
//!
//! **The shim's own faults.** The trap takes the thread for the shim before
//! anything else ([`patina_trap_enter`]); a SIGSEGV that arrives while shim
//! code owns it (an entry, a shim lock held, the trap's own glue) is a named
//! stop ([`patina_trap_shim_fault`]), never the guest's.
//!
//! SIGSEGV stays out of every host mask here as everywhere under the trap (a
//! counter read must trap wherever it runs, a handler included): a handler
//! runs with SIGSEGV unblocked, so a fault inside it runs it again where the
//! kernel, finding SIGSEGV blocked, would take the default action.
use super::*;

/// Take the fault as the kernel's default action does: the trap restores the
/// default disposition and the retried instruction kills the process.
const FAULT_DEFAULT: i32 = 0;
/// Run the guest handler written to the action out-parameter.
const FAULT_HANDLER: i32 = 1;

/// Whether the timestamp-counter trap owns `sig`'s host disposition.
pub(super) fn trap_routed(sig: u8) -> bool {
    sig == SIGSEGV && crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0
}

/// Give the trap's host action the guest action's `SA_ONSTACK`: the kernel
/// then builds the fault's frame on the alternate stack exactly when it would
/// have built the guest handler's there.
pub(super) fn mirror_onstack(flags: u64) {
    let mut trap = Action::default();
    let query = [
        u64::from(SIGSEGV),
        0,
        &mut trap as *mut _ as u64,
        SIGSET_BYTES as u64,
        0,
        0,
    ];
    if host(SYS_RT_SIGACTION, query) != 0 {
        fatal("host SIGSEGV trap action query failed (rt_sigaction)");
    }
    if (trap.flags ^ flags) & SA_ONSTACK == 0 {
        return;
    }
    trap.flags ^= SA_ONSTACK;
    let install = [
        u64::from(SIGSEGV),
        &trap as *const _ as u64,
        0,
        SIGSET_BYTES as u64,
        0,
        0,
    ];
    if host(SYS_RT_SIGACTION, install) != 0 {
        fatal("host SIGSEGV trap action install failed (rt_sigaction)");
    }
}

/// The trap handler's first act: take the thread for the shim. Answers 1
/// when guest code was interrupted, 0 when shim code already owned the thread
/// (an entry, a shim lock held, or the trap's own glue), whose fault is
/// [`patina_trap_shim_fault`].
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_enter() -> i32 {
    let owned = crate::panic_boundary::claim() || crate::in_shim_critical();
    i32::from(!owned)
}

/// The trap hands the thread back to the guest code it interrupted.
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_leave() {
    crate::panic_boundary::release();
}

/// A fault while shim code owned the thread: a named stop, never the guest's
/// handler, which would run over half-done shim state. It is said with one
/// raw write (the shim state the fault interrupted may hold its allocator or
/// its locks), then the default action takes the signal.
///
/// # Safety
/// `info` names the fault's siginfo.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_trap_shim_fault(info: *const Info, pc: usize) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let info = unsafe { *info };
    let mut line = Line::default();
    line.text(b"patina: fault inside the shim's own code: signal ");
    line.number(info.signo().into(), 10);
    line.text(b" code ");
    line.number(u64::from(info.code() as u32), 16);
    line.text(b" at pc ");
    line.number(pc as u64, 16);
    line.text(b" address ");
    line.number(info.words[2], 16);
    line.text(b"\n");
    let _ = crate::host_write_all(2, line.bytes());
    take_default(info.signo())
}

/// A SIGSEGV the kernel sent itself (`SI_KERNEL`) that the guest's action
/// takes as the default: now, since retrying the instruction need not raise
/// it again (a signal frame that did not fit on its stack is not the
/// instruction's).
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_take_default(sig: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    take_default(sig as u8)
}

/// The default action of `sig`, now: its disposition restored, the signal
/// unblocked and sent to this thread. Sent, not raised again by the
/// instruction, so a core dump's siginfo is `SI_TKILL` with no address where
/// natively it is the kernel's; the wait status is the same.
fn take_default(sig: u8) -> ! {
    let default = Action::default();
    host(
        SYS_RT_SIGACTION,
        [
            u64::from(sig),
            &default as *const _ as u64,
            0,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    );
    let unblock = bit(sig);
    host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_UNBLOCK as u64,
            &unblock as *const _ as u64,
            0,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    );
    let pid = host(SYS_GETPID, [0; 6]);
    let tid = host(SYS_GETTID, [0; 6]);
    host(
        SYS_TGKILL,
        [pid as u64, tid as u64, u64::from(sig), 0, 0, 0],
    );
    crate::host_abort()
}

/// One diagnostic line built without allocating.
struct Line {
    bytes: [u8; 160],
    len: usize,
}
impl Default for Line {
    fn default() -> Self {
        Self {
            bytes: [0; 160],
            len: 0,
        }
    }
}
impl Line {
    fn text(&mut self, text: &[u8]) {
        let end = (self.len + text.len()).min(self.bytes.len());
        self.bytes[self.len..end].copy_from_slice(&text[..end - self.len]);
        self.len = end;
    }
    fn number(&mut self, mut value: u64, radix: u64) {
        let mut digits = [0u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b"0123456789abcdef"[(value % radix) as usize];
            value /= radix;
            if value == 0 {
                break;
            }
        }
        if radix == 16 {
            self.text(b"0x");
        }
        self.text(&digits[start..]);
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

thread_local! {
    /// The action a SIGSEGV [`deliver`] is about to queue captured at its
    /// dequeue: its frame runs that one, as the kernel's does, whatever a
    /// sibling handler of the same batch installs meanwhile.
    static SENT: Cell<Option<Action>> = const { Cell::new(None) };
    /// While the trap serves a counter read off the alternate stack
    /// ([`with_altstack_below`]): the guest's host mask the read interrupted.
    static SERVING: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The next SIGSEGV this thread takes is the one [`deliver`] queues, with
/// the action captured at its dequeue.
pub(super) fn send(action: Action) {
    SENT.set(Some(action));
}

/// A counter read the trap took on the alternate stack, to be served off it
/// (`c/posix/init.c`).
#[repr(C)]
pub struct Served {
    /// The lowest address of the trap's live frames on the alternate stack.
    live: usize,
    /// Where the kernel's frame for the trap begins, below which are the
    /// trap's own frames.
    entry: usize,
    /// The alternate stack that frame saved (`uc_stack`), which its
    /// `rt_sigreturn` registers again.
    stack: *const Stack,
}

const AT_MINSIGSTKSZ: u64 = 51;
/// The named stop's own frames over a nested trap's: 896 bytes measured in a
/// debug x86_64 build (`patina_trap_shim_fault` and what it calls).
const STOP_FRAMES: usize = 1024;

/// Run `body`, a counter read the trap took on the alternate stack and serves
/// off it (`served`; null: served where the trap's frame is, which needs
/// nothing). No guest code runs until the read is done, so none can build a
/// frame over the trap's live frames there or register a stack meanwhile:
/// every signal but the containment ones is held blocked (the
/// trap frame's `rt_sigreturn` installs the guest's mask again, and what
/// arrived meanwhile is delivered then, after the instruction, as it may be
/// natively), and a delivery that would run a handler, a `sigaltstack` or a
/// nested counter read is a named stop. The kernel's alternate stack ends
/// below the live frames meanwhile, so the one frame it may still build
/// there (a fault in the shim's own code, a named stop) lands below them;
/// the cut must leave room for it (`AT_MINSIGSTKSZ`), the trap's own frames
/// over it and the stop's ([`STOP_FRAMES`]), or the read stops by name. At the read's end the kernel
/// holds again the stack it held at its entry.
pub(crate) fn with_altstack_below<T>(served: *const Served, body: impl FnOnce() -> T) -> T {
    // SAFETY: null, or the trap handler's description of its own frame.
    let Some(served) = (unsafe { served.as_ref() }) else {
        return body();
    };
    // SAFETY: the trap frame's `uc_stack`.
    let frame = unsafe { *served.stack };
    let live = served.live & !15;
    if frame.flags & SS_DISABLE != 0 || !on(live, (frame.base, frame.size)) {
        return body();
    }
    let top = frame.base + frame.size;
    let minimum = crate::sud::auxv_value(AT_MINSIGSTKSZ).unwrap_or(0) as usize;
    let floor = minimum.max(top - served.entry) + (served.entry - live) + STOP_FRAMES;
    if live - frame.base < floor {
        crate::trap_fatal(
            "a counter read on the alternate stack leaves too little of it below the trap's \
             frames for a nested signal frame, the trap's own and a named stop's: not modeled",
        );
    }
    let mut interrupted = 0u64;
    let held = host_mask(u64::MAX);
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_SETMASK as u64,
            &held as *const _ as u64,
            &mut interrupted as *mut _ as u64,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host signal mask install failed (rt_sigprocmask)");
    }
    if SERVING.replace(Some(interrupted)).is_some() {
        crate::trap_fatal(
            "a counter read nested in one the trap serves off the alternate stack: not modeled",
        );
    }
    let before = kernel_altstack();
    install_altstack(Stack {
        flags: frame.flags & !SS_ONSTACK,
        size: live - frame.base,
        ..frame
    });
    let value = body();
    install_altstack(before);
    if SERVING.take().is_none() {
        crate::trap_fatal(
            "a counter read served off the alternate stack ended twice: shim state is corrupt",
        );
    }
    value
}

/// While the trap serves a counter read off the alternate stack, the guest's
/// mask the read interrupted (the host's holds every signal back meanwhile).
pub(super) fn serving_counter_read() -> Option<u64> {
    SERVING.get()
}

/// No guest code runs while a counter read is served off the alternate stack
/// ([`with_altstack_below`]): where some would, the run stops by name.
pub(super) fn stop_while_serving(what: &str) -> ! {
    crate::trap_fatal(&format!(
        "{what} while a counter read is served off the alternate stack: not modeled"
    ))
}

/// The kernel's `on_sig_stack`.
fn on(sp: usize, (base, size): (usize, usize)) -> bool {
    sp > base && sp - base <= size
}

fn kernel_altstack() -> Stack {
    let mut stack = Stack::default();
    if host(
        SYS_SIGALTSTACK,
        [0, &mut stack as *mut _ as u64, 0, 0, 0, 0],
    ) != 0
    {
        fatal("host alternate stack query failed (sigaltstack)");
    }
    stack
}

fn install_altstack(stack: Stack) {
    if host(SYS_SIGALTSTACK, [&stack as *const _ as u64, 0, 0, 0, 0, 0]) != 0 {
        fatal("host alternate stack install failed (sigaltstack)");
    }
}

/// A SIGSEGV the trap's handler did not answer as a counter read, with the
/// frame's siginfo. On [`FAULT_HANDLER`] the guest handler to run is written
/// to `handler` and the mask it runs under is installed; its return goes
/// through [`patina_signal_fault_return`].
///
/// # Safety
/// `info` names the trap frame's siginfo and `handler` writable storage for
/// one action.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_fault(info: *const Info, handler: *mut Action) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let info = unsafe { *info };
    let action = match SENT.take() {
        Some(action) => action,
        None => {
            // No kernel fault path uses such a code, and patina queued none.
            if info.code() <= 0 {
                crate::trap_fatal(
                    "a SIGSEGV sent from outside the run (another process's kill) reached \
                     the counter trap: not modeled",
                );
            }
            let mut state = lock_state();
            let action = state.signals.actions[usize::from(SIGSEGV)];
            // `force_sig_info_to_task`: a synchronous fault that the thread
            // ignores takes the default action.
            if matches!(action.handler, SIG_DFL | SIG_IGN) {
                return FAULT_DEFAULT;
            }
            if action.flags & SA_RESETHAND != 0 {
                // Linux resets only sa_handler (see `deliver`).
                state.signals.actions[usize::from(SIGSEGV)].handler = SIG_DFL;
            }
            action
        }
    };
    // The handler returns into the trap's handler, never into a restorer.
    #[cfg(target_arch = "x86_64")]
    if action.flags & SA_RESTORER == 0 || action.restorer != RESTORER.load(Ordering::Relaxed) {
        crate::trap_fatal(
            "a SIGSEGV handler registered with a restorer of its own (a raw sigaction) under \
             the counter trap: its return is not modeled",
        );
    }
    let before = read_mask();
    let running = host_mask(before | action.mask);
    if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
        task.mask = running;
    }
    if running != before {
        install_mask(running);
    }
    unsafe { handler.write(action) };
    FAULT_HANDLER
}

/// A guest handler [`patina_signal_fault`] named returned to the trap's
/// frame, whose saved mask at `frame_mask` the kernel installs next. The
/// containment signals are kept out of it, as out of every frame (one the
/// handler added is named once).
///
/// # Safety
/// `frame_mask` names the trap frame's saved mask.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_fault_return(frame_mask: *mut u64) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let saved = unsafe { *frame_mask };
    let kept = host_mask(saved);
    if kept != saved {
        containment_kept_unblocked(saved & !kept);
        unsafe { frame_mask.write(kept) };
    }
    if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
        task.mask = kept;
    }
}
