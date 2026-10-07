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
//! kernel builds that frame on the thread's private stack ([`frames`]), a
//! guard-page fault's included, and the guest's handler runs on the stack
//! its action asks for.
//!
//! **The shim's own faults.** The trap takes the thread for the shim before
//! anything else ([`patina_trap_enter`]); a SIGSEGV that arrives while shim
//! code owns it (an entry, a shim lock held, the trap's own glue) is a named
//! stop ([`patina_trap_shim_fault`]), never the guest's. The same holds on
//! every Linux arch for the other signals an instruction raises (SIGBUS,
//! SIGFPE, SIGILL, SIGTRAP), and for SIGSEGV where the trap is not armed: a
//! front handler (`patina_fault_front`, `c/posix/init.c`) owns their host
//! disposition, with the guest's flags, mask and restorer, and runs the
//! guest's virtual action from its frame ([`patina_fault_route`]).
//!
//! **Blocking SIGSEGV.** The host can never block SIGSEGV (a counter read
//! must trap wherever it runs), so whether the guest has it blocked is kept
//! here, per thread ([`SegvBlock`]). Visible mask changes set it; a handler, a
//! delivery batch or a temporary mask opens a scope whose return restores it.
//! glibc's `siglongjmp` and `setcontext` restore a mask without a system call
//! the shim sees, so a scope a guest left that way is found by the kernel's
//! own stack test ([`left`]): off the scope's alternate stack, above its
//! frame, or with its frame overwritten. Stack pointers are compared only on
//! one stack: the alternate stacks the guest registered are known by their
//! bounds (an `SS_AUTODISARM` one too, which the kernel forgets while a
//! handler runs on it, and one a handler installs by editing its frame's
//! `uc_stack`), and a stack pointer on none of them is on the thread's
//! ordinary stack. On an ordinary stack, below an
//! intact frame, a handler still running and one left by `siglongjmp` whose
//! caller went deeper look the same; where the two would answer differently
//! the answer is [`SegvBlock::Unknown`], which every caller turns into a named
//! stop. A spare signal bit carried in the host mask cannot stand in for
//! SIGSEGV instead: there is none (SIGKILL and SIGSTOP cannot be blocked,
//! SIGSYS is containment's own, and every other bit is a guest signal's), and
//! a borrowed one reads back wrong wherever the guest sets the two apart:
//! `sigfillset` less SIGSEGV (blocking all but the synchronous signals), a
//! non-`SA_NODEFER` SIGSEGV handler's frame, any real use of the borrowed
//! signal (SIGRTMAX, say).
use super::*;
use std::cell::RefCell;

/// Take the fault as the kernel's default action does: the trap restores the
/// default disposition and the retried instruction kills the process.
const FAULT_DEFAULT: i32 = 0;
/// Run the guest handler written to the action out-parameter.
const FAULT_HANDLER: i32 = 1;

/// Whether the timestamp-counter trap owns `sig`'s host disposition.
pub(super) fn trap_routed(sig: u8) -> bool {
    sig == SIGSEGV && crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0
}

/// The front handler's address, once the C layer installed it.
static FRONT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[unsafe(no_mangle)]
/// The C layer put the front handler at `handler` before the signals an
/// instruction raises, SIGSEGV where the counter trap does not own it: from
/// now on it is also the host handler of every guest handler, and each
/// managed thread builds the frames of the shim's handlers on its private
/// stack ([`frames`]). The calling thread's is armed now.
pub extern "C" fn patina_fault_front_installed(handler: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    FRONT.store(handler, Ordering::Relaxed);
    frames::arm();
}

/// Whether the managed run's front handler is installed: every managed
/// thread then arms a private stack before its guest code runs.
pub(crate) fn front_installed() -> bool {
    FRONT.load(Ordering::Relaxed) != 0
}

/// Whether the front handler owns `sig`'s host disposition when the guest's
/// action is a handler: every catchable signal but containment's own.
pub(super) fn front_routed(sig: u8) -> bool {
    !matches!(sig, SIGSYS | SIGKILL | SIGSTOP) && !trap_routed(sig) && front_installed()
}

/// The host action that stands for a guest's `action` on a front-routed
/// signal: the front handler, with the guest action's flags and mask, so the
/// kernel blocks as for the guest's handler, on the private stack
/// (`SA_ONSTACK`), returning through glibc's restorer (the guest's handler
/// returns into the front handler, never into a restorer of its own).
/// `SA_RESETHAND` resets the virtual action only: the front handler stays.
pub(super) fn front_action(action: Action) -> Action {
    #[cfg(target_arch = "x86_64")]
    let (restorer_flag, restorer) = (SA_RESTORER, RESTORER.load(Ordering::Relaxed));
    // arm64's kernel returns through the vDSO trampoline.
    #[cfg(not(target_arch = "x86_64"))]
    let (restorer_flag, restorer) = (0, 0);
    Action {
        handler: FRONT.load(Ordering::Relaxed),
        // `SA_RESTORER` (0x0400_0000) is the shim's to set, never the guest's.
        flags: action.flags & !(SA_RESETHAND | 0x0400_0000)
            | SA_SIGINFO
            | SA_ONSTACK
            | restorer_flag,
        restorer,
        mask: action.mask,
    }
}

#[unsafe(no_mangle)]
/// A signal reached the front handler: one [`deliver`] queued for a guest
/// handler, or one an instruction raised (SIGSEGV where the counter trap
/// does not own it) in guest code. On [`FAULT_HANDLER`] the guest handler to
/// run is written to `handler` and where it runs to `frame` ([`enter`]), and
/// its return goes through [`patina_signal_fault_return`]; on
/// [`FAULT_DEFAULT`] the retried instruction takes the fault under the
/// default action. The kernel blocks the handler's mask as it built the
/// frame (the host action carries it), all but a SIGSEGV under the counter
/// trap, which the host never blocks: that one is blocked virtually while the
/// handler runs, as for a handler the trap runs.
///
/// # Safety
/// `info` names the frame's siginfo, `frame` describes the front handler's
/// frame and `handler` is writable storage for one action.
pub unsafe extern "C" fn patina_fault_route(
    sig: i32,
    info: *const Info,
    _context: *const c_void,
    frame: *mut Frame,
    handler: *mut Action,
) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let sig = sig as u8;
    let (info, frame) = unsafe { (*info, &mut *frame) };
    // Scopes the guest left before this fault are found left from where it
    // faulted, before its handler can take it to an alternate stack ([`left`]).
    if scoped() {
        blocked();
    }
    let sent = take_sent(sig, &info);
    if sent.is_none() && SYNCHRONOUS & bit(sig) == 0 {
        crate::trap_fatal(
            "a signal sent from outside the run (another process's kill) reached a guest \
             handler: not modeled",
        );
    }
    fault_entered(sig, sent.is_some());
    let action = match sent {
        Some(action) => action,
        None => {
            if info.code() <= 0 {
                crate::trap_fatal(
                    "a SIGBUS, SIGFPE, SIGILL, SIGTRAP or SIGSEGV sent from outside the run \
                     (another process's kill) reached the fault handler: not modeled",
                );
            }
            let mut state = lock_state();
            let action = state.signals.actions[usize::from(sig)];
            // `force_sig_info_to_task`: an ignored fault takes the default
            // action (a blocked one never reaches here: the host blocks it).
            if matches!(action.handler, SIG_DFL | SIG_IGN) {
                return FAULT_DEFAULT;
            }
            if action.flags & SA_RESETHAND != 0 {
                state.signals.actions[usize::from(sig)].handler = SIG_DFL;
            }
            action
        }
    };
    let alt = enter(frame, action.flags);
    if trap_routed(SIGSEGV) {
        SEGV.with_borrow_mut(|segv| {
            segv.open(frame.canary, frame.position, alt, false);
            if action.mask & bit(SIGSEGV) != 0 {
                segv.current = SegvBlock::Yes;
            }
        });
    }
    unsafe { handler.write(action) };
    FAULT_HANDLER
}

/// A guest handler with `flags` runs from `frame`: where ([`frames::enter`]),
/// and the frame's `uc_stack` as the handler sees it. Answers the guest
/// alternate stack the registration names, as the fault's scope needs it.
fn enter(frame: &mut Frame, flags: u64) -> Option<(usize, usize)> {
    let sp = frames::guest_position(frame.sp);
    frame.position = frame.canary as usize;
    let Some(entered) = frames::enter(flags, sp, frame.floor) else {
        // SAFETY: the frame's `uc_stack`.
        let stack = unsafe { *frame.stack };
        return (stack.flags & SS_DISABLE == 0).then_some((stack.base, stack.size));
    };
    frame.target = entered.slot;
    frame.position = entered.slot;
    frame.canary = (entered.slot + 8) as *mut u64;
    frame.nested = entered.nested;
    // SAFETY: the frame's `uc_stack`.
    unsafe { frame.stack.write(entered.saved) };
    (entered.saved.flags & SS_DISABLE == 0).then_some((entered.saved.base, entered.saved.size))
}

#[unsafe(no_mangle)]
/// A planted fault in shim code, for the containment tests: inside a shim
/// entry, a read of an unmapped address (`kind` 0, SIGSEGV) or of a file
/// mapping past the file's end (`kind` 1, SIGBUS), or an illegal instruction
/// (`kind` 2, SIGILL). Said on the host's stderr first, so the stop it ends
/// in is known to be this one.
#[cfg(feature = "planted-faults")]
pub extern "C" fn patina_planted_fault(kind: i32) -> u8 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    use patina_dst_syscalls::Syscall;
    if kind == 2 {
        let _ = crate::host_write_all(2, b"PATINA_PLANTED_FAULT\n");
        // SAFETY: raises SIGILL and never returns.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::asm!("ud2", options(noreturn))
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            std::arch::asm!("udf #0", options(noreturn))
        }
    }
    let address = if kind == 0 {
        8
    } else {
        let syscall = |call: Syscall, args: [i64; 6]| unsafe {
            crate::sud_host_syscall(
                call.number() as i64,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            )
        };
        let name = c"planted";
        let fd = syscall(
            Syscall::N_memfd_create,
            [name.as_ptr() as i64, 0, 0, 0, 0, 0],
        );
        // PROT_READ, MAP_SHARED: one page of an empty file.
        let page = syscall(Syscall::N_mmap, [0, 4096, 1, 1, fd, 0]);
        assert!(fd >= 0 && page > 0, "planted fault setup");
        page as usize
    };
    let _ = crate::host_write_all(2, b"PATINA_PLANTED_FAULT\n");
    unsafe { std::ptr::read_volatile(address as *const u8) }
}

/// The trap handler's first act: take the thread for the shim, with the
/// interrupted stack pointer. Answers 1 when guest code was interrupted, 0
/// when shim code already owned the thread (an entry, a shim lock held, or
/// the trap's own glue), whose fault is [`patina_trap_shim_fault`]. An
/// interrupted stack pointer on the private stack is shim code that let a
/// delivery in (its unblock): the guest code it stands for is its entry's.
/// Where `stack` names the frame's `uc_stack`, the handlers guest code has
/// provably left are dropped ([`frames::resync`]).
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_enter(sp: usize, stack: *mut Stack) -> i32 {
    let (entry_sp, _) = crate::panic_boundary::guest_entry();
    let private = frames::private_contains(sp);
    let sp = if private { entry_sp } else { sp };
    let owned = crate::panic_boundary::claim(sp) || crate::in_shim_critical();
    if !owned && !private {
        frames::resync(stack);
    }
    i32::from(!owned)
}

/// The trap hands the thread back to the guest code it interrupted.
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_leave() {
    crate::panic_boundary::release();
}

/// The SIGSYS door's interrupted stack pointer, for the entry it calls next,
/// and its frame's `uc_stack`: the handlers guest code has provably left
/// are dropped ([`frames::resync`]).
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_guest_sp(sp: usize, stack: *mut Stack) {
    crate::panic_boundary::note_guest_sp(sp);
    frames::resync(stack);
}

#[unsafe(no_mangle)]
/// A fault while shim code owned the thread: a named stop, never the guest's
/// handler, which would run over half-done shim state. It is said with one
/// raw write (the shim state the fault interrupted may hold its allocator or
/// its locks), then the default action takes the signal.
///
/// # Safety
/// `info` names the fault's siginfo.
pub unsafe extern "C" fn patina_trap_shim_fault(info: *const Info, pc: usize) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let info = unsafe { *info };
    let mut line = Line::default();
    // Guest code the shim runs while it owns the thread (a guest allocator
    // it calls, say) may read the counter: the trap cannot answer it there.
    #[cfg(target_arch = "x86_64")]
    let counter = trap_routed(SIGSEGV)
        && info.signo() == SIGSEGV
        && info.code() == SI_KERNEL
        && crate::tsc::counter_read_at(pc);
    #[cfg(not(target_arch = "x86_64"))]
    let counter = false;
    // A trace or breakpoint trap: single-stepping (`TRAP_TRACE`), a hardware
    // breakpoint (`TRAP_HWBKPT`), or on x86_64 any SIGTRAP (an `int3`; the
    // shim's own traps there are `ud2`, a SIGILL). An arm64 `brk` is also
    // how the shim's own code traps, so that one stays the shim's fault.
    const TRAP_TRACE: i32 = 2;
    const TRAP_HWBKPT: i32 = 4;
    let traced = info.signo() == SIGTRAP
        && (cfg!(target_arch = "x86_64") || matches!(info.code(), TRAP_TRACE | TRAP_HWBKPT));
    if counter {
        line.text(
            b"patina: a timestamp-counter read while the shim owned the thread (guest code it \
              ran, an allocator say): not modeled: signal ",
        );
    } else if traced {
        line.text(
            b"patina: a trace or breakpoint trap while the shim owned the thread (single-stepping \
              through a shim entry, a breakpoint in guest code the shim ran): not modeled: \
              signal ",
        );
    } else {
        line.text(b"patina: fault inside the shim's own code: signal ");
    }
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

#[unsafe(no_mangle)]
/// A SIGSEGV the kernel sent itself (`SI_KERNEL`) that the guest's action
/// takes as the default: now, since retrying the instruction need not raise
/// it again (a signal frame that did not fit on its stack is not the
/// instruction's).
pub extern "C" fn patina_trap_take_default(sig: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    take_default(sig as u8)
}

/// The default action of `sig`, now: its disposition restored, the signal
/// unblocked and sent to this thread. Sent, not raised again by the
/// instruction, so a core dump's siginfo is `SI_TKILL` with no address where
/// natively it is the kernel's; the wait status is the same.
pub(super) fn take_default(sig: u8) -> ! {
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
    bytes: [u8; 256],
    len: usize,
}
impl Default for Line {
    fn default() -> Self {
        Self {
            bytes: [0; 256],
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
    /// The action a signal an instruction raises (by number) [`deliver`] is
    /// about to queue captured at its dequeue, with the instance's siginfo:
    /// its frame runs that one, as the kernel's does, whatever a sibling
    /// handler of the same batch installs meanwhile.
    static SENT: [Cell<Option<(Action, Info)>>; SENT_SLOTS] =
        const { [const { Cell::new(None) }; SENT_SLOTS] };
    static SEGV: RefCell<SegvMask> = const {
        RefCell::new(SegvMask {
            current: SegvBlock::No,
            scopes: [None; SCOPES],
            depth: 0,
            next: 0x5e67_5c09_e000_0001,
            registered: None,
            stacks: [(0, 0); STACKS],
            known: 0,
        })
    };
}

/// The next `sig` (one an instruction raises) this thread takes is the one
/// [`deliver`] queues, with the action captured at its dequeue.
pub(super) fn send(sig: u8, action: Action, info: &Info) {
    SENT.with(|sent| sent[usize::from(sig)].set(Some((action, *info))));
}
/// The action captured for the `sig` this thread takes with `info`, if it is
/// the one [`deliver`] queued, taken by that frame only. The frame's siginfo
/// is the queued record as the kernel carries it (its `kernel_siginfo`, the
/// first 48 bytes; the rest it zeroes), which a genuine fault's never is,
/// whatever code the record has (a guest may queue itself one with a
/// fault's positive code).
fn take_sent(sig: u8, info: &Info) -> Option<Action> {
    const CARRIED: usize = 6;
    SENT.with(|sent| {
        let slot = &sent[usize::from(sig)];
        let (action, sent) = slot.get()?;
        (sent.words[..CARRIED] == info.words[..CARRIED]).then(|| {
            slot.set(None);
            action
        })
    })
}

/// One slot per signal number: every signal a guest handler runs for is
/// queued through the front handler.
const SENT_SLOTS: usize = SIGNAL_MAX as usize + 1;

/// The guest's alternate stack registration: virtual where the thread's
/// shim handlers build their frames privately, else the kernel's.
pub(super) fn current_altstack() -> Stack {
    if frames::armed() {
        return frames::guest_stack();
    }
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

/// Whether SIGSEGV is blocked for this thread's guest code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SegvBlock {
    No,
    Yes,
    /// Blocked if a handler is still running, not if it was left by
    /// `siglongjmp`, and the two cannot be told apart.
    Unknown,
}

/// Guest code whose return restores the SIGSEGV state it started under: a
/// handler the trap runs, a delivery batch, a temporary mask.
#[derive(Clone, Copy)]
struct Scope {
    /// The shim entry that opened it: while that entry runs, it has not been
    /// left.
    entry: u64,
    /// A word of the frame that encloses the scope and everything it runs,
    /// overwritten once guest code left the scope and ran there.
    canary: usize,
    /// What was written there.
    value: u64,
    /// Where on the guest's stacks the scope's guest code runs below: a
    /// stack pointer above it, on the same stack, has left the scope. The
    /// canary's own address, unless that is on the private stack (shim code
    /// serving a trap), where it is the trapped guest code's.
    sp: usize,
    /// The alternate stack `sp` is on, if it is on one: else it is on the
    /// thread's ordinary stack.
    alt: Option<(usize, usize)>,
    /// Opened by shim code (a delivery batch, a temporary mask), whose own
    /// frames the guest code it runs is below.
    shim: bool,
    /// The state the scope's return restores.
    saved: SegvBlock,
}

const SCOPES: usize = 16;
/// The alternate stacks one thread's open scopes can tell apart.
const STACKS: usize = 8;

struct SegvMask {
    current: SegvBlock,
    scopes: [Option<Scope>; SCOPES],
    depth: usize,
    next: u64,
    /// The alternate stack the guest registered last on this thread.
    registered: Option<(usize, usize)>,
    /// While a scope is open: every alternate stack guest code may be on,
    /// the one registered when the outermost opened and each registered
    /// since.
    stacks: [(usize, usize); STACKS],
    known: usize,
}

/// Where guest code runs: its stack pointer and the shim entry serving it.
#[derive(Clone, Copy)]
struct Position {
    sp: usize,
    entry: u64,
}

/// The kernel's `on_sig_stack`.
fn on(sp: usize, (base, size): (usize, usize)) -> bool {
    sp > base && sp - base <= size
}

impl Position {
    /// The guest code the running shim entry interrupted.
    fn guest() -> Self {
        let (sp, entry) = crate::panic_boundary::guest_entry();
        Self { sp, entry }
    }
}

/// The known alternate stack `sp` is on, if any: else it is on the thread's
/// ordinary stack.
fn alternate(stacks: &[(usize, usize)], sp: usize) -> Option<(usize, usize)> {
    stacks.iter().copied().find(|stack| on(sp, *stack))
}

/// Whether guest code at `at` has provably left `scope`. Stack pointers are
/// compared on one stack only: guest code the scope runs on another stack is
/// a handler the kernel moved to an alternate one, and guest code that left
/// it (by `siglongjmp`) came back through a shim entry or fault that found it
/// left from where it was.
fn left(scope: &Scope, at: &Position, stacks: &[(usize, usize)]) -> bool {
    if at.entry == scope.entry {
        return false;
    }
    let here = alternate(stacks, at.sp);
    let same = match scope.alt {
        Some(frame) => on(at.sp, frame),
        None => here.is_none(),
    };
    // Everything the scope runs is strictly below `sp`: guest code at `sp`
    // itself (the code a trap interrupted, say) has left it.
    if same && at.sp >= scope.sp {
        return true;
    }
    // On the ordinary stack, off the alternate stack the frame is on:
    // nothing the scope runs is running.
    if scope.alt.is_some() && here.is_none() {
        return true;
    }
    // Overwritten: what ran there since has left the scope.
    !crate::uaccess::read::<u64>(scope.canary).is_ok_and(|value| value == scope.value)
}

/// The state at `at` under `scopes` (none of whose tops is provably left).
fn answer(
    scopes: &[Option<Scope>],
    current: SegvBlock,
    at: &Position,
    stacks: &[(usize, usize)],
) -> SegvBlock {
    let Some((top, below)) = scopes.split_last() else {
        return current;
    };
    let top = top.expect("live scope");
    if left(&top, at, stacks) {
        return answer(below, top.saved, at, stacks);
    }
    // Asked by the entry that opened it, on its alternate stack, or below
    // the shim's own intact frame: still inside.
    if top.entry == at.entry || top.alt.is_some() || top.shim {
        return current;
    }
    // On an ordinary stack below the trap's intact frame: still inside the
    // handler, or left by `siglongjmp` and deeper since. Known only where
    // both answer the same.
    if answer(below, top.saved, at, stacks) == current {
        current
    } else {
        SegvBlock::Unknown
    }
}

impl SegvMask {
    fn at(&mut self, at: &Position) -> SegvBlock {
        let stacks = &self.stacks[..self.known];
        while let Some(top) = self.depth.checked_sub(1).and_then(|top| self.scopes[top]) {
            if !left(&top, at, stacks) {
                break;
            }
            self.current = top.saved;
            self.depth -= 1;
        }
        answer(&self.scopes[..self.depth], self.current, at, stacks)
    }
    /// Guest code may run on `stack` while a scope is open.
    fn note(&mut self, stack: (usize, usize)) {
        if self.stacks[..self.known].contains(&stack) {
            return;
        }
        if self.known == STACKS {
            crate::trap_fatal(
                "more alternate stacks registered inside signal handlers under the counter \
                 trap than the shim tells apart for SIGSEGV's block: not modeled",
            );
        }
        self.stacks[self.known] = stack;
        self.known += 1;
    }
    /// Open a scope whose frame word is `canary`, whose guest code runs
    /// below `sp`, with `stack` the guest's alternate stack, if any.
    fn open(&mut self, canary: *mut u64, sp: usize, stack: Option<(usize, usize)>, shim: bool) {
        if self.depth == SCOPES {
            crate::trap_fatal(
                "signal handlers under the counter trap nest deeper than the shim tracks \
                 SIGSEGV's block for: not modeled",
            );
        }
        if self.depth == 0 {
            self.known = 0;
            if let Some(registered) = self.registered {
                self.note(registered);
            }
        }
        if let Some(stack) = stack {
            self.note(stack);
        }
        let alt = alternate(&self.stacks[..self.known], sp);
        let value = self.next;
        self.next = self.next.wrapping_add(2);
        // SAFETY: the caller's own frame word.
        unsafe { canary.write_volatile(value) };
        self.scopes[self.depth] = Some(Scope {
            entry: crate::panic_boundary::guest_entry().1,
            canary: canary as usize,
            value,
            sp,
            alt,
            shim,
            saved: self.current,
        });
        self.depth += 1;
    }
    /// The scope whose frame word is `canary` returned, and with it every
    /// scope opened inside it. Nothing if it was already found left.
    fn close(&mut self, canary: usize) {
        let open = &self.scopes[..self.depth];
        if let Some(index) = open
            .iter()
            .rposition(|scope| scope.is_some_and(|scope| scope.canary == canary))
        {
            self.current = open[index].expect("open scope").saved;
            self.depth = index;
        }
    }
}

/// Whether SIGSEGV is blocked for the guest code the running entry serves.
pub(super) fn blocked() -> SegvBlock {
    if SEGV.with_borrow(|segv| segv.depth) == 0 {
        return SEGV.with_borrow(|segv| segv.current);
    }
    let at = Position::guest();
    SEGV.with_borrow_mut(|segv| segv.at(&at))
}

/// Whether the thread has a scope to leave.
pub(super) fn scoped() -> bool {
    SEGV.with_borrow(|segv| segv.depth) != 0
}

/// The guest's own mask changes SIGSEGV's block to `state`.
pub(super) fn set(state: SegvBlock) {
    SEGV.with_borrow_mut(|segv| segv.current = state);
}

/// The guest registered `stack` as this thread's alternate stack (disabled:
/// it has none). Scopes it already left are found left first, from where it
/// is, so none of them keeps a stack counted.
pub(super) fn registered(stack: Stack) {
    let at = Position::guest();
    SEGV.with_borrow_mut(|segv| {
        if stack.flags & SS_DISABLE != 0 {
            segv.registered = None;
            return;
        }
        segv.registered = Some((stack.base, stack.size));
        if segv.depth != 0 {
            let _ = segv.at(&at);
        }
        if segv.depth != 0 {
            segv.note((stack.base, stack.size));
        }
    });
}

/// A frame's return left `stack` the kernel's alternate stack for the thread
/// (`restore_altstack` installs the frame's `uc_stack`, which its handler may
/// have edited): an enabled one the guest did not register is registered
/// now. A disabled one is not taken as the guest's: the kernel also reports
/// an `SS_AUTODISARM` stack disabled while a handler runs on it.
pub(super) fn restored(stack: Stack) {
    if stack.flags & SS_DISABLE == 0 {
        let known = SEGV.with_borrow(|segv| segv.registered);
        if known != Some((stack.base, stack.size)) {
            registered(stack);
        }
    }
}

/// After a delivery batch: the kernel's alternate stack is what the last
/// frame's return restored ([`restored`]).
pub(super) fn batch_returned() {
    if trap_routed(SIGSEGV) || front_installed() {
        restored(current_altstack());
    }
}

/// A scope opened in the frame that holds this guard, closed in place by
/// [`Scoped::close`] (or its drop). The scope is found by the address its
/// word had when it opened, so moving the guard can never lose it.
#[must_use]
pub(super) struct Scoped {
    canary: u64,
    /// Where `canary` was when the scope opened; 0 while none is open.
    at: usize,
}
impl Scoped {
    /// Opens nothing where the trap is not armed: the host holds SIGSEGV's
    /// block itself there.
    pub(super) fn new() -> Self {
        Self { canary: 0, at: 0 }
    }
    /// Open the scope. The guard stays where it is until it closes: its word
    /// is what tells a scope still running from one left.
    pub(super) fn open(&mut self) {
        if !trap_routed(SIGSEGV) {
            return;
        }
        let canary = &mut self.canary as *mut u64;
        let stack = current_altstack();
        let stack = (stack.flags & SS_DISABLE == 0).then_some((stack.base, stack.size));
        let sp = frames::guest_position(canary as usize);
        SEGV.with_borrow_mut(|segv| segv.open(canary, sp, stack, true));
        self.at = canary as usize;
    }
    /// The scope returned: the block is again what it opened under.
    pub(super) fn close(&mut self) {
        let at = std::mem::take(&mut self.at);
        if at != 0 {
            SEGV.with_borrow_mut(|segv| segv.close(at));
        }
    }
}
impl Drop for Scoped {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
pub(super) fn open_scopes() -> (usize, SegvBlock) {
    SEGV.with_borrow(|segv| (segv.depth, segv.current))
}

/// The frame a signal arrived on, as the C front or trap handler describes
/// it, and where the guest handler it runs goes.
#[repr(C)]
pub struct Frame {
    /// The interrupted stack pointer.
    sp: usize,
    /// The frame's `uc_stack`, which `rt_sigreturn` installs as the host
    /// registration; the guest handler sees its own registration there.
    stack: *mut Stack,
    /// A word every guest frame the handler runs is below: the C handler's
    /// own (in place), or the second word of the shim's slot on the guest's
    /// stack.
    canary: *mut u64,
    /// The frame's saved mask (`uc_sigmask`), which `rt_sigreturn` installs.
    mask: *mut u64,
    /// The private stack the C handler's frame stands above: nested frames
    /// go below it while the guest handler runs.
    floor: usize,
    /// Where the guest handler is called (its slot), or 0: in place.
    target: usize,
    /// The host registration while the guest handler runs.
    nested: Stack,
    /// The frame's `uc_stack` as the kernel saved it.
    host: Stack,
    /// The stack pointer the frame resumes at, once the handler returned.
    resume: usize,
    /// Where the guest handler runs, as the SIGSEGV scope compares it.
    position: usize,
}

#[cfg(test)]
impl Frame {
    /// A frame on no alternate stack for a fault at `sp`.
    pub(super) fn below(sp: usize, canary: *mut u64, mask: *mut u64) -> Self {
        static mut NONE: Stack = Stack {
            base: 0,
            flags: SS_DISABLE,
            size: 0,
        };
        Self {
            sp,
            stack: &raw mut NONE,
            canary,
            mask,
            floor: 0,
            target: 0,
            nested: Stack::default(),
            host: Stack::default(),
            resume: sp,
            position: canary as usize,
        }
    }
}

#[unsafe(no_mangle)]
/// The counter trap's SIGSEGV route: a counter read the trap declined is a
/// named stop before any route ([`patina_signal_fault`]).
///
/// # Safety
/// As [`patina_signal_fault`]'s, and `context` is the trap frame's ucontext.
#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn patina_tsc_route(
    _sig: i32,
    info: *const Info,
    context: *const c_void,
    frame: *mut Frame,
    handler: *mut Action,
) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if unsafe { (*info).code() } == SI_KERNEL {
        let context = context.cast::<libc::ucontext_t>();
        let pc = unsafe { (*context).uc_mcontext.gregs[libc::REG_RIP as usize] } as usize;
        crate::tsc::patina_tsc_declined(pc);
    }
    unsafe { patina_signal_fault(info, frame, handler) }
}

#[unsafe(no_mangle)]
/// A SIGSEGV the trap's handler did not answer as a counter read, with the
/// frame's siginfo. On [`FAULT_HANDLER`] the guest handler to run is written
/// to `handler` and the mask it runs under is installed; its return goes
/// through [`patina_signal_fault_return`].
///
/// # Safety
/// `info` names the trap frame's siginfo, `frame` describes that frame and
/// `handler` is writable storage for one action.
pub unsafe extern "C" fn patina_signal_fault(
    info: *const Info,
    frame: *mut Frame,
    handler: *mut Action,
) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (info, frame) = unsafe { (*info, &mut *frame) };
    let at = Position {
        sp: frames::guest_position(frame.sp),
        entry: crate::panic_boundary::guest_entry().1,
    };
    let sent = take_sent(SIGSEGV, &info);
    fault_entered(SIGSEGV, sent.is_some());
    let action = match sent {
        Some(action) => action,
        None => {
            // No kernel fault path uses such a code, and patina queued none.
            if info.code() <= 0 {
                crate::trap_fatal(
                    "a SIGSEGV sent from outside the run (another process's kill) reached \
                     the counter trap: not modeled",
                );
            }
            // `force_sig_info_to_task`: a fault the thread blocks takes the
            // default action.
            match SEGV.with_borrow_mut(|segv| segv.at(&at)) {
                SegvBlock::No => {}
                SegvBlock::Yes => return FAULT_DEFAULT,
                SegvBlock::Unknown => crate::trap_fatal(
                    "a SIGSEGV fault below a SIGSEGV handler that blocks it: a fault inside the \
                     handler (which the kernel takes as the default action) and one after a \
                     siglongjmp out of it cannot be told apart",
                ),
            }
            let mut state = lock_state();
            let action = state.signals.actions[usize::from(SIGSEGV)];
            // Ignored, it takes the default action too.
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
    let alt = enter(frame, action.flags);
    SEGV.with_borrow_mut(|segv| {
        segv.open(frame.canary, frame.position, alt, false);
        if action.flags & SA_NODEFER == 0 || action.mask & bit(SIGSEGV) != 0 {
            segv.current = SegvBlock::Yes;
        }
    });
    let before = read_mask();
    let running = host_mask(before | action.mask);
    if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
        task.mask = with_segv(running);
    }
    if running != before {
        install_mask(running);
    }
    unsafe { handler.write(action) };
    FAULT_HANDLER
}

#[unsafe(no_mangle)]
/// A guest handler [`patina_signal_fault`] or [`patina_fault_route`] named
/// returned to its fault handler's frame, whose saved mask the kernel
/// installs next. The containment signals
/// are kept out of it, as out of every frame; SIGSEGV's block is what the
/// fault interrupted, or blocked if the handler added it to the frame. The
/// signals the handler's mask held back are delivered as its return
/// unblocks them.
///
/// # Safety
/// `frame` describes the frame [`patina_signal_fault`] or
/// [`patina_fault_route`] was given.
pub unsafe extern "C" fn patina_signal_fault_return(frame: *const Frame) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let frame = unsafe { &*frame };
    let saved = unsafe { *frame.mask };
    let kept = host_mask(saved);
    if kept != saved {
        containment_kept_unblocked(saved & !kept);
        unsafe { frame.mask.write(kept) };
    }
    SEGV.with_borrow_mut(|segv| {
        segv.close(frame.canary as usize);
        if saved & bit(SIGSEGV) != 0 {
            segv.current = SegvBlock::Yes;
        }
    });
    // SAFETY: the frame's `uc_stack`, as the handler left it.
    let left_as = unsafe { *frame.stack };
    if frame.target != 0 {
        frames::leave(frame.target, left_as, frames::guest_position(frame.resume));
        // The host registration the frame's return installs.
        let host = frames::frame_return(frame.resume, frame.host);
        unsafe { frame.stack.write(host) };
    }
    restored(left_as);
    let me = current_task();
    let deliverable = {
        let mut state = lock_state();
        let Some(task) = state.signals.tasks.get_mut(&me) else {
            return;
        };
        task.mask = with_segv(kept);
        state.signals.has_deliverable(me)
    };
    if deliverable {
        install_mask(kept);
        deliver();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registration a thread's scopes start from: a `sigaltstack` that
    /// disables it leaves none, and a frame's return registers the enabled
    /// stack it restores (a handler's edited `uc_stack`), never a disabled
    /// one (an `SS_AUTODISARM` stack a handler still runs on).
    #[test]
    fn the_registration_follows_sigaltstack_and_frame_returns() {
        let stack = |base, flags| Stack {
            base,
            flags,
            size: 0x4000,
        };
        let (a, b, off) = (stack(0x10_000, 0), stack(0x20_000, 0), stack(0, SS_DISABLE));
        let set = |stack: Stack| (true, stack);
        let back = |stack: Stack| (false, stack);
        for (steps, expected) in [
            (&[set(a)][..], Some(a)),
            (&[set(a), set(off)][..], None),
            (&[set(a), back(off)][..], Some(a)),
            (&[set(a), back(b)][..], Some(b)),
        ] {
            SEGV.with_borrow_mut(|segv| segv.registered = None);
            for &(call, stack) in steps {
                if call {
                    registered(stack);
                } else {
                    restored(stack);
                }
            }
            let expected = expected.map(|stack| (stack.base, stack.size));
            assert_eq!(
                SEGV.with_borrow(|segv| segv.registered),
                expected,
                "{steps:x?}"
            );
        }
    }

    /// A stack pointer above a scope's frame has left it only on the frame's
    /// own stack: one on another stack is a handler the kernel moved there,
    /// and one on the ordinary stack has left a frame on an alternate stack.
    #[test]
    fn stack_pointers_are_compared_on_one_stack() {
        let mut word = 0u64;
        let canary = &mut word as *mut u64 as usize;
        let scope = |alt| Scope {
            entry: 1,
            canary,
            value: 0,
            sp: canary,
            alt,
            shim: true,
            saved: SegvBlock::No,
        };
        // An alternate stack above the frame's, another below it, and one
        // the frame is on.
        let above = (canary + 0x10_000, 0x10_000);
        let below = (canary - 0x20_000, 0x10_000);
        let around = (canary - 0x1000, 0x2000);
        for (frame, sp, stacks, expected) in [
            (None, above.0 + 0x8000, &[above][..], false),
            (None, canary + 0x100, &[above][..], true),
            (None, canary - 0x100, &[above][..], false),
            (Some(around), around.0 + 0x1800, &[around, above][..], true),
            (Some(around), canary - 0x100, &[around, above][..], false),
            (Some(around), above.0 + 0x8000, &[around, above][..], false),
            (Some(around), below.0 + 0x8000, &[around, below][..], false),
            (Some(around), canary + 0x4000, &[around][..], true),
        ] {
            let at = Position { sp, entry: 2 };
            assert_eq!(
                left(&scope(frame), &at, stacks),
                expected,
                "frame {frame:x?} sp {:#x}",
                sp - canary
            );
        }
    }
}
