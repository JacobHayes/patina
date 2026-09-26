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
//! stop ([`patina_trap_shim_fault`]), never the guest's. The same holds on
//! every Linux arch for SIGBUS, and for SIGSEGV where the trap is not armed:
//! a front handler (`patina_fault_front`, `c/posix/init.c`) owns their host
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
//! frame, or with its frame overwritten. On an ordinary stack, below an
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

/// The C layer put the fault front handler at `handler` before SIGBUS, and
/// before SIGSEGV where the counter trap does not own it.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fault_front_installed(handler: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    FRONT.store(handler, Ordering::Relaxed);
}

/// Whether the fault front handler owns `sig`'s host disposition.
pub(super) fn front_routed(sig: u8) -> bool {
    matches!(sig, SIGBUS | SIGSEGV) && !trap_routed(sig) && FRONT.load(Ordering::Relaxed) != 0
}

/// The host action that stands for a guest's `action` on a front-routed
/// signal: the front handler, with the guest action's flags, mask and
/// restorer, so the kernel builds and blocks as for the guest's handler.
/// `SA_RESETHAND` resets the virtual action only: the front handler stays.
pub(super) fn front_action(action: Action) -> Action {
    let mut front = Action {
        handler: FRONT.load(Ordering::Relaxed),
        flags: action.flags & !SA_RESETHAND | SA_SIGINFO,
        ..action
    };
    // A default or ignored action returns from the front handler too.
    #[cfg(target_arch = "x86_64")]
    if matches!(action.handler, SIG_DFL | SIG_IGN) && action.flags & SA_RESTORER == 0 {
        front.flags |= SA_RESTORER;
        front.restorer = RESTORER.load(Ordering::Relaxed);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = &mut front;
    front
}

/// A SIGBUS, or a SIGSEGV the counter trap does not own, reached the front
/// handler from guest code. On [`FAULT_HANDLER`] the guest handler to run
/// from the frame is written to `handler`; on [`FAULT_DEFAULT`] the retried
/// instruction takes the fault under the default action.
///
/// # Safety
/// `info` names the frame's siginfo and `handler` writable storage for one
/// action.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fault_route(
    sig: i32,
    info: *const Info,
    handler: *mut Action,
) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let sig = sig as u8;
    let info = unsafe { *info };
    let action = match take_sent(sig, &info) {
        Some(action) => action,
        None => {
            if info.code() <= 0 {
                crate::trap_fatal(
                    "a SIGBUS or SIGSEGV sent from outside the run (another process's kill) \
                     reached the fault handler: not modeled",
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
    unsafe { handler.write(action) };
    FAULT_HANDLER
}

/// A planted fault in shim code, for the containment tests: a read inside a
/// shim entry of an unmapped address (`bus` 0, SIGSEGV) or of a file mapping
/// past the file's end (`bus` 1, SIGBUS). Said on the host's stderr first,
/// so the stop it ends in is known to be this one.
#[cfg(feature = "planted-faults")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_planted_fault(bus: i32) -> u8 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    use patina_dst_syscalls::Syscall;
    let address = if bus == 0 {
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

/// The trap handler's first act: take the thread for the shim, with the
/// interrupted stack pointer. Answers 1 when guest code was interrupted, 0
/// when shim code already owned the thread (an entry, a shim lock held, or
/// the trap's own glue), whose fault is [`patina_trap_shim_fault`].
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_enter(sp: usize) -> i32 {
    let owned = crate::panic_boundary::claim(sp) || crate::in_shim_critical();
    i32::from(!owned)
}

/// The trap hands the thread back to the guest code it interrupted.
#[unsafe(no_mangle)]
pub extern "C" fn patina_trap_leave() {
    crate::panic_boundary::release();
}

/// The SIGSYS door's interrupted stack pointer, for the entry it calls next.
#[unsafe(no_mangle)]
pub extern "C" fn patina_note_guest_sp(sp: usize) {
    crate::panic_boundary::note_guest_sp(sp);
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
    // Guest code the shim runs while it owns the thread (a guest allocator
    // it calls, say) may read the counter: the trap cannot answer it there.
    #[cfg(target_arch = "x86_64")]
    let counter = trap_routed(SIGSEGV)
        && info.signo() == SIGSEGV
        && info.code() == SI_KERNEL
        && crate::tsc::counter_read_at(pc);
    #[cfg(not(target_arch = "x86_64"))]
    let counter = false;
    if counter {
        line.text(
            b"patina: a timestamp-counter read while the shim owned the thread (guest code it \
              ran, an allocator say): not modeled: signal ",
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
    /// The action a SIGSEGV or SIGBUS [`deliver`] is about to queue captured
    /// at its dequeue, with the instance's siginfo: its frame runs that one,
    /// as the kernel's does, whatever a sibling handler of the same batch
    /// installs meanwhile.
    static SENT: [Cell<Option<(Action, Info)>>; 2] = const { [Cell::new(None), Cell::new(None)] };
    /// While the trap serves a counter read off the alternate stack
    /// ([`with_altstack_below`]): the guest's host mask the read interrupted.
    static SERVING: Cell<Option<u64>> = const { Cell::new(None) };
    static SEGV: RefCell<SegvMask> = const {
        RefCell::new(SegvMask {
            current: SegvBlock::No,
            scopes: [None; SCOPES],
            depth: 0,
            next: 0x5e67_5c09_e000_0001,
        })
    };
}

/// The next `sig` (SIGSEGV or SIGBUS) this thread takes is the one
/// [`deliver`] queues, with the action captured at its dequeue.
pub(super) fn send(sig: u8, action: Action, info: &Info) {
    SENT.with(|sent| sent[usize::from(sig == SIGBUS)].set(Some((action, *info))));
}
/// The action captured for the `sig` this thread takes with `info`, if it is
/// the one [`deliver`] queued: a genuine fault is not, nor is anything once
/// an upper handler left that frame unrun by `siglongjmp`.
fn take_sent(sig: u8, info: &Info) -> Option<Action> {
    SENT.with(|sent| sent[usize::from(sig == SIGBUS)].take())
        .filter(|(_, sent)| info.code() <= 0 && sent.words[..3] == info.words[..3])
        .map(|(action, _)| action)
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
/// every signal but the containment ones and SIGBUS (whose front handler
/// names a fault in the shim's own code) is held blocked (the
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
    let held = host_mask(!bit(SIGBUS));
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
    /// A word of the frame that encloses the scope and everything it runs:
    /// a stack pointer above it has left the scope.
    canary: usize,
    /// What was written there.
    value: u64,
    /// The alternate stack the frame is on, if it is on one.
    alt: Option<(usize, usize)>,
    /// Opened by shim code (a delivery batch, a temporary mask), whose own
    /// frames the guest code it runs is below.
    shim: bool,
    /// The state the scope's return restores.
    saved: SegvBlock,
}

const SCOPES: usize = 16;

struct SegvMask {
    current: SegvBlock,
    scopes: [Option<Scope>; SCOPES],
    depth: usize,
    next: u64,
}

/// Where guest code runs: its stack pointer, the alternate stack, and the
/// shim entry serving it.
#[derive(Clone, Copy)]
struct Position {
    sp: usize,
    alt: Option<(usize, usize)>,
    entry: u64,
}

/// The kernel's `on_sig_stack`.
fn on(sp: usize, (base, size): (usize, usize)) -> bool {
    sp > base && sp - base <= size
}

impl Position {
    /// The guest code the running shim entry interrupted.
    fn guest() -> Self {
        let stack = kernel_altstack();
        let (sp, entry) = crate::panic_boundary::guest_entry();
        Self {
            sp,
            alt: (stack.flags & SS_DISABLE == 0).then_some((stack.base, stack.size)),
            entry,
        }
    }
}

/// Whether guest code at `at` has provably left `scope`.
fn left(scope: &Scope, at: &Position) -> bool {
    if at.entry == scope.entry {
        return false;
    }
    let comparable = match scope.alt {
        // Off the frame's alternate stack, nothing the scope runs is running.
        Some(alt) if !on(at.sp, alt) => return true,
        Some(_) => true,
        // An ordinary stack's frame cannot be compared from an alternate one.
        None => !at.alt.is_some_and(|alt| on(at.sp, alt)),
    };
    if comparable && at.sp > scope.canary {
        return true;
    }
    // Overwritten: what ran there since has left the scope.
    !crate::uaccess::read::<u64>(scope.canary).is_ok_and(|value| value == scope.value)
}

/// The state at `at` under `scopes` (none of whose tops is provably left).
fn answer(scopes: &[Option<Scope>], current: SegvBlock, at: &Position) -> SegvBlock {
    let Some((top, below)) = scopes.split_last() else {
        return current;
    };
    let top = top.expect("live scope");
    if left(&top, at) {
        return answer(below, top.saved, at);
    }
    // Asked by the entry that opened it, on its alternate stack, or below
    // the shim's own intact frame: still inside.
    if top.entry == at.entry || top.alt.is_some() || top.shim {
        return current;
    }
    // On an ordinary stack below the trap's intact frame: still inside the
    // handler, or left by `siglongjmp` and deeper since. Known only where
    // both answer the same.
    if answer(below, top.saved, at) == current {
        current
    } else {
        SegvBlock::Unknown
    }
}

impl SegvMask {
    fn at(&mut self, at: &Position) -> SegvBlock {
        while let Some(top) = self.depth.checked_sub(1).and_then(|top| self.scopes[top]) {
            if !left(&top, at) {
                break;
            }
            self.current = top.saved;
            self.depth -= 1;
        }
        answer(&self.scopes[..self.depth], self.current, at)
    }
    fn open(&mut self, canary: *mut u64, alt: Option<(usize, usize)>, shim: bool) {
        if self.depth == SCOPES {
            crate::trap_fatal(
                "signal handlers under the counter trap nest deeper than the shim tracks \
                 SIGSEGV's block for: not modeled",
            );
        }
        let value = self.next;
        self.next = self.next.wrapping_add(2);
        // SAFETY: the caller's own frame word.
        unsafe { canary.write_volatile(value) };
        self.scopes[self.depth] = Some(Scope {
            entry: crate::panic_boundary::guest_entry().1,
            canary: canary as usize,
            value,
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
        let stack = kernel_altstack();
        let alt = (stack.flags & SS_DISABLE == 0)
            .then_some((stack.base, stack.size))
            .filter(|alt| on(canary as usize, *alt));
        SEGV.with_borrow_mut(|segv| segv.open(canary, alt, true));
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

/// The trap frame a SIGSEGV arrived on, as the C handler describes it.
#[repr(C)]
pub struct Frame {
    /// The interrupted stack pointer.
    sp: usize,
    /// The alternate stack the kernel saved in the frame (`uc_stack`).
    stack: Stack,
    /// A word of the C handler's own frame: every guest handler it calls runs
    /// below it.
    canary: *mut u64,
    /// The frame's saved mask (`uc_sigmask`), which `rt_sigreturn` installs.
    mask: *mut u64,
}

#[cfg(test)]
impl Frame {
    /// A frame on no alternate stack for a fault at `sp`.
    pub(super) fn below(sp: usize, canary: *mut u64, mask: *mut u64) -> Self {
        Self {
            sp,
            stack: Stack::default(),
            canary,
            mask,
        }
    }
}

/// A SIGSEGV the trap's handler did not answer as a counter read, with the
/// frame's siginfo. On [`FAULT_HANDLER`] the guest handler to run is written
/// to `handler` and the mask it runs under is installed; its return goes
/// through [`patina_signal_fault_return`].
///
/// # Safety
/// `info` names the trap frame's siginfo, `frame` describes that frame and
/// `handler` is writable storage for one action.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_fault(
    info: *const Info,
    frame: *const Frame,
    handler: *mut Action,
) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (info, frame) = unsafe { (*info, &*frame) };
    let alt = (frame.stack.flags & SS_DISABLE == 0).then_some((frame.stack.base, frame.stack.size));
    let at = Position {
        sp: frame.sp,
        alt,
        entry: crate::panic_boundary::guest_entry().1,
    };
    let action = match take_sent(SIGSEGV, &info) {
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
    #[cfg(target_arch = "x86_64")]
    if action.flags & SA_RESTORER == 0 || action.restorer != RESTORER.load(Ordering::Relaxed) {
        crate::trap_fatal(
            "a SIGSEGV handler registered with a restorer of its own (a raw sigaction) under \
             the counter trap: its return is not modeled",
        );
    }
    let canary_alt = alt.filter(|alt| on(frame.canary as usize, *alt));
    SEGV.with_borrow_mut(|segv| {
        segv.open(frame.canary, canary_alt, false);
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

/// A guest handler [`patina_signal_fault`] named returned to the trap's
/// frame, whose saved mask the kernel installs next. The containment signals
/// are kept out of it, as out of every frame; SIGSEGV's block is what the
/// fault interrupted, or blocked if the handler added it to the frame. The
/// signals the handler's mask held back are delivered as its return
/// unblocks them.
///
/// # Safety
/// `frame` describes the trap frame [`patina_signal_fault`] was given.
#[unsafe(no_mangle)]
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
