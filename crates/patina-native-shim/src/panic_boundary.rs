//! Panic ownership follows Rust ABI entries, not panic source paths. Guest
//! callbacks temporarily suspend ownership and can still catch their panics.
use patina_dst_abi::ChargeClass;
use std::cell::Cell;
#[cfg(any(test, feature = "planted-faults"))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Who owns the thread ([`IN_SHIM`]): guest code, a shim entry, or a trap
/// handler that delivers at its own C exit (see [`Owner::Exit`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Owner {
    Guest,
    /// A shim entry that took the thread from guest code, and everything it
    /// calls.
    Shim,
    /// A trap handler (`c/posix/init.c`) holds the thread and delivers at its
    /// own C exit: no Rust frame of the shim is between it and guest code.
    Exit,
    /// A shim entry the [`Owner::Exit`] holder called itself.
    ExitEntry,
    /// Whatever an [`Owner::ExitEntry`] calls. Under all three the C exit
    /// delivers what a delivery point leaves pending.
    ExitCalled,
}

thread_local! {
    static IN_SHIM: Cell<Owner> = const { Cell::new(Owner::Guest) };
    /// How many scopes, owning or suspended, this thread holds: every Rust
    /// frame of the shim's ABI entries (and the guest callbacks they suspend
    /// for) that is still on the stack. A frame a nonlocal exit discards
    /// never gives its scope back, so a count above the frames really live
    /// is the trace such an exit leaves. Only this thread updates it, each
    /// time in one read-modify-write ([`count`]), so a signal handler that
    /// interrupts an update (and leaves frames of its own behind) cannot
    /// erase its count; 64 bits never wrap, whatever a run abandons. Kept
    /// only for the detectors (a shim built with `planted-faults`, and the
    /// unit tests): every entry pays for it.
    #[cfg(any(test, feature = "planted-faults"))]
    static LIVE: AtomicU64 = const { AtomicU64::new(0) };
    /// How many suspended scopes this thread holds: shim Rust frames, live
    /// beneath the guest code they called (a callback, a delivery's
    /// handlers), that a delivery from there would run handlers over.
    /// 64 bits: suspended scopes a nonlocal exit discards stay counted,
    /// and no run abandons enough of them to wrap it to zero.
    static SUSPENDED: Cell<u64> = const { Cell::new(0) };
    /// Where the guest's stack stood when the shim last took the thread from
    /// it: the address below which guest code was running. A trap handler
    /// that holds the thread ([`claim`]) knows it exactly: its frame's.
    #[cfg(target_os = "linux")]
    static GUEST_SP: Cell<usize> = const { Cell::new(0) };
    /// Which of this thread's guest-interrupting entries is running: each
    /// time the shim takes the thread from guest code it is a new one.
    #[cfg(target_os = "linux")]
    static ENTRY: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

// Only POSIX-interposed binaries need this policy. Bare prefixed-C links have
// no public abort interposer and may intentionally omit the host alias vehicle.
#[cfg(not(test))]
static POLICY_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[must_use]
pub(crate) struct PanicScope {
    previous: Owner,
    #[cfg(target_os = "linux")]
    previous_sp: usize,
    #[cfg(target_os = "linux")]
    previous_entry: u64,
    /// The guest call this entry began, if it took the thread from guest
    /// code as one.
    call: Option<crate::charge::Began>,
    #[cfg(not(test))]
    panicking_on_entry: bool,
    // Ownership belongs to the calling host thread, never another thread.
    _thread: std::marker::PhantomData<*mut ()>,
}
impl PanicScope {
    /// A door's entry: a guest call, charged as a system call when it takes
    /// the thread from guest code.
    pub(crate) fn enter() -> Self {
        Self::set(true, Some(ChargeClass::Syscall))
    }
    /// A door's entry for `op`, charged as that operation's class when it
    /// takes the thread from guest code.
    pub(crate) fn enter_op(op: crate::charge::Op) -> Self {
        Self::set(true, Some(op.class()))
    }
    /// The trapped system call `nr`'s entry, charged as its operation's
    /// class ([`crate::charge::syscall_class`]).
    #[cfg(target_os = "linux")]
    pub(crate) fn enter_syscall(nr: i64) -> Self {
        Self::set(true, Some(crate::charge::syscall_class(nr)))
    }
    /// An entry the C side calls around a guest call (glue: a boundary note,
    /// a cancellation bracket, trap decode or completion, thread start): it
    /// takes the thread but is no guest call of its own, so it is not charged.
    pub(crate) fn enter_glue() -> Self {
        Self::set(true, None)
    }
    /// Hand the thread to guest code the shim calls (a callback, a
    /// delivery's handlers) while this frame stays live beneath it.
    pub(crate) fn suspend() -> Suspended {
        // Counted before the thread is the guest's, and (in [`Suspended`]'s
        // drop) uncounted only once it is the shim's again: a signal
        // arriving at any point between never finds guest ownership with
        // the suspended frame uncounted.
        SUSPENDED.with(|suspended| suspended.set(suspended.get() + 1));
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let mut scope = Self::set(false, None);
        // The call this frame belongs to gets its class back when the guest
        // code returns, whatever that code's own calls left behind (one a
        // handler's `siglongjmp` abandoned never ends itself).
        scope.call = Some(crate::charge::interrupted());
        Suspended {
            scope: std::mem::ManuallyDrop::new(scope),
        }
    }
    fn set(value: bool, charge: Option<ChargeClass>) -> Self {
        count(1);
        let previous = IN_SHIM.with(|scope| {
            let previous = scope.get();
            scope.set(match (value, previous) {
                (false, _) => Owner::Guest,
                (true, Owner::Guest | Owner::Shim) => Owner::Shim,
                (true, Owner::Exit) => Owner::ExitEntry,
                (true, Owner::ExitEntry | Owner::ExitCalled) => Owner::ExitCalled,
            });
            previous
        });
        // A guest call is the entry that takes the thread from guest code,
        // or the first one a trap holder makes for it (a trapped system call,
        // a libc door its C thunk holds the thread around): the holder's own
        // C is glue.
        let call = charge
            .filter(|_| value && matches!(previous, Owner::Guest | Owner::Exit))
            .map(crate::charge::begin);
        #[cfg(target_os = "linux")]
        let (previous_sp, previous_entry) = (GUEST_SP.get(), ENTRY.get().0);
        #[cfg(target_os = "linux")]
        if value && previous == Owner::Guest {
            // The shim never hands the thread to guest code (a suspended
            // scope) while it holds a shim lock. A handler that interrupted
            // shim code runs, and leaves by `siglongjmp`, with the thread still
            // the shim's, so it never reaches this: relocking a lock it left
            // held is the lock's own self-deadlock stop.
            #[cfg(not(test))]
            if crate::in_shim_critical() {
                let _ = crate::host_write_all(
                    2,
                    b"patina: guest code entered the shim while this thread holds a shim lock: \
                      not modeled\n",
                );
                crate::host_abort();
            }
            let here = 0u8;
            took(std::hint::black_box(&here) as *const u8 as usize);
        }
        Self {
            previous,
            call,
            #[cfg(target_os = "linux")]
            previous_sp,
            #[cfg(target_os = "linux")]
            previous_entry,
            #[cfg(not(test))]
            panicking_on_entry: std::thread::panicking(),
            _thread: std::marker::PhantomData,
        }
    }
}
/// A suspended scope ([`PanicScope::suspend`]), counted in [`SUSPENDED`]
/// while it lives; only these pay for the count.
#[must_use]
pub(crate) struct Suspended {
    scope: std::mem::ManuallyDrop<PanicScope>,
}

impl Drop for Suspended {
    fn drop(&mut self) {
        // SAFETY: dropped once, here; the field is never used again.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.scope) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        SUSPENDED.with(|suspended| suspended.set(suspended.get() - 1));
    }
}

impl Drop for PanicScope {
    fn drop(&mut self) {
        // A guest may replace the process-global hook. Unwinding out of shim
        // code still cannot publish a successful trace through std's abort.
        #[cfg(not(test))]
        if POLICY_INSTALLED.load(std::sync::atomic::Ordering::Acquire)
            && in_shim()
            && !self.panicking_on_entry
            && std::thread::panicking()
        {
            let _ = crate::host_write_all(
                2,
                b"patina native shim panic: unwinding an owned boundary\n",
            );
            crate::host_abort();
        }
        if let Some(call) = self.call {
            crate::charge::end(call);
        }
        IN_SHIM.with(|scope| scope.set(self.previous));
        count(u64::MAX);
        #[cfg(target_os = "linux")]
        {
            GUEST_SP.set(self.previous_sp);
            ENTRY.set((self.previous_entry, ENTRY.get().1));
        }
    }
}

/// The shim took the thread from guest code whose stack pointer was `sp`.
#[cfg(target_os = "linux")]
fn took(sp: usize) {
    GUEST_SP.set(sp);
    let (_, next) = ENTRY.get();
    ENTRY.set((next + 1, next + 1));
}

/// Add `delta` (wrapping: `u64::MAX` takes one away) to this thread's
/// [`LIVE`] in one read-modify-write a signal cannot split. No other thread
/// touches the count, so on x86-64 that is one plain `add`: a `lock`ed one
/// costs a full barrier on every entry. Elsewhere it is a relaxed atomic add.
#[inline(always)]
fn count(delta: u64) {
    #[cfg(not(any(test, feature = "planted-faults")))]
    let _ = delta;
    #[cfg(any(test, feature = "planted-faults"))]
    LIVE.with(|live| {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `live` is this thread's own, live for the thread; one
        // `add` to it is a single instruction, which a signal cannot split.
        unsafe {
            core::arch::asm!(
                "add qword ptr [{live}], {delta}",
                live = in(reg) live.as_ptr(),
                delta = in(reg) delta,
                options(nostack),
            );
        }
        #[cfg(not(target_arch = "x86_64"))]
        live.fetch_add(delta, Relaxed);
    });
}

pub(crate) fn in_shim() -> bool {
    IN_SHIM.with(Cell::get) != Owner::Guest
}

/// Whether the thread's holder delivers at its own C exit: a delivery
/// point under it leaves the signal pending for that exit.
#[cfg(target_os = "linux")]
pub(crate) fn exit_owned() -> bool {
    matches!(
        IN_SHIM.with(Cell::get),
        Owner::Exit | Owner::ExitEntry | Owner::ExitCalled
    )
}

/// Whether shim Rust frames are suspended beneath the running code (a
/// delivery from Rust whose handlers run, a guest callback): a trap exit
/// there would deliver over them.
#[cfg(target_os = "linux")]
pub(crate) fn frames_suspended() -> bool {
    SUSPENDED.with(Cell::get) != 0
}

/// Whether the running entry was called by the C exit of the trap handler
/// holding the thread itself, with no shim Rust frame between: the only
/// caller a delivery's steps may have.
#[cfg(target_os = "linux")]
pub(crate) fn entered_by_trap_exit() -> bool {
    IN_SHIM.with(Cell::get) == Owner::ExitEntry
}

/// The scopes this thread holds besides the caller's `own`: the shim Rust
/// frames, owning or suspended, beneath the caller (see [`LIVE`]).
#[cfg(any(test, feature = "planted-faults"))]
pub(crate) fn scopes_beneath(own: u64) -> u64 {
    LIVE.with(|live| live.load(Relaxed)) - own
}

/// The scopes the calling guest code has beneath it: none, unless a shim
/// frame below it is still live or was discarded without giving its scope
/// back. For the signal-frame detectors (a shim built with `planted-faults`).
#[cfg(feature = "planted-faults")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_planted_live_scopes() -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    scopes_beneath(1)
}

/// A fault handler takes the thread for the shim before it does anything
/// else, so a fault in its own glue (a stack switch, a prologue) is known to
/// be the shim's. `sp` is the interrupted stack pointer. Answers whether shim
/// code already owned the thread.
#[cfg(target_os = "linux")]
pub(crate) fn claim(sp: usize) -> bool {
    let owned = IN_SHIM.with(|scope| scope.replace(Owner::Exit)) != Owner::Guest;
    if !owned {
        took(sp);
    }
    owned
}

/// Where the guest's stack stood when the shim took the thread from it, and
/// which entry that was.
#[cfg(target_os = "linux")]
pub(crate) fn guest_entry() -> (usize, u64) {
    (GUEST_SP.get(), ENTRY.get().0)
}

/// Hand the thread back to the guest code a fault handler interrupted.
#[cfg(target_os = "linux")]
pub(crate) fn release() {
    IN_SHIM.with(|scope| scope.set(Owner::Guest));
}

/// The entry a trap exit hands the thread to guest handlers from, and takes
/// it back into ([`hand_over`], [`take_back`]): as a suspended scope keeps it.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Held {
    sp: usize,
    entry: u64,
}

/// The trap exit's release runs guest handlers: the thread is theirs until
/// [`take_back`], and the entry it served is kept for then.
#[cfg(target_os = "linux")]
pub(crate) fn hand_over() -> Held {
    let (sp, entry) = guest_entry();
    IN_SHIM.with(|scope| scope.set(Owner::Guest));
    Held { sp, entry }
}

/// The handlers returned: the trap exit holds the thread again, serving the
/// entry it served before [`hand_over`].
#[cfg(target_os = "linux")]
pub(crate) fn take_back(held: Held) {
    IN_SHIM.with(|scope| scope.set(Owner::Exit));
    GUEST_SP.set(held.sp);
    ENTRY.set((held.entry, ENTRY.get().1));
}

// The library test harness owns its hook and deliberately catches test panics.
#[cfg(test)]
pub(crate) fn install() {}

#[cfg(not(test))]
pub(crate) fn install() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        // Resolve before installing a hook that needs these private vehicles.
        let _ = crate::hostapi::get();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !in_shim() && !crate::in_shim_critical() {
                previous(info);
                return;
            }
            use std::fmt::Write;
            struct HostDiagnostic;
            impl Write for HostDiagnostic {
                fn write_str(&mut self, value: &str) -> std::fmt::Result {
                    let _ = crate::host_write_all(2, value.as_bytes());
                    Ok(())
                }
            }
            // Formatting writes directly to the host, without captured stdio,
            // allocation, runtime locks, or the public guest abort interposer.
            let _ = writeln!(HostDiagnostic, "patina native shim panic: {info}");
            crate::host_abort();
        }));
        POLICY_INSTALLED.store(true, std::sync::atomic::Ordering::Release);
    });
}

#[cfg(test)]
mod tests {
    // Class pairing: real-ABI panic injection in native_signals exercises the
    // fatal policy; this checks nesting/callback ownership on every platform.
    #[test]
    fn panic_scopes_restore_ownership_across_callbacks_and_threads() {
        use super::{PanicScope, in_shim, scopes_beneath};
        assert!(!in_shim());
        assert_eq!(scopes_beneath(0), 0);
        let outer = PanicScope::enter();
        assert!(in_shim());
        {
            let _guest = PanicScope::suspend();
            assert!(!in_shim());
            {
                let _entry = PanicScope::enter();
                assert!(in_shim());
                // Owning and suspended scopes alike are live frames.
                assert_eq!(scopes_beneath(1), 2);
            }
            assert!(!in_shim());
        }
        assert!(in_shim());
        std::thread::spawn(|| {
            assert!(!in_shim());
            assert_eq!(scopes_beneath(0), 0);
        })
        .join()
        .unwrap();
        drop(outer);
        assert!(!in_shim());
        assert_eq!(scopes_beneath(0), 0);
        // A trap handler's hold (`claim`) delivers at its own C exit: entries
        // under it leave delivery points pending, and only one it called
        // itself is a delivery step's caller.
        #[cfg(target_os = "linux")]
        std::thread::spawn(|| {
            use super::{claim, entered_by_trap_exit, exit_owned, hand_over, release, take_back};
            assert!(!claim(0x1000) && exit_owned());
            {
                let _step = PanicScope::enter();
                assert!(exit_owned() && entered_by_trap_exit());
                let _inner = PanicScope::enter();
                assert!(exit_owned() && !entered_by_trap_exit());
            }
            let held = hand_over();
            assert!(!in_shim() && !exit_owned());
            {
                let _door = PanicScope::enter();
                assert!(in_shim() && !exit_owned() && !entered_by_trap_exit());
            }
            take_back(held);
            assert!(exit_owned());
            release();
            assert!(!in_shim());
        })
        .join()
        .unwrap();
        // A scope a nonlocal exit discards stays counted: its drop is what
        // gives it back. (On a thread of its own, which it leaves owned.)
        std::thread::spawn(|| {
            std::mem::forget(PanicScope::enter());
            assert_eq!(scopes_beneath(0), 1);
        })
        .join()
        .unwrap();
    }
}
