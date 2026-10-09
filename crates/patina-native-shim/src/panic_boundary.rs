//! Panic ownership follows Rust ABI entries, not panic source paths. Guest
//! callbacks temporarily suspend ownership and can still catch their panics.
use std::cell::Cell;
#[cfg(any(test, feature = "planted-faults"))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

thread_local! {
    static IN_SHIM: Cell<bool> = const { Cell::new(false) };
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
    /// Where the guest's stack stood when the shim last took the thread from
    /// it: the address below which guest code was running. A door that knows
    /// the interrupted stack pointer exactly (a trap frame's) notes it first.
    #[cfg(target_os = "linux")]
    static GUEST_SP: Cell<usize> = const { Cell::new(0) };
    #[cfg(target_os = "linux")]
    static NOTED_SP: Cell<usize> = const { Cell::new(0) };
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
    previous: bool,
    #[cfg(target_os = "linux")]
    previous_sp: usize,
    #[cfg(target_os = "linux")]
    previous_entry: u64,
    #[cfg(not(test))]
    panicking_on_entry: bool,
    // Ownership belongs to the calling host thread, never another thread.
    _thread: std::marker::PhantomData<*mut ()>,
}
impl PanicScope {
    pub(crate) fn enter() -> Self {
        Self::set(true)
    }
    pub(crate) fn suspend() -> Self {
        Self::set(false)
    }
    fn set(value: bool) -> Self {
        count(1);
        let previous = IN_SHIM.with(|scope| scope.replace(value));
        #[cfg(target_os = "linux")]
        let (previous_sp, previous_entry) = (GUEST_SP.get(), ENTRY.get().0);
        // A door's noted stack pointer belongs to the entry it calls next,
        // whoever owned the thread then: never to a later one.
        #[cfg(target_os = "linux")]
        let noted = if value { NOTED_SP.replace(0) } else { 0 };
        #[cfg(target_os = "linux")]
        if value && !previous {
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
            took(if noted != 0 {
                noted
            } else {
                std::hint::black_box(&here) as *const u8 as usize
            });
        }
        Self {
            previous,
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
    IN_SHIM.with(Cell::get)
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
    NOTED_SP.set(0);
    let owned = IN_SHIM.with(|scope| scope.replace(true));
    if !owned {
        took(sp);
    }
    owned
}

/// The exact stack pointer of the guest code the next entry interrupts, from
/// a door that has it (the SIGSYS frame's).
#[cfg(target_os = "linux")]
pub(crate) fn note_guest_sp(sp: usize) {
    NOTED_SP.set(sp);
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
    IN_SHIM.with(|scope| scope.set(false));
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
