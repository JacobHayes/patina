//! SUD rows — signals and process control: `rt_sigaction` (SIGSYS re-registration
//! is fatal), and `prctl`, whose only routed option is `PR_GET_AUXV` served from
//! the shim's scrubbed auxv.

use super::*;

/// The one `prctl(2)` option the dispatch table routes: `PR_GET_AUXV` (Linux
/// 6.4 and later). rustix's `linux_raw` backend calls `prctl(PR_GET_AUXV, buf,
/// size, 0, 0)` to read the aux vector during init. Read as an `unsigned int`
/// exactly as the kernel does (`option = (unsigned int) arg`); see
/// [`prctl_option`].
pub(super) const PR_GET_AUXV: u32 = 0x4155_5856;

/// The shim's own **scrubbed** auxv region, captured once at init by the C
/// arming path (`patina_sud_scrub_auxv`): the base pointer of the initial-stack
/// aux array and its byte length through the terminating `AT_NULL` pair
/// (inclusive). OWNED by Rust and written by C — the same C→Rust ownership
/// direction as [`crate::PATINA_SUD_ARMED`], so the lib's own test binary (which
/// links no C) still defines the symbols. The `PR_GET_AUXV` dispatch row copies
/// from here so a raw `prctl(PR_GET_AUXV)` serves the SAME determinized auxv the
/// shim already produced in memory — `AT_RANDOM` replaced with seed-derived
/// bytes and `AT_SYSINFO_EHDR` renamed to `AT_IGNORE` — instead of the kernel's
/// pristine `saved_auxv`, which would reintroduce the entropy / vDSO escape
/// (SUD-DESIGN.md §6, §9). `0` until C captures it; a trap seeing `0` fails
/// closed rather than serve garbage (see [`sys_prctl`]).
#[unsafe(no_mangle)]
pub static PATINA_SUD_AUXV_BASE: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub static PATINA_SUD_AUXV_LEN: AtomicUsize = AtomicUsize::new(0);

pub(super) fn sys_rt_sigaction(signum: i64) -> i64 {
    // SIGSYS registration by the guest would replace the dispatch handler:
    // containment over. Fatal (the raw door of the §7.5 SIGSYS hardening; the
    // symbol door is the interposed sigaction/signal in patina_posix.c).
    const SIGSYS: i64 = 31;
    if signum == SIGSYS {
        crate::trap_fatal(
            "SUD trapped rt_sigaction(SIGSYS): a guest may not re-register the syscall-dispatch \
             handler — doing so would disable deterministic containment",
        );
    }
    // No ambient signals exist, so registering any other handler is a
    // deterministic success no-op that records nothing (mirrors the allowlist
    // stance for bare sigaction/signal).
    0
}

/// Read a `prctl` option register as the kernel does. The kernel's prctl entry
/// is `SYSCALL_DEFINE5(prctl, int, option, …)` and immediately narrows it to an
/// `unsigned int` for its option dispatch (`option = (unsigned int) arg`), so a
/// caller's upper 32 register bits — sign-extended by hand asm or zero-extended
/// by rustix — never affect the comparison. Truncating to `u32` recovers that
/// exact view (mirrors [`arg_fd`]'s treatment of `int` fd args).
#[inline]
pub(super) fn prctl_option(reg: u64) -> u32 {
    reg as u32
}

/// Serve `PR_GET_AUXV` from the shim's captured, already-scrubbed auxv `saved`,
/// mirroring the kernel's `prctl_get_auxv` (kernel/sys.c) byte-for-byte EXCEPT
/// the source is our determinized auxv rather than the kernel's pristine
/// `saved_auxv`:
///  - `arg4`/`arg5` nonzero ⇒ `-EINVAL` (the kernel rejects a non-zero tail).
///  - copy `min(user_size, saved.len())` bytes into the user buffer.
///  - return the FULL auxv byte length (`saved.len()`, NOT the copied count) —
///    the value rustix uses to size a second, exact-fit buffer (its dynamic path
///    asserts the re-query returns that same length) and, in the static path,
///    the slice length it then walks until `AT_NULL`. Because `saved` runs
///    through the terminating `AT_NULL` pair inclusively, a full copy always
///    contains the terminator rustix's unbounded `AuxPointer` walk stops on.
pub(super) fn pr_get_auxv_copy(
    saved: &[u8],
    user_buf: *mut u8,
    user_size: usize,
    arg4: u64,
    arg5: u64,
) -> i64 {
    if arg4 != 0 || arg5 != 0 {
        return -EINVAL;
    }
    let copy = user_size.min(saved.len());
    if copy > 0 {
        if user_buf.is_null() {
            // The kernel's copy_to_user would fault on a bad/absent buffer.
            return -EFAULT;
        }
        // SAFETY: `user_buf` is the guest's buffer, valid for at least
        // `user_size >= copy` bytes; `saved` is the shim-owned scrubbed auxv,
        // valid for its whole length. The regions never overlap (distinct
        // allocations: guest buffer vs. the initial-stack auxv).
        unsafe {
            std::ptr::copy_nonoverlapping(saved.as_ptr(), user_buf, copy);
        }
    }
    saved.len() as i64
}

/// `prctl(2)`: the ONLY routed option is `PR_GET_AUXV`. Every other option is
/// the process/escape class (`PR_SET_SECCOMP`, `PR_SET_SYSCALL_USER_DISPATCH`,
/// `PR_SET_NAME`, …) and must never reach the host — it fails closed with a
/// named, diagnosable abort exactly like an unmapped syscall.
pub(super) fn sys_prctl(option_reg: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    let option = prctl_option(option_reg);
    if option != PR_GET_AUXV {
        crate::trap_fatal(&format!(
            "SUD trapped prctl(option={option:#x}): only PR_GET_AUXV is a deterministic route. Every \
             other prctl option is the process/escape class (PR_SET_SECCOMP, \
             PR_SET_SYSCALL_USER_DISPATCH, PR_SET_NAME, …) and fails closed — routing it would let a \
             guest reconfigure the process behind the deterministic runtime"
        ));
    }
    let base = PATINA_SUD_AUXV_BASE.load(Ordering::Relaxed);
    let len = PATINA_SUD_AUXV_LEN.load(Ordering::Relaxed);
    if base == 0 || len == 0 {
        // Init never captured the auxv: refuse rather than serve the kernel's
        // pristine (un-scrubbed, vDSO/AT_RANDOM-leaking) auxv or return 0/garbage.
        crate::trap_fatal(
            "SUD trapped prctl(PR_GET_AUXV) but the shim never captured the scrubbed auxv at init: \
             refusing to serve auxv bytes (serving the kernel's pristine saved_auxv would reintroduce \
             the AT_RANDOM entropy and AT_SYSINFO_EHDR vDSO escapes)",
        );
    }
    // SAFETY: `base`/`len` describe the shim's own scrubbed auxv region on the
    // initial stack, captured once during init and never mutated thereafter, so
    // the slice is valid for the whole (synchronous) dispatch.
    let saved = unsafe { std::slice::from_raw_parts(base as *const u8, len) };
    pr_get_auxv_copy(saved, arg2 as *mut u8, arg3 as usize, arg4, arg5)
}
