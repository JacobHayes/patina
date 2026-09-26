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

const PR_SET_NAME: u32 = 15;
const PR_GET_NAME: u32 = 16;
const PR_SET_PDEATHSIG: u32 = 1;
const PR_GET_PDEATHSIG: u32 = 2;
const PR_GET_DUMPABLE: u32 = 3;
const PR_SET_DUMPABLE: u32 = 4;
const PR_SET_NO_NEW_PRIVS: u32 = 38;
const PR_GET_NO_NEW_PRIVS: u32 = 39;
const PR_SET_TIMERSLACK: u32 = 29;
const PR_GET_TIMERSLACK: u32 = 30;
const PR_SET_VMA: u32 = 0x53564d41;
const PR_SET_THP_DISABLE: u32 = 41;
const PR_GET_THP_DISABLE: u32 = 42;

const DEFAULT_TIMERSLACK_NS: u64 = 50_000;
const SIGRTMAX: u64 = 64;

#[derive(Clone, Copy)]
struct PrctlState {
    pdeathsig: u32,
    dumpable: u32,
    no_new_privs: bool,
    timerslack_ns: u64,
    /// `MMF_DISABLE_THP` as the guest last set it. The host process runs with
    /// THP off whatever the guest asks (`__libc_start_main`), so residency
    /// stays per base page.
    thp_disabled: bool,
}

impl PrctlState {
    const fn new() -> Self {
        Self {
            pdeathsig: 0,
            dumpable: 1,
            no_new_privs: false,
            timerslack_ns: DEFAULT_TIMERSLACK_NS,
            thp_disabled: true,
        }
    }
}

static PRCTL_STATE: Mutex<PrctlState> = Mutex::new(PrctlState::new());

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

fn prctl_get_auxv(arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
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

/// `PR_SET_NAME`: name the calling thread, reading at most 15 bytes.
fn prctl_set_name(user_name: u64) -> i64 {
    if user_name == 0 {
        return -EFAULT;
    }
    let mut name = [0u8; 15];
    let mut len = 0;
    // SAFETY: mirrors the kernel copy_from_user shape for this per-thread
    // row. A bad non-null pointer may still fault like the real kernel access;
    // the conformance row exercises the deterministic valid/null cases.
    let src = user_name as *const u8;
    while len < name.len() {
        let value = unsafe { *src.add(len) };
        if value == 0 {
            break;
        }
        name[len] = value;
        len += 1;
    }
    crate::thread::sched::set_current_name(&name[..len]);
    0
}

/// `PR_GET_NAME`: the calling thread's name, into a 16-byte buffer.
fn prctl_get_name(user_name: u64) -> i64 {
    if user_name == 0 {
        return -EFAULT;
    }
    let name = crate::thread::sched::current_name();
    // SAFETY: `user_name` is the caller-provided 16-byte buffer for PR_GET_NAME.
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), user_name as *mut u8, name.len());
    }
    0
}

fn prctl_get_pdeathsig(state: &PrctlState, user_ptr: u64) -> i64 {
    if user_ptr == 0 {
        return -EFAULT;
    }
    // SAFETY: `user_ptr` is the caller-provided int*.
    unsafe {
        (user_ptr as *mut i32).write(state.pdeathsig as i32);
    }
    0
}

/// `prctl(2)`: model the process-local options owned by the signals/process
/// conformance family and keep PR_GET_AUXV on its scrubbed auxv route. Other
/// options fail with EINVAL, matching the family oracle's unknown-option row and
/// never reaching the host process.
pub(super) fn sys_prctl(option_reg: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    let option = prctl_option(option_reg);
    match option {
        PR_GET_AUXV => return prctl_get_auxv(arg2, arg3, arg4, arg5),
        // Per-thread state, in the thread runtime's lock (never under
        // `PRCTL_STATE`'s).
        PR_SET_NAME => return prctl_set_name(arg2),
        PR_GET_NAME => return prctl_get_name(arg2),
        _ => {}
    }

    let mut state = PRCTL_STATE.lock().unwrap();
    match option {
        PR_SET_VMA => 0,
        PR_SET_THP_DISABLE if arg3 != 0 || arg4 != 0 || arg5 != 0 => -EINVAL,
        PR_SET_THP_DISABLE => {
            state.thp_disabled = arg2 != 0;
            0
        }
        PR_GET_THP_DISABLE if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 => -EINVAL,
        PR_GET_THP_DISABLE => i64::from(state.thp_disabled),
        PR_SET_PDEATHSIG => {
            if arg2 > SIGRTMAX {
                -EINVAL
            } else {
                state.pdeathsig = arg2 as u32;
                0
            }
        }
        PR_GET_PDEATHSIG => prctl_get_pdeathsig(&state, arg2),
        PR_GET_DUMPABLE => state.dumpable as i64,
        PR_SET_DUMPABLE => match arg2 {
            0 | 1 => {
                state.dumpable = arg2 as u32;
                0
            }
            _ => -EINVAL,
        },
        PR_GET_NO_NEW_PRIVS => i64::from(state.no_new_privs),
        PR_SET_NO_NEW_PRIVS => {
            if arg2 == 1 && arg3 == 0 && arg4 == 0 && arg5 == 0 {
                state.no_new_privs = true;
                0
            } else {
                -EINVAL
            }
        }
        PR_GET_TIMERSLACK => state.timerslack_ns as i64,
        PR_SET_TIMERSLACK => {
            state.timerslack_ns = if arg2 == 0 {
                DEFAULT_TIMERSLACK_NS
            } else {
                arg2
            };
            0
        }
        _ => -EINVAL,
    }
}

/// `wait4(2)` in the kernel's order (kernel/exit.c `kernel_wait4`): an
/// option bit outside `WNOHANG|WUNTRACED|WCONTINUED|__WNOTHREAD|__WCLONE|
/// __WALL` is `EINVAL` and a pid of `INT_MIN` `ESRCH`, both before any child
/// is looked for; the virtual process has no child, so the rest is `ECHILD`.
pub(super) fn sys_wait4(pid: u64, options: u64) -> i64 {
    const WNOHANG: u32 = 0x0000_0001;
    const WUNTRACED: u32 = 0x0000_0002;
    const WCONTINUED: u32 = 0x0000_0008;
    const __WNOTHREAD: u32 = 0x2000_0000;
    const __WALL: u32 = 0x4000_0000;
    const __WCLONE: u32 = 0x8000_0000;
    const ALLOWED: u32 = WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;
    if (options as u32) & !ALLOWED != 0 {
        -EINVAL
    } else if pid as i32 == i32::MIN {
        -ESRCH
    } else {
        -ECHILD
    }
}

pub(super) fn sys_waitid(options: u64) -> i64 {
    const WNOHANG: u32 = 0x0000_0001;
    const WSTOPPED: u32 = 0x0000_0002;
    const WEXITED: u32 = 0x0000_0004;
    const WCONTINUED: u32 = 0x0000_0008;
    const WNOWAIT: u32 = 0x0100_0000;
    const __WNOTHREAD: u32 = 0x2000_0000;
    const __WALL: u32 = 0x4000_0000;
    const __WCLONE: u32 = 0x8000_0000;
    const ALLOWED: u32 =
        WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | __WNOTHREAD | __WALL | __WCLONE;
    const WAIT_CLASSES: u32 = WSTOPPED | WEXITED | WCONTINUED;

    let options = options as u32;
    if (options & !ALLOWED) != 0 || (options & WAIT_CLASSES) == 0 {
        -EINVAL
    } else {
        -ECHILD
    }
}

pub(super) fn sys_kill(pid: i64, sig: i64) -> i64 {
    unsafe {
        generate_signal(
            GenerationTarget::Process { pid: pid as i32 },
            sig as i32,
            GenerationInfo::User,
        )
    }
}
pub(super) fn sys_tgkill(tgid: i64, tid: i64, sig: i64) -> i64 {
    unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(tgid as i32),
                tid: tid as i32,
            },
            sig as i32,
            GenerationInfo::Thread,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_prctl_state() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        let guard = SERIAL.lock().unwrap();
        *PRCTL_STATE.lock().unwrap() = PrctlState::new();
        guard
    }

    #[test]
    fn prctl_no_new_privs_accepts_only_one_with_zero_tail() {
        let _serial = reset_prctl_state();
        assert_eq!(sys_prctl(PR_GET_NO_NEW_PRIVS as u64, 0, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_SET_NO_NEW_PRIVS as u64, 0, 0, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_SET_NO_NEW_PRIVS as u64, 1, 1, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_GET_NO_NEW_PRIVS as u64, 0, 0, 0, 0), 1);
        assert_eq!(sys_prctl(PR_SET_NO_NEW_PRIVS as u64, 0, 0, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_GET_NO_NEW_PRIVS as u64, 0, 0, 0, 0), 1);
    }

    #[test]
    fn prctl_dumpable_refuses_two() {
        let _serial = reset_prctl_state();
        assert_eq!(sys_prctl(PR_GET_DUMPABLE as u64, 0, 0, 0, 0), 1);
        assert_eq!(sys_prctl(PR_SET_DUMPABLE as u64, 0, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_GET_DUMPABLE as u64, 0, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_SET_DUMPABLE as u64, 1, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_GET_DUMPABLE as u64, 0, 0, 0, 0), 1);
        assert_eq!(sys_prctl(PR_SET_DUMPABLE as u64, 2, 0, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_SET_DUMPABLE as u64, 999, 0, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_GET_DUMPABLE as u64, 0, 0, 0, 0), 1);
    }

    #[test]
    fn prctl_pdeathsig_range() {
        let _serial = reset_prctl_state();
        let mut value = -1i32;
        for sig in 0_u64..=64 {
            assert_eq!(sys_prctl(PR_SET_PDEATHSIG as u64, sig, 0, 0, 0), 0);
            assert_eq!(
                sys_prctl(
                    PR_GET_PDEATHSIG as u64,
                    (&mut value as *mut i32) as u64,
                    0,
                    0,
                    0,
                ),
                0
            );
            assert_eq!(value, sig as i32);
        }
        assert_eq!(sys_prctl(PR_SET_PDEATHSIG as u64, 65, 0, 0, 0), -EINVAL);
        assert_eq!(sys_prctl(PR_GET_PDEATHSIG as u64, 0, 0, 0, 0), -EFAULT);
    }

    #[test]
    fn prctl_timerslack_zero_restores_default() {
        let _serial = reset_prctl_state();
        assert_eq!(sys_prctl(PR_GET_TIMERSLACK as u64, 0, 0, 0, 0), 50_000);
        assert_eq!(sys_prctl(PR_SET_TIMERSLACK as u64, 123_456, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_GET_TIMERSLACK as u64, 0, 0, 0, 0), 123_456);
        assert_eq!(sys_prctl(PR_SET_TIMERSLACK as u64, 0, 0, 0, 0), 0);
        assert_eq!(sys_prctl(PR_GET_TIMERSLACK as u64, 0, 0, 0, 0), 50_000);
    }

    #[test]
    fn wait_rows_answer_echild_and_einval() {
        let any = (-1i64) as u64;
        assert_eq!(sys_wait4(any, 0), -ECHILD);
        assert_eq!(sys_wait4(any, 0x0000_0001 | 0x4000_0000), -ECHILD); // WNOHANG|__WALL
        assert_eq!(sys_wait4(any, 0x100), -EINVAL);
        assert_eq!(sys_wait4(any, 0x0000_0004), -EINVAL); // WEXITED is waitid's
        assert_eq!(sys_wait4(i32::MIN as u64, 0), -ESRCH);
        assert_eq!(sys_wait4(i32::MIN as u64, 0x100), -EINVAL); // options first
        assert_eq!(sys_waitid(0x0000_0004), -ECHILD); // WEXITED
        assert_eq!(sys_waitid(0x0000_0004 | 0x0000_0001), -ECHILD); // WEXITED|WNOHANG
        assert_eq!(sys_waitid(0), -EINVAL);
        assert_eq!(sys_waitid(0x0001_0000), -EINVAL);
        assert_eq!(sys_waitid(0x4000_0000), -EINVAL); // __WALL alone lacks an event class
    }
}
