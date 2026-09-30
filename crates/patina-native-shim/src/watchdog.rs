//! Native compute-only starvation is a terminal refusal, never a preemption.
//! The observer reads existing state under the normal lock order. No host clock,
//! atomic publication, or new counter is added to a scheduling point.

use std::ffi::{CStr, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Once, OnceLock};

use super::TaskId;
use patina_dst_runtime::RuntimeError;

pub(crate) const ENV: &str = "PATINA_COMPUTE_WATCHDOG_MS";
const DEFAULT_MS: u64 = 10_000;
static BOUND_MS: OnceLock<u64> = OnceLock::new();

pub(crate) fn configure() -> Result<(), RuntimeError> {
    let bound = super::parse_control_u64(ENV)?.unwrap_or(DEFAULT_MS);
    if bound == 0 || bound > 86_400_000 {
        return Err(RuntimeError::Config(format!(
            "{ENV} must be 1..=86400000 milliseconds"
        )));
    }
    BOUND_MS.get_or_init(|| bound);
    Ok(())
}

pub(crate) fn host_thread_self() -> usize {
    unsafe { (super::hostapi::get().host_pthread_self)() }
}

pub(crate) fn start() {
    static START: Once = Once::new();
    START.call_once(|| {
        let _ = super::hostapi::get();
        // dladdr may need a loader lock owned by the stopped guest. Prestart a
        // helper, so lookup cannot block the stop or allocate a thread at abort.
        for entry in [
            monitor as extern "C" fn(*mut c_void) -> *mut c_void,
            symbolize,
        ] {
            let mut handle = std::ptr::null_mut();
            let rc = unsafe {
                super::thread::spawn_host_thread(
                    &mut handle,
                    std::ptr::null(),
                    entry,
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                super::trap_fatal(&format!(
                    "compute watchdog host thread creation failed: {rc}"
                ));
            }
            let rc = unsafe { (super::hostapi::get().host_pthread_detach)(handle) };
            if rc != 0 {
                super::trap_fatal(&format!("compute watchdog host thread detach failed: {rc}"));
            }
        }
    });
}

#[derive(Default)]
struct Window {
    last: Option<((u64, TaskId), u64)>,
}
impl Window {
    // None is a missed lock; Some(None) is a confirmed ineligible state.
    fn observe(
        &mut self,
        observation: Option<Option<(u64, TaskId)>>,
        now: u64,
        bound: u64,
    ) -> Option<TaskId> {
        let candidate = observation?;
        let Some(candidate) = candidate else {
            self.last = None;
            return None;
        };
        let since = match self.last {
            Some((previous, since)) if previous == candidate => since,
            _ => now,
        };
        self.last = Some((candidate, since));
        (now.saturating_sub(since) >= bound).then_some(candidate.1)
    }
}

extern "C" fn monitor(_: *mut c_void) -> *mut c_void {
    platform::enter_observer();
    let _scope = super::panic_boundary::PanicScope::enter();
    let bound = *BOUND_MS.get_or_init(|| DEFAULT_MS);
    let poll = (bound / 4).clamp(1, 100);
    let mut window = Window::default();
    while !super::thread::main_returned() {
        platform::wait_ms(poll);
        let now = platform::monotonic_ms();
        let mut observed = false;
        super::thread::watchdog_observe(|context, handles| {
            observed = true;
            if let Some(stop) = context.replay_compute_stop_due() {
                let error = context.stop_compute_bound(stop.task);
                report_and_abort(&error, None);
            }
            let Some(task) = window.observe(Some(context.compute_watchdog_candidate()), now, bound)
            else {
                return;
            };
            // Both locks stay held: the guest cannot add a modeled effect or
            // change eligibility between commitment, export and termination.
            let handle = handles
                .iter()
                .find_map(|(handle, owner)| (*owner == task).then_some(*handle));
            let error = context.stop_compute_bound(task);
            report_and_abort(&error, handle);
        });
        if !observed {
            window.observe(None, now, bound);
        }
    }
    std::ptr::null_mut()
}

struct Text {
    bytes: [u8; 1024],
    len: usize,
}
impl std::fmt::Write for Text {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len + text.len();
        if end > self.bytes.len() {
            return Err(std::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
fn signed_hex(out: &mut impl std::fmt::Write, delta: isize) -> std::fmt::Result {
    write!(
        out,
        "{}{:#x}",
        if delta < 0 { '-' } else { '+' },
        delta.unsigned_abs()
    )
}

pub(crate) fn report_and_abort(error: &RuntimeError, handle: Option<usize>) -> ! {
    // No guest callback, deallocation, or stdio lock wait, even before sampling.
    super::flush_observed_stdio();
    use std::fmt::Write;
    let mut text = Text {
        bytes: [0; 1024],
        len: 0,
    };
    // The guest may have left a partial stderr line (including while locked).
    let _ = writeln!(text, "\n{error}");
    let _ = super::host_write_all(2, &text.bytes[..text.len]);
    text.len = 0;
    if let Some(pc) = handle.and_then(platform::sample_terminal_pc) {
        let anchor = super::patina_yield_point as *const () as usize;
        let _ = write!(
            text,
            "patina: compute-bound sampled_pc={pc:#x} patina_yield_point_delta="
        );
        let _ = signed_hex(&mut text, pc.wrapping_sub(anchor) as isize);
        let _ = writeln!(text);
        let _ = super::host_write_all(2, &text.bytes[..text.len]);
        text.len = 0;
        let mut named = false;
        for _ in 0..200 {
            if let Some(result) = SYMBOL.try_lock() {
                if let Some(symbol) = result.as_ref() {
                    if symbol.len != 0 {
                        if let Ok(name) = std::str::from_utf8(&symbol.name[..symbol.len]) {
                            let _ =
                                write!(text, "patina: sampled_symbol={name}+{:#x} ", symbol.offset);
                            if let Some(size) = symbol.size {
                                let _ = writeln!(text, "symbol_size={size} symbol_range=checked");
                            } else {
                                let _ = writeln!(
                                    text,
                                    "symbol_size=unavailable symbol_range=loader-nearest"
                                );
                            }
                            named = true;
                        }
                    }
                    break;
                }
            }
            platform::wait_ms(1);
        }
        if !named {
            let _ = writeln!(
                text,
                "patina: sampled_symbol=unavailable location=PC-only (loader has no confirmed symbol or lookup could not finish)"
            );
        }
    } else {
        let _ = writeln!(
            text,
            "patina: compute-bound sampled_pc=unavailable (replay boundary, blocked signal, or unavailable host sample)"
        );
    }
    let _ = super::host_write_all(2, &text.bytes[..text.len]);
    super::host_abort()
}

struct Symbol {
    name: [u8; 256],
    len: usize,
    offset: usize,
    size: Option<usize>,
}
static PC: AtomicUsize = AtomicUsize::new(0);
static SYMBOL: super::SpinMutex<Option<Symbol>> = super::SpinMutex::new(None);

#[cfg(any(target_os = "linux", test))]
fn symbol_contains(offset: usize, size: usize) -> bool {
    offset < size || (size == 0 && offset == 0)
}
fn lookup_symbol(pc: usize) -> Option<Symbol> {
    let host = super::hostapi::get();
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { (host.host_dladdr)(pc as *const c_void, &mut info) } == 0
        || info.dli_sname.is_null()
        || info.dli_saddr.is_null()
    {
        return None;
    }
    let offset = pc.checked_sub(info.dli_saddr as usize)?;
    #[cfg(target_os = "linux")]
    let size = {
        let mut entry = std::ptr::null_mut();
        if unsafe {
            (host.host_dladdr1)(
                pc as *const c_void,
                &mut info,
                &mut entry,
                1, // <dlfcn.h>: RTLD_DL_SYMENT (not exposed by libc).
            )
        } == 0
            || entry.is_null()
            || info.dli_sname.is_null()
            || info.dli_saddr.is_null()
        {
            return None;
        }
        let size = unsafe { (*entry.cast::<libc::Elf64_Sym>()).st_size as usize };
        if pc.checked_sub(info.dli_saddr as usize)? != offset || !symbol_contains(offset, size) {
            return None;
        }
        Some(size)
    };
    #[cfg(target_os = "macos")]
    let size = None;
    let name = unsafe { CStr::from_ptr(info.dli_sname) }.to_bytes();
    let mut result = Symbol {
        name: [0; 256],
        len: name.len(),
        offset,
        size,
    };
    if name.is_empty() || name.len() > result.name.len() {
        return None;
    }
    result.name[..name.len()].copy_from_slice(name);
    Some(result)
}
extern "C" fn symbolize(_: *mut c_void) -> *mut c_void {
    platform::enter_observer();
    while !super::thread::main_returned() {
        let pc = PC.load(Ordering::Acquire);
        if pc != 0 {
            let symbol = lookup_symbol(pc).unwrap_or(Symbol {
                name: [0; 256],
                len: 0,
                offset: 0,
                size: None,
            });
            *SYMBOL.lock() = Some(symbol);
            break;
        }
        platform::wait_ms(100);
    }
    std::ptr::null_mut()
}

/// Native context layouts and waits, using only the single HostApi alias table.
/// SIGSYS is borrowed AFTER export, never reserved during live execution.
mod platform {
    use super::*;
    pub(super) fn enter_observer() {
        // PR_SET_TSC is inherited. Private observers execute no guest code.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if unsafe {
            (super::super::hostapi::get().host_syscall)(
                libc::SYS_prctl,
                libc::PR_SET_TSC as _,
                libc::PR_TSC_ENABLE as _,
                0,
                0,
                0,
                0,
            )
        } != 0
        {
            super::super::trap_fatal("compute watchdog could not enable its private host clock");
        }
    }
    pub(super) fn monotonic_ms() -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe {
            (super::super::hostapi::get().host_clock_gettime)(libc::CLOCK_MONOTONIC, &mut time)
        } != 0
        {
            super::super::trap_fatal("compute watchdog host clock failed");
        }
        (time.tv_sec as u64).saturating_mul(1000) + time.tv_nsec as u64 / 1_000_000
    }
    #[cfg(target_os = "linux")]
    pub(super) fn wait_ms(ms: u64) {
        // A private futex word with no waker. Relative FUTEX_WAIT is monotonic
        // and predates supported glibc; no sem_clockwait version dependency.
        let word = 0u32;
        let deadline = monotonic_ms().saturating_add(ms);
        loop {
            let remaining = deadline.saturating_sub(monotonic_ms());
            if remaining == 0 {
                return;
            }
            let timeout = libc::timespec {
                tv_sec: (remaining / 1000) as _,
                tv_nsec: ((remaining % 1000) * 1_000_000) as _,
            };
            let rc = unsafe {
                (super::super::hostapi::get().host_syscall)(
                    libc::SYS_futex,
                    (&word as *const u32) as _,
                    (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as _,
                    0,
                    (&timeout as *const libc::timespec) as _,
                    0,
                    0,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error();
            if rc == -1 && errno == Some(libc::ETIMEDOUT) {
                return;
            }
            if rc != -1 || errno != Some(libc::EINTR) {
                super::super::trap_fatal("compute watchdog host wait failed");
            }
        }
    }
    #[cfg(target_os = "macos")]
    pub(super) fn wait_ms(ms: u64) {
        static SEM: OnceLock<usize> = OnceLock::new();
        let host = super::super::hostapi::get();
        let sem = *SEM.get_or_init(|| {
            let sem = unsafe { (host.dispatch_semaphore_create)(0) };
            if sem.is_null() {
                super::super::trap_fatal("compute watchdog semaphore initialization failed");
            }
            sem as usize
        });
        let deadline = unsafe { (host.host_dispatch_time)(0, (ms * 1_000_000) as i64) };
        if unsafe { (host.dispatch_semaphore_wait)(sem as *mut c_void, deadline) } == 0 {
            super::super::trap_fatal("compute watchdog semaphore unexpectedly signalled");
        }
    }
    extern "C" fn capture(_: i32, _: *mut libc::siginfo_t, context: *mut c_void) {
        let context = unsafe { &*context.cast::<libc::ucontext_t>() };
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let pc = context.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        let pc = context.uc_mcontext.pc as usize;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let pc = unsafe { (*context.uc_mcontext).__ss.__pc as usize };
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        let pc = unsafe { (*context.uc_mcontext).__ss.__rip as usize };
        PC.store(pc, Ordering::Release);
        loop {
            std::hint::spin_loop();
        }
    }
    pub(super) fn sample_terminal_pc(handle: usize) -> Option<usize> {
        let host = super::super::hostapi::get();
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = capture as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        if unsafe { (host.host_sigaction)(libc::SIGSYS, &action, std::ptr::null_mut()) } != 0 {
            return None;
        }
        if unsafe { (host.host_pthread_kill)(handle as libc::pthread_t, libc::SIGSYS) } != 0 {
            return None;
        }
        for _ in 0..50 {
            let pc = PC.load(Ordering::Acquire);
            if pc != 0 {
                return Some(pc);
            }
            wait_ms(1);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_offsets_and_loader_ranges_are_not_guesses() {
        for (delta, expected) in [(-0x5c6e36, "-0x5c6e36"), (42, "+0x2a"), (0, "+0x0")] {
            let mut out = String::new();
            signed_hex(&mut out, delta).unwrap();
            assert_eq!(out, expected);
        }
        let mut out = String::new();
        signed_hex(&mut out, isize::MIN).unwrap();
        assert_eq!(out, format!("-{:#x}", isize::MIN.unsigned_abs()));
        assert!(symbol_contains(0, 0));
        assert!(!symbol_contains(1, 0));
        assert!(symbol_contains(9, 10));
        assert!(!symbol_contains(10, 10));
        let pc = super::super::hostapi::get().host_read as *const () as usize;
        let symbol = lookup_symbol(pc).expect("loader must know its exported read vehicle");
        assert_ne!(symbol.len, 0);
        assert_eq!(symbol.offset, 0);
    }
    #[test]
    fn missed_locks_preserve_the_bound_but_progress_and_ineligibility_reset_it() {
        let mut window = Window::default();
        let task = TaskId(1);
        assert_eq!(window.observe(Some(Some((3, task))), 0, 100), None);
        assert_eq!(window.observe(Some(Some((3, task))), 25, 100), None);
        for now in [40, 60, 80, 110] {
            assert_eq!(window.observe(None, now, 100), None);
        }
        assert_eq!(window.observe(Some(Some((3, task))), 111, 100), Some(task));
        assert_eq!(window.observe(Some(Some((4, task))), 112, 100), None);
        assert_eq!(window.observe(Some(None), 180, 100), None);
        assert_eq!(window.observe(Some(Some((4, task))), 300, 100), None);
    }
}
