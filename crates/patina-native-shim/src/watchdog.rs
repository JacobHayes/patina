//! Native no-boundary-progress is a terminal refusal, never a preemption.
//! Wall time cannot distinguish computation from untracked host blocking.
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
        // Prepare before either unmanaged helper can contend on Rust's Once.
        // Darwin's contended Once parks through public dispatch semaphores,
        // which belong to the guest scheduler, not these private host threads.
        platform::prepare_wait();
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
                let handle = handles
                    .iter()
                    .find_map(|(handle, owner)| (*owner == stop.task).then_some(*handle));
                let error = context.stop_compute_bound(stop.task);
                report_and_abort(&error, handle, None);
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
            report_and_abort(&error, handle, Some(bound));
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

pub(crate) fn report(error: &RuntimeError) {
    use std::fmt::Write;
    let mut text = Text {
        bytes: [0; 1024],
        len: 0,
    };
    // The guest may have left a partial stderr line (including while locked).
    let _ = writeln!(text, "\n{error}");
    let _ = super::host_write_all(2, &text.bytes[..text.len]);
}

pub(crate) fn report_synchronous(error: &RuntimeError) {
    report(error);
    // The recorded terminal prefix was reached at a guest boundary, not by
    // the off-baton observer. Do not signal/sample the thread stopping itself.
    let _ = super::host_write_all(
        2,
        b"patina: compute-bound sampled_pc=unavailable reason=synchronous-stop\n",
    );
}

pub(crate) fn report_and_abort(
    error: &RuntimeError,
    handle: Option<usize>,
    observed_bound_ms: Option<u64>,
) -> ! {
    // Off baton: never call C stream salvage or wait for guest-owned storage.
    super::flush_observed_stdio();
    report(error);
    use std::fmt::Write;
    let mut text = Text {
        bytes: [0; 1024],
        len: 0,
    };
    if let Some(bound) = observed_bound_ms {
        let _ = writeln!(
            text,
            "patina: no scheduling point for at least {bound} ms of host wall time (includes descheduling and untracked host blocking)"
        );
        let _ = super::host_write_all(2, &text.bytes[..text.len]);
        text.len = 0;
    }
    let sample = handle
        .ok_or(SampleFailure::NoTarget)
        .and_then(platform::sample_terminal_pc);
    if let Ok(pc) = sample {
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
            if let Some(result) = SYMBOL.try_lock()
                && let Some(symbol) = result.as_ref()
            {
                if symbol.len != 0
                    && let Ok(name) = std::str::from_utf8(&symbol.name[..symbol.len])
                {
                    let _ = write!(text, "patina: sampled_symbol={name}+{:#x} ", symbol.offset);
                    if let Some(size) = symbol.size {
                        let _ = writeln!(text, "symbol_size={size} symbol_range=checked");
                    } else {
                        let _ =
                            writeln!(text, "symbol_size=unavailable symbol_range=loader-nearest");
                    }
                    named = true;
                }
                break;
            }
            platform::wait_ms(1);
        }
        if !named {
            let _ = writeln!(
                text,
                "patina: sampled_symbol=unavailable location=PC-only (loader has no confirmed symbol or lookup could not finish)"
            );
        }
    } else if let Err(reason) = sample {
        let _ = writeln!(
            text,
            "patina: compute-bound sampled_pc=unavailable reason={reason}"
        );
    }
    let _ = super::host_write_all(2, &text.bytes[..text.len]);
    super::host_abort()
}

#[derive(Clone, Copy)]
enum SampleFailure {
    NoTarget,
    Install(i32),
    Send(i32),
    Deadline,
}
impl std::fmt::Display for SampleFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTarget => out.write_str("no-target-handle"),
            Self::Install(code) => write!(out, "sigaction-error-{code}"),
            Self::Send(code) => write!(out, "pthread-kill-error-{code}"),
            Self::Deadline => out.write_str("sample-deadline"),
        }
    }
}

struct Symbol {
    name: [u8; 256],
    len: usize,
    offset: usize,
    size: Option<usize>,
}
struct Sample {
    target: AtomicUsize,
    pc: AtomicUsize,
}
impl Sample {
    const fn new() -> Self {
        Self {
            target: AtomicUsize::new(0),
            pc: AtomicUsize::new(0),
        }
    }
    fn capture(&self, thread: usize, pc: usize) -> bool {
        if self.target.load(Ordering::Acquire) != thread || pc == 0 {
            return false;
        }
        self.pc
            .compare_exchange(0, pc, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    }
}
static SAMPLE: Sample = Sample::new();
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
        let pc = SAMPLE.pc.load(Ordering::Acquire);
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
        // Helpers never deliver guest handlers, in particular while holding
        // ThreadRuntime/Context. pthread_sigmask leaves libc's internal and
        // unmaskable signals alone. sigset_t contains only integer bit storage.
        let all = unsafe {
            let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            set.as_mut_ptr().write_bytes(0xff, 1);
            set.assume_init()
        };
        if unsafe {
            (super::super::hostapi::get().host_pthread_sigmask)(
                libc::SIG_BLOCK,
                &all,
                std::ptr::null_mut(),
            )
        } != 0
        {
            super::super::trap_fatal("compute watchdog could not block helper signals");
        }
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
    #[cfg(target_os = "linux")]
    pub(super) fn prepare_wait() {}

    #[cfg(target_os = "macos")]
    static SEM: OnceLock<usize> = OnceLock::new();

    #[cfg(target_os = "macos")]
    pub(super) fn prepare_wait() {
        let host = super::super::hostapi::get();
        SEM.get_or_init(|| {
            let sem = unsafe { (host.dispatch_semaphore_create)(0) };
            if sem.is_null() {
                super::super::trap_fatal("compute watchdog semaphore initialization failed");
            }
            sem as usize
        });
    }

    #[cfg(target_os = "macos")]
    pub(super) fn wait_ms(ms: u64) {
        let host = super::super::hostapi::get();
        let Some(&sem) = SEM.get() else {
            super::super::trap_fatal(
                "compute watchdog wait was not prepared before helper startup",
            );
        };
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
        if !SAMPLE.capture(host_thread_self(), pc) {
            return;
        }
        loop {
            std::hint::spin_loop();
        }
    }
    pub(super) fn sample_terminal_pc(handle: usize) -> Result<usize, SampleFailure> {
        SAMPLE.target.store(handle, Ordering::Release);
        let host = super::super::hostapi::get();
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = capture as *const () as usize;
        // On the sampled thread's private signal stack (Linux), like every
        // shim handler's frame: the guest's own stack may be a few KiB with no
        // room for a kernel frame. Where none is registered (macOS), the
        // frame is on the stack it interrupted, as natively.
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        if unsafe { (host.host_sigaction)(libc::SIGSYS, &action, std::ptr::null_mut()) } != 0 {
            return Err(SampleFailure::Install(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ));
        }
        let rc = unsafe { (host.host_pthread_kill)(handle as libc::pthread_t, libc::SIGSYS) };
        if rc != 0 {
            return Err(SampleFailure::Send(rc));
        }
        await_pc(50, || SAMPLE.pc.load(Ordering::Acquire), || wait_ms(1))
            .ok_or(SampleFailure::Deadline)
    }
}

fn await_pc(
    wait_budget: usize,
    mut read: impl FnMut() -> usize,
    mut wait: impl FnMut(),
) -> Option<usize> {
    for _ in 0..wait_budget {
        let pc = read();
        if pc != 0 {
            return Some(pc);
        }
        wait();
    }
    // The target can acknowledge during the FINAL wait. Returning None here
    // without this acquire discards a delivered sample and aborts its owner.
    let pc = read();
    (pc != 0).then_some(pc)
}

#[cfg(test)]
#[path = "watchdog/delivery_tests.rs"]
mod delivery_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_sample_only_pins_its_target_and_first_acknowledgement() {
        let sample = Sample::new();
        sample.target.store(42, Ordering::Release);
        assert!(!sample.capture(7, 0x777));
        assert_eq!(sample.pc.load(Ordering::Acquire), 0);
        assert!(sample.capture(42, 0x123));
        assert!(!sample.capture(42, 0x456));
        assert_eq!(sample.pc.load(Ordering::Acquire), 0x123);
    }

    #[test]
    fn observer_blocks_guest_signals() {
        std::thread::spawn(|| unsafe {
            let empty: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()),
                0
            );
            platform::enter_observer();
            let mut mask: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGSYS] {
                assert_eq!(
                    libc::sigismember(&mask, signal),
                    1,
                    "observer left signal {signal} unblocked"
                );
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn terminal_sample_observes_acknowledgement_during_the_last_wait() {
        for budget in [1, 2, 7, 50, 51, 127] {
            let waits = std::cell::Cell::new(0);
            let published = std::cell::Cell::new(0);
            assert_eq!(
                await_pc(
                    budget,
                    || published.get(),
                    || {
                        waits.set(waits.get() + 1);
                        if waits.get() == budget {
                            published.set(0x1234);
                        }
                    }
                ),
                Some(0x1234),
                "acknowledgement in final wait, budget={budget}"
            );
            assert_eq!(waits.get(), budget);
        }
        for budget in [0, 1, 2, 7, 50, 51, 127] {
            let waits = std::cell::Cell::new(0);
            assert_eq!(await_pc(budget, || 0, || waits.set(waits.get() + 1)), None);
            assert_eq!(waits.get(), budget, "must not exceed the wait budget");
            assert_eq!(
                await_pc(budget, || 0x1234, || panic!("already acknowledged")),
                Some(0x1234)
            );
        }
    }

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
