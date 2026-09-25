//! Shared handler state for the signal-family scenarios (`use
//! crate::signals as support;`): counting handlers that record the signal, the
//! `siginfo` sender fields and the tid they ran on, sigset helpers, and bounded
//! unobserved waits.

use libc::*;

/// glibc's `SIGRTMIN`: the kernel's first realtime signal (32) past the two
/// glibc reserves for itself; the same number on every Linux architecture.
pub const FIRST_RT: c_int = 34;
/// The realtime signal after [`FIRST_RT`].
pub const SECOND_RT: c_int = 35;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

pub static COUNT: AtomicUsize = AtomicUsize::new(0);
pub static LAST_SIG: AtomicI32 = AtomicI32::new(0);
pub static LAST_CODE: AtomicI32 = AtomicI32::new(0);
pub static LAST_PID: AtomicI32 = AtomicI32::new(0);
pub static LAST_UID: AtomicI32 = AtomicI32::new(0);
pub static LAST_INT: AtomicI32 = AtomicI32::new(0);
/// The tid (`gettid()`) of the thread the last handler ran on.
pub static HANDLER_TID: AtomicI32 = AtomicI32::new(0);
/// The signals delivered, in handler order (up to eight).
pub static ORDER: [AtomicI32; 8] = [const { AtomicI32::new(0) }; 8];
/// Per delivery: whether SIGUSR1 (bit 0) and SIGUSR2 (bit 1) were blocked in
/// the thread's mask when the handler was entered (the frame's mask).
pub static ENTRY_MASK: [AtomicI32; 8] = [const { AtomicI32::new(-1) }; 8];

pub extern "C" fn handler(sig: c_int) {
    note(sig);
}

/// # Safety
///
/// `info` is null or the `siginfo_t` the kernel hands a `SA_SIGINFO` handler.
pub unsafe extern "C" fn info_handler(sig: c_int, info: *mut siginfo_t, _: *mut c_void) {
    note(sig);
    if !info.is_null() {
        unsafe {
            LAST_CODE.store((*info).si_code, Ordering::SeqCst);
            LAST_PID.store((*info).si_pid(), Ordering::SeqCst);
            LAST_UID.store((*info).si_uid() as i32, Ordering::SeqCst);
            if (*info).si_code == SI_QUEUE {
                LAST_INT.store(
                    (*info).si_value().sival_ptr as usize as i32,
                    Ordering::SeqCst,
                );
            }
        }
    }
}

fn note(sig: c_int) {
    // Every fact is stored BEFORE the count moves: a scenario on another thread
    // waits on `COUNT` and then reads the facts, so the count is the publish.
    let index = COUNT.load(Ordering::SeqCst);
    LAST_SIG.store(sig, Ordering::SeqCst);
    HANDLER_TID.store(gettid(), Ordering::SeqCst);
    if index < ORDER.len() {
        ORDER[index].store(sig, Ordering::SeqCst);
        let mut cur = empty_set();
        unsafe {
            pthread_sigmask(SIG_BLOCK, std::ptr::null(), &mut cur);
        }
        let bits = i32::from(has(&cur, SIGUSR1)) | (i32::from(has(&cur, SIGUSR2)) << 1);
        ENTRY_MASK[index].store(bits, Ordering::SeqCst);
    }
    COUNT.store(index + 1, Ordering::SeqCst);
}

/// The frame masks recorded at each handler entry, as `(usr1_blocked,
/// usr2_blocked)` pairs in delivery order.
pub fn entry_masks() -> Vec<(bool, bool)> {
    ENTRY_MASK
        .iter()
        .map(|slot| slot.load(Ordering::SeqCst))
        .take(COUNT.load(Ordering::SeqCst).min(ENTRY_MASK.len()))
        .map(|bits| (bits & 1 != 0, bits & 2 != 0))
        .collect()
}

pub fn order() -> Vec<i32> {
    ORDER
        .iter()
        .map(|slot| slot.load(Ordering::SeqCst))
        .take(COUNT.load(Ordering::SeqCst).min(ORDER.len()))
        .collect()
}

pub fn count() -> usize {
    COUNT.load(Ordering::SeqCst)
}

pub fn empty_set() -> sigset_t {
    unsafe {
        let mut set: sigset_t = std::mem::zeroed();
        sigemptyset(&mut set);
        set
    }
}

pub fn one_set(sig: c_int) -> sigset_t {
    unsafe {
        let mut set = empty_set();
        sigaddset(&mut set, sig);
        set
    }
}

pub fn set_of(sigs: &[c_int]) -> sigset_t {
    unsafe {
        let mut set = empty_set();
        for sig in sigs {
            sigaddset(&mut set, *sig);
        }
        set
    }
}

/// The `siginfo_t` glibc's `sigqueue` fills: `SI_QUEUE` from `pid`/`uid`
/// with `value` as its `sival_int`.
pub fn queued_info(pid: pid_t, uid: uid_t, sig: c_int, value: i32) -> siginfo_t {
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    #[allow(deprecated)]
    {
        // The union starts at offset 16: _pad[0] is padding, then
        // si_pid, si_uid, si_value.
        info._pad[1] = pid;
        info._pad[2] = uid as i32;
        info._pad[3] = value;
    }
    info
}

pub fn has(set: &sigset_t, sig: c_int) -> bool {
    unsafe { sigismember(set as *const sigset_t as *mut sigset_t, sig) == 1 }
}

/// Install `handler`/`info_handler` for `sig` through libc `sigaction`
/// (unrecorded setup; the scenario's checks say what it observed).
pub fn install(sig: c_int, flags: c_int, info: bool) {
    install_with(
        sig,
        flags,
        if info {
            info_handler as unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void) as usize
        } else {
            handler as extern "C" fn(c_int) as usize
        },
    );
}

/// Install a scenario's own `handler` (an `extern "C"` function's address)
/// for `sig` with `flags` and an empty `sa_mask`, through libc `sigaction`
/// (unrecorded setup).
pub fn install_with(sig: c_int, flags: c_int, handler: usize) {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = flags;
        sa.sa_sigaction = handler;
        assert_eq!(sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

pub fn install_disposition(sig: c_int, disposition: usize) {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = disposition;
        assert_eq!(sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

/// The current disposition of `sig` as libc reports it: `SIG_DFL`, `SIG_IGN`
/// or `handler`.
pub fn disposition(sig: c_int) -> &'static str {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        assert_eq!(sigaction(sig, std::ptr::null(), &mut sa), 0);
        match sa.sa_sigaction {
            SIG_DFL => "SIG_DFL",
            SIG_IGN => "SIG_IGN",
            _ => "handler",
        }
    }
}

pub fn reset() {
    COUNT.store(0, Ordering::SeqCst);
    LAST_SIG.store(0, Ordering::SeqCst);
    LAST_CODE.store(0, Ordering::SeqCst);
    LAST_PID.store(0, Ordering::SeqCst);
    LAST_UID.store(0, Ordering::SeqCst);
    LAST_INT.store(0, Ordering::SeqCst);
    HANDLER_TID.store(0, Ordering::SeqCst);
    for slot in &ORDER {
        slot.store(0, Ordering::SeqCst);
    }
    for slot in &ENTRY_MASK {
        slot.store(-1, Ordering::SeqCst);
    }
}

pub fn gettid() -> pid_t {
    unsafe { syscall(SYS_gettid) as pid_t }
}

/// The longest a scenario waits for another thread's (or the kernel's)
/// progress before it gives up and lets the following check fail. A generous
/// upper bound, never a timing assertion: natively a wait ends the moment its
/// condition holds, and a loaded host (the conformance tests run in parallel)
/// only makes it longer.
pub const PROGRESS_DEADLINE: Duration = Duration::from_secs(20);

/// [`PROGRESS_DEADLINE`] in nanoseconds, a blocking call's timeout.
pub const PROGRESS_DEADLINE_NS: i64 = PROGRESS_DEADLINE.as_nanos() as i64;

/// Poll `done` every `interval` until it holds, for at most
/// [`PROGRESS_DEADLINE`] of sleeping; whether it held. The bound is a number of
/// sleeps, not a clock reading, so under patina the wait adds no clock
/// operation to the trace.
pub fn wait_until(interval: Duration, mut done: impl FnMut() -> bool) -> bool {
    let rounds = PROGRESS_DEADLINE.as_micros() / interval.as_micros();
    for _ in 0..rounds {
        if done() {
            return true;
        }
        std::thread::sleep(interval);
    }
    done()
}

/// The computation between two of [`spin_until`]'s `done` calls: a
/// microsecond or two of CPU. Short, because under patina CPU time accrues
/// only by the clock observations (`done`) themselves (the runtime's
/// advance-on-spin rescue), so the computation between them is pure cost
/// there, and a natively cheap `done` keeps the spin CPU-bound either way.
const SPIN_CHUNK_STEPS: u32 = 1_000;

/// The most CPU-bound chunks [`spin_until`] runs: tens of seconds of CPU,
/// the bound that ends a spin where no clock moves while the process
/// computes (a model whose virtual clocks stand still between calls).
const SPIN_CHUNKS: u32 = 4_000_000;

/// Compute (no system call) in short chunks until `done` holds, for at most
/// [`PROGRESS_DEADLINE`] of monotonic time or [`SPIN_CHUNKS`] chunks; whether
/// it held. CPU time accrues only while the process runs, so a loaded host
/// makes the spin take longer in wall time and never makes it end early;
/// `done` reads whatever clock or pending set the scenario waits on, through
/// its own door.
pub fn spin_until(mut done: impl FnMut() -> bool) -> bool {
    let started = std::time::Instant::now();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..SPIN_CHUNKS {
        if done() {
            return true;
        }
        if started.elapsed() > PROGRESS_DEADLINE {
            break;
        }
        for _ in 0..SPIN_CHUNK_STEPS {
            state = std::hint::black_box(
                state
                    .wrapping_mul(0x5851_f42d_4c95_7f2d)
                    .wrapping_add(0x1405_7b7e_f767_814f),
            );
        }
    }
    done()
}

/// The helper's pause before it signals the main thread: long enough for the
/// main thread to be parked in its blocking call natively; virtual time under
/// patina, where the wait must be a real park.
pub fn short_pause() {
    std::thread::sleep(Duration::from_millis(40));
}

/// The helper's wait before it signals the main thread, keyed on the main
/// thread actually being asleep in its blocking call: natively
/// `/proc/self/task/<tid>/stat` reports state `S` once it is, whatever the
/// host's load (a fixed pause could fire before the call was entered, and a
/// handler that runs BEFORE the call leaves it blocking forever); the virtual
/// kernel has no `/proc`, so under patina this is the plain `short_pause`,
/// where virtual time makes the order deterministic. Unobserved either way.
pub fn until_parked(main_tid: pid_t) {
    let path = format!("/proc/self/task/{main_tid}/stat");
    let state = |text: &str| {
        text.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
    };
    match std::fs::read_to_string(&path) {
        Ok(_) => {
            wait_until(Duration::from_millis(1), || {
                std::fs::read_to_string(&path)
                    .ok()
                    .as_deref()
                    .and_then(state)
                    == Some('S')
            });
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(_) => short_pause(),
    }
}

/// Once the thread `main_tid` is parked ([`until_parked`]), mark the stream
/// `helper_kill` and send `sig` to `pid`: a wait that returned before the
/// signal existed shows as its event preceding the mark.
pub fn kill_when_parked(p: &crate::probe::Probe, main_tid: pid_t, pid: pid_t, sig: c_int) {
    until_parked(main_tid);
    p.mark("helper_kill", &[("sig", Value::from(sig))]);
    unsafe {
        kill(pid, sig);
    }
}

/// A helper thread in `scope` that sends `pid` each of `sigs` in turn, each
/// once the calling thread is parked ([`kill_when_parked`]).
pub fn delayed_kills<'a>(
    scope: &'a std::thread::Scope<'a, '_>,
    p: &'a crate::probe::Probe,
    pid: pid_t,
    sigs: &'static [c_int],
) {
    let main_tid = gettid();
    scope.spawn(move || {
        for &sig in sigs {
            kill_when_parked(p, main_tid, pid, sig);
        }
    });
}

/// Turn-taking between a scenario's main thread and one worker: a phase
/// each advances when its turn ends, the worker's published tid, and a
/// release flag the main thread's guard sets on every exit path (including
/// the panic a failed `--strict` check raises), so a waiting worker never
/// hangs the scope's join. Every wait is unobserved and bounded.
#[derive(Default)]
pub struct Turns {
    phase: AtomicI32,
    worker: AtomicI32,
    released: AtomicBool,
}

impl Turns {
    /// On the worker, first: publish its tid; answers it.
    pub fn worker_starts(&self) -> pid_t {
        let tid = gettid();
        self.worker.store(tid, Ordering::SeqCst);
        tid
    }

    /// The tid the worker published (0 before it did).
    pub fn worker_tid(&self) -> pid_t {
        self.worker.load(Ordering::SeqCst)
    }

    /// On the main thread: wait for the worker's tid, which the scenario
    /// cannot continue without.
    pub fn await_worker(&self, p: &crate::probe::Probe) -> pid_t {
        p.rec
            .quiet(|| wait_until(Duration::from_millis(1), || self.worker_tid() != 0));
        p.require("the worker reported its tid", self.worker_tid() != 0);
        self.worker_tid()
    }

    /// End the caller's turn: enter `phase`.
    pub fn pass(&self, phase: i32) {
        self.phase.store(phase, Ordering::SeqCst);
    }

    /// Wait until `phase` or the release; whether `phase` was reached.
    pub fn wait(&self, p: &crate::probe::Probe, phase: i32) -> bool {
        p.rec.quiet(|| {
            wait_until(Duration::from_millis(1), || {
                self.phase.load(Ordering::SeqCst) >= phase || self.released.load(Ordering::SeqCst)
            })
        });
        self.phase.load(Ordering::SeqCst) >= phase
    }

    /// On the worker, last: idle until the main thread releases it.
    pub fn hold(&self) {
        while !self.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// On the main thread, right after spawning the worker: the guard that
    /// releases it when dropped.
    pub fn release_guard(&self) -> Release<'_> {
        Release(&self.released)
    }
}

/// Wait (unobserved) until `COUNT` reaches `n`, bounded so a delivery that
/// never happens fails the following check instead of hanging the run.
pub fn wait_for_count(p: &crate::probe::Probe, n: usize) {
    p.rec
        .quiet(|| wait_until(Duration::from_millis(2), || count() >= n));
}

/// Drop guard that sets a stop flag: declared in the main thread after the
/// worker is spawned, it releases the worker on every exit path — including
/// the panic a failed `--strict` check raises — so a scoped join never hangs.
pub struct Release<'a>(pub &'a std::sync::atomic::AtomicBool);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
