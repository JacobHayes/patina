// What CPU time a process spends (Linux): a sleep spends almost none; a loop
// of system calls raises the process CPU clock and getrusage, whose user plus
// system time is that clock; an ITIMER_PROF fires in such a loop (one of
// calls that are no scheduling point, and one of yields) and an
// ITIMER_VIRTUAL in a loop of clock reads, each seen by the loop itself
// before it makes any other call; so does a thread CPU-clock timer in a loop
// of calls that are no scheduling point. Under Patina each is the charge of
// the guest's calls; natively it is the CPU the loops burn. The result line
// is the same either way.
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn clock_gettime(clock: c_int, time: *mut [i64; 2]) -> c_int;
    fn getrusage(who: c_int, usage: *mut [i64; 18]) -> c_int;
    fn setitimer(which: c_int, new: *const [i64; 4], old: *mut [i64; 4]) -> c_int;
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    fn nanosleep(request: *const [i64; 2], remaining: *mut [i64; 2]) -> c_int;
    fn sched_yield() -> c_int;
    fn getuid() -> u32;
    fn timer_create(clock: c_int, event: *const u8, timer: *mut usize) -> c_int;
    fn timer_settime(timer: usize, flags: c_int, new: *const [i64; 4], old: *mut [i64; 4]) -> c_int;
}

const CLOCK_MONOTONIC: c_int = 1;
const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
const ITIMER_VIRTUAL: c_int = 1;
const ITIMER_PROF: c_int = 2;
const SIGVTALRM: c_int = 26;
const SIGPROF: c_int = 27;
const SIGALRM: c_int = 14;

static VIRTUAL: AtomicBool = AtomicBool::new(false);
static PROF: AtomicBool = AtomicBool::new(false);
static THREAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_virtual(_: c_int) {
    VIRTUAL.store(true, Ordering::SeqCst);
}

extern "C" fn on_prof(_: c_int) {
    PROF.store(true, Ordering::SeqCst);
}

extern "C" fn on_thread_timer(_: c_int) {
    THREAD.store(true, Ordering::SeqCst);
}

fn clock(id: c_int) -> u64 {
    let mut time = [0i64; 2];
    // SAFETY: `time` is local storage.
    assert_eq!(unsafe { clock_gettime(id, &mut time) }, 0);
    time[0] as u64 * 1_000_000_000 + time[1] as u64
}

/// The process's user plus system time, from getrusage, in nanoseconds.
fn usage() -> u64 {
    let mut usage = [0i64; 18];
    // SAFETY: `usage` is local storage the size of `struct rusage`.
    assert_eq!(unsafe { getrusage(0, &mut usage) }, 0);
    ((usage[0] + usage[2]) as u64 * 1_000_000 + (usage[1] + usage[3]) as u64) * 1_000
}

/// One system call that is no scheduling point: a due timer is delivered
/// as it returns (natively, on the return to user space).
fn syscall() {
    // SAFETY: no arguments.
    std::hint::black_box(unsafe { getuid() });
}

/// One yield, a scheduling point.
fn yield_now() {
    // SAFETY: no arguments.
    std::hint::black_box(unsafe { sched_yield() });
}

/// Make `call` until `flag` is set, at most ten million times: whether the
/// loop saw it set, read after each call before any other.
fn until(flag: &AtomicBool, call: fn()) -> bool {
    for _ in 0..10_000_000 {
        call();
        if flag.load(Ordering::SeqCst) {
            return true;
        }
    }
    false
}

/// Arm `which` for 1 ms of its CPU time, one-shot.
fn arm(which: c_int) {
    let timer = [0i64, 0, 0, 1_000];
    // SAFETY: `timer` is local; no old value.
    assert_eq!(unsafe { setitimer(which, &timer, std::ptr::null_mut()) }, 0);
}

fn main() {
    // SAFETY: plain handlers that only store a flag.
    unsafe {
        signal(SIGVTALRM, on_virtual);
        signal(SIGPROF, on_prof);
        signal(SIGALRM, on_thread_timer);
    }
    let (monotonic, cpu) = (clock(CLOCK_MONOTONIC), clock(CLOCK_PROCESS_CPUTIME_ID));
    // SAFETY: a local request, no remainder.
    assert_eq!(unsafe { nanosleep(&[0, 100_000_000], std::ptr::null_mut()) }, 0);
    let slept = clock(CLOCK_MONOTONIC) - monotonic >= 100_000_000;
    let idle_cpu = clock(CLOCK_PROCESS_CPUTIME_ID) - cpu;

    let (cpu, used) = (clock(CLOCK_PROCESS_CPUTIME_ID), usage());
    (0..1_000).for_each(|_| syscall());
    let rises = clock(CLOCK_PROCESS_CPUTIME_ID) > cpu && usage() > used;
    // Read back to back, the two agree to the microsecond getrusage reports.
    let (used, cpu) = (usage(), clock(CLOCK_PROCESS_CPUTIME_ID));
    let agree = cpu >= used && cpu - used < 1_000_000;

    arm(ITIMER_PROF);
    let prof = until(&PROF, syscall);
    PROF.store(false, Ordering::SeqCst);
    arm(ITIMER_PROF);
    let prof_yielding = until(&PROF, yield_now);
    // A POSIX timer on this thread's CPU clock, 1 ms, signalling SIGALRM.
    let mut timer = 0usize;
    // SAFETY: a null event (SIGALRM); `timer` is local storage.
    assert_eq!(unsafe { timer_create(CLOCK_THREAD_CPUTIME_ID, std::ptr::null(), &mut timer) }, 0);
    // SAFETY: `timer` was just created; the value is local; no old value.
    assert_eq!(unsafe { timer_settime(timer, 0, &[0, 0, 0, 1_000_000], std::ptr::null_mut()) }, 0);
    let thread_fired = until(&THREAD, syscall);
    arm(ITIMER_VIRTUAL);
    let virtual_fired = until(&VIRTUAL, || {
        std::hint::black_box(clock(CLOCK_MONOTONIC));
    });
    println!(
        "NATIVE_CPU_CHARGE_RESULT slept={slept} idle_cpu_under_1ms={} rises={rises} \
rusage_is_cpu_clock={agree} prof_fired={prof} prof_fired_yielding={prof_yielding} \
thread_timer_fired={thread_fired} virtual_fired={virtual_fired}",
        idle_cpu < 1_000_000,
    );
}
