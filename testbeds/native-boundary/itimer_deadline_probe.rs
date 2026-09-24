// A timer and a wait that end at the same virtual instant (Linux): an
// interval timer and a `nanosleep` of the same length, armed from one reading
// of the clock. The kernel may order the two ends either way; the run must
// neither lose the timer nor wake the sleeper twice.
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    fn nanosleep(request: *const [i64; 2], remaining: *mut [i64; 2]) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_arch = "x86_64")]
const SYS_SETITIMER: c_long = 38;
#[cfg(target_arch = "aarch64")]
const SYS_SETITIMER: c_long = 103;

const ITIMER_REAL: c_long = 0;
const SIGALRM: c_int = 14;
const EINTR: c_int = 4;

static ALARMS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alarm(_: c_int) {
    ALARMS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    // SAFETY: plain libc calls on local buffers.
    unsafe {
        signal(SIGALRM, on_alarm);
        // {interval, value}: a 10 ms one-shot, then a 10 ms sleep.
        let timer: [i64; 4] = [0, 0, 0, 10_000];
        if syscall(SYS_SETITIMER, ITIMER_REAL, timer.as_ptr(), 0usize) != 0 {
            std::process::exit(20);
        }
        let slept = nanosleep(&[0, 10_000_000], std::ptr::null_mut());
        let slept = if slept == 0 {
            "0"
        } else if *__errno_location() == EINTR {
            "EINTR"
        } else {
            std::process::exit(21);
        };
        let alarms = ALARMS.load(Ordering::SeqCst);
        println!("ITIMER_DEADLINE slept={slept} alarms={alarms}");
    }
}
