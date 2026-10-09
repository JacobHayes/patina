// A loop that only yields, waiting on time (Linux): first on a peer that
// sleeps 10 µs and then sets a flag, then on a 10 µs ITIMER_REAL whose
// handler sets one. Natively the yields burn the time; under Patina each
// yield is a charged call, and the time it costs reaches the peer's deadline
// and the timer at the next scheduling point.
use std::ffi::c_int;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// glibc's `struct sigaction` on x86_64 and aarch64.
#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: c_int,
    restorer: usize,
}

unsafe extern "C" {
    fn sigaction(sig: c_int, action: *const SigAction, old: *mut SigAction) -> c_int;
    fn setitimer(which: c_int, new: *const [i64; 4], old: *mut [i64; 4]) -> c_int;
}

const SIGALRM: c_int = 14;
const ITIMER_REAL: c_int = 0;

static ALARM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_: c_int) {
    ALARM.store(true, Ordering::SeqCst);
}

fn main() {
    let woke = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&woke);
    let sleeper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_micros(10));
        flag.store(true, Ordering::SeqCst);
    });
    while !woke.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    sleeper.join().unwrap();

    let action = SigAction {
        handler: on_alarm as extern "C" fn(c_int) as usize,
        mask: [0; 16],
        flags: 0,
        restorer: 0,
    };
    // SAFETY: a valid action; no old action.
    assert_eq!(unsafe { sigaction(SIGALRM, &action, std::ptr::null_mut()) }, 0);
    // One-shot, 10 µs of real time away.
    let timer = [0i64, 0, 0, 10];
    // SAFETY: a local value; no old value.
    assert_eq!(unsafe { setitimer(ITIMER_REAL, &timer, std::ptr::null_mut()) }, 0);
    while !ALARM.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    println!("NATIVE_YIELD_WAIT_RESULT sleeper_woke=true alarm_fired=true");
}
