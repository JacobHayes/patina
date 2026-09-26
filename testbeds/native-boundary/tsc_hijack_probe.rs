use std::arch::x86_64::_rdtsc;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

unsafe extern "C" {
    fn signal(signum: c_int, handler: *mut c_void) -> *mut c_void;
    fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count(_signum: c_int) {
    CALLS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    // SAFETY: a plain signal(2) registration. Under the timestamp-counter trap
    // it stays the guest's own action: the trap keeps the host disposition, so
    // a counter read is still answered from the virtual clock and never reaches
    // this handler (a hijacked trap would re-run the read forever).
    unsafe {
        signal(11, count as *mut c_void);
    }
    // SAFETY: a counter read.
    let tick = unsafe { _rdtsc() };
    let mut now = Timespec { sec: 0, nsec: 0 };
    // SAFETY: CLOCK_MONOTONIC into local storage.
    assert_eq!(unsafe { clock_gettime(1, &mut now) }, 0);
    // The virtual clock answered it: one tick per nanosecond, never past the
    // monotonic clock read after it (the host counter is far beyond both).
    let answered = u128::from(tick) <= now.sec as u128 * 1_000_000_000 + now.nsec as u128;
    println!(
        "HIJACK answered={answered} handler_calls={}",
        CALLS.load(Ordering::SeqCst)
    );
}
