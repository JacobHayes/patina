//! `FUTEX_WAITS` relative timed `futex` waits of `FUTEX_TIMEOUT_NS` that time
//! out, through the raw syscall. The guest reads no clock itself: a nonzero
//! wait's anchor is the kernel's own read of the clock, and the wait's park
//! and the sleep that ends it are what the runtime sees; a zero wait is a
//! deadline check that returns at once. Prints
//! `NATIVE_FUTEX_ANCHOR <timeouts>`.
use std::ffi::{c_int, c_long};

#[cfg(target_arch = "x86_64")]
const SYS_FUTEX: c_long = 202;
#[cfg(target_arch = "aarch64")]
const SYS_FUTEX: c_long = 98;
const FUTEX_WAIT_PRIVATE: c_int = 128;
const ETIMEDOUT: i32 = 110;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

fn main() {
    let waits: usize = std::env::var("FUTEX_WAITS").unwrap().parse().unwrap();
    let nsec: i64 = std::env::var("FUTEX_TIMEOUT_NS").unwrap().parse().unwrap();
    let word: u32 = 0;
    let timeout = Timespec { sec: 0, nsec };
    let timeouts = (0..waits)
        .filter(|_| {
            // SAFETY: a futex word and a timespec that outlive the call.
            let result = unsafe {
                syscall(SYS_FUTEX, &word as *const u32, FUTEX_WAIT_PRIVATE, 0u32, &timeout)
            };
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(ETIMEDOUT)
        })
        .count();
    println!("NATIVE_FUTEX_ANCHOR {timeouts}");
}
