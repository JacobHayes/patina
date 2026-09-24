// A timer and a wait that end at the same virtual instant (Linux): a timer
// descriptor and a `poll` on it with the same timeout, armed from one reading
// of the clock. The kernel may order the two ends either way; the run must
// neither lose the expiration nor wake the poller twice.
use std::ffi::{c_int, c_long, c_void};

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn poll(fds: *mut PollFd, count: u64, timeout: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[cfg(target_arch = "x86_64")]
const SYS_TIMERFD_CREATE: c_long = 283;
#[cfg(target_arch = "aarch64")]
const SYS_TIMERFD_CREATE: c_long = 85;
#[cfg(target_arch = "x86_64")]
const SYS_TIMERFD_SETTIME: c_long = 286;
#[cfg(target_arch = "aarch64")]
const SYS_TIMERFD_SETTIME: c_long = 86;

const CLOCK_MONOTONIC: c_long = 1;
const POLLIN: i16 = 1;

fn main() {
    // SAFETY: plain libc calls on local buffers.
    unsafe {
        let fd = syscall(SYS_TIMERFD_CREATE, CLOCK_MONOTONIC, 0) as c_int;
        if fd < 0 {
            std::process::exit(22);
        }
        // {interval, value}: a 10 ms one-shot, then a 10 ms poll on it.
        let spec: [i64; 4] = [0, 0, 0, 10_000_000];
        if syscall(SYS_TIMERFD_SETTIME, fd as c_long, 0, spec.as_ptr(), 0usize) != 0 {
            std::process::exit(23);
        }
        let mut fds = [PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        }];
        let ready = poll(fds.as_mut_ptr(), 1, 10);
        if !(0..=1).contains(&ready) {
            std::process::exit(24);
        }
        let mut count = 0u64;
        if read(fd, (&raw mut count).cast(), 8) != 8 {
            std::process::exit(25);
        }
        println!("TIMERFD_DEADLINE ready={ready} expirations={count}");
    }
}
