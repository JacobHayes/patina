// A process whose only timer is an ITIMER_PROF one second of CPU time away
// (Linux, Patina only): it polls a UDP socket that never receives, `polls`
// times without blocking, then blocks on it. Under Patina the receive that
// completes a poll streak earns an escalation, charged as that call ends,
// before it parks: the CPU time it stands for reaches the timer, whose
// signal interrupts the receive. (Natively a blocked process spends no CPU
// time, so the receive waits forever: there is no native oracle.)
use std::ffi::c_int;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

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
    fn recv(fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> isize;
    fn __errno_location() -> *mut c_int;
}

const SIGPROF: c_int = 27;
const ITIMER_PROF: c_int = 2;
const EINTR: c_int = 4;

static FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_prof(_: c_int) {
    FIRED.store(true, Ordering::SeqCst);
}

fn main() {
    let polls: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    // No SA_RESTART: the handler interrupts the receive.
    let action = SigAction {
        handler: on_prof as extern "C" fn(c_int) as usize,
        mask: [0; 16],
        flags: 0,
        restorer: 0,
    };
    // SAFETY: a valid action; no old action.
    assert_eq!(unsafe { sigaction(SIGPROF, &action, std::ptr::null_mut()) }, 0);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    // One-shot, one second of CPU time away.
    let timer = [0i64, 0, 1, 0];
    // SAFETY: a local value; no old value.
    assert_eq!(unsafe { setitimer(ITIMER_PROF, &timer, std::ptr::null_mut()) }, 0);
    let mut buf = [0u8; 16];
    for _ in 0..polls {
        let _ = socket.recv(&mut buf);
    }
    let fired_before = FIRED.load(Ordering::SeqCst);
    socket.set_nonblocking(false).unwrap();
    // SAFETY: `buf` is local and writable for its length.
    let rc = unsafe { recv(socket.as_raw_fd(), buf.as_mut_ptr(), buf.len(), 0) };
    // SAFETY: the thread's errno.
    let interrupted = rc == -1 && unsafe { *__errno_location() } == EINTR;
    println!(
        "PROF_PARK fired_before={fired_before} interrupted={interrupted} fired={}",
        FIRED.load(Ordering::SeqCst)
    );
}
