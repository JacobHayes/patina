// A reader (main) registers EPOLLIN|EPOLLET on a socketpair endpoint and blocks
// in epoll_wait; a writer task writes, waking the fan-in park through the
// baton. Then the edge-latch discipline is asserted with the writes issued from
// main itself, so the sequence is schedule-independent.
use std::ffi::{c_int, c_void};

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLET: u32 = 1 << 31;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
}
fn zero() -> EpollEvent {
    EpollEvent { events: 0, data: 0 }
}

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0,
        "socketpair"
    );
    let (a, b) = (sv[0], sv[1]);
    let ep = unsafe { epoll_create1(0) };
    assert!(ep >= 0, "epoll_create1");
    let mut reg = EpollEvent {
        events: EPOLLIN | EPOLLET,
        data: 0x1234,
    };
    assert_eq!(
        unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, a, &mut reg) },
        0,
        "epoll_ctl add"
    );

    let writer = std::thread::spawn(move || {
        let msg = b"ping";
        assert_eq!(
            unsafe { write(b, msg.as_ptr() as *const c_void, msg.len()) },
            4
        );
    });
    let mut evs = [zero()];
    let n = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, -1) };
    assert_eq!(n, 1, "one ready event");
    assert_eq!({ evs[0].data }, 0x1234, "event data");
    assert!({ evs[0].events } & EPOLLIN != 0, "EPOLLIN set");
    writer.join().unwrap();

    // Partial drain: 2 of the 4 bytes. The fd stays readable, but the ET edge
    // is latched — a poll must NOT re-report it.
    let mut buf = [0u8; 2];
    assert_eq!(unsafe { read(a, buf.as_mut_ptr() as *mut c_void, 2) }, 2);
    assert_eq!(&buf, b"pi");
    let latched = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(
        latched, 0,
        "latched edge must not re-report after partial drain"
    );

    // New data re-fires the edge even though readiness never dropped.
    assert_eq!(unsafe { write(b, b"!!".as_ptr() as *const c_void, 2) }, 2);
    let refired = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(refired, 1, "new arrival must re-fire the edge");
    let mut rest = [0u8; 4];
    assert_eq!(unsafe { read(a, rest.as_mut_ptr() as *mut c_void, 4) }, 4);
    assert_eq!(&rest, b"ng!!");
    println!("NATIVE_EPOLL_RESULT latched={latched} refired={refired}");
}
