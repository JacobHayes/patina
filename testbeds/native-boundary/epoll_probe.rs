// Linux readiness through the deterministic scheduler, one report line per
// case.
//
// - epoll: a reader (main) registers EPOLLIN|EPOLLET on a socketpair endpoint
//   and blocks in epoll_wait; a writer task writes, waking the fan-in park
//   through the baton. Then the edge-latch discipline, with the writes issued
//   from main itself, so the sequence is schedule-independent.
// - eventfd: a second thread's eventfd write unparks a blocked epoll_wait; an
//   undrained counter's latch holds until a new write; a read returns and
//   resets, a drained nonblocking read is EAGAIN; EFD_SEMAPHORE counts down.
// - timeout: an epoll_wait timeout elapses exactly its virtual duration.
use std::ffi::{c_int, c_void};
use std::time::Instant;

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
const EFD_CLOEXEC: c_int = 0o2000000;
const EFD_NONBLOCK: c_int = 0o4000;
const EFD_SEMAPHORE: c_int = 0o1;
const EAGAIN: i32 = 11;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn eventfd(initval: u32, flags: c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn __errno_location() -> *mut i32;
}
fn zero() -> EpollEvent {
    EpollEvent { events: 0, data: 0 }
}

/// An epoll instance watching `fd` for edge-triggered input, tagged `data`.
fn watching(fd: c_int, data: u64) -> c_int {
    let ep = unsafe { epoll_create1(0) };
    assert!(ep >= 0, "epoll_create1");
    let mut reg = EpollEvent {
        events: EPOLLIN | EPOLLET,
        data,
    };
    assert_eq!(
        unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, fd, &mut reg) },
        0,
        "epoll_ctl add"
    );
    ep
}

fn socket_pair() -> (c_int, c_int) {
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0,
        "socketpair"
    );
    (sv[0], sv[1])
}

fn edges() {
    let (a, b) = socket_pair();
    let ep = watching(a, 0x1234);

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

fn wr1(fd: c_int) {
    let one: u64 = 1;
    assert_eq!(
        unsafe { write(fd, &one as *const u64 as *const c_void, 8) },
        8
    );
}

fn counter() {
    let efd = unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) };
    assert!(efd >= 0, "eventfd");
    let ep = watching(efd, 7);

    // A second thread's write unparks the blocked epoll_wait.
    let waker = std::thread::spawn(move || wr1(efd));
    let mut evs = [zero()];
    let woke = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, -1) };
    assert_eq!(woke, 1, "eventfd write unparks epoll_wait");
    assert_eq!({ evs[0].data }, 7);
    waker.join().unwrap();

    // Undrained counter: the latch holds until a NEW write arrives.
    assert_eq!(
        unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) },
        0,
        "latched"
    );
    wr1(efd);
    let refired = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(refired, 1, "undrained re-arrival re-fires");

    // Read returns-and-resets; a drained nonblocking read is EAGAIN.
    let mut val: u64 = 0;
    assert_eq!(unsafe { read(efd, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 2, "counter accumulated both writes");
    assert_eq!(unsafe { read(efd, (&raw mut val).cast(), 8) }, -1);
    assert_eq!(
        unsafe { *__errno_location() },
        EAGAIN,
        "drained read is EAGAIN"
    );

    // EFD_SEMAPHORE decrements by one per read.
    let sem = unsafe { eventfd(2, EFD_SEMAPHORE) };
    assert_eq!(unsafe { read(sem, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 1);
    assert_eq!(unsafe { read(sem, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 1);
    println!("NATIVE_EVENTFD_RESULT woke={woke} refired={refired} sem_ok=true");
}

fn timeout() {
    let (a, _b) = socket_pair();
    let ep = watching(a, 0);
    let before = Instant::now();
    let mut evs = [zero()];
    let n = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 50) };
    let elapsed_ms = before.elapsed().as_millis();
    assert_eq!(n, 0, "timeout returns zero events");
    assert_eq!(
        elapsed_ms, 50,
        "timeout elapsed exactly the virtual duration"
    );
    println!("NATIVE_EPOLL_TIMEOUT timeout_ms={elapsed_ms}");
}

fn main() {
    edges();
    counter();
    timeout();
}
