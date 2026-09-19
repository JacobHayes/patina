use std::ffi::{c_int, c_void};

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLET: u32 = 1 << 31;
const EFD_CLOEXEC: c_int = 0o2000000;
const EFD_NONBLOCK: c_int = 0o4000;
const EFD_SEMAPHORE: c_int = 0o1;
const EAGAIN: i32 = 11;

unsafe extern "C" {
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
fn wr1(fd: c_int) {
    let one: u64 = 1;
    assert_eq!(
        unsafe { write(fd, &one as *const u64 as *const c_void, 8) },
        8
    );
}

fn main() {
    let efd = unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) };
    assert!(efd >= 0, "eventfd");
    let ep = unsafe { epoll_create1(0) };
    let mut reg = EpollEvent {
        events: EPOLLIN | EPOLLET,
        data: 7,
    };
    assert_eq!(unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, efd, &mut reg) }, 0);

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
