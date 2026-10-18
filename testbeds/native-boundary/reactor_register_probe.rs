// A waiter thread parks in the reactor (kevent on macOS, epoll_wait on Linux)
// on an instance with nothing registered; main then registers read interest in
// a socket that already holds a byte. The kernel attaches the interest ready
// and wakes the parked waiter, which delivers it.
use std::ffi::c_int;
use std::time::Duration;

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn write(fd: c_int, buf: *const u8, count: usize) -> isize;
}

#[cfg(target_os = "macos")]
mod reactor {
    use std::ffi::{c_int, c_void};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KEvent {
        ident: usize,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: isize,
        udata: *mut c_void,
    }

    const EVFILT_READ: i16 = -1;
    const EV_ADD: u16 = 0x0001;
    const EV_CLEAR: u16 = 0x0020;

    unsafe extern "C" {
        fn kqueue() -> c_int;
        fn kevent(
            kq: c_int,
            changes: *const KEvent,
            nchanges: c_int,
            events: *mut KEvent,
            nevents: c_int,
            timeout: *const c_void,
        ) -> c_int;
    }

    pub fn create() -> c_int {
        unsafe { kqueue() }
    }

    /// Block until one event arrives; answer whether it is the read interest.
    pub fn wait_one(kq: c_int) -> bool {
        let mut event = KEvent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let n = unsafe { kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null()) };
        n == 1 && event.filter == EVFILT_READ
    }

    pub fn register_read(kq: c_int, fd: c_int) {
        let change = KEvent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_ADD | EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let n = unsafe { kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        assert_eq!(n, 0);
    }
}

#[cfg(target_os = "linux")]
mod reactor {
    use std::ffi::c_int;

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

    unsafe extern "C" {
        fn epoll_create1(flags: c_int) -> c_int;
        fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
        fn epoll_wait(epfd: c_int, events: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    }

    pub fn create() -> c_int {
        unsafe { epoll_create1(0) }
    }

    /// Block until one event arrives; answer whether it is the read interest.
    pub fn wait_one(ep: c_int) -> bool {
        let mut event = EpollEvent { events: 0, data: 0 };
        let n = unsafe { epoll_wait(ep, &mut event, 1, -1) };
        let events = event.events;
        n == 1 && events & EPOLLIN != 0
    }

    pub fn register_read(ep: c_int, fd: c_int) {
        let mut interest = EpollEvent {
            events: EPOLLIN | EPOLLET,
            data: fd as u64,
        };
        assert_eq!(
            unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, fd, &mut interest) },
            0
        );
    }
}

fn main() {
    let reactor = reactor::create();
    assert!(reactor >= 0);
    let waiter = std::thread::spawn(move || reactor::wait_one(reactor));
    // Let the waiter park first.
    std::thread::sleep(Duration::from_millis(5));
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0
    );
    assert_eq!(unsafe { write(sv[1], b"x".as_ptr(), 1) }, 1);
    reactor::register_read(reactor, sv[0]);
    println!(
        "NATIVE_REACTOR_REGISTER_RESULT woke_ready={}",
        waiter.join().unwrap()
    );
}
