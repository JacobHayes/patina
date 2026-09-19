use std::ffi::c_int;
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

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
}

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0
    );
    let ep = unsafe { epoll_create1(0) };
    let mut reg = EpollEvent {
        events: EPOLLIN | EPOLLET,
        data: 0,
    };
    assert_eq!(unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &mut reg) }, 0);
    let before = Instant::now();
    let mut evs = [EpollEvent { events: 0, data: 0 }];
    let n = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 50) };
    let elapsed_ms = before.elapsed().as_millis();
    assert_eq!(n, 0, "timeout returns zero events");
    assert_eq!(
        elapsed_ms, 50,
        "timeout elapsed exactly the virtual duration"
    );
    println!("NATIVE_EPOLL_TIMEOUT timeout_ms={elapsed_ms}");
}
