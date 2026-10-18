// An epoll interest outlives the number it was registered under: the kernel
// keys it by `(fd, struct file)`, so while a `dup` keeps the socket open,
// closing the registered number leaves the interest watching the socket.
// Each wait below is woken by a segment the peer sends afterwards, first under
// a bounded timeout, then with none. The last line is how long the bounded
// wait took from the send, on the virtual clock under Patina.
use std::ffi::c_int;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::time::Instant;

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;

unsafe extern "C" {
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, events: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut u8, count: usize) -> isize;
}

fn wait(ep: c_int, timeout_ms: c_int) -> c_int {
    let mut event = EpollEvent { events: 0, data: 0 };
    unsafe { epoll_wait(ep, &mut event, 1, timeout_ms) }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7100").unwrap();
    let mut client = TcpStream::connect("127.0.0.1:7100").unwrap();
    let registered = listener.accept().unwrap().0.into_raw_fd();
    let ep = unsafe { epoll_create1(0) };
    let mut interest = EpollEvent {
        events: EPOLLIN,
        data: 7,
    };
    assert_eq!(
        unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, registered, &mut interest) },
        0
    );
    let alias = unsafe { dup(registered) };
    assert!(alias >= 0);
    assert_eq!(unsafe { close(registered) }, 0);

    let sent = Instant::now();
    client.write_all(b"a").unwrap();
    let bounded = wait(ep, 50);
    let bounded_us = sent.elapsed().as_micros();
    let mut byte = 0u8;
    assert_eq!(unsafe { read(alias, &mut byte, 1) }, 1);

    client.write_all(b"b").unwrap();
    let unbounded = wait(ep, -1);
    assert_eq!(unsafe { read(alias, &mut byte, 1) }, 1);

    println!("NATIVE_EPOLL_ALIAS_RESULT bounded={bounded} unbounded={unbounded}");
    println!("NATIVE_EPOLL_ALIAS_ELAPSED bounded_us={bounded_us}");
}
