// A reader (main) registers EVFILT_READ on a socketpair endpoint and blocks in
// kevent; a writer task writes, waking the fan-in park through the baton.
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

// The previously uncovered wide adapter shares this real reactor guest.
#[repr(C)]
struct KEvent64 {
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: i64,
    udata: u64,
    ext: [u64; 2],
}
const _: () = {
    assert!(size_of::<KEvent64>() == 48);
    assert!(core::mem::offset_of!(KEvent64, data) == 16);
    assert!(core::mem::offset_of!(KEvent64, udata) == 24);
    assert!(core::mem::offset_of!(KEvent64, ext) == 32);
};

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EVFILT_READ: i16 = -1;
const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;
const EV_DISPATCH: u16 = 0x0080;
const EVFILT_WRITE: i16 = -2;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 4;
const EV_RECEIPT: u16 = 0x0040;
const EV_ERROR: u16 = 0x4000;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn kqueue() -> c_int;
    fn kevent(
        kq: c_int,
        cl: *const KEvent,
        nc: c_int,
        el: *mut KEvent,
        ne: c_int,
        ts: *const c_void,
    ) -> c_int;
    fn kevent64(kq: c_int, cl: *const KEvent64, nc: c_int, el: *mut KEvent64, ne: c_int, flags: u32, ts: *const c_void) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn pipe(fds: *mut c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

/// The events a zero-timeout gather on `kq` reports.
fn poll_events(kq: c_int) -> c_int {
    let zero = Timespec { sec: 0, nsec: 0 };
    let mut out = [zero_event(); 4];
    unsafe { kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, (&raw const zero).cast()) }
}

fn put(fd: c_int, bytes: &[u8]) {
    assert_eq!(unsafe { write(fd, bytes.as_ptr().cast(), bytes.len()) }, bytes.len() as isize);
}

fn take(fd: c_int, count: usize) {
    let mut buf = [0u8; 8];
    assert_eq!(unsafe { read(fd, buf.as_mut_ptr().cast(), count) }, count as isize);
}

/// EV_CLEAR fires again on every arrival after its last delivery, even when
/// the reader drained the bytes before any gather saw the descriptor not
/// ready (a tokio reader that read to EAGAIN, then more data arrived), and
/// stays quiet while nothing new arrives.
fn clear_refires(kq: c_int, reader: c_int, writer: c_int) -> [c_int; 4] {
    put(writer, b"x");
    let refill = poll_events(kq);
    take(reader, 1);
    let quiet = poll_events(kq);
    put(writer, b"yz");
    assert_eq!(poll_events(kq), 1, "fresh bytes");
    take(reader, 1);
    put(writer, b"w");
    let partial = poll_events(kq);
    let partial_quiet = poll_events(kq);
    take(reader, 2);
    [refill, quiet, partial, partial_quiet]
}

/// An EV_CLEAR pipe writer is told the pipe is writable only once a whole
/// `PIPE_BUF` (512) fits: freeing one byte of a full pipe is no event.
fn write_threshold(kq: c_int) -> [c_int; 3] {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe");
    assert_eq!(unsafe { fcntl(fds[1], F_SETFL, O_NONBLOCK) }, 0, "nonblocking writer");
    register(kq, fds[1], EVFILT_WRITE, EV_CLEAR);
    let empty = poll_events(kq);
    while unsafe { write(fds[1], b"f".as_ptr().cast(), 1) } == 1 {}
    take(fds[0], 1);
    let one_free = poll_events(kq);
    for _ in 0..511 {
        take(fds[0], 1);
    }
    let pipe_buf_free = poll_events(kq);
    [empty, one_free, pipe_buf_free]
}

/// A knote registered without EV_CLEAR (here EV_DISPATCH) gets no further
/// event from a new arrival after its delivery.
fn dispatch_quiet(kq: c_int) -> [c_int; 2] {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe");
    register(kq, fds[0], EVFILT_READ, EV_DISPATCH);
    put(fds[1], b"a");
    let first = poll_events(kq);
    put(fds[1], b"b");
    [first, poll_events(kq)]
}

fn register_read(kq: c_int, fd: c_int) {
    register(kq, fd, EVFILT_READ, EV_CLEAR);
}

fn register(kq: c_int, fd: c_int, filter: i16, mode: u16) {
    let change = KEvent {
        ident: fd as usize,
        filter,
        flags: EV_ADD | mode,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    assert_eq!(unsafe { kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) }, 0);
}
fn zero_event() -> KEvent {
    KEvent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0,
        "socketpair"
    );
    let (a, b) = (sv[0], sv[1]);
    let kq = unsafe { kqueue() };
    assert!(kq >= 0, "kqueue");

    let change = KEvent {
        ident: a as usize,
        filter: EVFILT_READ,
        flags: EV_ADD | EV_CLEAR | EV_RECEIPT,
        fflags: 0,
        data: 0,
        udata: 0x1234 as *mut c_void,
    };
    let mut receipt = [zero_event()];
    assert_eq!(
        unsafe { kevent(kq, &change, 1, receipt.as_mut_ptr(), 1, std::ptr::null()) },
        1,
        "register receipt"
    );
    assert!(
        receipt[0].flags & EV_ERROR != 0 && receipt[0].data == 0,
        "receipt ok"
    );

    let mut event64 = KEvent64 {
        ident: a as u64, filter: EVFILT_READ,
        flags: EV_ADD | EV_CLEAR | EV_RECEIPT, fflags: 0,
        data: 0, udata: 0x1234, ext: [1, 2],
    };
    assert_eq!(unsafe { kevent64(kq, &raw const event64, 1, &raw mut event64, 1, 0, std::ptr::null()) }, 1);
    assert!(event64.flags & EV_ERROR != 0 && event64.data == 0);
    assert_eq!(event64.ext, [0, 0]);

    let writer = std::thread::spawn(move || {
        let msg = b"ping";
        assert_eq!(
            unsafe { write(b, msg.as_ptr() as *const c_void, msg.len()) },
            4
        );
    });

    let n = unsafe {
        kevent64(kq, std::ptr::null(), 0, &raw mut event64, 1, 0, std::ptr::null())
    };
    assert_eq!(n, 1, "one ready event");
    assert_eq!(event64.ident, a as u64, "event ident");
    assert_eq!(event64.filter, EVFILT_READ, "event filter");
    assert_eq!(event64.udata, 0x1234, "event udata");

    assert_eq!(event64.ext, [0, 0]);
    let mut buf = [0u8; 8];
    let got = unsafe { read(a, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(got, 4);
    writer.join().unwrap();
    println!(
        "NATIVE_KQUEUE_RESULT got={}",
        std::str::from_utf8(&buf[..got as usize]).unwrap()
    );

    // `a` was delivered and drained above with no gather since.
    let socket = clear_refires(kq, a, b);
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe");
    register_read(kq, fds[0]);
    put(fds[1], b"p");
    assert_eq!(poll_events(kq), 1, "pipe bytes");
    take(fds[0], 1);
    let pipe = clear_refires(kq, fds[0], fds[1]);
    println!("NATIVE_KQUEUE_CLEAR socket={socket:?} pipe={pipe:?}");
    let threshold = write_threshold(kq);
    let dispatch = dispatch_quiet(kq);
    println!("NATIVE_KQUEUE_MODES write={threshold:?} dispatch={dispatch:?}");
}
