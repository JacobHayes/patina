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

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EVFILT_READ: i16 = -1;
const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;
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
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
}
fn zero() -> KEvent {
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
    let mut receipt = [zero()];
    assert_eq!(
        unsafe { kevent(kq, &change, 1, receipt.as_mut_ptr(), 1, std::ptr::null()) },
        1,
        "register receipt"
    );
    assert!(
        receipt[0].flags & EV_ERROR != 0 && receipt[0].data == 0,
        "receipt ok"
    );

    let writer = std::thread::spawn(move || {
        let msg = b"ping";
        assert_eq!(
            unsafe { write(b, msg.as_ptr() as *const c_void, msg.len()) },
            4
        );
    });

    let mut events = [zero()];
    let n = unsafe {
        kevent(
            kq,
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            1,
            std::ptr::null(),
        )
    };
    assert_eq!(n, 1, "one ready event");
    assert_eq!(events[0].ident, a as usize, "event ident");
    assert_eq!(events[0].filter, EVFILT_READ, "event filter");
    assert_eq!(events[0].udata, 0x1234 as *mut c_void, "event udata");

    let mut buf = [0u8; 8];
    let got = unsafe { read(a, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(got, 4);
    writer.join().unwrap();
    println!(
        "NATIVE_KQUEUE_RESULT got={}",
        std::str::from_utf8(&buf[..got as usize]).unwrap()
    );
}
