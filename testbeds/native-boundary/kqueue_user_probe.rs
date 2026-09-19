use std::ffi::{c_int, c_void};
use std::time::Instant;

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
#[repr(C)]
struct TimeSpec {
    tv_sec: isize,
    tv_nsec: isize,
}

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EVFILT_READ: i16 = -1;
const EVFILT_USER: i16 = -10;
const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;
const EV_RECEIPT: u16 = 0x0040;
const NOTE_TRIGGER: u32 = 0x0100_0000;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn kqueue() -> c_int;
    fn kevent(
        kq: c_int,
        cl: *const KEvent,
        nc: c_int,
        el: *mut KEvent,
        ne: c_int,
        ts: *const TimeSpec,
    ) -> c_int;
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
    // EVFILT_USER: a writer task triggers, main's blocked kevent returns it.
    let kq = unsafe { kqueue() };
    let reg = KEvent {
        ident: 42,
        filter: EVFILT_USER,
        flags: EV_ADD | EV_CLEAR | EV_RECEIPT,
        fflags: 0,
        data: 0,
        udata: 0 as *mut c_void,
    };
    let mut r = [zero()];
    assert_eq!(
        unsafe { kevent(kq, &reg, 1, r.as_mut_ptr(), 1, std::ptr::null()) },
        1
    );
    let t = std::thread::spawn(move || {
        let trig = KEvent {
            ident: 42,
            filter: EVFILT_USER,
            flags: EV_ADD | EV_RECEIPT,
            fflags: NOTE_TRIGGER,
            data: 0,
            udata: 0 as *mut c_void,
        };
        let mut rr = [zero()];
        assert_eq!(
            unsafe { kevent(kq, &trig, 1, rr.as_mut_ptr(), 1, std::ptr::null()) },
            1
        );
    });
    let mut ev = [zero()];
    let user_n = unsafe {
        kevent(
            kq,
            std::ptr::null(),
            0,
            ev.as_mut_ptr(),
            1,
            std::ptr::null(),
        )
    };
    assert_eq!(user_n, 1, "user event");
    assert_eq!(ev[0].filter, EVFILT_USER);
    assert_eq!(ev[0].ident, 42);
    t.join().unwrap();

    // Timeout: nothing ready, kevent returns 0 after exactly 50ms virtual time.
    let mut sv = [0 as c_int; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0
    );
    let kq2 = unsafe { kqueue() };
    let reg2 = KEvent {
        ident: sv[0] as usize,
        filter: EVFILT_READ,
        flags: EV_ADD | EV_CLEAR | EV_RECEIPT,
        fflags: 0,
        data: 0,
        udata: 0 as *mut c_void,
    };
    let mut r2 = [zero()];
    assert_eq!(
        unsafe { kevent(kq2, &reg2, 1, r2.as_mut_ptr(), 1, std::ptr::null()) },
        1
    );
    let ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    let before = Instant::now();
    let mut ev2 = [zero()];
    let n2 = unsafe { kevent(kq2, std::ptr::null(), 0, ev2.as_mut_ptr(), 1, &ts) };
    let elapsed_ms = before.elapsed().as_millis();
    assert_eq!(n2, 0, "timeout returns zero events");
    assert_eq!(
        elapsed_ms, 50,
        "timeout elapsed exactly the virtual duration"
    );
    println!(
        "NATIVE_KQUEUE_USER_TIMEOUT user_ok={} timeout_ms={}",
        user_n == 1,
        elapsed_ms
    );
}
