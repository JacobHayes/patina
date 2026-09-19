use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn main() {
    const SOCKETPAIR: i64 = 53;
    const WRITE: i64 = 1;
    const READ: i64 = 0;
    const CLOSE: i64 = 3;
    const EVENTFD2: i64 = 290;
    const DUP2: i64 = 33;
    const AF_UNIX: i64 = 1;
    const SOCK_STREAM: i64 = 1;
    let mut sv = [0i32; 2];
    let rc = unsafe { sc(SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as i64) };
    assert_eq!(rc, 0, "socketpair rc {rc}");
    let (a, b) = (sv[0] as i64, sv[1] as i64);
    assert!(a >= 0 && b >= 0, "socketpair fds {a} {b}");
    let msg = b"pair-ping";
    let w = unsafe { sc(WRITE, a, msg.as_ptr() as i64, msg.len() as i64, 0) };
    assert_eq!(w, msg.len() as i64, "socketpair write {w}");
    let mut buf = [0u8; 16];
    let n = unsafe { sc(READ, b, buf.as_mut_ptr() as i64, buf.len() as i64, 0) };
    assert_eq!(&buf[..n as usize], msg, "socketpair payload mismatch");
    let _ = unsafe { sc(CLOSE, a, 0, 0, 0) };
    let _ = unsafe { sc(CLOSE, b, 0, 0, 0) };
    // dup2(eventfd, eventfd) validates the number and returns it; dup2 onto a
    // chosen number binds a second descriptor to the SAME counter, so a read
    // through it drains what was written through the original.
    let efd = unsafe { sc(EVENTFD2, 7, 0, 0, 0) };
    assert!(efd >= 0, "eventfd2 {efd}");
    let d = unsafe { sc(DUP2, efd, efd, 0, 0) };
    assert_eq!(
        d, efd,
        "dup2(eventfd,eventfd) must return the number, got {d}"
    );
    let d2 = unsafe { sc(DUP2, efd, 40, 0, 0) };
    assert_eq!(d2, 40, "dup2(eventfd, 40) must bind 40, got {d2}");
    let mut counter = [0u8; 8];
    let n = unsafe { sc(READ, 40, counter.as_mut_ptr() as i64, 8, 0) };
    assert_eq!(n, 8, "read through the dup {n}");
    assert_eq!(
        u64::from_ne_bytes(counter),
        7,
        "the dup reads the same counter"
    );
    let _ = unsafe { sc(CLOSE, 40, 0, 0, 0) };
    let _ = unsafe { sc(CLOSE, efd, 0, 0, 0) };
    println!("SOCKETPAIR_ROW pair+dup2eventfd ok");
}
