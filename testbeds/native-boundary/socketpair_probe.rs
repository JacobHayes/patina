// A duplex AF_UNIX/SOCK_STREAM socketpair: a server task reads a request on one
// endpoint and writes the uppercased reply back through the SAME endpoint; main
// writes the request and reads the reply on the other. Both directions flow
// through the deterministic scheduler.
use std::thread;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
unsafe extern "C" {
    fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn write_all(fd: i32, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { write(fd, bytes[off..].as_ptr(), bytes.len() - off) };
        assert!(n > 0, "write returned {n}");
        off += n as usize;
    }
}
fn main() {
    let mut sv = [0i32; 2];
    assert_eq!(
        unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0
    );
    let (a, b) = (sv[0], sv[1]);
    let server = thread::spawn(move || {
        let mut buf = [0u8; 16];
        let n = unsafe { read(b, buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0);
        let reply: Vec<u8> = buf[..n as usize]
            .iter()
            .map(|c| c.to_ascii_uppercase())
            .collect();
        write_all(b, &reply);
        unsafe { close(b) };
    });
    write_all(a, b"ping");
    let mut reply = Vec::new();
    let mut buf = [0u8; 16];
    loop {
        let n = unsafe { read(a, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0);
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&buf[..n as usize]);
    }
    server.join().unwrap();
    unsafe { close(a) };
    println!(
        "NATIVE_SOCKETPAIR_RESULT reply={}",
        String::from_utf8_lossy(&reply)
    );
}
