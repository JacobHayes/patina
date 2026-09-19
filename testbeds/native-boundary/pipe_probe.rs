// Two managed tasks exchange bytes through an in-process pipe(). The reader
// (main) blocks on the empty pipe and is woken through the baton when the writer
// thread writes; partial writes (4-byte buffer vs 9-byte message) and EOF on the
// writer's close are exercised. The result is a pure function of the transfer,
// so it is byte-identical across same-seed runs.
use std::thread;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn main() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe() failed");
    let (r, w) = (fds[0], fds[1]);
    let writer = thread::spawn(move || {
        let msg = b"ping-pong";
        let mut off = 0usize;
        while off < msg.len() {
            let n = unsafe { write(w, msg[off..].as_ptr(), msg.len() - off) };
            assert!(n > 0, "write returned {n}");
            off += n as usize;
        }
        unsafe { close(w) };
    });
    let mut got = Vec::new();
    let mut buf = [0u8; 4];
    loop {
        let n = unsafe { read(r, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0, "read returned {n}");
        if n == 0 {
            break;
        } // EOF: the writer closed its end.
        got.extend_from_slice(&buf[..n as usize]);
    }
    writer.join().unwrap();
    unsafe { close(r) };
    println!("NATIVE_PIPE_RESULT got={}", String::from_utf8_lossy(&got));
}
