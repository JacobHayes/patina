// In-process pipes and a socketpair through the deterministic scheduler, one
// report line per case; every result is a pure function of the transfer, so
// it is byte-identical across same-seed runs.
//
// - pipe: the reader (main) blocks on the empty pipe and is woken through the
//   baton when the writer thread writes; partial writes (4-byte buffer vs
//   9-byte message) and EOF on the writer's close.
// - socketpair: a duplex AF_UNIX/SOCK_STREAM pair; a server task reads a
//   request on one endpoint and writes the uppercased reply back through the
//   SAME endpoint.
// - dup: dup aliases a pipe endpoint into the same channel side: bytes written
//   through either fd reach the one reader, EOF appears only after the LAST
//   write-side fd closes, and EPIPE (with no SIGPIPE: the report is printed)
//   only after the LAST read-side fd closes. Both entry points: raw dup(2) and
//   fcntl(F_DUPFD_CLOEXEC) (std's try_clone path).
// - nonblock: an empty non-blocking read is EWOULDBLOCK instead of parking,
//   set later by fcntl(F_SETFL) and, on Linux, at creation by pipe2.
use std::thread;

#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
const EWOULDBLOCK: i32 = 35;
#[cfg(target_os = "linux")]
const EWOULDBLOCK: i32 = 11;
#[cfg(target_os = "macos")]
const F_DUPFD_CLOEXEC: i32 = 67;
#[cfg(target_os = "linux")]
const F_DUPFD_CLOEXEC: i32 = 1030;
const EPIPE: i32 = 32;
const F_SETFL: i32 = 4;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;

unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn pair(make: impl FnOnce(*mut i32) -> i32) -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert_eq!(make(fds.as_mut_ptr()), 0, "creating a pair failed");
    (fds[0], fds[1])
}

fn write_all(fd: i32, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { write(fd, bytes[off..].as_ptr(), bytes.len() - off) };
        assert!(n > 0, "write returned {n}");
        off += n as usize;
    }
}

fn read_to_end(fd: i32, chunk: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr(), chunk) };
        assert!(n >= 0, "read returned {n}");
        if n == 0 {
            return got;
        }
        got.extend_from_slice(&buf[..n as usize]);
    }
}

fn piped() {
    let (r, w) = pair(|fds| unsafe { pipe(fds) });
    let writer = thread::spawn(move || {
        write_all(w, b"ping-pong");
        unsafe { close(w) };
    });
    let got = read_to_end(r, 4);
    writer.join().unwrap();
    unsafe { close(r) };
    println!("NATIVE_PIPE_RESULT got={}", String::from_utf8_lossy(&got));
}

fn socket_pair() {
    let (a, b) = pair(|sv| unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv) });
    let server = thread::spawn(move || {
        let mut buf = [0u8; 16];
        let n = unsafe { read(b, buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0);
        write_all(b, &buf[..n as usize].to_ascii_uppercase());
        unsafe { close(b) };
    });
    write_all(a, b"ping");
    let reply = read_to_end(a, 16);
    server.join().unwrap();
    unsafe { close(a) };
    println!(
        "NATIVE_SOCKETPAIR_RESULT reply={}",
        String::from_utf8_lossy(&reply)
    );
}

fn aliases() {
    let mut ok = true;
    let mut buf = [0u8; 4];
    // Write-side alias: close the ORIGINAL writer first; the drained reader
    // must see would-block (side still open), not EOF, until the dup closes.
    let (r, w) = pair(|fds| unsafe { pipe(fds) });
    assert_eq!(unsafe { fcntl(r, F_SETFL, O_NONBLOCK) }, 0);
    let w_dup = unsafe { dup(w) };
    ok &= w_dup >= 0;
    ok &= unsafe { write(w, b"a".as_ptr(), 1) } == 1;
    unsafe { close(w) };
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 1 && buf[0] == b'a';
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
    ok &= unsafe { write(w_dup, b"b".as_ptr(), 1) } == 1;
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 1 && buf[0] == b'b';
    unsafe { close(w_dup) };
    let eof = unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 0;
    unsafe { close(r) };
    // Read-side alias: writes succeed while EITHER read fd lives; EPIPE only
    // after the last one closes.
    let (r2, w2) = pair(|fds| unsafe { pipe(fds) });
    let r2_dup = unsafe { fcntl(r2, F_DUPFD_CLOEXEC, 0) };
    ok &= r2_dup >= 0;
    unsafe { close(r2) };
    ok &= unsafe { write(w2, b"x".as_ptr(), 1) } == 1;
    unsafe { close(r2_dup) };
    let epipe = unsafe { write(w2, b"y".as_ptr(), 1) } == -1 && errno() == EPIPE;
    unsafe { close(w2) };
    println!("NATIVE_PIPE_DUP_RESULT ok={ok} eof={eof} epipe={epipe}");
}

fn nonblocking() {
    let mut buf = [0u8; 4];
    let mut ok = true;
    let (r, w) = pair(|fds| unsafe { pipe(fds) });
    assert_eq!(unsafe { fcntl(r, F_SETFL, O_NONBLOCK) }, 0);
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
    unsafe { write(w, b"hi".as_ptr(), 2) };
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 2;
    unsafe { close(r) };
    unsafe { close(w) };
    #[cfg(target_os = "linux")]
    {
        let (r, w) = pair(|fds| unsafe { pipe2(fds, O_NONBLOCK) });
        ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
        unsafe { close(r) };
        unsafe { close(w) };
    }
    println!("NATIVE_PIPE_NONBLOCK_RESULT ok={ok}");
}

fn main() {
    piped();
    socket_pair();
    aliases();
    nonblocking();
}
