// dup aliases a pipe endpoint into the same channel side: bytes written through
// either fd reach the one reader, EOF appears only after the LAST write-side fd
// closes, and EPIPE only after the LAST read-side fd closes. Both entry points
// are exercised: raw dup(2) and fcntl(F_DUPFD_CLOEXEC) (std's try_clone path).
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
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
fn main() {
    let mut ok = true;
    let mut buf = [0u8; 4];
    // Write-side alias: close the ORIGINAL writer first — the drained reader
    // must see would-block (side still open), not EOF, until the dup closes too.
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);
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
    let mut fds2 = [0i32; 2];
    assert_eq!(unsafe { pipe(fds2.as_mut_ptr()) }, 0);
    let (r2, w2) = (fds2[0], fds2[1]);
    let r2_dup = unsafe { fcntl(r2, F_DUPFD_CLOEXEC, 0) };
    ok &= r2_dup >= 0;
    unsafe { close(r2) };
    ok &= unsafe { write(w2, b"x".as_ptr(), 1) } == 1;
    unsafe { close(r2_dup) };
    let epipe = unsafe { write(w2, b"y".as_ptr(), 1) } == -1 && errno() == EPIPE;
    unsafe { close(w2) };
    println!("NATIVE_PIPE_DUP_RESULT ok={ok} eof={eof} epipe={epipe}");
}
