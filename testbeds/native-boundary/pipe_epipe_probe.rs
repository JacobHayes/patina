// EOF + EPIPE semantics. Writing to a pipe whose read end is closed returns
// EPIPE (errno 32) and, crucially, raises NO SIGPIPE — reaching the println at
// all proves the process was not killed by a signal. EOF: a pipe whose write end
// is closed reads 0.
const EPIPE: i32 = 32;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
fn main() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);
    unsafe { close(r) };
    let n = unsafe { write(w, b"x".as_ptr(), 1) };
    let epipe = n == -1 && errno() == EPIPE;
    unsafe { close(w) };
    let mut fds2 = [0i32; 2];
    assert_eq!(unsafe { pipe(fds2.as_mut_ptr()) }, 0);
    let (r2, w2) = (fds2[0], fds2[1]);
    unsafe { close(w2) };
    let mut buf = [0u8; 4];
    let eof = unsafe { read(r2, buf.as_mut_ptr(), buf.len()) } == 0;
    unsafe { close(r2) };
    println!("NATIVE_PIPE_EPIPE_RESULT epipe={epipe} eof={eof}");
}
