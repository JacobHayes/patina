// O_NONBLOCK honored on an in-process pipe: an empty non-blocking read returns
// EWOULDBLOCK instead of parking. The fcntl(F_SETFL) path (set later) is
// portable; the pipe2(O_NONBLOCK) creation path is Linux-only. `ok` ANDs every
// applicable sub-check so the output line is stable across platforms.
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
const EWOULDBLOCK: i32 = 35;
#[cfg(target_os = "linux")]
const EWOULDBLOCK: i32 = 11;
const F_SETFL: i32 = 4;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
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
fn main() {
    let mut buf = [0u8; 4];
    let mut ok = true;
    // fcntl(F_SETFL, O_NONBLOCK) on a plain pipe — the "set later" path, portable.
    let mut b = [0i32; 2];
    assert_eq!(unsafe { pipe(b.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { fcntl(b[0], F_SETFL, O_NONBLOCK) }, 0);
    ok &= unsafe { read(b[0], buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
    unsafe { write(b[1], b"hi".as_ptr(), 2) };
    ok &= unsafe { read(b[0], buf.as_mut_ptr(), buf.len()) } == 2;
    unsafe { close(b[0]) };
    unsafe { close(b[1]) };
    // Creation-time O_NONBLOCK via pipe2 (Linux exports it).
    #[cfg(target_os = "linux")]
    {
        let mut a = [0i32; 2];
        assert_eq!(unsafe { pipe2(a.as_mut_ptr(), O_NONBLOCK) }, 0);
        ok &= unsafe { read(a[0], buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
        unsafe { close(a[0]) };
        unsafe { close(a[1]) };
    }
    println!("NATIVE_PIPE_NONBLOCK_RESULT ok={ok}");
}
