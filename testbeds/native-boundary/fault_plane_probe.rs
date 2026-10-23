//! Calls that do no filesystem I/O, under any filesystem fault rate. Linux
//! answers each of them from memory (an inode's size, a lock table, a
//! descriptor table, the working directory), so an injected filesystem
//! fault never reaches one. Each row prints `NATIVE_FAULT_PLANE <row>
//! <answer>`; the answers are the same at every fault rate.
//!
//! The descriptors are `memfd_create` files, whose creation is no
//! filesystem operation, so the setup itself draws no fault. The rows:
//! `FIONREAD`; `F_SETLK`, `F_GETLK` and `F_OFD_SETLK` with a `SEEK_END` or
//! `SEEK_CUR` base; `flock`; `mmap`; `cachestat`; `fchdir` onto a file;
//! `getcwd`; and `open(O_CREAT)` at `RLIMIT_NOFILE`, which Linux refuses
//! (`EMFILE`) before the open reaches the filesystem.
use std::ffi::{c_char, c_int, c_long, c_void};
use std::io;

const FIONREAD: c_long = 0x541B;
const F_GETLK: c_int = 5;
const F_SETLK: c_int = 6;
const F_OFD_SETLK: c_int = 37;
const F_WRLCK: i16 = 1;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const PROT_READ: c_int = 1;
const MAP_SHARED: c_int = 1;
const MAP_FAILED: usize = usize::MAX;
const RLIMIT_NOFILE: c_int = 7;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const SYS_CACHESTAT: c_long = 451;
const PAGE: usize = 4096;

#[repr(C)]
#[derive(Default)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

unsafe extern "C" {
    fn memfd_create(name: *const c_char, flags: u32) -> c_int;
    fn ioctl(fd: c_int, request: c_long, ...) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> usize;
    fn munmap(addr: usize, len: usize) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char;
    fn fchdir(fd: c_int) -> c_int;
    fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
    fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
}

/// `0` or a value, or `errnoN` for a call that returned -1.
fn answer(result: c_long) -> String {
    if result < 0 {
        format!("errno{}", io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        result.to_string()
    }
}

fn row(name: &str, answer: String) {
    println!("NATIVE_FAULT_PLANE {name} {answer}");
}

fn memfd() -> c_int {
    // SAFETY: a NUL-terminated name, no flags.
    let fd = unsafe { memfd_create(c"plane".as_ptr(), 0) };
    assert!(fd >= 0, "memfd_create: {}", io::Error::last_os_error());
    fd
}

fn lock(fd: c_int, command: c_int, whence: i16) -> String {
    let mut lock = Flock {
        l_type: F_WRLCK,
        l_whence: whence,
        l_start: 0,
        l_len: 1,
        ..Flock::default()
    };
    // SAFETY: a `struct flock` the call reads and (F_GETLK) writes.
    let result = unsafe { fcntl(fd, command, &mut lock as *mut Flock) };
    match (command, result) {
        (F_GETLK, 0) => format!("type{}", lock.l_type),
        _ => answer(result.into()),
    }
}

fn main() {
    let fd = memfd();
    let mut queued: c_int = -1;
    // SAFETY: FIONREAD writes one int.
    let result = unsafe { ioctl(fd, FIONREAD, &mut queued as *mut c_int) };
    row("fionread", if result < 0 { answer(result.into()) } else { queued.to_string() });
    row("setlk_end", lock(fd, F_SETLK, SEEK_END));
    row("getlk_end", lock(fd, F_GETLK, SEEK_END));
    let other = memfd();
    row("ofd_setlk_cur", lock(other, F_OFD_SETLK, SEEK_CUR));
    // SAFETY: plain descriptor calls.
    row("flock", answer(unsafe { flock(other, LOCK_EX | LOCK_NB) }.into()));
    // SAFETY: a shared read-only mapping of the empty file, unmapped at once.
    let mapped = unsafe { mmap(std::ptr::null_mut(), PAGE, PROT_READ, MAP_SHARED, fd, 0) };
    row("mmap", if mapped == MAP_FAILED { answer(-1) } else { "mapped".into() });
    if mapped != MAP_FAILED {
        // SAFETY: the mapping made above.
        unsafe { munmap(mapped, PAGE) };
    }
    let range = [0u64, PAGE as u64];
    let mut stat = [u64::MAX; 5];
    // SAFETY: a `struct cachestat_range` read and a `struct cachestat` written.
    let result = unsafe { syscall(SYS_CACHESTAT, fd, range.as_ptr(), stat.as_mut_ptr(), 0) };
    row("cachestat", if result < 0 { answer(result) } else { format!("{stat:?}") });
    // SAFETY: a plain descriptor call.
    row("fchdir_file", answer(unsafe { fchdir(fd) }.into()));
    let mut cwd = [0u8; 256];
    // SAFETY: `cwd` holds `cwd.len()` bytes.
    let got = unsafe { getcwd(cwd.as_mut_ptr().cast(), cwd.len()) };
    let cwd = if got.is_null() {
        answer(-1)
    } else {
        String::from_utf8_lossy(&cwd[..cwd.iter().position(|&b| b == 0).unwrap()]).into_owned()
    };
    row("getcwd", cwd);
    row("open_at_emfile", open_at_emfile(fd));
}

/// `open(O_CREAT)` with every descriptor number below `RLIMIT_NOFILE` taken.
fn open_at_emfile(fd: c_int) -> String {
    let mut saved = Rlimit { cur: 0, max: 0 };
    // SAFETY: a `struct rlimit` written, then one read.
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut saved) }, 0);
    let low = Rlimit { cur: 32, max: saved.max };
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &low) }, 0);
    let mut held = Vec::new();
    loop {
        // SAFETY: a plain descriptor call.
        let copy = unsafe { dup(fd) };
        if copy < 0 {
            break;
        }
        held.push(copy);
    }
    // SAFETY: a NUL-terminated path.
    let opened = unsafe { open(c"/tmp/created".as_ptr(), O_CREAT | O_RDWR, 0o600) };
    let result = answer(opened.into());
    for copy in held {
        // SAFETY: descriptors this function opened.
        unsafe { close(copy) };
    }
    // SAFETY: the limit read above.
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &saved) }, 0);
    result
}
