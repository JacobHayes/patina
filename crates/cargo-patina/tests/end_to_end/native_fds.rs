//! Native descriptor-table semantics and file operations Linux performs atomically:
//! appends, vectored I/O, descriptor reservation at the limit and across waits.

// Every case is a Linux descriptor-table behaviour.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::*;

    // One guest; `FDS_MODE` (an `--env` value, so it is recorded and restored)
    // picks the scenario.
    //
    // `append` — three threads append records to one file, each through a
    //   different append spelling: `pwrite` through an `O_APPEND` description
    //   (which Linux lands at the end whatever the offset), a two-segment
    //   `pwritev` through it, and a two-segment `pwritev2(.., -1, RWF_APPEND)`
    //   through a plain description. Linux reads the end and writes the whole
    //   call under `inode_lock`, so no record is lost, overwritten, or split.
    // `vectored` — three threads `writev` two-segment records through one
    //   `O_APPEND` description, then three threads `readv` record-sized vectors
    //   through one shared description. Linux writes a vector under `inode_lock`
    //   and reads one under `f_pos_lock`, so no record is split either way.
    // `contended` — with one number free, one thread creates a file while
    //   another takes the number with `dup`. Linux reserves the number before
    //   the open creates anything, so an open that answers EMFILE created nothing.
    // `accept` — a thread blocks in `accept` while the main thread opens a file
    //   and connects: the accepted descriptor's number was taken before the wait.
    // `fifo` — a thread blocks opening a FIFO for reading. Linux holds the
    //   number for the waiting open without binding it: it names nothing
    //   (`EBADF`), cannot be taken over (`EBUSY`), and is the reader's once the
    //   open completes.
    // `sigwait` — a blocking `accept` and FIFO open interrupted by a handler that
    //   takes a number let their number go before the handler runs, as the
    //   kernel's `ERESTARTSYS` exit does; a restarted call takes the lowest free
    //   number again.
    // `fifo_range` — `close_range` over the number a waiting FIFO open holds
    //   leaves it held, and `CLOSE_RANGE_CLOEXEC` marks the descriptor the open
    //   binds there.
    // `retry` — every call that makes a descriptor, retried at `RLIMIT_NOFILE`
    //   while a peer waits to close one: each answers `EMFILE` at the limit, and
    //   each refusal is a scheduling point, so the peer runs and a retry succeeds.
    const FDS_SOURCE: &str = r#"
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

#[repr(C)]
struct Action {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize;
    fn writev(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize;
    fn readv(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize;
    fn syscall(number: i64, ...) -> i64;
    fn dup(fd: i32) -> i32;
    fn dup2(from: i32, to: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    fn unlink(path: *const std::ffi::c_char) -> i32;
    fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn eventfd(initial: u32, flags: i32) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn timerfd_create(clock: i32, flags: i32) -> i32;
    fn signalfd(fd: i32, mask: *const u64, flags: i32) -> i32;
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn socketpair(domain: i32, kind: i32, protocol: i32, fds: *mut i32) -> i32;
    fn close_range(first: u32, last: u32, flags: i32) -> i32;
    fn getpid() -> i32;
    fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
    fn pthread_self() -> usize;
    fn pthread_kill(thread: usize, sig: i32) -> i32;
    fn sigaction(sig: i32, action: *const Action, old: *mut Action) -> i32;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const PWRITEV2: i64 = 328;
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_GETFD: i64 = 438;
    pub const INOTIFY_INIT1: i64 = 294;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const PWRITEV2: i64 = 287;
    pub const PIDFD_OPEN: i64 = 434;
    pub const PIDFD_GETFD: i64 = 438;
    pub const INOTIFY_INIT1: i64 = 26;
}

const RWF_APPEND: i64 = 0x10;
const RLIMIT_NOFILE: i32 = 7;
const EMFILE: i32 = 24;
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const O_WRONLY: i32 = 1;
const O_NONBLOCK: i32 = 0o4000;
const CLOSE_RANGE_CLOEXEC: i32 = 4;
const SIGUSR1: i32 = 10;
const SA_RESTART: i32 = 0x1000_0000;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const CLOCK_MONOTONIC: i32 = 1;
const THREADS: usize = 3;
const ROUNDS: usize = 16;
const ATTEMPTS: usize = 10_000;

fn errno() -> i32 {
    unsafe { *__errno_location() }
}

fn limit() -> [u64; 2] {
    let mut limit = [0_u64; 2];
    assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) }, 0);
    limit
}

fn halves(bytes: &[u8]) -> [Iovec; 2] {
    let (head, tail) = bytes.split_at(bytes.len() / 2);
    [
        Iovec { base: head.as_ptr(), len: head.len() },
        Iovec { base: tail.as_ptr(), len: tail.len() },
    ]
}

/// Six bytes per record: two halves of three.
fn record(thread: usize, round: usize) -> String {
    format!("t{thread}r{round:02}\n")
}

/// Whether `path` holds every thread's every record exactly once.
fn records_intact(path: &str) -> bool {
    let contents = std::fs::read_to_string(path).unwrap();
    let mut found: Vec<&str> = contents.split_inclusive('\n').collect();
    found.sort_unstable();
    let mut expected: Vec<String> = (0..THREADS)
        .flat_map(|thread| (0..ROUNDS).map(move |round| record(thread, round)))
        .collect();
    expected.sort_unstable();
    found == expected
}

fn append() {
    let path = "/appended";
    let appending = Arc::new(OpenOptions::new().create(true).append(true).open(path).unwrap());
    let plain = Arc::new(OpenOptions::new().write(true).open(path).unwrap());
    let writers: Vec<_> = (0..THREADS)
        .map(|writer| {
            let appending = Arc::clone(&appending);
            let plain = Arc::clone(&plain);
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let line = record(writer, round);
                    let bytes = line.as_bytes();
                    let iov = halves(bytes);
                    let wrote = match writer {
                        0 => appending.write_at(bytes, 0).unwrap() as isize,
                        1 => unsafe { pwritev(appending.as_raw_fd(), iov.as_ptr(), 2, 0) },
                        _ => unsafe {
                            syscall(nr::PWRITEV2, i64::from(plain.as_raw_fd()), iov.as_ptr(), 2_i64, -1_i64, 0_i64, RWF_APPEND) as isize
                        },
                    };
                    assert_eq!(wrote, bytes.len() as isize, "writer {writer} round {round}");
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    println!("APPEND records_intact={}", records_intact(path));
}

fn vectored() {
    let path = "/vectored";
    let appending = Arc::new(OpenOptions::new().create(true).append(true).open(path).unwrap());
    let writers: Vec<_> = (0..THREADS)
        .map(|thread| {
            let appending = Arc::clone(&appending);
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let line = record(thread, round);
                    let wrote = unsafe { writev(appending.as_raw_fd(), halves(line.as_bytes()).as_ptr(), 2) };
                    assert_eq!(wrote, line.len() as isize);
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    println!("VECTORED writev_records_intact={}", records_intact(path));

    let reading = Arc::new(OpenOptions::new().read(true).open(path).unwrap());
    let readers: Vec<_> = (0..THREADS)
        .map(|_| {
            let reading = Arc::clone(&reading);
            std::thread::spawn(move || {
                let mut whole = true;
                loop {
                    let (mut head, mut tail) = ([0u8; 3], [0u8; 3]);
                    let iov = [
                        Iovec { base: head.as_mut_ptr(), len: 3 },
                        Iovec { base: tail.as_mut_ptr(), len: 3 },
                    ];
                    let got = unsafe { readv(reading.as_raw_fd(), iov.as_ptr(), 2) };
                    if got <= 0 {
                        break;
                    }
                    let bytes = [&head[..], &tail[..]].concat();
                    whole &= got == 6 && bytes[0] == b't' && bytes[5] == b'\n' && !bytes[1..].contains(&b't');
                }
                whole
            })
        })
        .collect();
    let whole = readers.into_iter().all(|reader| reader.join().unwrap());
    println!("VECTORED readv_records_whole={whole}");
}

fn contended() {
    let limit = limit();
    let lowest = unsafe { dup(0) };
    assert!(lowest >= 0);
    unsafe { close(lowest) };
    assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &[lowest as u64 + 1, limit[1]]) }, 0);
    let (mut refused, mut created_anyway) = (0, 0);
    for round in 0..12 {
        let path = format!("/contended-{round}");
        let opener = {
            let path = path.clone();
            std::thread::spawn(move || {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map(IntoRawFd::into_raw_fd)
                    .map_err(|error| error.raw_os_error())
            })
        };
        let duplicator = std::thread::spawn(|| unsafe { dup(0) });
        let opened = opener.join().unwrap();
        let duplicate = duplicator.join().unwrap();
        if opened == Err(Some(EMFILE)) {
            refused += 1;
            if std::path::Path::new(&path).exists() {
                created_anyway += 1;
            }
        }
        if let Ok(fd) = opened {
            unsafe { close(fd) };
        }
        if duplicate >= 0 {
            unsafe { close(duplicate) };
        }
    }
    println!("CONTENDED refused={refused} created_anyway={created_anyway}");
}

fn accepted() {
    use std::os::unix::net::{UnixListener, UnixStream};
    let listener = UnixListener::bind("/accept.sock").unwrap();
    let acceptor = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream.into_raw_fd()));
    std::thread::sleep(Duration::from_millis(50));
    let file = std::fs::File::create("/during-accept").unwrap();
    let _client = UnixStream::connect("/accept.sock").unwrap();
    let accepted = acceptor.join().unwrap().unwrap();
    println!("ACCEPT numbered_before_the_wait={}", accepted < file.as_raw_fd());
}

fn errno_of(result: i32) -> i32 {
    if result < 0 { errno() } else { 0 }
}

fn fifo() {
    assert_eq!(unsafe { mkfifo(c"/fifo".as_ptr(), 0o600) }, 0);
    let next = unsafe { dup(0) };
    unsafe { close(next) };
    let reader = std::thread::spawn(|| std::fs::File::open("/fifo").unwrap().into_raw_fd());
    std::thread::sleep(Duration::from_millis(50));
    let getfd = errno_of(unsafe { fcntl(next, F_GETFD) });
    let file = std::fs::File::create("/during-fifo").unwrap();
    let dup2 = errno_of(unsafe { dup2(file.as_raw_fd(), next) });
    let writer = OpenOptions::new().write(true).open("/fifo").unwrap();
    let read_end = reader.join().unwrap();
    println!("FIFO waiting getfd_errno={getfd} dup2_errno={dup2}");
    println!("FIFO opened reader_has_the_number={}", read_end == next);
    drop(writer);
}

static HANDLER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn take_a_number(_: i32) {
    HANDLER.store(unsafe { socket(AF_UNIX, SOCK_STREAM, 0) }, Ordering::SeqCst);
}

/// Interrupt `wait` with a handler that takes a number, then (on restart) let
/// `partner` end the wait. Prints where the handler's number and the call's
/// answer land relative to the lowest free number before the call.
fn interrupted(name: &str, restart: bool, wait: impl FnOnce() -> i32, partner: impl FnOnce() -> i32 + Send + 'static) {
    let first = unsafe { dup(0) };
    unsafe { close(first) };
    let action = Action {
        handler: take_a_number as *const () as usize,
        mask: [0; 16],
        flags: if restart { SA_RESTART } else { 0 },
        restorer: 0,
    };
    assert_eq!(unsafe { sigaction(SIGUSR1, &action, std::ptr::null_mut()) }, 0);
    let me = unsafe { pthread_self() };
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(unsafe { pthread_kill(me, SIGUSR1) }, 0);
        if restart {
            std::thread::sleep(Duration::from_millis(10));
            partner()
        } else {
            -1
        }
    });
    let result = wait();
    let error = errno();
    let partner = sender.join().unwrap();
    let handler = HANDLER.swap(-1, Ordering::SeqCst);
    let answer = if result >= 0 {
        format!("fd=first+{}", result - first)
    } else {
        format!("errno={error}")
    };
    println!("SIGWAIT {name} restart={restart} handler=first+{} {answer}", handler - first);
    for fd in [handler, result, partner] {
        if fd >= 0 {
            unsafe { close(fd) };
        }
    }
}

fn sigwait() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let listening = listener.as_raw_fd();
    let path = CString::new("/sigwait-fifo").unwrap();
    assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
    for restart in [false, true] {
        interrupted(
            "accept",
            restart,
            || unsafe { accept(listening, std::ptr::null_mut(), std::ptr::null_mut()) },
            move || std::net::TcpStream::connect(address).unwrap().into_raw_fd(),
        );
        let reader = path.clone();
        let writer = path.clone();
        interrupted(
            "fifo_open",
            restart,
            move || unsafe { open(reader.as_ptr(), 0) },
            move || unsafe { open(writer.as_ptr(), O_WRONLY | O_NONBLOCK) },
        );
    }
}

fn fifo_range() {
    let path = CString::new("/range-fifo").unwrap();
    assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
    let first = unsafe { dup(0) };
    assert_eq!(unsafe { close(first) }, 0);
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || unsafe { open(reader_path.as_ptr(), 0) });
    // The waiting reader holds `first` once a probe numbers past it.
    let held = (0..1000).any(|_| {
        let probe = unsafe { dup(0) };
        unsafe { close(probe) };
        probe > first || {
            std::thread::sleep(Duration::from_millis(1));
            false
        }
    });
    assert!(held);
    let getfd = unsafe { fcntl(first, F_GETFD) };
    let getfd_errno = errno();
    assert_eq!(unsafe { close_range(first as u32, first as u32, 0) }, 0);
    assert_eq!(unsafe { close_range(first as u32, u32::MAX, CLOSE_RANGE_CLOEXEC) }, 0);
    let writer = unsafe { open(path.as_ptr(), O_WRONLY | O_NONBLOCK) };
    assert!(writer >= 0);
    let fd = reader.join().unwrap();
    let flags = unsafe { fcntl(fd, F_GETFD) };
    println!("FIFO_RANGE getfd={getfd} errno={getfd_errno} reader=first+{} cloexec={flags}", fd - first);
    unsafe {
        close(fd);
        close(writer);
    }
}

/// One new descriptor, or the errno.
fn one(fd: i64) -> Result<Vec<i32>, i32> {
    if fd >= 0 { Ok(vec![fd as i32]) } else { Err(errno()) }
}

/// A pair of new descriptors, or the errno.
fn pair(result: i32, fds: [i32; 2]) -> Result<Vec<i32>, i32> {
    if result == 0 { Ok(fds.to_vec()) } else { Err(errno()) }
}

fn retry() {
    let limit = limit();
    let pidfd = unsafe { syscall(nr::PIDFD_OPEN, getpid(), 0) } as i32;
    assert!(pidfd >= 0);
    let mask = [0_u64; 16];
    let rows: Vec<(&str, usize, Box<dyn Fn() -> Result<Vec<i32>, i32>>)> = vec![
        ("open", 1, Box::new(|| std::fs::File::create("/retried").map(|file| vec![file.into_raw_fd()]).map_err(|error| error.raw_os_error().unwrap()))),
        ("pipe", 2, Box::new(|| { let mut fds = [0; 2]; pair(unsafe { pipe(fds.as_mut_ptr()) }, fds) })),
        ("eventfd", 1, Box::new(|| one(unsafe { eventfd(0, 0) }.into()))),
        ("epoll_create1", 1, Box::new(|| one(unsafe { epoll_create1(0) }.into()))),
        ("timerfd_create", 1, Box::new(|| one(unsafe { timerfd_create(CLOCK_MONOTONIC, 0) }.into()))),
        ("signalfd", 1, Box::new(move || one(unsafe { signalfd(-1, mask.as_ptr(), 0) }.into()))),
        ("inotify_init1", 1, Box::new(|| one(unsafe { syscall(nr::INOTIFY_INIT1, 0) }))),
        ("socket", 1, Box::new(|| one(unsafe { socket(AF_UNIX, SOCK_STREAM, 0) }.into()))),
        ("socketpair", 2, Box::new(|| { let mut fds = [0; 2]; pair(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()) }, fds) })),
        ("dup", 1, Box::new(|| one(unsafe { dup(0) }.into()))),
        ("F_DUPFD", 1, Box::new(|| one(unsafe { fcntl(0, F_DUPFD, 0) }.into()))),
        ("pidfd_open", 1, Box::new(|| one(unsafe { syscall(nr::PIDFD_OPEN, getpid(), 0) }))),
        ("pidfd_getfd", 1, Box::new(move || one(unsafe { syscall(nr::PIDFD_GETFD, pidfd, 0, 0) }))),
    ];
    for (name, needs, create) in rows {
        // `last` is the highest open number, so the table is full but for
        // `needs - 1` numbers under the limit.
        let last = unsafe { dup(0) };
        assert!((last + 1..last + 64).all(|fd| unsafe { fcntl(fd, F_GETFD) } == -1));
        assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &[last as u64 + needs as u64, limit[1]]) }, 0);
        let at_limit = create().err().unwrap_or(0);
        // The closer runs only once the retries start, and only when a retry
        // lets another task run.
        let go = Arc::new(AtomicBool::new(false));
        let closer = {
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                unsafe { close(last) }
            })
        };
        go.store(true, Ordering::SeqCst);
        let created = (1..=ATTEMPTS).find_map(|_| create().ok());
        assert_eq!(closer.join().unwrap(), 0);
        for fd in created.iter().flatten() {
            unsafe { close(*fd) };
        }
        assert_eq!(unsafe { setrlimit(RLIMIT_NOFILE, &limit) }, 0);
        println!("FD_RETRY {name} at_limit={at_limit} created={}", created.is_some());
    }
}

fn main() {
    match std::env::var("FDS_MODE").unwrap().as_str() {
        "append" => append(),
        "vectored" => vectored(),
        "contended" => contended(),
        "accept" => accepted(),
        "fifo" => fifo(),
        "sigwait" => sigwait(),
        "fifo_range" => fifo_range(),
        "retry" => retry(),
        other => panic!("unknown mode {other}"),
    }
}
"#;

    // The standard streams are pipes: the guest starts with standard input on
    // the read end of an empty pipe whose writer is gone and its output and
    // error on the write ends of two others. Every metadata door answers each
    // as 6.8 answers a pipe end (`S_IFIFO|0600`, one link, empty, a page-sized
    // block, its own pipefs node), and so do the calls a program asks of a
    // stream before using it (`F_GETFL`, `isatty`, `lseek`, `fstatfs`,
    // `poll`, `FIONREAD`, `fallocate`, `posix_fadvise`, `fchmod`).
    const STD_STREAMS_SOURCE: &str = r#"
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

unsafe extern "C" {
    fn syscall(number: i64, ...) -> i64;
    fn fstat(fd: i32, buf: *mut u8) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn isatty(fd: i32) -> i32;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn poll(fds: *mut [i32; 2], count: u64, timeout: i32) -> i32;
    fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i32;
    fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    fn fchmod(fd: i32, mode: u32) -> i32;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const FSTAT: i64 = 5;
    pub const NEWFSTATAT: i64 = 262;
    pub const FSTATFS: i64 = 138;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const FSTAT: i64 = 80;
    pub const NEWFSTATAT: i64 = 79;
    pub const FSTATFS: i64 = 44;
}

const AT_EMPTY_PATH: i64 = 0x1000;
const F_GETFL: i32 = 3;
const FIONREAD: u64 = 0x541b;
const PIPEFS_MAGIC: i64 = 0x5049_5045;

fn errno() -> i32 {
    unsafe { *__errno_location() }
}

/// `st_ino` of a kernel `struct stat`: the second word on both arches.
fn ino(buf: &[u64; 18]) -> u64 {
    buf[1]
}

fn main() {
    let mut nodes = Vec::new();
    let mut devices = Vec::new();
    for fd in 0..3 {
        // std's metadata is `statx(fd, "", AT_EMPTY_PATH)`.
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                println!("STD fd={fd} metadata_error={}", error.raw_os_error().unwrap_or(-1));
                continue;
            }
        };
        let mut libc_stat = [0_u64; 18];
        let mut raw_stat = [0_u64; 18];
        let mut at_stat = [0_u64; 18];
        let libc_rc = unsafe { fstat(fd, libc_stat.as_mut_ptr().cast()) };
        let raw_rc = unsafe { syscall(nr::FSTAT, fd, raw_stat.as_mut_ptr()) };
        let at_rc = unsafe {
            syscall(nr::NEWFSTATAT, fd, c"".as_ptr(), at_stat.as_mut_ptr(), AT_EMPTY_PATH)
        };
        let same_node = libc_rc == 0
            && raw_rc == 0
            && at_rc == 0
            && [ino(&libc_stat), ino(&raw_stat), ino(&at_stat)].iter().all(|&i| i == meta.ino());
        let mut statfs = [0_i64; 15];
        let fs_rc = unsafe { syscall(nr::FSTATFS, fd, statfs.as_mut_ptr()) };
        let pipefs = fs_rc == 0 && statfs[0] == PIPEFS_MAGIC;
        let getfl = unsafe { fcntl(fd, F_GETFL) } & 0o3;
        let tty = unsafe { isatty(fd) };
        let tty_errno = errno();
        let seek = unsafe { lseek(fd, 0, 1) };
        let seek_errno = errno();
        println!(
            "STD fd={fd} fifo={} perm={:o} nlink={} size={} blksize={} same_node={same_node} \
             pipefs={pipefs} access={getfl} isatty={tty}/{tty_errno} lseek={seek}/{seek_errno}",
            meta.file_type().is_fifo(),
            meta.mode() & 0o7777,
            meta.nlink(),
            meta.size(),
            meta.blksize(),
        );
        nodes.push(meta.ino());
        devices.push(meta.dev());
    }
    nodes.sort();
    nodes.dedup();
    devices.dedup();
    println!("STD nodes={} devices={}", nodes.len(), devices.len());

    let mut pending = -1_i32;
    let fionread = unsafe { ioctl(0, FIONREAD, &mut pending) };
    let mut stdin = [0_i32, 1 /* POLLIN */];
    let ready = unsafe { poll(&mut stdin, 1, 0) };
    println!(
        "STD stdin fionread={fionread}/{pending} poll={ready} revents={:#x}",
        stdin[1] >> 16
    );
    let falloc = unsafe { fallocate(1, 0, 0, 1) };
    let falloc_errno = errno();
    let advice = unsafe { posix_fadvise(1, 0, 0, 0) };
    println!("STD stdout fallocate={falloc}/{falloc_errno} fadvise={advice}");
    let chmod = unsafe { fchmod(1, 0o640) };
    let after = ManuallyDrop::new(unsafe { File::from_raw_fd(1) }).metadata().unwrap();
    println!("STD stdout fchmod={chmod} perm={:o}", after.mode() & 0o7777);
}
"#;

    #[test]
    fn native_standard_streams_answer_as_pipes() {
        let guest = native_build::source_guest("std_streams", STD_STREAMS_SOURCE);
        let run = common::native::assert_success(guest.command("run", &["--seed", "1"]));
        let stdout = String::from_utf8_lossy(&run.stdout);
        let facts: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("STD "))
            .collect();
        let stream = |fd: u8, access: u8| {
            format!(
                "STD fd={fd} fifo=true perm=600 nlink=1 size=0 blksize=4096 same_node=true \
                 pipefs=true access={access} isatty=0/25 lseek=-1/29"
            )
        };
        assert_eq!(
            facts,
            [
                stream(0, 0).as_str(),
                stream(1, 1).as_str(),
                stream(2, 1).as_str(),
                "STD nodes=3 devices=1",
                "STD stdin fionread=0/0 poll=1 revents=0x10",
                "STD stdout fallocate=-1/29 fadvise=29",
                "STD stdout fchmod=0 perm=640",
            ],
            "{stdout}"
        );
    }

    /// The seeded scheduler, and PCT with its change points spread over a short
    /// run's decisions rather than the default 2000 the run never reaches.
    const PCT: [&str; 3] = ["--sched-pct=2", "--sched-pct-steps", "150"];

    #[test]
    fn native_descriptor_table_holds_linux_atomicity_and_reservation() {
        let guest = native_build::source_guest("fds", FDS_SOURCE);
        let lines = |output: &Output, prefix: &str| -> Vec<String> {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| line.starts_with(prefix))
                .map(str::to_owned)
                .collect()
        };
        // Each scenario answers `expected` under the seeded scheduler at every
        // seed and under PCT, where one seed is also recorded and replayed.
        let assert_answers = |mode: &str, seeds: &[u64], expected: &[&str]| {
            let selector = format!("FDS_MODE={mode}");
            let prefix = format!("{} ", expected[0].split_once(' ').unwrap().0);
            let mut pct = vec!["--env", selector.as_str()];
            pct.extend(PCT);
            let mut runs = vec![guest.assert_run_success(seeds[0], &pct)];
            for &seed in seeds {
                let seed = seed.to_string();
                runs.push(common::native::assert_success(
                    guest.command("run", &["--seed", &seed, "--env", &selector]),
                ));
            }
            for run in &runs {
                assert_eq!(
                    lines(run, &prefix),
                    expected,
                    "{mode}:\n{}",
                    String::from_utf8_lossy(&run.stdout)
                );
            }
        };

        assert_answers("append", &[1, 2], &["APPEND records_intact=true"]);
        assert_answers(
            "vectored",
            &[1, 2],
            &[
                "VECTORED writev_records_intact=true",
                "VECTORED readv_records_whole=true",
            ],
        );
        assert_answers("accept", &[1], &["ACCEPT numbered_before_the_wait=true"]);
        assert_answers(
            "fifo",
            &[1],
            &[
                "FIFO waiting getfd_errno=9 dup2_errno=16",
                "FIFO opened reader_has_the_number=true",
            ],
        );
        assert_answers(
            "sigwait",
            &[1],
            &[
                "SIGWAIT accept restart=false handler=first+0 errno=4",
                "SIGWAIT fifo_open restart=false handler=first+0 errno=4",
                "SIGWAIT accept restart=true handler=first+0 fd=first+1",
                "SIGWAIT fifo_open restart=true handler=first+0 fd=first+1",
            ],
        );
        assert_answers(
            "fifo_range",
            &[1],
            &["FIFO_RANGE getfd=-1 errno=9 reader=first+0 cloexec=1"],
        );
        let creators = [
            "open",
            "pipe",
            "eventfd",
            "epoll_create1",
            "timerfd_create",
            "signalfd",
            "inotify_init1",
            "socket",
            "socketpair",
            "dup",
            "F_DUPFD",
            "pidfd_open",
            "pidfd_getfd",
        ]
        .map(|name| format!("FD_RETRY {name} at_limit=24 created=true"));
        assert_answers("retry", &[1], &creators.each_ref().map(String::as_str));

        // Whichever thread loses the last number, an open refused with EMFILE has
        // created nothing; across the seeds the open loses at least once.
        let field = |stdout: &str, name: &str| -> u64 {
            stdout
                .lines()
                .find(|line| line.starts_with("CONTENDED "))
                .and_then(|line| {
                    line.split(' ')
                        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
                })
                .unwrap_or_else(|| panic!("no CONTENDED {name}= field:\n{stdout}"))
                .parse()
                .unwrap()
        };
        let mut refused = 0;
        for seed in ["1", "2", "3"] {
            let run = common::native::assert_success(
                guest.command("run", &["--seed", seed, "--env", "FDS_MODE=contended"]),
            );
            let stdout = String::from_utf8_lossy(&run.stdout);
            assert_eq!(
                field(&stdout, "created_anyway"),
                0,
                "seed {seed}: an open that answered EMFILE created its file:\n{stdout}"
            );
            refused += field(&stdout, "refused");
        }
        assert!(refused > 0, "no seed made the open lose the last number");
    }
}
