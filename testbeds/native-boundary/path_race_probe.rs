//! Path and directory calls racing another thread. `PATH_RACE_MODE` picks the
//! race; each prints one `NATIVE_PATH_RACE <mode> <answer>` line.
//!
//! - `poll`: the main thread polls `stat` of a name another thread creates,
//!   and answers `seen` once it exists or `never` after `POLLS` polls. A call
//!   whose path walk fails is still a call into the kernel, where the other
//!   thread gets to run.
//! - `stat_swap`: another thread keeps replacing `/tmp/x` by a symlink to a
//!   regular file and by a regular file again, while the main thread
//!   `stat`s `/tmp/x`. `stat` follows the link, so it never answers a
//!   symlink; the answer is how many times it did.
//! - `getdents_dup2`: each round opens directories `a` and `b`, and another
//!   thread `dup2`s `b` over `a`'s number while the main thread reads it with
//!   `getdents64`. Every other round a duplicate keeps `a`'s description
//!   open past the `dup2`. The read that races the `dup2` reads one
//!   directory or the other, and fails in neither case. When it read `a`,
//!   `b`'s description is still at its start, so the next read lists `b`'s
//!   entries. The answer counts the rounds where it did not (it went on
//!   with `a`'s), and the reads that failed.
//! - `starve`: for each spelling a `stat` answers without a filesystem walk
//!   (an empty or overlong path or name, a device node, a namespace file, a
//!   pseudoterminal that does not exist), the main thread polls it while a
//!   runnable peer waits to run once. The answer lists the spellings whose
//!   polls never let it run, or `none`.
//! - `getdents_notify`: as `getdents_dup2`, with an inotify watch on each
//!   directory. A `getdents64` reports access to the directory it lists, so
//!   a read that listed `b` reported `b`'s access, not `a`'s. The answer
//!   counts the rounds where it did not.
//! - `dirfd_ops`: the main thread holds directory `d` open, and another
//!   thread keeps renaming it aside and a second directory over its name,
//!   and back, while the main thread makes each directory-relative call
//!   family ([`DIRFD_OPS`]) through the held descriptor. Each acts in the
//!   held directory whatever its name is now; the answer lists the families
//!   that ever acted in the other one or failed, or `none`.
//! - `fifo_rename`: another thread renames a regular file over a FIFO while
//!   the main thread opens the FIFO read-write. The name exists throughout,
//!   so the open reaches one node or the other; the answer counts the opens
//!   that failed.
//! - `rebind_rename`: a bound socket binds again to a free name, which the
//!   kernel refuses after it made the name's node, then removes that node;
//!   another thread renames a regular file over the name meanwhile. The
//!   removal takes the node the call made, never the renamed file; the answer
//!   counts the rounds that lost it.
use std::ffi::{CStr, c_char, c_int, c_long};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::os::unix::fs::symlink;

const POLLS: usize = 2000;
const SWAPS: usize = 200;
const ROUNDS: usize = 50;
// O_DIRECTORY's value is per architecture: aarch64 gives 0o200000 to O_DIRECT.
#[cfg(target_arch = "x86_64")]
const O_RDONLY_DIRECTORY: c_int = 0o200000;
#[cfg(target_arch = "aarch64")]
const O_RDONLY_DIRECTORY: c_int = 0o40000;
#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: c_long = 217;
#[cfg(target_arch = "aarch64")]
const SYS_GETDENTS64: c_long = 61;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_INIT1: c_long = 294;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_ADD_WATCH: c_long = 254;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_INIT1: c_long = 26;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_ADD_WATCH: c_long = 27;
const IN_NONBLOCK: c_int = 0o4000;
const IN_ACCESS: u32 = 1;
const O_PATH: c_int = 0o10000000;
const O_WRONLY_CREAT: c_int = 0o101;

/// Keep renaming `d` aside and `ro` over its name, and back, until `stop`.
fn swapper(stop: &'static AtomicBool) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(SeqCst) {
            std::fs::rename("/tmp/d", "/tmp/t").unwrap();
            std::fs::rename("/tmp/ro", "/tmp/d").unwrap();
            std::fs::rename("/tmp/d", "/tmp/ro").unwrap();
            std::fs::rename("/tmp/t", "/tmp/d").unwrap();
        }
    })
}

fn fifo_rename() -> usize {
    (0..ROUNDS)
        .filter(|_| {
            // SAFETY: a NUL-terminated path.
            assert_eq!(unsafe { mkfifo(c"/tmp/fifo".as_ptr(), 0o600) }, 0, "mkfifo");
            std::fs::write("/tmp/regular", b"regular").unwrap();
            let peer =
                std::thread::spawn(|| std::fs::rename("/tmp/regular", "/tmp/fifo").unwrap());
            // SAFETY: a NUL-terminated path; `O_RDWR` never waits for a peer.
            let fd = unsafe { open(c"/tmp/fifo".as_ptr(), 2) };
            if fd >= 0 {
                // SAFETY: the descriptor just opened.
                unsafe { close(fd) };
            }
            peer.join().unwrap();
            std::fs::remove_file("/tmp/fifo").unwrap();
            fd < 0
        })
        .count()
}

fn rebind_rename() -> usize {
    use std::os::fd::AsRawFd;
    let name = b"/tmp/second";
    let mut addr = [0u8; 110];
    addr[..2].copy_from_slice(&1u16.to_ne_bytes());
    addr[2..2 + name.len()].copy_from_slice(name);
    (0..ROUNDS)
        .filter(|_| {
            let sock = std::os::unix::net::UnixDatagram::bind("/tmp/first").unwrap();
            std::fs::write("/tmp/regular", b"regular").unwrap();
            let peer =
                std::thread::spawn(|| std::fs::rename("/tmp/regular", "/tmp/second").unwrap());
            // SAFETY: a sockaddr_un `addr` holds, with its length.
            let rebound = unsafe { bind(sock.as_raw_fd(), addr.as_ptr(), (3 + name.len()) as u32) };
            assert_eq!(rebound, -1, "a second bind is refused");
            peer.join().unwrap();
            let lost = std::fs::read("/tmp/second").map_or(true, |bytes| bytes != b"regular");
            drop(sock);
            std::fs::remove_file("/tmp/first").unwrap();
            let _ = std::fs::remove_file("/tmp/second");
            lost
        })
        .count()
}

/// A file `name` in `dir` holding `tag`, as `dir`'s own.
fn put(dir: c_int, name: &CStr, tag: u8) {
    // SAFETY: a NUL-terminated name relative to a held directory.
    let fd = unsafe { openat(dir, name.as_ptr(), O_WRONLY_CREAT, 0o644) };
    assert!(fd >= 0, "create {name:?}: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` is the file just opened; one byte from `tag`.
    unsafe {
        assert_eq!(write(fd, (&raw const tag).cast(), 1), 1);
        close(fd);
    }
}

/// `name`'s statx in `dir` (`""`: `dir` itself), not following a trailing
/// symlink, or `None`.
fn look(dir: c_int, name: &CStr) -> Option<[u8; 256]> {
    let mut out = Statx([0; 256]);
    let flags = AT_SYMLINK_NOFOLLOW | if name.is_empty() { AT_EMPTY_PATH } else { 0 };
    // SAFETY: `out` is larger than `struct statx`.
    let found = unsafe { statx(dir, name.as_ptr(), flags, 0xfff, &mut out) } == 0;
    found.then_some(out.0)
}

/// Room for `struct statx`, aligned as it is.
#[repr(C, align(8))]
struct Statx([u8; 256]);

fn has(dir: c_int, name: &CStr) -> bool {
    look(dir, name).is_some()
}

/// `statx` fields: `stx_mode` (u16 at 28), `stx_ino` (u64 at 32) and
/// `stx_mtime.tv_sec` (i64 at 112).
fn mode(st: &[u8; 256]) -> u32 {
    u32::from(u16::from_ne_bytes([st[28], st[29]]))
}
fn ino(st: &[u8; 256]) -> u64 {
    u64::from_ne_bytes(st[32..40].try_into().unwrap())
}
fn mtime(st: &[u8; 256]) -> i64 {
    i64::from_ne_bytes(st[112..120].try_into().unwrap())
}

/// The byte file `name` in `dir` holds.
fn tag_of(dir: c_int, name: &CStr) -> Option<u8> {
    // SAFETY: a NUL-terminated name relative to a held directory.
    let fd = unsafe { openat(dir, name.as_ptr(), 0) };
    if fd < 0 {
        return None;
    }
    let mut byte = 0;
    // SAFETY: one writable byte; `fd` is the file just opened.
    let got = unsafe { read(fd, (&raw mut byte).cast(), 1) };
    // SAFETY: as above.
    unsafe { close(fd) };
    (got == 1).then_some(byte)
}

/// One directory-relative call family: what each directory holds first
/// (`setup`, given the directory's tag), the call through the held one
/// (`act`), and whether what it did happened in the held directory and
/// nowhere else (`landed`, read once the renames stopped).
struct DirfdOp {
    name: &'static str,
    setup: fn(dir: c_int, tag: u8),
    act: fn(held: c_int) -> bool,
    landed: fn(held: c_int, other: c_int, acted: bool) -> bool,
}

const HELD: u8 = b'h';
const OTHER: u8 = b'o';
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_REMOVEDIR: c_int = 0x200;
const AT_EMPTY_PATH: c_int = 0x1000;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFIFO: u32 = 0o10000;
const STAMP: i64 = 1_000_000;

fn nothing(_: c_int, _: u8) {}

fn acted(_: c_int, _: c_int, acted: bool) -> bool {
    acted
}

fn file_f(dir: c_int, tag: u8) {
    put(dir, c"f", tag);
}

fn file_a(dir: c_int, tag: u8) {
    put(dir, c"a", tag);
}

/// Every directory-relative call family the shim walks a path for. A new
/// family belongs here: its walk and its operation must be one step against
/// a thread renaming the directory, as they are in the kernel.
const DIRFD_OPS: &[DirfdOp] = &[
    DirfdOp {
        name: "open_dot",
        setup: nothing,
        act: |held| {
            // SAFETY: a NUL-terminated path relative to a held directory.
            let fd = unsafe { openat(held, c".".as_ptr(), O_PATH | O_RDONLY_DIRECTORY) };
            if fd < 0 {
                return false;
            }
            let same = matches!(
                (look(fd, c""), look(held, c"")),
                (Some(reached), Some(held)) if ino(&reached) == ino(&held)
            );
            // SAFETY: the descriptor just opened.
            unsafe { close(fd) };
            same
        },
        landed: acted,
    },
    DirfdOp {
        name: "open_read",
        setup: file_f,
        act: |held| tag_of(held, c"f") == Some(HELD),
        landed: acted,
    },
    DirfdOp {
        name: "open_create",
        setup: nothing,
        act: |held| {
            // SAFETY: a NUL-terminated name relative to a held directory.
            let fd = unsafe { openat(held, c"n".as_ptr(), O_WRONLY_CREAT, 0o644) };
            if fd >= 0 {
                // SAFETY: the descriptor just opened.
                unsafe { close(fd) };
            }
            fd >= 0
        },
        landed: |held, other, acted| acted && has(held, c"n") && !has(other, c"n"),
    },
    DirfdOp {
        name: "stat",
        // The held directory's `f` is a file, the other's a directory.
        setup: |dir, tag| {
            if tag == HELD {
                put(dir, c"f", tag);
            } else {
                // SAFETY: a NUL-terminated name relative to a held directory.
                assert_eq!(unsafe { mkdirat(dir, c"f".as_ptr(), 0o755) }, 0);
            }
        },
        act: |held| look(held, c"f").is_some_and(|st| mode(&st) & S_IFMT == S_IFREG),
        landed: acted,
    },
    DirfdOp {
        name: "access",
        // Only the held directory has an `f`.
        setup: |dir, tag| {
            if tag == HELD {
                put(dir, c"f", tag);
            }
        },
        // SAFETY: a NUL-terminated name relative to a held directory.
        act: |held| unsafe { faccessat(held, c"f".as_ptr(), 0, 0) } == 0,
        landed: acted,
    },
    DirfdOp {
        name: "unlink",
        setup: file_f,
        // SAFETY: a NUL-terminated name relative to a held directory.
        act: |held| unsafe { unlinkat(held, c"f".as_ptr(), 0) } == 0,
        landed: |held, other, acted| acted && !has(held, c"f") && has(other, c"f"),
    },
    DirfdOp {
        name: "mkdir",
        setup: nothing,
        // SAFETY: a NUL-terminated name relative to a held directory.
        act: |held| unsafe { mkdirat(held, c"m".as_ptr(), 0o755) } == 0,
        landed: |held, other, acted| acted && has(held, c"m") && !has(other, c"m"),
    },
    DirfdOp {
        name: "rmdir",
        // SAFETY: a NUL-terminated name relative to a held directory.
        setup: |dir, _| assert_eq!(unsafe { mkdirat(dir, c"m".as_ptr(), 0o755) }, 0),
        // SAFETY: as above.
        act: |held| unsafe { unlinkat(held, c"m".as_ptr(), AT_REMOVEDIR) } == 0,
        landed: |held, other, acted| acted && !has(held, c"m") && has(other, c"m"),
    },
    DirfdOp {
        name: "mknod",
        setup: nothing,
        // SAFETY: a NUL-terminated name relative to a held directory.
        act: |held| unsafe { mknodat(held, c"p".as_ptr(), S_IFIFO | 0o600, 0) } == 0,
        landed: |held, other, acted| acted && has(held, c"p") && !has(other, c"p"),
    },
    DirfdOp {
        name: "symlink",
        setup: nothing,
        // SAFETY: NUL-terminated strings; the link is relative to a held directory.
        act: |held| unsafe { symlinkat(c"target".as_ptr(), held, c"s".as_ptr()) } == 0,
        landed: |held, other, acted| acted && has(held, c"s") && !has(other, c"s"),
    },
    DirfdOp {
        name: "readlink",
        setup: |dir, tag| {
            let target: &CStr = if tag == HELD { c"held" } else { c"other" };
            // SAFETY: NUL-terminated strings; the link is relative to a held directory.
            assert_eq!(unsafe { symlinkat(target.as_ptr(), dir, c"s".as_ptr()) }, 0);
        },
        act: |held| {
            let mut buf = [0u8; 16];
            // SAFETY: `buf` is writable for its length.
            let len = unsafe { readlinkat(held, c"s".as_ptr(), buf.as_mut_ptr(), buf.len()) };
            len >= 0 && &buf[..len as usize] == b"held"
        },
        landed: acted,
    },
    DirfdOp {
        name: "rename",
        setup: file_a,
        // SAFETY: NUL-terminated names relative to the held directory.
        act: |held| unsafe { renameat(held, c"a".as_ptr(), held, c"b".as_ptr()) } == 0,
        landed: |held, other, acted| {
            acted
                && tag_of(held, c"b") == Some(HELD)
                && !has(held, c"a")
                && has(other, c"a")
                && !has(other, c"b")
        },
    },
    DirfdOp {
        name: "link",
        setup: file_a,
        // SAFETY: NUL-terminated names relative to the held directory.
        act: |held| unsafe { linkat(held, c"a".as_ptr(), held, c"b".as_ptr(), 0) } == 0,
        landed: |held, other, acted| {
            acted && tag_of(held, c"b") == Some(HELD) && !has(other, c"b")
        },
    },
    DirfdOp {
        name: "chmod",
        setup: file_f,
        // SAFETY: a NUL-terminated name relative to a held directory.
        act: |held| unsafe { fchmodat(held, c"f".as_ptr(), 0o600, 0) } == 0,
        landed: |held, other, acted| {
            let perm = |dir| look(dir, c"f").map(|st| mode(&st) & 0o777);
            acted && perm(held) == Some(0o600) && perm(other) == Some(0o644)
        },
    },
    DirfdOp {
        name: "utimens",
        setup: file_f,
        act: |held| {
            let times = [STAMP, 0, STAMP, 0];
            // SAFETY: two timespecs; a NUL-terminated name relative to a held directory.
            unsafe { utimensat(held, c"f".as_ptr(), &times, 0) == 0 }
        },
        landed: |held, other, acted| {
            let stamp = |dir| look(dir, c"f").map(|st| mtime(&st));
            acted && stamp(held) == Some(STAMP) && stamp(other) != Some(STAMP)
        },
    },
];

/// Every [`DIRFD_OPS`] family, `ROUNDS` times each, while another thread
/// keeps renaming the held directory aside and the other over its name.
fn dirfd_ops() -> String {
    static STOP: AtomicBool = AtomicBool::new(false);
    std::fs::create_dir("/tmp/d").unwrap();
    std::fs::create_dir("/tmp/ro").unwrap();
    let held = open_dir(c"/tmp/d");
    let other = open_dir(c"/tmp/ro");
    let wrong: Vec<&str> = DIRFD_OPS
        .iter()
        .filter(|op| {
            (0..ROUNDS).any(|_| {
                (op.setup)(held, HELD);
                (op.setup)(other, OTHER);
                STOP.store(false, SeqCst);
                let renamer = swapper(&STOP);
                let acted = (op.act)(held);
                STOP.store(true, SeqCst);
                renamer.join().unwrap();
                let landed = (op.landed)(held, other, acted);
                for dir in [held, other] {
                    for name in [c"f", c"n", c"a", c"b", c"s", c"p"] {
                        // SAFETY: NUL-terminated names; a missing one is fine.
                        unsafe { unlinkat(dir, name.as_ptr(), 0) };
                    }
                    for name in [c"f", c"m"] {
                        // SAFETY: as above.
                        unsafe { unlinkat(dir, name.as_ptr(), AT_REMOVEDIR) };
                    }
                }
                !landed
            })
        })
        .map(|op| op.name)
        .collect();
    if wrong.is_empty() { "none".into() } else { wrong.join(",") }
}

unsafe extern "C" {
    fn open(path: *const std::ffi::c_char, flags: c_int, ...) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut std::ffi::c_void, len: usize) -> isize;
    fn write(fd: c_int, buf: *const std::ffi::c_void, len: usize) -> isize;
    fn openat(dirfd: c_int, path: *const std::ffi::c_char, flags: c_int, ...) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const std::ffi::c_char, flags: c_int) -> c_int;
    fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn mknodat(dirfd: c_int, path: *const c_char, mode: u32, dev: u64) -> c_int;
    fn renameat(from_dir: c_int, from: *const c_char, to_dir: c_int, to: *const c_char) -> c_int;
    fn linkat(
        from_dir: c_int,
        from: *const c_char,
        to_dir: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> c_int;
    fn symlinkat(target: *const c_char, dirfd: c_int, path: *const c_char) -> c_int;
    fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut u8, len: usize) -> isize;
    fn fchmodat(dirfd: c_int, path: *const c_char, mode: u32, flags: c_int) -> c_int;
    fn utimensat(dirfd: c_int, path: *const c_char, times: *const [i64; 4], flags: c_int) -> c_int;
    fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int;
    fn statx(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: u32,
        out: *mut Statx,
    ) -> c_int;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> c_int;
    fn bind(fd: c_int, addr: *const u8, len: u32) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

/// Whether a peer that is runnable throughout gets to run while the main
/// thread makes `POLLS` calls of `poll`.
fn peer_runs(poll: impl Fn()) -> bool {
    static READY: AtomicBool = AtomicBool::new(false);
    static GO: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicBool = AtomicBool::new(false);
    for flag in [&READY, &GO, &DONE] {
        flag.store(false, SeqCst);
    }
    let peer = std::thread::spawn(|| {
        READY.store(true, SeqCst);
        while !GO.load(SeqCst) {
            std::thread::yield_now();
        }
        DONE.store(true, SeqCst);
    });
    while !READY.load(SeqCst) {
        std::thread::yield_now();
    }
    GO.store(true, SeqCst);
    let ran = (0..POLLS).any(|_| {
        poll();
        DONE.load(SeqCst)
    });
    peer.join().unwrap();
    ran
}

fn starve() -> String {
    let overlong_path = "a".repeat(4096);
    let overlong_name = format!("/{}", "a".repeat(256));
    let spellings = [
        ("empty", ""),
        ("overlong_path", overlong_path.as_str()),
        ("overlong_name", overlong_name.as_str()),
        ("urandom", "/dev/urandom"),
        ("namespace", "/proc/self/ns/uts"),
        ("pts", "/dev/pts/9999"),
    ];
    let starved: Vec<&str> = spellings
        .into_iter()
        .filter(|(_, path)| {
            !peer_runs(|| {
                let _ = std::fs::metadata(path);
            })
        })
        .map(|(name, _)| name)
        .collect();
    if starved.is_empty() { "none".into() } else { starved.join(",") }
}

/// Whether the inotify events pending on `watch` hold an access to `wd`.
fn accessed(events: &[u8], wd: c_int) -> bool {
    let mut at = 0;
    let mut seen = false;
    while at + 16 <= events.len() {
        let event_wd = i32::from_ne_bytes(events[at..at + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(events[at + 4..at + 8].try_into().unwrap());
        let len = u32::from_ne_bytes(events[at + 12..at + 16].try_into().unwrap());
        seen |= event_wd == wd && mask & IN_ACCESS != 0;
        at += 16 + len as usize;
    }
    seen
}

fn getdents_notify() -> usize {
    for dir in ["a", "b"] {
        std::fs::create_dir(format!("/tmp/{dir}")).unwrap();
        std::fs::write(format!("/tmp/{dir}/in_{dir}"), b"").unwrap();
    }
    // SAFETY: raw inotify calls on NUL-terminated paths.
    let (watch, wa, wb) = unsafe {
        let watch = syscall(SYS_INOTIFY_INIT1, IN_NONBLOCK) as c_int;
        assert!(watch >= 0, "inotify_init1: {}", std::io::Error::last_os_error());
        let wa = syscall(SYS_INOTIFY_ADD_WATCH, watch, c"/tmp/a".as_ptr(), IN_ACCESS) as c_int;
        let wb = syscall(SYS_INOTIFY_ADD_WATCH, watch, c"/tmp/b".as_ptr(), IN_ACCESS) as c_int;
        assert!(wa >= 0 && wb >= 0, "inotify_add_watch");
        (watch, wa, wb)
    };
    let mismatched = (0..ROUNDS)
        .filter(|_| {
            let a = open_dir(c"/tmp/a");
            let b = open_dir(c"/tmp/b");
            // SAFETY: two descriptors this round opened.
            let replacer = std::thread::spawn(move || assert_eq!(unsafe { dup2(b, a) }, a));
            let listed = names(a).unwrap();
            replacer.join().unwrap();
            let mut events = [0u8; 4096];
            // SAFETY: `events` is writable for its length.
            let len = unsafe { read(watch, events.as_mut_ptr().cast(), events.len()) };
            let events = &events[..len.max(0) as usize];
            // SAFETY: descriptors this round opened.
            unsafe {
                close(a);
                close(b);
            }
            let listed_b = listed.iter().any(|name| name == "in_b");
            listed_b && !accessed(events, wb)
                || !listed_b && listed.iter().any(|name| name == "in_a") && !accessed(events, wa)
        })
        .count();
    // SAFETY: the watch this function made.
    unsafe { close(watch) };
    mismatched
}

fn poll() -> &'static str {
    let writer = std::thread::spawn(|| {
        std::fs::create_dir("/tmp/pending").unwrap();
        std::fs::write("/tmp/pending/file", b"here").unwrap();
    });
    let seen = (0..POLLS).any(|_| std::fs::metadata("/tmp/pending/file").is_ok());
    writer.join().unwrap();
    if seen { "seen" } else { "never" }
}

fn stat_swap() -> usize {
    std::fs::write("/tmp/target", b"target").unwrap();
    std::fs::write("/tmp/x", b"file").unwrap();
    let swapper = std::thread::spawn(|| {
        for _ in 0..SWAPS {
            symlink("/tmp/target", "/tmp/link").unwrap();
            std::fs::rename("/tmp/link", "/tmp/x").unwrap();
            std::fs::write("/tmp/file", b"file").unwrap();
            std::fs::rename("/tmp/file", "/tmp/x").unwrap();
        }
    });
    let symlinks = (0..SWAPS)
        .filter(|_| std::fs::metadata("/tmp/x").unwrap().file_type().is_symlink())
        .count();
    swapper.join().unwrap();
    symlinks
}

fn open_dir(path: &std::ffi::CStr) -> c_int {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY_DIRECTORY) };
    assert!(fd >= 0, "open {path:?}: {}", std::io::Error::last_os_error());
    fd
}

/// The names one `getdents64` on `fd` lists, or its errno.
fn names(fd: c_int) -> Result<Vec<String>, i32> {
    let mut buf = [0u8; 4096];
    // SAFETY: `buf` is writable for its length.
    let len = unsafe { syscall(SYS_GETDENTS64, fd, buf.as_mut_ptr(), buf.len()) };
    if len < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    let mut names = Vec::new();
    let mut at = 0;
    while at < len as usize {
        let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
        let name = &buf[at + 19..at + reclen];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap()];
        names.push(String::from_utf8_lossy(name).into_owned());
        at += reclen;
    }
    Ok(names)
}

fn getdents_dup2() -> String {
    for dir in ["a", "b"] {
        std::fs::create_dir(format!("/tmp/{dir}")).unwrap();
        std::fs::write(format!("/tmp/{dir}/in_{dir}"), b"").unwrap();
    }
    let (mut stale, mut failed) = (0, 0);
    for round in 0..ROUNDS {
        let a = open_dir(c"/tmp/a");
        let b = open_dir(c"/tmp/b");
        // SAFETY: a descriptor this round opened.
        let keep = (round % 2 == 0).then(|| unsafe { dup(a) });
        // SAFETY: two descriptors this round opened.
        let replacer = std::thread::spawn(move || assert_eq!(unsafe { dup2(b, a) }, a));
        let racing = names(a);
        replacer.join().unwrap();
        let after = names(a);
        failed += usize::from(racing.is_err()) + usize::from(after.is_err());
        let listed = |names: &Result<Vec<String>, i32>, name: &str| {
            names.as_ref().is_ok_and(|names| names.iter().any(|listed| listed == name))
        };
        stale += usize::from(listed(&racing, "in_a") && !listed(&after, "in_b"));
        // SAFETY: descriptors this round opened.
        unsafe {
            close(a);
            close(b);
            keep.map(|keep| close(keep));
        }
    }
    format!("stale={stale} failed={failed}")
}

fn main() {
    let mode = std::env::var("PATH_RACE_MODE").unwrap();
    let answer = match mode.as_str() {
        "poll" => poll().to_owned(),
        "stat_swap" => stat_swap().to_string(),
        "getdents_dup2" => getdents_dup2(),
        "starve" => starve(),
        "getdents_notify" => getdents_notify().to_string(),
        "dirfd_ops" => dirfd_ops(),
        "fifo_rename" => fifo_rename().to_string(),
        "rebind_rename" => rebind_rename().to_string(),
        mode => panic!("PATH_RACE_MODE names no race: {mode}"),
    };
    println!("NATIVE_PATH_RACE {mode} {answer}");
}
