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
use std::ffi::{c_int, c_long};
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

unsafe extern "C" {
    fn open(path: *const std::ffi::c_char, flags: c_int, ...) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut u8, len: usize) -> isize;
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
            let len = unsafe { read(watch, events.as_mut_ptr(), events.len()) };
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
        mode => panic!("PATH_RACE_MODE names no race: {mode}"),
    };
    println!("NATIVE_PATH_RACE {mode} {answer}");
}
