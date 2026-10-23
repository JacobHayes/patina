//! The path walk under filesystem faults. Every lookup the walk makes is the
//! kernel's own (namei), so no injected fault, latency or trace op reaches
//! it: only the call's own operation does.
//!
//! `PATH_WALK_MODE=lookups` makes calls that are nothing but a path walk over
//! the directories every run boots with (`/`, `/tmp`, `/home`), through `..`
//! and `.`: `statfs`, `inotify_add_watch`, `realpath`, and a `statfs` whose
//! walk ends at a missing name. They answer as Linux does under any fault
//! rate. Then one `open` and one `mkdir` through such a walk, whose own
//! operations an injected fault fails.
//!
//! `PATH_WALK_MODE=plain` and `PATH_WALK_MODE=walked` make the same `ROUNDS`
//! rounds of `open(O_CREAT)`, `stat` and `mkdir`, spelled directly
//! (`/tmp/f3`) or through `..`, `.` and a symlink (`/home/../tmp/link/./f3`),
//! and print every answer. The guest's calls are the same in both, so the
//! fault stream they draw is too: under one seed both print the same answers.
//! The setup (the symlink) is the same in both and retries the errors an
//! injected fault answers (`EINTR`, `EIO`, `ENOSPC`).
use std::ffi::{CString, c_char, c_int};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;

const ROUNDS: usize = 24;
const ATTEMPTS: usize = 256;
const IN_CREATE: u32 = 0x100;
const IN_ONLYDIR: u32 = 0x0100_0000;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_INIT1: i64 = 294;
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_ADD_WATCH: i64 = 254;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_INIT1: i64 = 26;
#[cfg(target_arch = "aarch64")]
const SYS_INOTIFY_ADD_WATCH: i64 = 27;

unsafe extern "C" {
    fn statfs(path: *const c_char, out: *mut u8) -> c_int;
    fn syscall(number: i64, ...) -> i64;
}

/// An answer: `0`, a value, or `errnoN`.
fn answer<T: ToString>(result: io::Result<T>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(error) => format!("errno{}", error.raw_os_error().unwrap_or(0)),
    }
}

/// A libc call returning -1 on failure, as an `io::Result`.
fn checked(result: c_int) -> io::Result<c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn path(spelling: &str) -> CString {
    CString::new(spelling).unwrap()
}

fn statfs_of(spelling: &str) -> String {
    let mut out = [0u8; 256];
    let path = path(spelling);
    // SAFETY: a NUL-terminated path; `out` is larger than `struct statfs`.
    answer(checked(unsafe { statfs(path.as_ptr(), out.as_mut_ptr()) }))
}

/// A watch on `spelling`, through the raw syscalls (glibc's inotify
/// wrappers are no doors of their own).
fn watch(spelling: &str) -> String {
    // SAFETY: no flags.
    let fd = checked(unsafe { syscall(SYS_INOTIFY_INIT1, 0) } as c_int).expect("inotify_init1");
    let path = path(spelling);
    // SAFETY: a NUL-terminated path on the probe's own inotify descriptor.
    answer(checked(unsafe {
        syscall(SYS_INOTIFY_ADD_WATCH, fd, path.as_ptr(), IN_CREATE | IN_ONLYDIR)
    } as c_int))
}

fn create(spelling: &str) -> String {
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(spelling);
    answer(opened.map(|_| 0))
}

fn lookups() {
    let answers = [
        ("statfs", statfs_of("/home/../tmp/./")),
        ("inotify_add_watch", watch("/home/../tmp/.")),
        (
            "realpath",
            answer(std::fs::canonicalize("/home/./../tmp/.").map(|path| path.display().to_string())),
        ),
        ("missing", statfs_of("/home/../tmp/absent/x")),
        ("open", create("/home/../tmp/./created")),
        ("mkdir", answer(std::fs::create_dir("/home/../tmp/./made").map(|()| 0))),
    ];
    for (call, answer) in answers {
        println!("NATIVE_PATH_WALK {call} {answer}");
    }
}

/// Whether `errno` is one an injected filesystem fault answers.
fn injected(errno: i32) -> bool {
    matches!(errno, 4 | 5 | 28)
}

fn rounds(prefix: &str) {
    let mut last = None;
    let linked = (0..ATTEMPTS).any(|_| match std::os::unix::fs::symlink("/tmp", "/tmp/link") {
        Ok(()) => true,
        Err(error) if error.raw_os_error().is_some_and(injected) => {
            last = Some(error);
            false
        }
        Err(error) => panic!("symlink: {error}"),
    });
    assert!(linked, "symlink failed {ATTEMPTS} times: {last:?}");
    let mut answers = Vec::new();
    for round in 0..ROUNDS {
        let file = format!("{prefix}f{round}");
        answers.push(create(&file));
        answers.push(answer(std::fs::metadata(&file).map(|_| 0)));
        answers.push(answer(std::fs::create_dir(format!("{prefix}d{round}")).map(|()| 0)));
    }
    println!("NATIVE_PATH_WALK rounds {}", answers.join(","));
}

fn main() {
    match std::env::var("PATH_WALK_MODE").as_deref() {
        Ok("lookups") => lookups(),
        Ok("plain") => rounds("/tmp/"),
        Ok("walked") => rounds("/home/../tmp/link/./"),
        mode => panic!("PATH_WALK_MODE must be lookups, plain or walked, not {mode:?}"),
    }
}
