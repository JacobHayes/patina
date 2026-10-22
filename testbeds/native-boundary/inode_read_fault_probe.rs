//! Calls that Linux answers from in-memory inode and file state: `FIONREAD`
//! and `FIOQSIZE` on a file, a `SEEK_END` record lock, `fchdir`,
//! `copy_file_range`'s size and same-file checks, `name_to_handle_at` on a
//! descriptor, and the attribute reads `utimensat` on a descriptor and
//! `fchown` (of a file and of a FIFO) make before they write. No storage
//! access happens in any of those reads, so no filesystem fault can fail them,
//! and this probe never calls `fstat` itself.
//!
//! `INODE_READ_SITE` names the one call to make; unset, the probe makes all of
//! them. Each call is made `CALLS` times and prints every distinct answer it
//! got. The probe's setup retries the errors an injected filesystem fault
//! answers (`EINTR`, `EIO`, `ENOSPC`), so it runs under any fault rate below
//! certainty. So do `utimensat` and `fchown`, because their own attribute
//! write is a storage access that can fail. The other calls are never retried.
use std::ffi::{CStr, c_char, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

const CALLS: usize = 16;
const ATTEMPTS: usize = 256;
const SIZE: usize = 4096;
const POSITION: u64 = 1000;

const FIONREAD: u64 = 0x541b;
const FIOQSIZE: u64 = 0x5460;
const F_SETLK: i32 = 6;
const F_WRLCK: i16 = 1;
const SEEK_END: i16 = 2;
const AT_EMPTY_PATH: i32 = 0x1000;
const EINVAL: i32 = 22;
#[cfg(target_arch = "x86_64")]
const SYS_NAME_TO_HANDLE_AT: i64 = 303;
#[cfg(target_arch = "aarch64")]
const SYS_NAME_TO_HANDLE_AT: i64 = 264;

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
struct FileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; 128],
}

unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn fchdir(fd: i32) -> i32;
    fn fchown(fd: i32, owner: u32, group: u32) -> i32;
    fn mkfifo(path: *const c_char, mode: u32) -> i32;
    fn utimensat(dirfd: i32, path: *const c_char, times: *const c_void, flags: i32) -> i32;
    fn copy_file_range(
        fd_in: i32,
        off_in: *mut i64,
        fd_out: i32,
        off_out: *mut i64,
        len: usize,
        flags: u32,
    ) -> isize;
    fn syscall(number: i64, ...) -> i64;
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A call's answer: its value, or `errnoN` when it failed.
fn answer(result: i64) -> String {
    if result < 0 {
        format!("errno{}", errno())
    } else {
        result.to_string()
    }
}

/// Whether `errno` is one an injected filesystem fault answers.
fn injected(errno: i32) -> bool {
    matches!(errno, 4 | 5 | 28)
}

/// The result of `op`, retried past the errors an injected filesystem fault
/// answers; any other error is the probe's failure.
fn retry<T>(what: &str, mut op: impl FnMut() -> io::Result<T>) -> T {
    let mut last = None;
    for _ in 0..ATTEMPTS {
        match op() {
            Ok(value) => return value,
            Err(error) if error.raw_os_error().is_some_and(injected) => last = Some(error),
            Err(error) => panic!("{what}: {error}"),
        }
    }
    panic!("{what} failed {ATTEMPTS} times: {last:?}")
}

/// A libc call returning -1 on failure, as an `io::Result`.
fn checked(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// `call` made `CALLS` times: every distinct answer, in the order first seen.
fn repeated(mut call: impl FnMut() -> String) -> String {
    let mut answers: Vec<String> = Vec::new();
    for _ in 0..CALLS {
        let answer = call();
        if !answers.contains(&answer) {
            answers.push(answer);
        }
    }
    answers.join("|")
}

/// A `SIZE`-byte file at `path`, open for reading and writing.
fn file(path: &str) -> File {
    let file = retry("open", || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    });
    retry("pwrite", || file.write_all_at(&[7; SIZE], 0));
    file
}

fn fionread() -> String {
    let mut file = file("/fionread.bin");
    retry("lseek", || file.seek(SeekFrom::Start(POSITION)));
    repeated(|| {
        let mut queued = 0i32;
        // SAFETY: FIONREAD writes one `int` through the pointer.
        let rc = unsafe { ioctl(file.as_raw_fd(), FIONREAD, &raw mut queued) };
        answer(if rc < 0 { -1 } else { i64::from(queued) })
    })
}

fn fioqsize() -> String {
    let file = file("/fioqsize.bin");
    repeated(|| {
        let mut bytes = 0i64;
        // SAFETY: FIOQSIZE writes one `loff_t` through the pointer.
        let rc = unsafe { ioctl(file.as_raw_fd(), FIOQSIZE, &raw mut bytes) };
        answer(if rc < 0 { -1 } else { bytes })
    })
}

fn lock_end() -> String {
    let file = file("/lock.bin");
    repeated(|| {
        let lock = Flock {
            l_type: F_WRLCK,
            l_whence: SEEK_END,
            l_start: -100,
            l_len: 100,
            l_pid: 0,
        };
        // SAFETY: F_SETLK reads one `struct flock`.
        answer(i64::from(unsafe {
            fcntl(file.as_raw_fd(), F_SETLK, &raw const lock)
        }))
    })
}

fn change_directory() -> String {
    retry("mkdir", || match std::fs::create_dir("/dir") {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    });
    let directory = retry("open /dir", || File::open("/dir"));
    // SAFETY: a descriptor the probe holds.
    repeated(|| answer(i64::from(unsafe { fchdir(directory.as_raw_fd()) })))
}

fn copy_range() -> String {
    let source = file("/copy.bin");
    let destination = file("/copy-out.bin");
    let at_end = repeated(|| {
        let (mut from, mut to) = (SIZE as i64, 0i64);
        // SAFETY: both offsets are local `loff_t`s.
        let copied = unsafe {
            copy_file_range(
                source.as_raw_fd(),
                &raw mut from,
                destination.as_raw_fd(),
                &raw mut to,
                100,
                0,
            )
        };
        answer(copied as i64)
    });
    let overlap = repeated(|| {
        let (mut from, mut to) = (0i64, 10i64);
        // SAFETY: both offsets are local `loff_t`s.
        let copied = unsafe {
            copy_file_range(
                source.as_raw_fd(),
                &raw mut from,
                source.as_raw_fd(),
                &raw mut to,
                100,
                0,
            )
        };
        if copied < 0 && errno() == EINVAL {
            "EINVAL".to_string()
        } else {
            answer(copied as i64)
        }
    });
    format!("at_end={at_end} overlap={overlap}")
}

fn name_to_handle() -> String {
    let file = file("/handle.bin");
    let empty: &CStr = c"";
    repeated(|| {
        let mut handle = FileHandle {
            handle_bytes: 128,
            handle_type: 0,
            f_handle: [0; 128],
        };
        let mut mount_id = 0i32;
        // SAFETY: the handle and the mount id are local storage of the sizes
        // the call writes.
        answer(unsafe {
            syscall(
                SYS_NAME_TO_HANDLE_AT,
                i64::from(file.as_raw_fd()),
                empty.as_ptr(),
                &raw mut handle,
                &raw mut mount_id,
                i64::from(AT_EMPTY_PATH),
            )
        })
    })
}

fn utimensat_descriptor() -> String {
    let file = file("/times.bin");
    let empty: &CStr = c"";
    repeated(|| {
        retry("utimensat", || {
            // SAFETY: an empty path with AT_EMPTY_PATH names the descriptor;
            // null times set both to now.
            checked(unsafe {
                utimensat(
                    file.as_raw_fd(),
                    empty.as_ptr(),
                    std::ptr::null(),
                    AT_EMPTY_PATH,
                )
            })
        })
        .to_string()
    })
}

/// `fchown` to the ids the descriptor's node already has (-1, -1).
fn change_owner(file: &File) -> String {
    repeated(|| {
        retry("fchown", || {
            // SAFETY: a descriptor the probe holds.
            checked(unsafe { fchown(file.as_raw_fd(), u32::MAX, u32::MAX) })
        })
        .to_string()
    })
}

fn fchown_file() -> String {
    change_owner(&file("/owner.bin"))
}

fn fchown_fifo() -> String {
    retry("mkfifo", || {
        // SAFETY: a NUL-terminated path.
        checked(unsafe { mkfifo(c"/fifo".as_ptr(), 0o600) })
    });
    let fifo = retry("open /fifo", || {
        OpenOptions::new().read(true).write(true).open("/fifo")
    });
    change_owner(&fifo)
}

const SITES: [(&str, fn() -> String); 9] = [
    ("fionread", fionread),
    ("fioqsize", fioqsize),
    ("lock_end", lock_end),
    ("fchdir", change_directory),
    ("copy_file_range", copy_range),
    ("name_to_handle_at", name_to_handle),
    ("utimensat_fd", utimensat_descriptor),
    ("fchown_file", fchown_file),
    ("fchown_fifo", fchown_fifo),
];

fn main() {
    let only = std::env::var("INODE_READ_SITE").ok();
    if let Some(site) = &only {
        assert!(
            SITES.iter().any(|(name, _)| name == site),
            "unknown INODE_READ_SITE {site}"
        );
    }
    for (name, site) in SITES {
        if only.as_deref().is_none_or(|only| only == name) {
            println!("NATIVE_INODE_READ {name} {}", site());
        }
    }
}
