//! `/proc/self/fd`: each open descriptor's magic link. Prints one
//! `PROC_FD <case> <answer>` line per case, the same natively and under
//! patina; paths are printed relative to the probe's own directory, and
//! numbers that differ between hosts (pids, inode numbers) only as relations.
//!
//! - an `O_PATH|O_NOFOLLOW` open of a symlink names the link itself: `fstat`
//!   reads `S_IFLNK`, `readlinkat(fd, "")` its target, its fd link the
//!   link's path, and a walk through the fd link lands on the link (a `stat`
//!   reads `S_IFLNK`, an open is `ELOOP`); under `O_DIRECTORY` it is
//!   `ENOTDIR`;
//! - a socket pinned by an `O_PATH` descriptor is reachable by `connect`
//!   through its fd link, after its name is renamed and after it is unlinked,
//!   while the old name is gone; a socket descriptor's own link is sockfs's
//!   inode, which no listener is bound to (`ECONNREFUSED`);
//! - a file reopened through its fd link is a new description of the same
//!   node, after a rename; once unlinked, a `stat` through the link still
//!   reads it (no names left, its inode number);
//! - a directory's fd link is a base the walk goes on from, after a rename;
//! - a link reads the node's current path, or `socket:[ino]`, `pipe:[ino]`,
//!   `anon_inode:[eventfd]` for an anonymous one; its own mode is the
//!   description's access; `O_NOFOLLOW` opens it as the link (`ELOOP`);
//! - the directory lists the open numbers, not a closed one, whose link is
//!   `ENOENT`, and a listing read a few entries at a time resumes at the next
//!   open number past one closed meanwhile; `/proc/<pid>/fd` is the caller's
//!   too.
use std::ffi::{CString, c_char, c_int, c_long};
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

const O_PATH: c_int = 0o10000000;
// O_NOFOLLOW's value is per architecture.
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: c_int = 0o400000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: c_int = 0o100000;
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: c_int = 0o200000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: c_int = 0o40000;
const O_RDONLY: c_int = 0;
const O_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: c_long = 217;
#[cfg(target_arch = "aarch64")]
const SYS_GETDENTS64: c_long = 61;

unsafe extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, len: usize) -> isize;
    fn pipe(fds: *mut c_int) -> c_int;
    fn eventfd(initval: u32, flags: c_int) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    // SAFETY: the calling thread's errno.
    unsafe { *__errno_location() }
}

fn say(case: &str, answer: impl std::fmt::Display) {
    println!("PROC_FD {case} {answer}");
}

/// `open(path, flags)`: the descriptor or the errno, negated.
fn open_raw(path: &Path, flags: c_int) -> Result<OwnedFd, c_int> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { open(path.as_ptr(), flags | O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: a descriptor just opened, owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn link_of(fd: c_int) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

fn errno_of(error: std::io::Error) -> String {
    format!("errno={}", error.raw_os_error().unwrap_or(-1))
}

/// A path printed relative to the probe's directory.
fn relative(dir: &Path, path: &Path) -> String {
    match path.strip_prefix(dir) {
        Ok(rest) => format!("<dir>/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn kind(metadata: &fs::Metadata) -> &'static str {
    let ty = metadata.file_type();
    if ty.is_symlink() {
        "link"
    } else if ty.is_dir() {
        "dir"
    } else if ty.is_file() {
        "file"
    } else if ty.is_socket() {
        "socket"
    } else if ty.is_fifo() {
        "fifo"
    } else {
        "other"
    }
}

fn connect(path: &Path) -> String {
    match UnixStream::connect(path) {
        Ok(_) => "ok".to_owned(),
        Err(error) => errno_of(error),
    }
}

fn symlinks(dir: &Path) {
    let target = dir.join("target");
    fs::write(&target, b"target").unwrap();
    let link = dir.join("link");
    symlink(&target, &link).unwrap();
    let fd = match open_raw(&link, O_PATH | O_NOFOLLOW) {
        Ok(fd) => fd,
        Err(errno) => return say("symlink_fstat", format!("errno={errno}")),
    };
    let file = fs::File::from(fd);
    say("symlink_fstat", kind(&file.metadata().unwrap()));
    let mut buf = [0u8; 256];
    // SAFETY: an empty name relative to a held descriptor, and a buffer of `len`.
    let n = unsafe {
        readlinkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let read = if n < 0 {
        format!("errno={}", errno())
    } else {
        relative(
            dir,
            Path::new(std::str::from_utf8(&buf[..n as usize]).unwrap()),
        )
    };
    say("symlink_readlinkat_empty", read);
    let through = link_of(file.as_raw_fd());
    say(
        "symlink_fd_link",
        relative(dir, &fs::read_link(&through).unwrap()),
    );
    say(
        "symlink_stat_through",
        fs::metadata(&through).map_or_else(errno_of, |m| kind(&m).to_owned()),
    );
    say(
        "symlink_open_through",
        open_raw(&through, O_RDONLY).map_or_else(|e| format!("errno={e}"), |_| "opened".into()),
    );
    say(
        "symlink_opath_directory",
        open_raw(&link, O_PATH | O_NOFOLLOW | O_DIRECTORY)
            .map_or_else(|e| format!("errno={e}"), |_| "opened".into()),
    );
    // Go's `os.Root.OpenFile(name, O_PATH)` on a symlink: the same open, a
    // descriptor on the link.
    say(
        "symlink_opath_follow",
        open_raw(&link, O_PATH).map_or_else(
            |e| format!("errno={e}"),
            |fd| kind(&fs::File::from(fd).metadata().unwrap()).to_owned(),
        ),
    );
}

fn sockets(dir: &Path) {
    let name = dir.join("bus.sock");
    let listener = UnixListener::bind(&name).unwrap();
    let pin = open_raw(&name, O_PATH | O_NOFOLLOW).expect("O_PATH on the socket");
    let pinned = link_of(pin.as_raw_fd());
    say(
        "socket_pin_kind",
        kind(&fs::File::from(pin.try_clone().unwrap()).metadata().unwrap()),
    );
    say("socket_connect_pinned", connect(&pinned));
    let moved = dir.join("moved.sock");
    fs::rename(&name, &moved).unwrap();
    say(
        "socket_link_after_rename",
        relative(dir, &fs::read_link(&pinned).unwrap()),
    );
    say("socket_connect_after_rename", connect(&pinned));
    say("socket_connect_old_name", connect(&name));
    fs::remove_file(&moved).unwrap();
    say("socket_connect_after_unlink", connect(&pinned));
    let own = link_of(listener.as_raw_fd());
    say(
        "socket_own_link_kind",
        fs::metadata(&own).map_or_else(errno_of, |m| kind(&m).to_owned()),
    );
    say("socket_connect_own_link", connect(&own));
    say(
        "mode_socket",
        format!("{:o}", fs::symlink_metadata(&own).unwrap().mode() & 0o7777),
    );
    let text = fs::read_link(&own).unwrap();
    let text = text.to_str().unwrap();
    say(
        "socket_own_link",
        text.starts_with("socket:[")
            && text.ends_with(']')
            && text[8..text.len() - 1] == listener_ino(&listener).to_string(),
    );
}

fn listener_ino(listener: &UnixListener) -> u64 {
    fs::metadata(link_of(listener.as_raw_fd())).unwrap().ino()
}

fn files(dir: &Path) {
    let path = dir.join("data");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    use std::io::Write;
    (&file).write_all(b"hello").unwrap();
    let through = link_of(file.as_raw_fd());
    let moved = dir.join("renamed");
    fs::rename(&path, &moved).unwrap();
    say(
        "file_link_after_rename",
        relative(dir, &fs::read_link(&through).unwrap()),
    );
    say(
        "file_reopen_after_rename",
        fs::read(&through).map_or_else(errno_of, |bytes| String::from_utf8(bytes).unwrap()),
    );
    let ino = file.metadata().unwrap().ino();
    fs::remove_file(&moved).unwrap();
    say(
        "file_stat_after_unlink",
        fs::metadata(&through).map_or_else(errno_of, |m| {
            format!("nlink={} same_ino={}", m.nlink(), m.ino() == ino)
        }),
    );
    say(
        "file_old_name_after_unlink",
        fs::metadata(&path).map_or_else(errno_of, |_| "found".into()),
    );

    let read_only = fs::File::open(dir).unwrap();
    let write_only = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(dir.join("w"))
        .unwrap();
    let path_only = open_raw(dir, O_PATH).unwrap();
    for (case, fd) in [
        ("mode_read_write", file.as_raw_fd()),
        ("mode_read", read_only.as_raw_fd()),
        ("mode_write", write_only.as_raw_fd()),
        ("mode_path", path_only.as_raw_fd()),
    ] {
        let metadata = fs::symlink_metadata(link_of(fd)).unwrap();
        say(
            case,
            format!("{} {:o}", kind(&metadata), metadata.mode() & 0o7777),
        );
    }
    say(
        "nofollow_open",
        open_raw(&through, O_RDONLY | O_NOFOLLOW)
            .map_or_else(|e| format!("errno={e}"), |_| "opened".into()),
    );
}

fn directories(dir: &Path) {
    let sub = dir.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("child"), b"child").unwrap();
    let held = fs::File::open(&sub).unwrap();
    fs::rename(&sub, dir.join("sub2")).unwrap();
    let child = link_of(held.as_raw_fd()).join("child");
    say(
        "dir_child_after_rename",
        fs::read(&child).map_or_else(errno_of, |b| String::from_utf8(b).unwrap()),
    );
    say(
        "dir_link_after_rename",
        relative(dir, &fs::read_link(link_of(held.as_raw_fd())).unwrap()),
    );
}

/// A `getdents64` of `/proc/self/fd` with room for an entry or two at a
/// time resumes at the next open number when the one it stopped before was
/// closed meanwhile.
fn resumed_listing() {
    let base = fs::File::open("/proc/self").unwrap();
    let numbers = [210, 211, 212];
    for number in numbers {
        // SAFETY: a held descriptor duplicated onto a free number.
        assert_eq!(unsafe { dup2(base.as_raw_fd(), number) }, number);
    }
    let dir = fs::File::open("/proc/self/fd").unwrap();
    let mut seen = Vec::new();
    let mut closed = false;
    loop {
        let mut buf = [0u8; 48];
        // SAFETY: a directory descriptor and a buffer of its length.
        let len = unsafe { syscall(SYS_GETDENTS64, dir.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
        assert!(len >= 0, "getdents64");
        if len == 0 {
            break;
        }
        let mut at = 0;
        while at < len as usize {
            let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let name = &buf[at + 19..at + reclen];
            let name = &name[..name.iter().position(|b| *b == 0).unwrap()];
            if let Some(number) = std::str::from_utf8(name)
                .ok()
                .and_then(|n| n.parse::<c_int>().ok())
            {
                seen.push(number);
            }
            at += reclen;
        }
        if !closed && seen.contains(&210) {
            // SAFETY: a number this probe made.
            unsafe { close(210) };
            closed = true;
        }
    }
    for number in &numbers[1..] {
        // SAFETY: numbers this probe made.
        unsafe { close(*number) };
    }
    say(
        "listing_resumes_past_closed",
        seen.contains(&211) && seen.contains(&212),
    );
}

fn anonymous() {
    let mut fds = [0; 2];
    // SAFETY: room for two descriptors.
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: two descriptors just made, owned here alone.
    let (read_end, _write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let text = fs::read_link(link_of(read_end.as_raw_fd())).unwrap();
    let ino = fs::metadata(link_of(read_end.as_raw_fd())).unwrap().ino();
    say(
        "pipe_link",
        text.to_str().unwrap() == format!("pipe:[{ino}]"),
    );
    // SAFETY: no pointers.
    let event = unsafe { eventfd(0, O_CLOEXEC) };
    assert!(event >= 0);
    // SAFETY: a descriptor just made, owned here alone.
    let event = unsafe { OwnedFd::from_raw_fd(event) };
    for (case, fd) in [
        ("mode_pipe_read", read_end.as_raw_fd()),
        ("mode_pipe_write", _write_end.as_raw_fd()),
        ("mode_eventfd", event.as_raw_fd()),
    ] {
        let metadata = fs::symlink_metadata(link_of(fd)).unwrap();
        say(case, format!("{:o}", metadata.mode() & 0o7777));
    }
    say(
        "eventfd_link",
        fs::read_link(link_of(event.as_raw_fd())).unwrap().display(),
    );
}

fn listing(dir: &Path) {
    let numbers = |path: &str| -> Vec<c_int> {
        let mut numbers: Vec<c_int> = fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        numbers.sort();
        numbers
    };
    let created = fs::File::create(dir.join("listed")).unwrap();
    // A number above any the listing's own open takes, so the closed one
    // stays free.
    // SAFETY: a held descriptor, duplicated onto a free number.
    let fd = unsafe { dup2(created.as_raw_fd(), 200) };
    assert_eq!(fd, 200);
    drop(created);
    // SAFETY: the number just made, owned here alone.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let held = numbers("/proc/self/fd");
    say(
        "listing_has_open",
        held.contains(&fd) && held.contains(&0) && held.contains(&1),
    );
    let by_pid = format!("/proc/{}/fd", std::process::id());
    say(
        "pid_spelling",
        fs::read_link(format!("{by_pid}/{fd}")).map_or_else(errno_of, |p| relative(dir, &p)),
    );
    drop(file);
    say(
        "listing_drops_closed",
        !numbers("/proc/self/fd").contains(&fd),
    );
    say(
        "closed_readlink",
        fs::read_link(link_of(fd)).map_or_else(errno_of, |_| "found".into()),
    );
    say(
        "closed_stat",
        fs::metadata(link_of(fd)).map_or_else(errno_of, |_| "found".into()),
    );
    say(
        "leading_zero",
        fs::symlink_metadata(format!("/proc/self/fd/0{fd}"))
            .map_or_else(errno_of, |_| "found".into()),
    );
}

fn main() {
    let dir = std::env::temp_dir().join(format!("proc_fd_probe-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    symlinks(&dir);
    sockets(&dir);
    files(&dir);
    directories(&dir);
    resumed_listing();
    anonymous();
    listing(&dir);
    fs::remove_dir_all(&dir).unwrap();
}
