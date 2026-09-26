//! fd/pty — a Unix98 pseudoterminal pair through glibc 2.39's functions
//! (posix_openpt, grantpt, unlockpt, ptsname_r, ttyname_r, openpty) over
//! drivers/tty/pty.c and devpts:
//!
//! * `posix_openpt` opens `/dev/ptmx`: devtmpfs's 5:2, root's and the tty
//!   group's (5 on the pinned host), `0666`; the pair's devpts index
//!   (`TIOCGPTN`) names its slave `/dev/pts/<index>` (`ptsname_r`, and
//!   `ERANGE` without room for the terminator), a character device
//!   136:index with inode index + 3, the caller's and the tty group's,
//!   `0620`, until the master closes (then `ENOENT`);
//! * the slave opens by name only once unlocked (`EIO` before `unlockpt`),
//!   is a terminal, and `ttyname_r` names it (with room for the name but
//!   not its terminator, `ENODEV`: glibc's `/proc` lookup comes back
//!   truncated and its scan of the devices finds no room either); the
//!   master's name is `/dev/ptmx`; the fortified forms `_FORTIFY_SOURCE`
//!   calls (`__ptsname_r_chk`, `__ttyname_r_chk`) name them too;
//! * `grantpt` and `unlockpt` refuse the slave (`EINVAL`, glibc's spelling
//!   of the ioctl's `ENOTTY`), `ptsname_r` answers `ENOTTY`, and
//!   `TIOCGPTPEER` through it is `EIO`;
//! * `openpty` makes a pair with the settings and window size it is given and
//!   names its slave.
//!
//! Which index a pair gets is the host's business: it is recorded relative
//! (the `pty` namespace), and names and device numbers are compared through
//! it. libc only.

use super::termios::{get, winsize};
use crate::catalog::{DEFAULTS, Scenario};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, errno, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::{CStr, CString};

/// The tty group's id on the pinned host (devpts's `gid=5`).
const TTY_GID: u32 = 5;

/// `posix_openpt(flags)`.
fn openpt(p: &Probe, flags: c_int) -> c_int {
    // SAFETY: plain flags.
    let r = fold_errno(i64::from(unsafe { posix_openpt(flags) }));
    p.rec
        .event("posix_openpt", r)
        .arg("flags", flags)
        .norm("ret", Norm::Relative("fd"))
        .emit();
    r as c_int
}

/// `TIOCGPTN`: the pair's index.
fn index_of(p: &Probe, fd: c_int) -> (i64, u32) {
    let mut index: c_uint = 0;
    // SAFETY: TIOCGPTN writes one unsigned int.
    let r = fold_errno(i64::from(unsafe { ioctl(fd, TIOCGPTN, &mut index) }));
    p.rec
        .event("TIOCGPTN", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .field("index", index)
        .norm("fields.index", Norm::Relative("pty"))
        .emit();
    (r, index)
}

/// A libc call answering 0 or -1 with errno.
fn answer(p: &Probe, op: &str, fd: c_int, r: c_int) -> i64 {
    let r = fold_errno(i64::from(r));
    p.rec
        .event(op, r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .emit();
    r
}

unsafe extern "C" {
    fn __ptsname_r_chk(fd: c_int, buf: *mut c_char, buflen: size_t, nreal: size_t) -> c_int;
    fn __ttyname_r_chk(fd: c_int, buf: *mut c_char, buflen: size_t, nreal: size_t) -> c_int;
}

/// The size of [`named`]'s buffer: the object the fortified forms are told
/// of, as `_FORTIFY_SOURCE` passes `__builtin_object_size`.
const NAME_ROOM: usize = 64;

/// `__ptsname_r_chk` with [`named`]'s buffer as the object.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes.
unsafe extern "C" fn ptsname_r_chk(fd: c_int, buf: *mut c_char, buflen: size_t) -> c_int {
    // SAFETY: forwarded; the object is `named`'s buffer.
    unsafe { __ptsname_r_chk(fd, buf, buflen, NAME_ROOM) }
}

/// `__ttyname_r_chk` with [`named`]'s buffer as the object.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes.
unsafe extern "C" fn ttyname_r_chk(fd: c_int, buf: *mut c_char, buflen: size_t) -> c_int {
    // SAFETY: forwarded; the object is `named`'s buffer.
    unsafe { __ttyname_r_chk(fd, buf, buflen, NAME_ROOM) }
}

/// A call on a descriptor: its answer, `-errno` on failure.
type Request = fn(&Probe, c_int) -> i64;

/// `TIOCGPTPEER` through `fd`: the peer's descriptor, or `-errno`.
fn peer_of(p: &Probe, fd: c_int) -> i64 {
    // SAFETY: TIOCGPTPEER takes open flags.
    let peer = fold_errno(unsafe { ioctl(fd, TIOCGPTPEER, O_RDWR | O_NOCTTY) } as i64);
    p.rec
        .event("TIOCGPTPEER", peer)
        .norm("ret", Norm::Relative("fd"))
        .emit();
    peer
}

/// A `*_r` naming call into a buffer with ample room (`true`) or room for
/// `expected` but not its terminator: its error number (negated, 0 on
/// success) and whether the name it wrote is `expected`.
fn named(
    p: &Probe,
    op: &str,
    fd: c_int,
    ample: bool,
    expected: &str,
    call: unsafe extern "C" fn(c_int, *mut c_char, size_t) -> c_int,
) -> (i64, bool) {
    let room = if ample { NAME_ROOM } else { expected.len() };
    let mut buf = vec![0xAAu8 as c_char; NAME_ROOM];
    // SAFETY: a live buffer of at least `room` bytes.
    let r = -i64::from(unsafe { call(fd, buf.as_mut_ptr(), room) });
    // SAFETY: on success the call wrote a NUL-terminated name.
    let matches =
        r == 0 && unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes() == expected.as_bytes();
    p.rec
        .event(op, r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("room", if ample { "ample" } else { "no terminator" })
        .field("names_it", matches)
        .emit();
    (r, matches)
}

/// `isatty`: 1, or `-errno` for a 0.
fn tty(p: &Probe, fd: c_int) -> i64 {
    // SAFETY: the calling thread's errno slot, then a plain number.
    let r = match unsafe {
        *__errno_location() = 0;
        isatty(fd)
    } {
        1 => 1,
        _ => -i64::from(errno()),
    };
    p.rec
        .event("isatty", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .emit();
    r
}

/// `openat(AT_FDCWD, path)` of a device the scenario names by role (the
/// slave's path carries the host's index).
fn open_named(p: &Probe, path: &str, role: &str, flags: c_int) -> c_int {
    let c = CString::new(path).expect("no NUL");
    // SAFETY: a NUL-terminated path.
    let r = fold_errno(i64::from(unsafe { openat(AT_FDCWD, c.as_ptr(), flags) }));
    p.rec
        .event("openat", r)
        .arg("path", role)
        .arg("flags", flags)
        .norm("ret", Norm::Relative("fd"))
        .emit();
    r as c_int
}

/// What a node's stat says, the host's numbers related to the pair: the
/// kind and mode, whether the caller owns it (root otherwise), the group,
/// the device's major, and for a slave node its minor and inode against
/// the pair's index.
struct Node {
    chr: bool,
    perm: u32,
    caller_owns: bool,
    root_owns: bool,
    gid: u32,
    major: u32,
    minor: u32,
    ino_less_index: i64,
}

fn node(
    p: &Probe,
    op: &str,
    role: &str,
    r: c_int,
    st: &libc::stat,
    index: Option<u32>,
) -> (i64, Option<Node>) {
    let r = fold_errno(i64::from(r));
    let event = p.rec.event(op, r).arg("node", role);
    if r != 0 {
        event.emit();
        return (r, None);
    }
    // SAFETY: plain reads of the process's ids.
    let uid = unsafe { getuid() };
    let node = Node {
        chr: st.st_mode & S_IFMT == S_IFCHR,
        perm: st.st_mode & 0o7777,
        caller_owns: st.st_uid == uid,
        root_owns: st.st_uid == 0,
        gid: st.st_gid,
        major: major(st.st_rdev),
        minor: minor(st.st_rdev),
        ino_less_index: st.st_ino as i64 - i64::from(index.unwrap_or(0)),
    };
    let event = event
        .field("chr", node.chr)
        .field("perm", node.perm)
        .field("caller_owns", node.caller_owns)
        .field("root_owns", node.root_owns)
        .field("gid", node.gid)
        .field("major", node.major)
        .field("minor", node.minor);
    let event = match index {
        Some(_) => event
            .norm("fields.minor", Norm::Relative("pty"))
            .field("ino_less_index", node.ino_less_index),
        None => event,
    };
    event.emit();
    (r, Some(node))
}

fn stat_path(p: &Probe, path: &str, role: &str, index: Option<u32>) -> (i64, Option<Node>) {
    let c = CString::new(path).expect("no NUL");
    // SAFETY: a zeroed stat for the call to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a live stat.
    let r = unsafe { stat(c.as_ptr(), &mut st) };
    node(p, "stat", role, r, &st, index)
}

fn stat_fd(p: &Probe, fd: c_int, role: &str, index: Option<u32>) -> (i64, Option<Node>) {
    // SAFETY: a zeroed stat for the call to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live stat.
    let r = unsafe { fstat(fd, &mut st) };
    node(p, "fstat", role, r, &st, index)
}

/// A slave node: a character device 136:index, inode index + 3, the
/// caller's and the tty group's, `0620`.
fn slave_node(node: &Node, index: u32) -> bool {
    node.chr
        && node.perm == 0o620
        && node.caller_owns
        && node.gid == TTY_GID
        && node.major == 136
        && node.minor == index
        && node.ino_less_index == 3
}

pub fn run(p: &Probe) {
    let master = openpt(p, O_RDWR | O_NOCTTY);
    p.require("posix_openpt", master >= 0);
    let (r, index) = index_of(p, master);
    p.require("TIOCGPTN", r == 0);
    let name = format!("/dev/pts/{index}");

    // SAFETY: plain descriptor numbers.
    p.check(
        "grantpt accepts the master",
        answer(p, "grantpt", master, unsafe { grantpt(master) }) == 0,
    );
    p.check(
        "ptsname_r names the slave by the pair's index",
        named(p, "ptsname_r", master, true, &name, ptsname_r) == (0, true),
    );
    p.check(
        "ptsname_r without room for the terminator is ERANGE",
        named(p, "ptsname_r", master, false, &name, ptsname_r).0 == neg(ERANGE),
    );
    let (r, n) = stat_path(p, &name, "slave", Some(index));
    p.check(
        "the slave node is 136:index, the caller's and the tty group's, 0620",
        r == 0 && n.is_some_and(|n| slave_node(&n, index)),
    );
    let (r, n) = stat_fd(p, master, "master", None);
    p.check(
        "the master is /dev/ptmx: 5:2, root's and the tty group's, 0666",
        r == 0
            && n.is_some_and(|n| {
                n.chr
                    && n.perm == 0o666
                    && n.root_owns
                    && n.gid == TTY_GID
                    && (n.major, n.minor) == (5, 2)
            }),
    );
    p.check(
        "the slave does not open while locked",
        open_named(p, &name, "slave", O_RDWR | O_NOCTTY) == neg(EIO) as c_int,
    );
    // SAFETY: a plain descriptor number.
    p.check(
        "unlockpt unlocks it",
        answer(p, "unlockpt", master, unsafe { unlockpt(master) }) == 0,
    );
    let slave = open_named(p, &name, "slave", O_RDWR | O_NOCTTY);
    p.require("open the slave by name", slave >= 0);
    p.check("the slave is a terminal", tty(p, slave) == 1);
    p.check(
        "ttyname_r names the slave",
        named(p, "ttyname_r", slave, true, &name, ttyname_r) == (0, true),
    );
    p.check(
        "ttyname_r without room for the terminator is ENODEV",
        named(p, "ttyname_r", slave, false, &name, ttyname_r).0 == neg(ENODEV),
    );
    p.check(
        "ttyname_r names the master /dev/ptmx",
        named(p, "ttyname_r", master, true, "/dev/ptmx", ttyname_r) == (0, true),
    );
    p.check(
        "the fortified ptsname_r names the slave",
        named(p, "__ptsname_r_chk", master, true, &name, ptsname_r_chk) == (0, true),
    );
    p.check(
        "and the fortified ttyname_r",
        named(p, "__ttyname_r_chk", slave, true, &name, ttyname_r_chk) == (0, true),
    );
    let (r, n) = stat_fd(p, slave, "slave", Some(index));
    p.check(
        "the slave descriptor is on its node",
        r == 0 && n.is_some_and(|n| slave_node(&n, index)),
    );
    // The master's functions and request, refused through the slave.
    let refusals: [(&str, Request, i64); 4] = [
        (
            "grantpt refuses the slave",
            // SAFETY: a plain descriptor number.
            |p, fd| answer(p, "grantpt", fd, unsafe { grantpt(fd) }),
            neg(EINVAL),
        ),
        (
            "unlockpt refuses the slave",
            // SAFETY: a plain descriptor number.
            |p, fd| answer(p, "unlockpt", fd, unsafe { unlockpt(fd) }),
            neg(EINVAL),
        ),
        (
            "ptsname_r of the slave is ENOTTY",
            |p, fd| named(p, "ptsname_r", fd, true, "", ptsname_r).0,
            neg(ENOTTY),
        ),
        ("TIOCGPTPEER through the slave is EIO", peer_of, neg(EIO)),
    ];
    for (label, call, refusal) in refusals {
        p.check(label, call(p, slave) == refusal);
    }
    p.close(slave);
    p.close(master);
    p.check(
        "the slave node goes with the master",
        stat_path(p, &name, "slave", Some(index)).0 == neg(ENOENT),
    );

    // ---- openpty -----------------------------------------------------------
    // SAFETY: an all-zero termios is a valid value to fill in.
    let mut wanted: termios = unsafe { std::mem::zeroed() };
    wanted.c_iflag = ICRNL;
    wanted.c_oflag = OPOST;
    wanted.c_cflag = B9600 | CS8 | CREAD;
    wanted.c_lflag = ICANON;
    wanted.c_cc[VMIN] = 1;
    wanted.c_cc[VEOF] = 4;
    let size = libc::winsize {
        ws_row: 30,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let (mut m, mut s) = (-1, -1);
    let mut buf = [0 as c_char; 64];
    // SAFETY: live out-parameters, a 64-byte name buffer (glibc's own is
    // PATH_MAX, the name far shorter), and live settings.
    let r = fold_errno(i64::from(unsafe {
        openpty(&mut m, &mut s, buf.as_mut_ptr(), &wanted, &size)
    }));
    p.rec
        .event("openpty", r)
        .field("master", m)
        .norm("fields.master", Norm::Relative("fd"))
        .field("slave", s)
        .norm("fields.slave", Norm::Relative("fd"))
        .emit();
    p.require("openpty", r == 0);
    let (r, index) = index_of(p, m);
    // SAFETY: openpty wrote a NUL-terminated name.
    let written = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes()
        == format!("/dev/pts/{index}").as_bytes();
    p.check("openpty names its slave", r == 0 && written);
    let (r, t) = get(p, s, "openpty slave");
    p.check(
        "the slave has the settings given",
        r == 0
            && t.is_some_and(|t| {
                t.c_iflag == ICRNL
                    && t.c_oflag == OPOST
                    && t.c_cflag == B9600 | CS8 | CREAD
                    && t.c_lflag == ICANON
            }),
    );
    p.check(
        "and the window size given",
        winsize(p, m, TIOCGWINSZ, None, "openpty master") == (0, [30, 100, 0, 0]),
    );
    p.close(s);
    p.close(m);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/pty",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_ioctl,
        Syscall::N_openat,
        Syscall::N_newfstatat,
        Syscall::N_fstat,
        Syscall::N_close,
    ],
    symbols: &[
        "posix_openpt",
        "grantpt",
        "unlockpt",
        "ptsname_r",
        "ttyname_r",
        "__ptsname_r_chk",
        "__ttyname_r_chk",
        "openpty",
        "isatty",
        "tcgetattr",
        "ioctl",
        "openat",
        "stat",
        "fstat",
        "close",
    ],
    ..DEFAULTS
};
