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
//! * the line discipline (drivers/tty/n_tty.c) under the pts driver's
//!   settings: the master's `\r` reaches a canonical slave as `\n` and is
//!   echoed `\r\n`; the slave's `\n` reaches the master as `\r\n`
//!   (`ONLCR`); a partial line is neither readable nor counted
//!   (`FIONREAD`); `tcflush` discards it; `VEOF` ends a line uncopied, alone
//!   reads as end of file, and a read that fills its room just before one
//!   takes it too (`canon_skip_eof`); switching to raw mode makes a partial
//!   line readable, and a raw slave reads what arrives, still translated;
//! * a table of receive and echo rows, each on a pair of its own: n_tty's
//!   `char_map` decides which bytes take the special path (a raw `\n` is no
//!   line end and echoes `^J`, a raw `\r` reads as `\n` and echoes a
//!   newline), `ECHOCTL`'s `^X` is for lib/ctype.c's control characters (C0
//!   and DEL, not UTF-8's 0x80-0x9f bytes), and a C1 byte takes a column
//!   before a tab `XTABS` expands;
//! * edge-triggered epoll sees the tty's wakeups: a canonical slave's
//!   readers wake on a line end, not on part of a line; `TCSETS` wakes the
//!   slave's queues alone; a read wakes the other side's writers;
//! * a master whose slave closed polls hung up and reads `EIO`, until
//!   `TIOCGPTPEER` opens the slave again; the master's close hangs the slave
//!   up: it polls every event, reads end of file, and writes and requests
//!   are `EIO`;
//! * `openpty` makes a pair with the settings and window size it is given and
//!   names its slave.
//!
//! The kernel moves bytes between the two sides in a work queue
//! (`flush_to_ldisc`), so readiness and counts are judged only once a
//! blocking read (or `read_exact`, for a side whose bytes may arrive in
//! parts) has shown everything written has arrived.
//!
//! Which index a pair gets is the host's business: it is recorded relative
//! (the `pty` namespace), and names and device numbers are compared through
//! it. libc only.

use super::termios::{Adjust, get, set, winsize};
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

/// Read exactly `want` bytes, however the other side's work queue hands them
/// over: the bytes, or the first error.
fn read_exact(p: &Probe, fd: c_int, want: usize) -> (i64, Vec<u8>) {
    let mut got = Vec::new();
    let mut r = 0;
    while got.len() < want {
        let mut buf = vec![0u8; want - got.len()];
        // SAFETY: a live buffer of its length.
        r = fold_errno(unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) } as i64);
        if r <= 0 {
            break;
        }
        got.extend_from_slice(&buf[..r as usize]);
    }
    let r = if r < 0 && got.is_empty() {
        r
    } else {
        got.len() as i64
    };
    p.rec
        .event("read_exact", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("want", want)
        .field(
            "data",
            got.iter().map(|&b| u32::from(b)).collect::<Vec<_>>(),
        )
        .emit();
    (r, got)
}

/// `read(fd, 64)`: the bytes, or `-errno`.
fn read_some(p: &Probe, fd: c_int, room: usize) -> (i64, Vec<u8>) {
    let mut buf = vec![0u8; room];
    // SAFETY: a live buffer of its length.
    let r = fold_errno(unsafe { read(fd, buf.as_mut_ptr().cast(), room) } as i64);
    buf.truncate(r.max(0) as usize);
    p.rec
        .event("read", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("room", room)
        .field(
            "data",
            buf.iter().map(|&b| u32::from(b)).collect::<Vec<_>>(),
        )
        .emit();
    (r, buf)
}

/// `FIONREAD`.
fn queued(p: &Probe, fd: c_int) -> i64 {
    let mut count: c_int = -1;
    // SAFETY: FIONREAD writes one int.
    let r = fold_errno(i64::from(unsafe { ioctl(fd, FIONREAD, &mut count) }));
    p.rec
        .event("FIONREAD", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .field("count", count)
        .emit();
    if r == 0 { i64::from(count) } else { r }
}

/// What `poll` reports for `fd` now, asked for input and output.
fn ready(p: &Probe, fd: c_int) -> i16 {
    let (r, revents) = p.ppoll(&[(fd, POLLIN | POLLOUT)], Some(0));
    if r < 0 { -1 } else { revents[0] }
}

/// `tcflush(fd, queue)`.
fn flush(p: &Probe, fd: c_int, queue: c_int) -> i64 {
    // SAFETY: plain values.
    let r = fold_errno(i64::from(unsafe { tcflush(fd, queue) }));
    p.rec
        .event("tcflush", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("queue", queue)
        .emit();
    r
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

/// A pair `openpty` makes with the pts driver's initial settings: its
/// master and slave.
fn pair(p: &Probe) -> (c_int, c_int) {
    let (mut m, mut s) = (-1, -1);
    // SAFETY: live out-parameters; no name, settings or window size.
    let r = fold_errno(i64::from(unsafe {
        openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    }));
    p.rec
        .event("openpty", r)
        .field("master", m)
        .norm("fields.master", Norm::Relative("fd"))
        .field("slave", s)
        .norm("fields.slave", Norm::Relative("fd"))
        .emit();
    p.require("openpty", r == 0);
    (m, s)
}

/// One row of the line discipline's receive and echo: the pts driver's
/// initial settings changed by `adjust`, the bytes the master writes, what
/// the slave reads of them and what the master reads back as their echo
/// (n_tty's `char_map`, `echo_char` under `ECHOCTL` with lib/ctype.c's
/// `iscntrl`, and `do_output_char`'s column).
struct Discipline {
    what: &'static str,
    adjust: Adjust,
    input: &'static [u8],
    read: &'static [u8],
    echo: &'static [u8],
}

const DISCIPLINE: &[Discipline] = &[
    Discipline {
        what: "a canonical C0 byte echoes as ^A",
        adjust: |_| {},
        input: b"\x01x\n",
        read: b"\x01x\n",
        echo: b"^Ax\r\n",
    },
    Discipline {
        what: "a raw DEL echoes as ^?",
        adjust: |t| t.c_lflag &= !ICANON,
        input: b"x\x7fy",
        read: b"x\x7fy",
        echo: b"x^?y",
    },
    Discipline {
        what: "UTF-8's 0x80-0x9f bytes echo as they are",
        adjust: |_| {},
        input: "€…\n".as_bytes(),
        read: "€…\n".as_bytes(),
        echo: "€…\r\n".as_bytes(),
    },
    Discipline {
        what: "a raw \\n is no line end: it echoes as ^J",
        adjust: |t| t.c_lflag &= !ICANON,
        input: b"a\nb",
        read: b"a\nb",
        echo: b"a^Jb",
    },
    Discipline {
        what: "a raw \\r reads as \\n and echoes as a newline",
        adjust: |t| t.c_lflag &= !ICANON,
        input: b"a\rb",
        read: b"a\nb",
        echo: b"a\r\nb",
    },
    Discipline {
        what: "ECHONL echoes the newline alone",
        adjust: |t| t.c_lflag = (t.c_lflag & !ECHO) | ECHONL,
        input: b"ab\n",
        read: b"ab\n",
        echo: b"\r\n",
    },
    Discipline {
        what: "a C1 byte takes a column before a tab XTABS expands",
        adjust: |t| {
            t.c_lflag &= !ECHOCTL;
            t.c_oflag = (t.c_oflag & !TABDLY) | TAB3;
        },
        input: b"\x85\t\n",
        read: b"\x85\t\n",
        echo: b"\x85       \r\n",
    },
];

/// Each [`DISCIPLINE`] row on a pair of its own, judged once the slave has
/// read everything and the master its whole echo, when nothing is left to
/// arrive.
fn discipline(p: &Probe) {
    for row in DISCIPLINE {
        let (m, s) = pair(p);
        let (_, settings) = get(p, s, row.what);
        let mut t = settings.expect("the slave's settings");
        (row.adjust)(&mut t);
        p.require("the row's settings", set(p, s, TCSANOW, &t, row.what) == 0);
        p.require(
            "the master writes the row's input",
            p.write(m, row.input) == row.input.len() as i64,
        );
        let (_, read) = read_exact(p, s, row.read.len());
        let (_, echo) = read_exact(p, m, row.echo.len());
        let settled = ready(p, m) == POLLOUT;
        p.check(row.what, read == row.read && echo == row.echo && settled);
        p.close(s);
        p.close(m);
    }
}

/// Edge-triggered epoll on a pair: the tty wakes its queues where 6.8's
/// n_tty and tty_io do (`ep_poll_callback` filters a keyed wakeup by the
/// interest's events): a canonical slave's readers on a line end only
/// (`n_tty_receive_handle_newline`), `TCSETS` the slave's queues alone
/// (`n_tty_set_termios`), and a read the other side's writers
/// (`n_tty_check_unthrottle`'s `tty_wakeup` of the link).
fn edges(p: &Probe) {
    let (m, s) = pair(p);
    let [slave_in, master_in, master_out] = [(); 3].map(|()| p.epoll_create1(EPOLL_CLOEXEC));
    p.require(
        "epoll_create1",
        slave_in >= 0 && master_in >= 0 && master_out >= 0,
    );
    let (read, write, edge) = (EPOLLIN as u32, EPOLLOUT as u32, EPOLLET as u32);
    p.require(
        "watch the slave",
        p.epoll_ctl(slave_in, EPOLL_CTL_ADD, s, read | edge, 1) == 0,
    );
    p.check("the master ends a line", p.write(m, b"a\n") == 2);
    p.check(
        "the line is an edge on the slave",
        p.epoll_wait(slave_in, 4, -1) == (1, vec![(1, read)]),
    );
    p.check("the master writes part of a line", p.write(m, b"b") == 1);
    p.check(
        "whose echo shows the slave took it",
        read_exact(p, m, 4) == (4, b"a\r\nb".to_vec()),
    );
    p.check(
        "part of a line is no edge",
        p.epoll_wait(slave_in, 4, 0) == (0, Vec::new()),
    );
    p.require(
        "watch the master's input",
        p.epoll_ctl(master_in, EPOLL_CTL_ADD, m, read | edge, 2) == 0,
    );
    p.check("the master writes more", p.write(m, b"c") == 1);
    p.check(
        "its echo is an edge on the master",
        p.epoll_wait(master_in, 4, -1) == (1, vec![(2, read)]),
    );
    let (_, settings) = get(p, s, "pty slave");
    let settings = settings.expect("the slave's settings");
    p.check(
        "tcsetattr, changing nothing",
        set(p, s, TCSANOW, &settings, "pty slave") == 0,
    );
    p.check(
        "wakes the slave's readers",
        p.epoll_wait(slave_in, 4, 0) == (1, vec![(1, read)]),
    );
    p.check(
        "and not the master's",
        p.epoll_wait(master_in, 4, 0) == (0, Vec::new()),
    );
    p.require(
        "watch the master's output",
        p.epoll_ctl(master_out, EPOLL_CTL_ADD, m, write | edge, 3) == 0,
    );
    p.check(
        "the master takes a write: one edge",
        p.epoll_wait(master_out, 4, 0) == (1, vec![(3, write)]),
    );
    p.check(
        "and no more",
        p.epoll_wait(master_out, 4, 0) == (0, Vec::new()),
    );
    p.check(
        "the slave reads its line",
        read_some(p, s, 64) == (2, b"a\n".to_vec()),
    );
    p.check(
        "which is an output edge on the master",
        p.epoll_wait(master_out, 4, 0) == (1, vec![(3, write)]),
    );
    for fd in [master_out, master_in, slave_in, s, m] {
        p.close(fd);
    }
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
    // Class pairing: the native ABI ownership matrix; these previously
    // uncovered libc aliases share this live host/model PTY probe.
    let master_name = unsafe { ptsname(master) };
    p.check(
        "ptsname names the slave",
        !master_name.is_null()
            && unsafe { CStr::from_ptr(master_name).to_bytes() == name.as_bytes() },
    );
    let slave_name = unsafe { ttyname(slave) };
    p.check(
        "ttyname names the slave",
        !slave_name.is_null()
            && unsafe { CStr::from_ptr(slave_name).to_bytes() == name.as_bytes() },
    );
    p.check(
        "tcdrain accepts the empty slave queue",
        answer(p, "tcdrain", slave, unsafe { tcdrain(slave) }) == 0,
    );
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

    // ---- the line discipline -------------------------------------------------
    p.check("the master writes a line", p.write(master, b"ab\r") == 3);
    p.check(
        "the canonical slave reads it, \\r as \\n",
        read_some(p, slave, 64) == (3, b"ab\n".to_vec()),
    );
    p.check(
        "the master reads the echo, \\n as \\r\\n",
        read_exact(p, master, 4) == (4, b"ab\r\n".to_vec()),
    );
    p.check("the slave writes", p.write(slave, b"x\ny") == 3);
    p.check(
        "the master reads it, \\n as \\r\\n",
        read_exact(p, master, 4) == (4, b"x\r\ny".to_vec()),
    );
    let output = POLLOUT;
    p.check(
        "nothing left: the master only takes a write",
        ready(p, master) == output,
    );
    p.check("nor the slave", ready(p, slave) == output);
    p.check(
        "the master writes part of a line",
        p.write(master, b"cd") == 2,
    );
    p.check(
        "which echoes",
        read_exact(p, master, 2) == (2, b"cd".to_vec()),
    );
    p.check("the slave has no line to read", ready(p, slave) == output);
    p.check("nor to count", queued(p, slave) == 0);
    p.check(
        "tcflush discards the slave's input",
        flush(p, slave, TCIFLUSH) == 0,
    );
    p.check("the master ends a line", p.write(master, b"e\n") == 2);
    p.check(
        "the slave reads only it",
        read_some(p, slave, 64) == (2, b"e\n".to_vec()),
    );
    p.check(
        "its echo",
        read_exact(p, master, 3) == (3, b"e\r\n".to_vec()),
    );
    p.check("VEOF ends a line", p.write(master, b"fg\x04") == 3);
    p.check(
        "which reads without it",
        read_some(p, slave, 64) == (2, b"fg".to_vec()),
    );
    p.check(
        "VEOF is not echoed",
        read_exact(p, master, 2) == (2, b"fg".to_vec()),
    );
    p.check("VEOF alone", p.write(master, b"\x04") == 1);
    p.check(
        "reads as end of file",
        read_some(p, slave, 64) == (0, Vec::new()),
    );
    p.check("and echoes nothing", queued(p, master) == 0);
    p.check("a line ending in VEOF", p.write(master, b"hi\x04") == 3);
    p.check(
        "read into room for the line alone",
        read_some(p, slave, 2) == (2, b"hi".to_vec()),
    );
    p.check("its echo", read_exact(p, master, 2) == (2, b"hi".to_vec()));
    let flags = p.fcntl(slave, F_GETFL, 0);
    p.check(
        "the slave made non-blocking",
        p.fcntl(slave, F_SETFL, flags | i64::from(O_NONBLOCK)) == 0,
    );
    p.check(
        "the VEOF went with the line: nothing is left",
        read_some(p, slave, 64).0 == neg(EAGAIN),
    );
    p.check("blocking again", p.fcntl(slave, F_SETFL, flags) == 0);

    p.check(
        "the master writes part of a line",
        p.write(master, b"zz") == 2,
    );
    p.check(
        "which echoes",
        read_exact(p, master, 2) == (2, b"zz".to_vec()),
    );
    let (_, settings) = get(p, slave, "pty slave");
    let canonical = settings.expect("the slave's settings");
    let mut raw = canonical;
    raw.c_lflag &= !(ICANON | ECHO);
    p.check(
        "the slave leaves canonical mode",
        set(p, slave, TCSANOW, &raw, "pty slave") == 0,
    );
    p.check(
        "the partial line becomes readable",
        ready(p, slave) == POLLIN | output,
    );
    p.check("and reads", read_some(p, slave, 64) == (2, b"zz".to_vec()));
    p.check("the master writes \\r\\n", p.write(master, b"\r\n") == 2);
    p.check(
        "the raw slave reads both, \\r as \\n, unechoed",
        read_exact(p, slave, 2) == (2, b"\n\n".to_vec()) && queued(p, master) == 0,
    );
    p.check("the slave writes a tab", p.write(slave, b"a\tb\n") == 4);
    p.check(
        "the master reads it unexpanded",
        read_exact(p, master, 5) == (5, b"a\tb\r\n".to_vec()),
    );

    // ---- hangups ---------------------------------------------------------------
    p.close(slave);
    p.check(
        "a master whose slave closed polls hung up",
        ready(p, master) == POLLHUP | output,
    );
    p.check("and reads EIO", read_some(p, master, 64).0 == neg(EIO));
    let peer = peer_of(p, master);
    p.require("TIOCGPTPEER opens the slave again", peer >= 0);
    let peer = peer as c_int;
    p.check(
        "the master is no longer hung up",
        ready(p, master) == output,
    );
    p.close(master);
    p.check(
        "the master's close hangs the slave up",
        ready(p, peer) == POLLIN | POLLOUT | POLLERR | POLLHUP,
    );
    p.check(
        "it reads end of file",
        read_some(p, peer, 64) == (0, Vec::new()),
    );
    p.check("its writes are EIO", p.write(peer, b"q") == neg(EIO));
    p.check(
        "and its requests",
        get(p, peer, "hung-up peer").0 == neg(EIO),
    );
    p.check(
        "the slave node goes with the master",
        stat_path(p, &name, "slave", Some(index)).0 == neg(ENOENT),
    );
    p.close(peer);

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

    discipline(p);
    edges(p);
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
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_ppoll,
        Syscall::N_fcntl,
        Syscall::N_close,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_wait,
    ],
    symbols: &[
        "posix_openpt",
        "grantpt",
        "unlockpt",
        "ptsname_r",
        "ttyname_r",
        "ptsname",
        "ttyname",
        "tcdrain",
        "__ptsname_r_chk",
        "__ttyname_r_chk",
        "openpty",
        "isatty",
        "tcgetattr",
        "tcsetattr",
        "tcflush",
        "read",
        "write",
        "ppoll",
        "fcntl",
        "ioctl",
        "openat",
        "stat",
        "fstat",
        "close",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
    ],
    ..DEFAULTS
};
