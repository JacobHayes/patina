//! fd/termios — glibc's `tcgetattr` (termios/tcgetattr.c over `TCGETS`):
//!
//! * a pseudoterminal's peer (`TIOCGPTPEER`) answers the pts driver's
//!   initial settings (`tty_std_termios` less `HUPCL`, drivers/tty/pty.c:
//!   canonical and echoing, `ICRNL|IXON`, `OPOST|ONLCR`, 38400 baud, 8 bits,
//!   receiver on, the default control characters), glibc padding the control
//!   characters past the kernel's 19 with `_POSIX_VDISABLE`; the master
//!   answers the same, its peer's (`tty_mode_ioctl` acts on `tty->link`);
//! * a pipe is ENOTTY (fs/ioctl holds the other kinds to `TCGETS`), a
//!   closed number EBADF;
//! * the pair's window size starts zero, and one the master sets
//!   (`TIOCSWINSZ`) is what the peer and the master read back
//!   (`TIOCGWINSZ`, `tiocgwinsz` of `tty->link` for the master).
//!
//! Every call starts from a termios of 0xAA bytes, so each recorded byte is
//! one glibc wrote.
//!
//! The pipe and the closed number come first. libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `tcgetattr(fd)`: the result and, on success, the settings.
fn get(p: &Probe, fd: c_int, what: &str) -> (i64, Option<termios>) {
    // SAFETY: a termios of 0xAA bytes is a valid out-parameter, and marks
    // every byte tcgetattr leaves unwritten.
    let mut t: termios = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::write_bytes(&raw mut t, 0xAA, 1) };
    // SAFETY: tcgetattr into a live termios.
    let r = fold_errno(i64::from(unsafe { tcgetattr(fd, &mut t) }));
    let event = p
        .rec
        .event("tcgetattr", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("what", what);
    let event = if r == 0 {
        event
            .field("iflag", t.c_iflag)
            .field("oflag", t.c_oflag)
            .field("cflag", t.c_cflag)
            .field("lflag", t.c_lflag)
            .field("line", t.c_line)
            .field("cc", t.c_cc.to_vec())
            .field("ispeed", t.c_ispeed)
            .field("ospeed", t.c_ospeed)
    } else {
        event
    };
    event.emit();
    (r, (r == 0).then_some(t))
}

/// `ioctl(fd, request, &winsize)` for a window-size request: the result and
/// the size as it stands after the call.
fn winsize(
    p: &Probe,
    fd: c_int,
    request: c_ulong,
    set: Option<[u16; 4]>,
    what: &str,
) -> (i64, [u16; 4]) {
    let [row, col, xpixel, ypixel] = set.unwrap_or([0xAAAA; 4]);
    let mut ws = libc::winsize {
        ws_row: row,
        ws_col: col,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    // SAFETY: a live winsize for the request to read or fill.
    let r = fold_errno(i64::from(unsafe { ioctl(fd, request, &mut ws) }));
    let size = [ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel];
    p.rec
        .event(
            if set.is_some() {
                "TIOCSWINSZ"
            } else {
                "TIOCGWINSZ"
            },
            r,
        )
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("what", what)
        .field("size", size.to_vec())
        .emit();
    (r, size)
}

/// The pts driver's initial settings, as glibc hands them out.
fn standard(t: termios) -> bool {
    t.c_iflag == ICRNL | IXON
        && t.c_oflag == OPOST | ONLCR
        && t.c_cflag == B38400 | CS8 | CREAD
        && t.c_lflag == ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN
        && t.c_cc[VINTR] == 3
        && t.c_cc[VEOF] == 4
        && t.c_cc[VMIN] == 1
        && t.c_cc[19..].iter().all(|&c| c == 0)
        && t.c_ispeed == B38400
        && t.c_ospeed == B38400
}

pub fn run(p: &Probe) {
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check("a pipe is ENOTTY", get(p, rd, "pipe").0 == neg(ENOTTY));
    p.close(rd);
    p.close(wr);
    p.check(
        "a closed number is EBADF",
        get(p, rd, "closed").0 == neg(EBADF),
    );

    let master = p.openat(AT_FDCWD, "/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    p.require("open a pseudoterminal master", master >= 0);
    let (r, t) = get(p, master, "pty master");
    p.check(
        "the master answers its peer's settings",
        r == 0 && t.is_some_and(standard),
    );

    let mut unlock: c_int = 0;
    // SAFETY: TIOCSPTLCK reads one int; TIOCGPTPEER takes open flags.
    let peer = unsafe {
        let unlocked = ioctl(master, TIOCSPTLCK, &mut unlock);
        p.require("unlock the peer", unlocked == 0);
        ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY) as i64
    };
    let peer = fold_errno(peer);
    p.rec
        .event("TIOCGPTPEER", peer)
        .norm("ret", Norm::Relative("fd"))
        .emit();
    p.require("open the peer", peer >= 0);
    let peer = peer as c_int;
    let (r, t) = get(p, peer, "pty peer");
    p.check(
        "the peer answers the pts driver's initial settings",
        r == 0 && t.is_some_and(standard),
    );

    p.check(
        "the pair's window size starts zero",
        winsize(p, peer, TIOCGWINSZ, None, "pty peer") == (0, [0; 4]),
    );
    let size = [24, 80, 640, 480];
    p.check(
        "the master sets the pair's window size",
        winsize(p, master, TIOCSWINSZ, Some(size), "pty master").0 == 0,
    );
    p.check(
        "the peer reads it",
        winsize(p, peer, TIOCGWINSZ, None, "pty peer") == (0, size),
    );
    p.check(
        "and so does the master",
        winsize(p, master, TIOCGWINSZ, None, "pty master") == (0, size),
    );
    p.close(peer);
    p.close(master);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/termios",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_ioctl,
        Syscall::N_openat,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &["tcgetattr", "ioctl", "openat", "pipe2", "close"],
    ..DEFAULTS
};
