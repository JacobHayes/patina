//! fd/termios — glibc's `tcgetattr` (termios/tcgetattr.c over `TCGETS`):
//!
//! * a pseudoterminal's peer (`TIOCGPTPEER`) answers the pts driver's
//!   initial settings (`tty_std_termios` less `HUPCL`, drivers/tty/pty.c:
//!   canonical and echoing, `ICRNL|IXON`, `OPOST|ONLCR`, 38400 baud, 8 bits,
//!   receiver on, the default control characters), glibc padding the control
//!   characters past the kernel's 19 with `_POSIX_VDISABLE`; the master
//!   answers the same, its peer's (`tty_mode_ioctl` acts on `tty->link`);
//! * a pipe is ENOTTY (fs/ioctl holds the other kinds to `TCGETS`), a
//!   closed number EBADF.
//!
//! Every call starts from a termios of 0xAA bytes, so each recorded byte is
//! one glibc wrote.
//!
//! The shim leaves `tcgetattr` undefined (registry `Absent`), so the
//! scenario reaches glibc's definition through `dlsym`. libc only.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

type Tcgetattr = unsafe extern "C" fn(c_int, *mut termios) -> c_int;

fn resolve(p: &Probe, symbol: &str) -> *mut c_void {
    let address = p.rec.quiet(|| p.resolve(symbol));
    p.require(&format!("glibc's {symbol} resolves"), address.is_some());
    address.unwrap_or(std::ptr::null_mut())
}

/// `tcgetattr(fd)`: the result and, on success, the settings.
fn get(p: &Probe, tcgetattr: Tcgetattr, fd: c_int, what: &str) -> (i64, Option<termios>) {
    // SAFETY: a termios of 0xAA bytes is a valid out-parameter, and marks
    // every byte tcgetattr leaves unwritten.
    let mut t: termios = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::write_bytes(&raw mut t, 0xAA, 1) };
    // SAFETY: glibc's tcgetattr into a live termios.
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
    // SAFETY: glibc's definition of this prototype.
    let tcgetattr: Tcgetattr = unsafe { std::mem::transmute(resolve(p, "tcgetattr")) };

    let master = p.openat(AT_FDCWD, "/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    p.require("open a pseudoterminal master", master >= 0);
    let (r, t) = get(p, tcgetattr, master, "pty master");
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
    let (r, t) = get(p, tcgetattr, peer, "pty peer");
    p.check(
        "the peer answers the pts driver's initial settings",
        r == 0 && t.is_some_and(standard),
    );
    p.close(peer);
    p.close(master);

    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "a pipe is ENOTTY",
        get(p, tcgetattr, rd, "pipe").0 == neg(ENOTTY),
    );
    p.close(rd);
    p.close(wr);
    p.check(
        "a closed number is EBADF",
        get(p, tcgetattr, rd, "closed").0 == neg(EBADF),
    );
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
    resolves: &["tcgetattr"],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: &[Vehicle::Libc],
        what: "the shim defines no tcgetattr (registry Absent), and its dlsym answers NULL for a name it does not route (c/posix/dlsym.c patina_dlsym_route), so the scenario cannot reach glibc's definition",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Exit(101),
            diagnostic: "fd/termios: cannot continue: glibc's tcgetattr resolves",
        },
    }],
    ..DEFAULTS
};
