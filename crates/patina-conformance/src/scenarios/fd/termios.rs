//! fd/termios — glibc's `tcgetattr` (termios/tcgetattr.c over `TCGETS`)
//! and `tcsetattr` (`TCSETS`, `TCSETSW`, `TCSETSF` by its action) on
//! descriptors that are no terminal: a pipe is ENOTTY (fs/ioctl holds the
//! other kinds to `TCGETS` and `TCSETS`) and a closed number EBADF.
//! Pseudoterminals are not modeled.
//!
//! Every call starts from a termios of 0xAA bytes, so each recorded byte is
//! one glibc wrote. libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `tcgetattr(fd)`: the result and, on success, the settings.
pub(super) fn get(p: &Probe, fd: c_int, what: &str) -> (i64, Option<termios>) {
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

/// `tcsetattr(fd, action, t)`.
pub(super) fn set(p: &Probe, fd: c_int, action: c_int, t: &termios, what: &str) -> i64 {
    // SAFETY: a live termios for tcsetattr to read.
    let r = fold_errno(i64::from(unsafe { tcsetattr(fd, action, t) }));
    p.rec
        .event("tcsetattr", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("action", action)
        .arg("what", what)
        .field("iflag", t.c_iflag)
        .field("oflag", t.c_oflag)
        .field("cflag", t.c_cflag)
        .field("lflag", t.c_lflag)
        .emit();
    r
}

pub fn run(p: &Probe) {
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check("a pipe is ENOTTY", get(p, rd, "pipe").0 == neg(ENOTTY));
    // SAFETY: an all-zero termios is a valid value to pass.
    let zero: termios = unsafe { std::mem::zeroed() };
    p.check(
        "tcsetattr of a pipe is ENOTTY",
        set(p, rd, TCSANOW, &zero, "pipe") == neg(ENOTTY),
    );
    p.close(rd);
    p.close(wr);
    p.check(
        "a closed number is EBADF",
        get(p, rd, "closed").0 == neg(EBADF),
    );
    p.check(
        "tcsetattr of a closed number is EBADF",
        set(p, rd, TCSANOW, &zero, "closed") == neg(EBADF),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/termios",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_pipe2, Syscall::N_close],
    symbols: &["tcgetattr", "tcsetattr", "pipe2", "close"],
    ..DEFAULTS
};
