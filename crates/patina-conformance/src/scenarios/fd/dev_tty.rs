//! fd/dev_tty — `/dev/tty` opens only for a process with a controlling
//! terminal (drivers/tty/tty_io.c `tty_open_current_tty`): without one it is
//! `ENXIO`, which the virtual process always answers. (crossterm opens it
//! when stdin is not a terminal.)

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    p.check(
        "/dev/tty without a controlling terminal is ENXIO",
        p.openat(AT_FDCWD, "/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC, 0) == neg(ENXIO) as i32,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/dev_tty",
    run,
    covers: &[Syscall::N_openat],
    needs: &[Need::NoControllingTerminal],
    ..DEFAULTS
};
