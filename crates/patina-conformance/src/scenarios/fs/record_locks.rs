//! fs/record_locks — `fcntl` record locks through every vehicle, the raw
//! instruction among them: the libc door, `syscall(2)` and (x86_64) the
//! trapped `syscall` reach the shim by separate paths, and each must answer
//! as the kernel does. Over two open file descriptions of one file:
//!
//! * `F_SETLK` takes a write lock, and `F_GETLK` never reports the caller's
//!   own lock;
//! * `F_OFD_GETLK` through the other description reports it (range and owner
//!   pid) and `F_OFD_SETLK` there is EAGAIN;
//! * an unlock frees the range, after which the other description's read
//!   lock succeeds and `F_GETLK` reports that OFD lock with pid -1.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::{
    EAGAIN, F_GETLK, F_OFD_GETLK, F_OFD_SETLK, F_RDLCK, F_SETLK, F_UNLCK, F_WRLCK, O_CREAT, O_RDWR,
};
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let file = format!("{}/locked", p.dir());
    let fd = p.open_or_stop(&file, O_RDWR | O_CREAT);
    let other = p.open_or_stop(&file, O_RDWR);
    let (wr, rd, un) = (F_WRLCK as i16, F_RDLCK as i16, F_UNLCK as i16);

    p.check(
        "F_SETLK takes a write lock on 10 bytes",
        p.fcntl_lock(fd, F_SETLK, wr, 0, 10).0 == 0,
    );
    let (r, lock) = p.fcntl_lock(fd, F_GETLK, wr, 0, 10);
    p.check(
        "F_GETLK does not report the caller's own lock",
        r == 0 && lock.l_type == un,
    );
    let pid = p.getpid();
    let (r, lock) = p.fcntl_lock(other, F_OFD_GETLK, wr, 5, 1);
    p.check(
        "F_OFD_GETLK through the other description reports the lock",
        r == 0
            && lock.l_type == wr
            && (lock.l_start, lock.l_len) == (0, 10)
            && i64::from(lock.l_pid) == pid,
    );
    p.check(
        "F_OFD_SETLK through the other description is EAGAIN",
        p.fcntl_lock(other, F_OFD_SETLK, rd, 0, 10).0 == neg(EAGAIN),
    );
    p.check(
        "F_SETLK F_UNLCK frees the range",
        p.fcntl_lock(fd, F_SETLK, un, 0, 10).0 == 0
            && p.fcntl_lock(other, F_OFD_SETLK, rd, 0, 10).0 == 0,
    );
    let (r, lock) = p.fcntl_lock(fd, F_GETLK, wr, 0, 10);
    p.check(
        "F_GETLK reports the OFD read lock with pid -1",
        r == 0 && lock.l_type == rd && lock.l_pid == -1,
    );
    p.close(other);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/record_locks",
    run,
    vehicles: Vehicle::ALL,
    covers: &[
        Syscall::N_openat,
        Syscall::N_fcntl,
        Syscall::N_getpid,
        Syscall::N_close,
    ],
    symbols: &["openat", "fcntl", "getpid", "close"],
    ..DEFAULTS
};
