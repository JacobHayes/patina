//! The program's descriptor space, and the runtime's.
//!
//! The invariant: the program's descriptors are numbers below the soft `RLIMIT_NOFILE` it is
//! shown, a limit that is never above `NOFILE_HARD`; every descriptor of the runtime, the
//! supervisor and the launcher is at `FD_HIDDEN_MIN` or above (`NOFILE_HARD <=
//! FD_HIDDEN_MIN`). So no number, error or listing the program sees depends on which hidden
//! descriptors exist (a spin probe's, opened when host timing says).
//!
//! The kernel holds the program's side: the real soft limit is the program's soft limit,
//! which the kernel keeps across `fork` and `execve`, so its lowest-free allocation, the
//! targets of `dup2`/`dup3`, `F_DUPFD`'s minimum, `poll`'s count and the descriptors an
//! `SCM_RIGHTS` message gives answer as on Linux and never reach a hidden number, whichever
//! call allocates. The real hard limit stays the sandbox's (`FD_LIMIT`): the runtime lifts the
//! soft limit to it around its own allocations (`raised`) and puts it back. The hard limit the
//! program sees is the runtime's (`Proc::nofile_hard`; carried across `execve` in the slot).
//! A hidden number the program names is `EBADF` (`sys::dispatch`), and listings of
//! `/proc/self/fd` leave them out.

use crate::raw::*;
use crate::state::{proc, thread};
use proto::layout::{NOFILE_HARD, NOFILE_SOFT};

const RLIMIT_NOFILE: u64 = 7;
/// The kernel's default `fs.nr_open`: no hard limit above it can be set.
const NR_OPEN: u64 = 1 << 20;
const F_DUPFD_CLOEXEC: u64 = 1030;
const O_CLOEXEC: u64 = 0o2_000_000;
const EMFILE: i64 = 24;

/// The real limits (soft, hard).
fn real() -> [u64; 2] {
    let mut old = [0u64; 2];
    unsafe { sc4(nr::PRLIMIT64, 0, RLIMIT_NOFILE, 0, old.as_mut_ptr() as u64) };
    old
}

fn set_real(v: [u64; 2]) -> i64 {
    unsafe { sc4(nr::PRLIMIT64, 0, RLIMIT_NOFILE, v.as_ptr() as u64, 0) }
}

/// At each image start. A soft limit above anything a program can set is the supervisor's
/// (the run's first image of a process tree): the program starts at the default. Otherwise
/// this image follows an `execve`, which kept the soft limit, and the hard one is in the slot.
pub fn start() {
    let [soft, hard] = real();
    if soft > NOFILE_HARD {
        if set_real([NOFILE_SOFT, hard]) != 0 {
            crate::fatal(proto::ctl::Setup::Rlimit, 0);
        }
        proc().nofile_hard = NOFILE_HARD;
    } else {
        let h = slot()
            .nofile_hard
            .load(core::sync::atomic::Ordering::Relaxed);
        proc().nofile_hard = if h == 0 { NOFILE_HARD } else { h };
    }
}

fn slot() -> &'static proto::ctl::Slot {
    unsafe { &*crate::state::ctl().slot(thread().slot as usize) }
}

/// Before this process's `execve`: the new image reads the hard limit from the slot.
pub fn before_exec() {
    slot()
        .nofile_hard
        .store(hard(), core::sync::atomic::Ordering::Relaxed);
}

/// The hard limit the calling process is shown (a vfork child's own copy).
pub fn hard() -> u64 {
    let ts = thread();
    if ts.vfork != 0 {
        ts.vf_nofile_hard
    } else {
        proc().nofile_hard
    }
}

/// The calling process's limits as `getrlimit` answers.
pub fn get() -> [u64; 2] {
    [real()[0], hard()]
}

/// `setrlimit`: Linux's checks in its order, for a process without `CAP_SYS_RESOURCE`.
pub fn set(new: [u64; 2]) -> i64 {
    let [soft, hard] = new;
    if soft > hard {
        return -e::EINVAL;
    }
    if hard > NR_OPEN || hard > self::hard() {
        return -e::EPERM;
    }
    let r = set_real([soft, real()[1]]);
    if r != 0 {
        crate::sup::host_error(r, nr::PRLIMIT64, proto::ctl::HE_SYSCALL);
    }
    let ts = thread();
    if ts.vfork != 0 {
        ts.vf_nofile_hard = hard;
    } else {
        proc().nofile_hard = hard;
    }
    0
}

/// Run `f`, the runtime's own allocation, with the whole descriptor range open to it, then
/// put the program's limit back (a nested call, a probe inside a handler, restores the
/// raised one). Only the calling thread runs program-visible code meanwhile.
pub fn raised<R>(f: impl FnOnce() -> R) -> R {
    let mut old = [0u64; 2];
    let r = unsafe {
        let [_, hard] = real();
        let up = [hard, hard];
        sc4(
            nr::PRLIMIT64,
            0,
            RLIMIT_NOFILE,
            up.as_ptr() as u64,
            old.as_mut_ptr() as u64,
        )
    };
    if r != 0 {
        crate::sup::host_error(r, nr::PRLIMIT64, proto::ctl::HE_SYSCALL);
    }
    let v = f();
    // A limit left raised would let the program allocate hidden numbers.
    let r = set_real(old);
    if r != 0 {
        crate::sup::host_error(r, nr::PRLIMIT64, proto::ctl::HE_SYSCALL);
    }
    v
}

/// A descriptor the runtime opens for a moment (and closes before the program runs again):
/// tried under the program's limit, again with the range open if the program's table is full,
/// so the program's own count never makes a runtime step fail.
pub fn transient(mut f: impl FnMut() -> i64) -> i64 {
    let r = f();
    if r == -EMFILE {
        raised(f)
    } else {
        r
    }
}

/// Move `fd` to the lowest free hidden number from `min` (close-on-exec); `fd` is closed.
pub fn hide(fd: i64, min: i32) -> i64 {
    let h = raised(|| unsafe { sc3(nr::FCNTL, fd as u64, F_DUPFD_CLOEXEC, min as u64) });
    unsafe { sc1(nr::CLOSE, fd as u64) };
    h
}

/// Move `fd` to the hidden number `at` (close-on-exec), replacing what was there; `fd` is
/// closed.
pub fn place(fd: i64, at: i32) -> i64 {
    if fd == at as i64 {
        return fd;
    }
    let r = raised(|| unsafe { sc3(nr::DUP3, fd as u64, at as u64, O_CLOEXEC) });
    unsafe { sc1(nr::CLOSE, fd as u64) };
    r
}
