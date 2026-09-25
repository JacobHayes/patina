//! proc/exec — glibc's `execvp` (posix/execvpe.c) where no program runs,
//! so the calling process continues with the error:
//!
//! * a name without `/` is searched along `PATH`: a file found there without
//!   execute permission is EACCES, a name no `PATH` entry has is ENOENT;
//! * the empty name is ENOENT;
//! * a name with `/` is not searched: a missing path is ENOENT, a directory
//!   EACCES.
//!
//! `PATH` is the run directory's `bin` alone. libc only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// `execvp(file, [file])`, which returns only on failure; `shown` stands for
/// `file` in the event (the run directory is the harness's).
fn exec(p: &Probe, file: &str, shown: &str) -> i64 {
    let c = CString::new(file).unwrap();
    let argv = [c.as_ptr(), std::ptr::null()];
    // SAFETY: a NUL-terminated file and a NULL-terminated argv.
    let r = fold_errno(i64::from(unsafe { execvp(c.as_ptr(), argv.as_ptr()) }));
    p.rec.event("execvp", r).arg("file", shown).emit();
    r
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let bin = format!("{root}/bin");
    p.require("mkdir bin", p.mkdirat(AT_FDCWD, &bin, 0o755) == 0);
    p.create(&format!("{bin}/plain"), 0o644);
    let path = CString::new(bin.as_str()).unwrap();
    // SAFETY: NUL-terminated strings, copied by setenv.
    let r = unsafe { setenv(c"PATH".as_ptr(), path.as_ptr(), 1) };
    p.require("set PATH", r == 0);

    p.check(
        "a file on PATH without execute permission is EACCES",
        exec(p, "plain", "plain") == neg(EACCES),
    );
    p.check(
        "a name no PATH entry has is ENOENT",
        exec(p, "patina-conformance-absent", "patina-conformance-absent") == neg(ENOENT),
    );
    p.check("the empty name is ENOENT", exec(p, "", "") == neg(ENOENT));
    p.check(
        "a missing path is ENOENT",
        exec(p, &format!("{root}/missing"), "<dir>/missing") == neg(ENOENT),
    );
    p.check(
        "a directory path is EACCES",
        exec(p, &bin, "<dir>/bin") == neg(EACCES),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/exec",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_execve,
        Syscall::N_mkdirat,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["execvp", "setenv", "mkdirat", "openat", "close"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "execvp is a process-lifecycle deny-trap (c/posix/signal_process.c patina_process_trap; docs/arcs/syscall-conformance.md §7): the first call aborts the run, even one that would only fail",
        failure: Failure::Stops {
            events: 3,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: process spawn reached under patina: execvp",
        },
    }],
    ..DEFAULTS
};
