//! proc/pidfd_spawn — glibc 2.39's `pidfd_spawnp` (posix/pidfd_spawnp.c):
//! it searches `PATH`, runs the program and answers a pidfd; `pidfd_getpid`
//! names the child's pid (from the descriptor's fdinfo), and `waitpid` reaps
//! it with its exit status.
//!
//! A process-lifecycle deny-trap under patina, so the first call is the one
//! judged. `PATH` is `/usr/bin:/bin`. libc only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::Probe;
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

unsafe extern "C" {
    static mut environ: *const *mut c_char;
    fn pidfd_spawnp(
        pidfd: *mut c_int,
        file: *const c_char,
        actions: *const posix_spawn_file_actions_t,
        attributes: *const posix_spawnattr_t,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn pidfd_getpid(pidfd: c_int) -> pid_t;
}

pub fn run(p: &Probe) {
    // SAFETY: NUL-terminated strings, copied by setenv.
    let r = unsafe { setenv(c"PATH".as_ptr(), c"/usr/bin:/bin".as_ptr(), 1) };
    p.require("set PATH", r == 0);
    let args = [c"sh", c"-c", c"exit 3"].map(CString::from);
    let argv: Vec<*mut c_char> = args
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut pidfd: c_int = -1;
    // SAFETY: NUL-terminated strings, no actions or attributes.
    let error = unsafe {
        pidfd_spawnp(
            &mut pidfd,
            c"sh".as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            environ,
        )
    };
    p.rec.event("pidfd_spawnp", -i64::from(error)).emit();
    p.check("pidfd_spawnp answers a pidfd", error == 0 && pidfd >= 0);
    // SAFETY: the pidfd just answered.
    let pid = unsafe { pidfd_getpid(pidfd) };
    p.rec
        .event("pidfd_getpid", if pid < 0 { fold_errno(-1) } else { 0 })
        .field("positive", pid > 0)
        .emit();
    let mut status = 0;
    // SAFETY: a live status word; `pid` is this process's child.
    let r = fold_errno(i64::from(unsafe { waitpid(pid, &mut status, 0) }));
    p.rec
        .event("waitpid", if r < 0 { r } else { 0 })
        .field("reaped_the_child", r == i64::from(pid))
        .field("exit_status", WEXITSTATUS(status))
        .emit();
    p.check(
        "pidfd_getpid names the child waitpid reaps exiting 3",
        pid > 0 && r == i64::from(pid) && WIFEXITED(status) && WEXITSTATUS(status) == 3,
    );
    p.close(pidfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/pidfd_spawn",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_clone3, Syscall::N_execve, Syscall::N_wait4],
    symbols: &["pidfd_spawnp", "pidfd_getpid", "waitpid", "setenv", "close"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "pidfd_spawnp and pidfd_getpid are process-lifecycle deny-traps (c/posix/signal_process.c patina_process_trap; docs/arcs/syscall-conformance.md §7): the first call, pidfd_spawnp, aborts the run, so pidfd_getpid is judged natively only",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: process spawn reached under patina: pidfd_spawnp",
        },
    }],
    ..DEFAULTS
};
