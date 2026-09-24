//! proc/traps — process-creating/replacing rows are harmless native calls here
//! but must be named process traps under patina.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

pub fn run(p: &Probe) {
    // The fork row exists on x86_64 only.
    #[cfg(target_arch = "x86_64")]
    {
        p.fork_child(|| p.call_unrecorded(Syscall::N_fork, [0; 6]), || 0)
            .wait();
        p.rec.event("fork", 0).emit();
        p.check("fork child exited cleanly", true);
    }

    p.check(
        "clone with impossible flags is EINVAL",
        p.call_observed(Syscall::N_clone, [!0, 0, 0, 0, 0, 0]) == neg(EINVAL),
    );
    p.check(
        "clone3 with null args and size 0 is EINVAL",
        p.call_observed(Syscall::N_clone3, [0, 0, 0, 0, 0, 0]) == neg(EINVAL),
    );
    let missing = CString::new(format!("{}/no-such-exec", p.dir())).unwrap();
    let argv: [*const c_char; 2] = [missing.as_ptr(), std::ptr::null()];
    let envp: [*const c_char; 1] = [std::ptr::null()];
    p.check(
        "execve missing path is ENOENT",
        p.call_observed(
            Syscall::N_execve,
            [
                missing.as_ptr() as i64,
                argv.as_ptr() as i64,
                envp.as_ptr() as i64,
                0,
                0,
                0,
            ],
        ) == neg(ENOENT),
    );
    p.check(
        "execveat missing path is ENOENT",
        p.call_observed(
            Syscall::N_execveat,
            [
                AT_FDCWD as i64,
                missing.as_ptr() as i64,
                argv.as_ptr() as i64,
                envp.as_ptr() as i64,
                0,
                0,
            ],
        ) == neg(ENOENT),
    );
}
/// The diagnostic of the first process-lifecycle row the scenario reaches:
/// `fork` where the table has it, else `clone`.
#[cfg(target_arch = "x86_64")]
const FIRST_TRAP: &str = "patina: SUD trapped unsupported syscall fork (nr 57, class process";
#[cfg(not(target_arch = "x86_64"))]
const FIRST_TRAP: &str = "patina: SUD trapped unsupported syscall clone (nr 220, class process";

pub const SCENARIO: Scenario = Scenario {
    name: "proc/traps",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_fork,
        Syscall::N_clone,
        Syscall::N_clone3,
        Syscall::N_execve,
        Syscall::N_execveat,
    ],
    symbols: &["fork", "syscall"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: FIRST_TRAP,
        },
    }],
    ..DEFAULTS
};
