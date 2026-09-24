//! proc/ids — process/thread id relations for a single-process guest, including
//! process-group/session ids and kill(0)/kill(-1) process selection semantics.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use libc::*;

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    let tid = p.gettid() as pid_t;
    let ppid = p.getppid();
    let pgid = p.getpgid(0);
    let sid = p.getsid(0);
    p.check("main thread tid equals pid", tid == pid);
    p.check("parent pid is nonnegative", ppid >= 0);
    p.check("process group id is positive", pgid > 0);
    p.check("session id is positive", sid > 0);
    p.check("getpgid(pid) equals getpgid(0)", p.getpgid(pid) == pgid);
    p.check("getsid(pid) equals getsid(0)", p.getsid(pid) == sid);
    p.check("tgkill(pid,pid,0) succeeds", p.tgkill(pid, pid, 0) == 0);
    p.check(
        "kill(0,0) succeeds for our process group",
        p.kill(0, 0) == 0,
    );
    p.check(
        "kill(-1,0) succeeds when at least one process is signalable",
        p.kill(-1, 0) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/ids",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_getppid,
        Syscall::N_getpgid,
        Syscall::N_getsid,
        Syscall::N_tgkill,
        Syscall::N_kill,
    ],
    symbols: &["getpid", "syscall", "getppid", "kill"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "the virtual pid namespace holds two processes, its init (pid 1) and the guest (pid 2, init's child; registry::INIT_PID/IDENTITY_PID, src/identity.rs): kill(-1, sig) reaches every process but init and the caller, of which there are none, so the kernel's answer for that tree is ESRCH (kill_something_info), where the native oracle's host has other processes of the caller's",
        failure: Failure::Differs(&[
            Difference::field(17, "kill", "errno", Observed::Str("ESRCH")),
            Difference::field(17, "kill", "ret", Observed::Int(-1)),
            Difference::check(
                18,
                "kill(-1,0) succeeds when at least one process is signalable",
            ),
        ]),
    }],
    ..DEFAULTS
};
