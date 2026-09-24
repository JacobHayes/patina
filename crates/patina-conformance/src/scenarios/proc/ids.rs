//! proc/ids — process/thread id relations for a single-process guest, including
//! process-group/session ids and kill(0)/kill(-1) process selection semantics.

use crate::catalog::{DEFAULTS, Scenario};
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
    ..DEFAULTS
};
