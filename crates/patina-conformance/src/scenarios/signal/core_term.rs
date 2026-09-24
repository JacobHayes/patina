//! signal/core_term — a `SIG_DFL` core-action signal (SIGABRT, man 7 signal:
//! Core) sent to self ends the process by that signal with the wait status's
//! core flag set when the kernel dumped (kernel/coredump.c do_coredump →
//! group_exit_code |= 0x80); the flag records what this host's core sink does
//! (an apport pipe pattern dumps regardless of RLIMIT_CORE), and the virtual
//! kernel must die through the real signal so the same host answers the same.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    support::install_disposition(SIGABRT, SIG_DFL);
    p.check(
        "SIGABRT is at its default disposition",
        support::disposition(SIGABRT) == "SIG_DFL",
    );
    p.dies_by(SIGABRT);
    p.kill(pid, SIGABRT);
    p.check(
        "unreachable: kill(self, SIGABRT) with SIG_DFL returned",
        false,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/core_term",
    run,
    covers: &[Syscall::N_getpid, Syscall::N_kill],
    symbols: &["getpid", "kill", "sigaction"],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGABRT)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
