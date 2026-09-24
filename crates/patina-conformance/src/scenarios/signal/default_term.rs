//! signal/default_term — a `SIG_DFL` terminating signal sent to self ends the
//! process by that signal (man 7 signal: SIGTERM default action Term), with
//! no core flag; the harness compares the process outcome each supervisor
//! observed, and `kill` never returns, so `expect_death` is the last event
//! the scenario records.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    support::install_disposition(SIGTERM, SIG_DFL);
    p.check(
        "SIGTERM is at its default disposition",
        support::disposition(SIGTERM) == "SIG_DFL",
    );
    p.check("kill(self, 0) still probes existence", p.kill(pid, 0) == 0);
    p.dies_by(SIGTERM);
    p.kill(pid, SIGTERM);
    p.check(
        "unreachable: kill(self, SIGTERM) with SIG_DFL returned",
        false,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/default_term",
    run,
    covers: &[Syscall::N_getpid, Syscall::N_kill],
    symbols: &["getpid", "kill", "sigaction"],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGTERM)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
