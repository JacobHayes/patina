//! signal/resethand_term — `SA_RESETHAND` restores `SIG_DFL` before the
//! handler runs (kernel/signal.c get_signal: SA_ONESHOT clears the handler),
//! so the first signal is handled once and the second ends the process by
//! that signal.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    support::install(SIGUSR2, SA_RESETHAND, false);
    p.check(
        "kill(self, SIGUSR2) with SA_RESETHAND",
        p.kill(pid, SIGUSR2) == 0,
    );
    p.check("the handler ran once", support::count() == 1);
    p.check(
        "SA_RESETHAND restored SIG_DFL",
        support::disposition(SIGUSR2) == "SIG_DFL",
    );
    let (r, raw) = p.rt_sigaction_query(SIGUSR2);
    p.check(
        "the raw door reports SIG_DFL too",
        r == 0 && raw.handler == 0,
    );
    p.dies_by(SIGUSR2);
    p.kill(pid, SIGUSR2);
    p.check("unreachable: the second SIGUSR2 returned", false);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/resethand_term",
    run,
    covers: &[Syscall::N_getpid, Syscall::N_kill, Syscall::N_rt_sigaction],
    symbols: &["getpid", "kill", "sigaction", "syscall"],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR2), Generation::process(SIGUSR2)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
