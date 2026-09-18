//! signal/default_term — a `SIG_DFL` terminating signal sent to self ends the
//! process by that signal (man 7 signal: SIGTERM default action Term), with
//! no core flag; the harness records the process outcome the supervisor
//! observed as the stream's `__termination` line, and `kill` never returns,
//! so `expect_death` is the last event the probe itself records.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use syscall_conformance::calls::Probe;

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
}

syscall_conformance::probe_main!("signal/default_term", scenario::run);
