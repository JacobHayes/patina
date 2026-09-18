//! signal/core_term — a `SIG_DFL` core-action signal (SIGABRT, man 7 signal:
//! Core) sent to self ends the process by that signal with the wait status's
//! core flag set when the kernel dumped (kernel/coredump.c do_coredump →
//! group_exit_code |= 0x80); the flag records what this host's core sink did
//! at blessing time (an apport pipe pattern dumps regardless of RLIMIT_CORE),
//! and the virtual kernel must die through the real signal so the same host
//! answers the same.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use syscall_conformance::calls::Probe;

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
}

syscall_conformance::probe_main!("signal/core_term", scenario::run);
