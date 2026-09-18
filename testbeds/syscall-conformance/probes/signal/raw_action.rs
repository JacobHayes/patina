//! signal/raw_action — the raw `rt_sigaction` door installs and reports
//! dispositions exactly like the libc door: a kernel-layout action with
//! glibc's own restorer (read back from a libc-installed action, since the
//! kernel returns `sa_restorer` through `oldact`) is installed raw, runs on a
//! raw `kill`, is reported back through `oldact` with its flags, a raw
//! `SIG_IGN` is honoured, and libc's `sigaction` query sees the raw door's
//! disposition (man 2 rt_sigaction: SA_RESTORER; kernel/signal.c
//! do_sigaction copies the whole k_sigaction both ways).

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::sync::atomic::Ordering;
    use syscall_conformance::calls::{KernelSigaction, Probe, SA_FLAGS_COMPARED, SA_RESTORER};

    pub fn run(p: &Probe) {
        support::reset();
        let pid = p.getpid() as pid_t;
        // A libc-installed action carries glibc's restorer; the kernel hands it
        // back through oldact, so a raw install can reuse it.
        support::install(SIGUSR2, 0, false);
        let (r, libc_installed) = p.rt_sigaction_query(SIGUSR2);
        p.require("raw query of a libc-installed action", r == 0);
        p.check(
            "the kernel reports SA_RESTORER and glibc's restorer for a libc-installed action",
            libc_installed.flags & SA_RESTORER != 0 && libc_installed.restorer != 0,
        );
        p.check(
            "the libc-installed handler is reported back raw",
            libc_installed.handler == support::handler as *const () as usize,
        );

        let act = KernelSigaction {
            handler: support::info_handler as *const () as usize,
            flags: (SA_SIGINFO | SA_RESTART) as u64 | SA_RESTORER,
            restorer: libc_installed.restorer,
            mask: 0,
        };
        let mut previous = KernelSigaction::default();
        p.check(
            "raw rt_sigaction installs a handler",
            p.rt_sigaction_install(SIGUSR1, Some(&act), Some(&mut previous)) == 0,
        );
        p.check(
            "the previous SIGUSR1 action was SIG_DFL",
            previous.handler == 0,
        );
        let (r, current) = p.rt_sigaction_query(SIGUSR1);
        p.check("raw query after the raw install", r == 0);
        p.check(
            "oldact reports the raw-installed handler, flags and restorer",
            current.handler == act.handler
                && current.flags & SA_FLAGS_COMPARED == (SA_SIGINFO | SA_RESTART) as u64
                && current.restorer == act.restorer
                && current.flags & SA_RESTORER != 0,
        );
        p.check(
            "libc sigaction sees the raw-installed handler",
            support::disposition(SIGUSR1) == "handler",
        );

        p.check(
            "kill(self, SIGUSR1) after a raw install",
            p.kill(pid, SIGUSR1) == 0,
        );
        p.check(
            "the raw-installed handler ran before kill returned",
            support::count() == 1,
        );
        p.check(
            "it saw SI_USER",
            support::LAST_CODE.load(Ordering::SeqCst) == SI_USER,
        );

        let ignore = KernelSigaction {
            handler: SIG_IGN,
            flags: SA_RESTORER,
            restorer: libc_installed.restorer,
            mask: 0,
        };
        let mut before_ignore = KernelSigaction::default();
        p.check(
            "raw rt_sigaction installs SIG_IGN",
            p.rt_sigaction_install(SIGUSR1, Some(&ignore), Some(&mut before_ignore)) == 0,
        );
        p.check(
            "oldact reports the handler SIG_IGN replaced",
            before_ignore.handler == act.handler,
        );
        p.check(
            "kill(self, SIGUSR1) while raw-ignored",
            p.kill(pid, SIGUSR1) == 0,
        );
        p.check(
            "a raw SIG_IGN is honoured (no handler run)",
            support::count() == 1,
        );
        p.check(
            "libc sigaction sees the raw SIG_IGN",
            support::disposition(SIGUSR1) == "SIG_IGN",
        );

        let restore = KernelSigaction {
            handler: SIG_DFL,
            flags: SA_RESTORER,
            restorer: libc_installed.restorer,
            mask: 0,
        };
        p.check(
            "raw rt_sigaction restores SIG_DFL",
            p.rt_sigaction_install(SIGUSR1, Some(&restore), None) == 0,
        );
        p.check(
            "libc sigaction sees SIG_DFL again",
            support::disposition(SIGUSR1) == "SIG_DFL",
        );
    }
}

syscall_conformance::probe_main!("signal/raw_action", scenario::run);
