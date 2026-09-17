//! signal/default — default terminating actions are reported by wait status,
//! including WTERMSIG and the core-dump bit for core-action signals.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::Probe;

    fn child_signal(sig: c_int) -> c_int {
        unsafe {
            let pid = fork();
            if pid == 0 {
                signal(sig, SIG_DFL);
                kill(getpid(), sig);
                _exit(99);
            }
            let mut status = 0;
            let waited = waitpid(pid, &mut status, 0);
            assert_eq!(waited, pid);
            status
        }
    }

    pub fn run(p: &Probe) {
        p.getpid();
        let term = child_signal(SIGTERM);
        p.rec.event("wait_status", 0)
            .arg("case", "SIGTERM")
            .field("signaled", WIFSIGNALED(term))
            .field("termsig", WTERMSIG(term))
            .field("core", WCOREDUMP(term))
            .emit();
        p.check("SIGTERM terminates with no core flag", WIFSIGNALED(term) && WTERMSIG(term) == SIGTERM && !WCOREDUMP(term));

        let core = child_signal(SIGABRT);
        p.rec.event("wait_status", 0)
            .arg("case", "SIGABRT")
            .field("signaled", WIFSIGNALED(core))
            .field("termsig", WTERMSIG(core))
            .field("core", WCOREDUMP(core))
            .emit();
        p.check("SIGABRT terminates and sets the core flag", WIFSIGNALED(core) && WTERMSIG(core) == SIGABRT && WCOREDUMP(core));
    }
}

syscall_conformance::probe_main!("signal/default", scenario::run);
