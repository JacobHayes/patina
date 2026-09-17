//! signal/pipe — SIGPIPE default action for pipe writes, ignored SIGPIPE turning
//! the write into EPIPE, and MSG_NOSIGNAL suppressing SIGPIPE on socket sends.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe};

    fn default_sigpipe_status() -> c_int {
        unsafe {
            let mut fds = [0; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let pid = fork();
            if pid == 0 {
                close(fds[0]);
                signal(SIGPIPE, SIG_DFL);
                let _ = write(fds[1], b"x".as_ptr() as *const _, 1);
                _exit(99);
            }
            close(fds[0]);
            close(fds[1]);
            let mut status = 0;
            waitpid(pid, &mut status, 0);
            status
        }
    }

    pub fn run(p: &Probe) {
        let status = default_sigpipe_status();
        p.rec.event("wait_status", 0)
            .arg("case", "SIGPIPE")
            .field("signaled", WIFSIGNALED(status))
            .field("termsig", WTERMSIG(status))
            .field("core", WCOREDUMP(status))
            .emit();
        p.check("default SIGPIPE terminates without core", WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE && !WCOREDUMP(status));

        unsafe { signal(SIGPIPE, SIG_IGN); }
        let (r, fds) = p.pipe2(0);
        p.require("pipe", r == 0);
        p.close(fds[0]);
        p.check("ignored SIGPIPE makes pipe write return EPIPE", p.write(fds[1], b"x") == neg(EPIPE));
        p.close(fds[1]);

        let s = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("tcp socket", s >= 0);
        p.check("MSG_NOSIGNAL makes socket send return EPIPE without a signal", p.sendto(s, b"x", MSG_NOSIGNAL, None) == neg(EPIPE));
        p.close(s);
    }
}

syscall_conformance::probe_main!("signal/pipe", scenario::run);
