//! signal/eintr — interrupted blocking calls: read without SA_RESTART returns
//! EINTR, read with SA_RESTART resumes, and nanosleep always returns EINTR and
//! fills a positive remaining duration.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

    use libc::*;
    use std::thread;
    use syscall_conformance::calls::{neg, Probe};

    fn delayed_signal(pid: pid_t, sig: c_int) {
        thread::spawn(move || {
            support::short_pause();
            unsafe { kill(pid, sig); }
        });
    }

    pub fn run(p: &Probe) {
        let pid = p.getpid() as pid_t;
        support::install(SIGUSR1, 0, false);
        let (r, fds) = p.pipe2(0);
        p.require("pipe", r == 0);
        delayed_signal(pid, SIGUSR1);
        p.check("blocking read without SA_RESTART is EINTR", p.read(fds[0], 1).0 == neg(EINTR));

        support::install(SIGUSR1, SA_RESTART, false);
        let wr = fds[1];
        thread::spawn(move || {
            support::short_pause();
            unsafe { kill(pid, SIGUSR1); }
            support::short_pause();
            unsafe { write(wr, b"x".as_ptr() as *const _, 1); }
        });
        let (n, data) = p.read(fds[0], 1);
        p.check("blocking read with SA_RESTART resumes", n == 1 && data == b"x");

        support::install(SIGUSR1, SA_RESTART, false);
        delayed_signal(pid, SIGUSR1);
        p.check("nanosleep is never restarted", p.nanosleep(1, 0) == neg(EINTR));
        p.close(fds[0]);
        p.close(fds[1]);
    }
}

syscall_conformance::probe_main!("signal/eintr", scenario::run);
