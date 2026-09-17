//! signal/nested — handler mask semantics, SA_NODEFER recursion, SA_RESETHAND's
//! reset-to-default action, and raw rt_sigaction's SA_RESTORER requirement.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use syscall_conformance::calls::Probe;

    static DEPTH: AtomicI32 = AtomicI32::new(0);
    static MAX_DEPTH: AtomicI32 = AtomicI32::new(0);
    static COUNT: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn raises_same(sig: c_int) {
        let d = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
        MAX_DEPTH.fetch_max(d, Ordering::SeqCst);
        if COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
            unsafe { kill(getpid(), sig); }
        }
        DEPTH.fetch_sub(1, Ordering::SeqCst);
    }

    fn install(sig: c_int, flags: c_int) {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = flags;
            sa.sa_sigaction = raises_same as *const () as usize;
            assert_eq!(sigaction(sig, &sa, std::ptr::null_mut()), 0);
        }
    }

    fn reset() { DEPTH.store(0, Ordering::SeqCst); MAX_DEPTH.store(0, Ordering::SeqCst); COUNT.store(0, Ordering::SeqCst); }

    fn reset_hand_status() -> c_int {
        unsafe {
            let pid = fork();
            if pid == 0 {
                install(SIGUSR2, SA_RESETHAND);
                kill(getpid(), SIGUSR2);
                kill(getpid(), SIGUSR2);
                _exit(99);
            }
            let mut status = 0;
            waitpid(pid, &mut status, 0);
            status
        }
    }

    pub fn run(p: &Probe) {
        reset();
        install(SIGUSR1, 0);
        p.kill(p.getpid() as pid_t, SIGUSR1);
        p.check("default handler mask defers same signal", COUNT.load(Ordering::SeqCst) == 2 && MAX_DEPTH.load(Ordering::SeqCst) == 1);

        reset();
        install(SIGUSR1, SA_NODEFER);
        p.kill(p.getpid() as pid_t, SIGUSR1);
        p.check("SA_NODEFER permits nested same-signal delivery", COUNT.load(Ordering::SeqCst) == 2 && MAX_DEPTH.load(Ordering::SeqCst) == 2);

        let status = reset_hand_status();
        p.rec.event("wait_status", 0)
            .arg("case", "SA_RESETHAND")
            .field("signaled", WIFSIGNALED(status))
            .field("termsig", WTERMSIG(status))
            .emit();
        p.check("SA_RESETHAND resets disposition before the second raise", WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR2);
        let mut bad: sigaction = unsafe { std::mem::zeroed() };
        bad.sa_sigaction = raises_same as *const () as usize;
        unsafe { sigemptyset(&mut bad.sa_mask); }
        bad.sa_flags = 0;
        p.check(
            "raw rt_sigaction without SA_RESTORER is accepted at registration time",
            p.call_observed(
                syscall_conformance::vehicle::Sys::RtSigaction,
                [SIGUSR1 as i64, &bad as *const sigaction as i64, 0, 8, 0, 0],
            ) == 0,
        );
    }
}

syscall_conformance::probe_main!("signal/nested", scenario::run);
