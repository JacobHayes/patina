//! signal/altstack — sigaltstack state/error vocabulary and SA_ONSTACK delivery
//! onto the alternate stack.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use syscall_conformance::calls::{neg, Probe};

    static LO: AtomicUsize = AtomicUsize::new(0);
    static HI: AtomicUsize = AtomicUsize::new(0);
    static ON_ALT: AtomicBool = AtomicBool::new(false);
    const SS_AUTODISARM: c_int = 0x8000_0000u32 as c_int;

    extern "C" fn onstack_handler(_: c_int) {
        let local = 0u8;
        let sp = &local as *const u8 as usize;
        ON_ALT.store(sp >= LO.load(Ordering::SeqCst) && sp < HI.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    fn install() {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = SA_ONSTACK;
            sa.sa_sigaction = onstack_handler as *const () as usize;
            assert_eq!(sigaction(SIGUSR1, &sa, std::ptr::null_mut()), 0);
        }
    }

    pub fn run(p: &Probe) {
        let mut old: stack_t = unsafe { std::mem::zeroed() };
        p.check("query initial altstack", p.sigaltstack(None, Some(&mut old)) == 0);
        p.check("initial altstack flags are a known state", old.ss_flags & !(SS_DISABLE | SS_ONSTACK | SS_AUTODISARM) == 0);

        let too_small = vec![0u8; MINSIGSTKSZ - 1];
        let small = stack_t { ss_sp: too_small.as_ptr() as *mut _, ss_flags: 0, ss_size: too_small.len() };
        p.check("altstack smaller than MINSIGSTKSZ is ENOMEM", p.sigaltstack(Some(&small), None) == neg(ENOMEM));
        let bad_flags = stack_t { ss_sp: std::ptr::null_mut(), ss_flags: 0x4000, ss_size: 0 };
        p.check("unknown sigaltstack flags are EINVAL", p.sigaltstack(Some(&bad_flags), None) == neg(EINVAL));

        let mut stack = vec![0u8; SIGSTKSZ];
        LO.store(stack.as_mut_ptr() as usize, Ordering::SeqCst);
        HI.store(stack.as_mut_ptr() as usize + stack.len(), Ordering::SeqCst);
        let new = stack_t { ss_sp: stack.as_mut_ptr() as *mut _, ss_flags: 0, ss_size: stack.len() };
        p.check("install altstack", p.sigaltstack(Some(&new), Some(&mut old)) == 0);
        let mut cur: stack_t = unsafe { std::mem::zeroed() };
        p.sigaltstack(None, Some(&mut cur));
        p.check("installed altstack is enabled", cur.ss_flags & SS_DISABLE == 0);
        install();
        p.kill(p.getpid() as pid_t, SIGUSR1);
        p.require("SA_ONSTACK handler ran on alternate stack", ON_ALT.load(Ordering::SeqCst));

        let disable = stack_t { ss_sp: std::ptr::null_mut(), ss_flags: SS_DISABLE, ss_size: 0 };
        p.check("disable altstack", p.sigaltstack(Some(&disable), None) == 0);
        let autodisarm = stack_t { ss_sp: stack.as_mut_ptr() as *mut _, ss_flags: SS_AUTODISARM, ss_size: stack.len() };
        p.check("SS_AUTODISARM is accepted", p.sigaltstack(Some(&autodisarm), None) == 0);
    }
}

syscall_conformance::probe_main!("signal/altstack", scenario::run);
