//! thread/kill — tgkill/tkill/pthread_kill target one thread, and a dead tid is
//! ESRCH.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use syscall_conformance::calls::{neg, Probe};

    static COUNT: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn handler(_: c_int) { COUNT.fetch_add(1, Ordering::SeqCst); }

    fn install() {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            sa.sa_sigaction = handler as *const () as usize;
            sigaction(SIGUSR1, &sa, std::ptr::null_mut());
        }
    }

    pub fn run(p: &Probe) {
        install();
        let pid = p.getpid() as pid_t;
        let tid_slot = Arc::new(AtomicI32::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let pthread_slot = Arc::new(AtomicU64::new(0));
        let tid_child = Arc::clone(&tid_slot);
        let stop_child = Arc::clone(&stop);
        let pthread_child = Arc::clone(&pthread_slot);
        let handle = std::thread::spawn(move || {
            install();
            pthread_child.store(unsafe { pthread_self() as u64 }, Ordering::SeqCst);
            tid_child.store(unsafe { syscall(SYS_gettid) as i32 }, Ordering::SeqCst);
            while !stop_child.load(Ordering::SeqCst) { std::thread::sleep(std::time::Duration::from_millis(10)); }
        });
        while tid_slot.load(Ordering::SeqCst) == 0 { std::thread::yield_now(); }
        let tid = tid_slot.load(Ordering::SeqCst);
        COUNT.store(0, Ordering::SeqCst);
        p.check("tgkill to a specific live tid", p.tgkill(pid, tid, SIGUSR1) == 0);
        std::thread::sleep(std::time::Duration::from_millis(40));
        p.check("tgkill delivered exactly one handler", COUNT.load(Ordering::SeqCst) == 1);
        p.check("tkill to a specific live tid", p.tkill(tid, SIGUSR1) == 0);
        std::thread::sleep(std::time::Duration::from_millis(40));
        p.check("tkill delivered another handler", COUNT.load(Ordering::SeqCst) == 2);
        p.check("the helper exposed a pthread identity", pthread_slot.load(Ordering::SeqCst) != 0);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        p.check("tgkill of a dead tid is ESRCH", p.tgkill(pid, tid, SIGUSR1) == neg(ESRCH));
    }
}

syscall_conformance::probe_main!("thread/kill", scenario::run);
