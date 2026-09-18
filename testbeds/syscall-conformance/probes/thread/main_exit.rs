//! thread/main_exit — a raw `exit` (the thread row, not `exit_group`) from
//! the main thread ends only that thread: the process lives while another
//! thread runs, that thread records events after the main thread is gone,
//! and its `exit_group` sets the process exit status (kernel/exit.c do_exit
//! vs do_group_exit; man 2 exit).

#[cfg(target_os = "linux")]
mod scenario {
    use std::sync::atomic::{AtomicBool, Ordering};
    use syscall_conformance::calls::Probe;

    pub fn run(p: &Probe) {
        static MAIN_LEAVING: AtomicBool = AtomicBool::new(false);
        let worker = std::thread::Builder::new()
            .spawn(move || {
                // The probe object outlives main's exit: it is leaked below.
                let p: &'static Probe =
                    unsafe { &*(WORKER_PROBE.load(Ordering::SeqCst) as *const Probe) };
                while !MAIN_LEAVING.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                std::thread::sleep(std::time::Duration::from_millis(40));
                p.check("the worker runs after the main thread's raw exit", true);
                p.mark("worker_done", &[]);
                p.exit_group(0);
            })
            .expect("spawn");
        drop(worker);
        static WORKER_PROBE: std::sync::atomic::AtomicPtr<Probe> =
            std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
        WORKER_PROBE.store(p as *const Probe as *mut Probe, Ordering::SeqCst);
        p.check(
            "the main thread is the thread group leader",
            p.gettid() == p.getpid(),
        );
        MAIN_LEAVING.store(true, Ordering::SeqCst);
        p.exit_thread(0);
    }
}

syscall_conformance::probe_main!("thread/main_exit", scenario::run);
