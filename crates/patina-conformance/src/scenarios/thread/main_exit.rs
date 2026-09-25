//! thread/main_exit — a raw `exit` (the thread row, not `exit_group`) from
//! the main thread ends only that thread: the process lives while another
//! thread runs, that thread records events after the main thread is gone,
//! and its `exit_group` sets the process exit status (kernel/exit.c do_exit
//! vs do_group_exit; man 2 exit).

use crate::catalog::{DEFAULTS, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub fn run(p: &Probe) {
    static MAIN_LEAVING: AtomicBool = AtomicBool::new(false);
    static WORKER_PROBE: AtomicPtr<Probe> = AtomicPtr::new(std::ptr::null_mut());
    // Published before the spawn, so the worker never reads it unset. The main
    // thread leaves by a raw exit that never returns, so the probe its frame
    // owns stays mapped for the worker.
    WORKER_PROBE.store(p as *const Probe as *mut Probe, Ordering::SeqCst);
    let worker = std::thread::Builder::new()
        .spawn(move || {
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
    p.check(
        "the main thread is the thread group leader",
        p.gettid() == p.getpid(),
    );
    MAIN_LEAVING.store(true, Ordering::SeqCst);
    p.exit_thread(0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/main_exit",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_exit,
        Syscall::N_exit_group,
    ],
    trace: Some(TraceFacts {
        generations: &[],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
