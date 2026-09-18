//! thread/tid_clear — `set_tid_address` returns the caller's tid and
//! registers the word the kernel clears and futex-wakes when that thread
//! exits (kernel/fork.c mm_release: put_user(0, clear_child_tid) +
//! futex_wake). A thread installs its own word, exits, and the main thread's
//! `FUTEX_WAIT` on the word returns with it cleared. The thread is detached:
//! glibc's own join bookkeeping relies on the clear_child_tid it registered
//! at clone, which this probe deliberately replaces.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
    use syscall_conformance::calls::Probe;

    static SLOT: AtomicU32 = AtomicU32::new(0);
    static STARTED: AtomicI32 = AtomicI32::new(0);
    static THREAD_TID: AtomicI32 = AtomicI32::new(0);
    static PROBE: AtomicPtr<Probe> = AtomicPtr::new(std::ptr::null_mut());
    const WAIT: i32 = FUTEX_WAIT;

    pub fn run(p: &Probe) {
        let own = AtomicI32::new(0);
        let my_tid = p.set_tid_address(own.as_ptr());
        p.check(
            "set_tid_address returns the caller's tid",
            my_tid == p.gettid(),
        );

        PROBE.store(p as *const Probe as *mut Probe, Ordering::SeqCst);
        // Detached: the JoinHandle is dropped, never joined (see the module doc).
        // The worker uses the probe only before it sets STARTED, and the main
        // thread waits for STARTED before leaving `run`, so the pointer is live.
        let handle = std::thread::Builder::new()
            .spawn(|| {
                let p: &Probe = unsafe { &*PROBE.load(Ordering::SeqCst) };
                let tid = unsafe { syscall(SYS_gettid) } as i32;
                SLOT.store(tid as u32, Ordering::SeqCst);
                THREAD_TID.store(tid, Ordering::SeqCst);
                let returned = p.set_tid_address(SLOT.as_ptr().cast::<i32>());
                p.check(
                    "set_tid_address on the worker returns the worker's tid",
                    returned == tid as i64,
                );
                STARTED.store(1, Ordering::SeqCst);
            })
            .expect("spawn");
        drop(handle);
        p.rec.quiet(|| {
            for _ in 0..2000 {
                if STARTED.load(Ordering::SeqCst) != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        p.require("the worker started", STARTED.load(Ordering::SeqCst) != 0);
        let tid = THREAD_TID.load(Ordering::SeqCst) as u32;
        // Wait for the exit-time clear: bounded so a virtual kernel that
        // never clears fails the check below instead of hanging the leg.
        p.rec.quiet(|| {
            for _ in 0..100 {
                if SLOT.load(Ordering::SeqCst) == 0 {
                    break;
                }
                p.futex(&SLOT, WAIT, tid, Some(20_000_000));
            }
        });
        p.check(
            "the worker's exit cleared its tid word and woke the futex waiter",
            SLOT.load(Ordering::SeqCst) == 0,
        );
        p.check(
            "the main thread's own word is untouched",
            own.load(Ordering::SeqCst) == 0,
        );
    }
}

syscall_conformance::probe_main!("thread/tid_clear", scenario::run);
