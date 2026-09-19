//! Class pairing: pthread deliver-and-resume ownership, grants and nested-park refusal.
use super::*;

static SYNC_PHASE: AtomicUsize = AtomicUsize::new(0);
extern "C" fn sync_handler(_: i32) {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    if SYNC_PHASE.load(Ordering::SeqCst) == 1 {
        // Let an ordinary grant arrive while the interrupted task is executing
        // its handler. It must not wake the already-runnable task a second time.
        SYNC_PHASE.store(2, Ordering::SeqCst);
        for _ in 0..100 {
            if SYNC_PHASE.load(Ordering::SeqCst) == 3 {
                return;
            }
            sched_point().unwrap();
        }
        panic!("ordinary sync notification never arrived during handler");
    }
}
fn signal_parked_sync(main: TaskId, during_handler: bool) {
    for _ in 0..100 {
        if parked_class(main) == Some(BlockClass::Sync) {
            break;
        }
        sched_point().unwrap();
    }
    assert_eq!(parked_class(main), Some(BlockClass::Sync));
    generate(SIGUSR1);
    for _ in 0..100 {
        if during_handler {
            if SYNC_PHASE.load(Ordering::SeqCst) == 2 {
                return;
            }
        } else if HANDLERS.load(Ordering::SeqCst) != 0 {
            assert_eq!(
                parked_class(main),
                Some(BlockClass::Sync),
                "handler alone must repark"
            );
            return;
        }
        sched_point().unwrap();
    }
    panic!("leader handler starved behind a pthread wait");
}

#[test]
fn join_delivers_process_signal_then_waits_for_worker_completion() {
    isolated(|| {
        install_handler(SIGUSR1, sync_handler, 0, 0);
        let main = current_task();
        let worker = spawn(move || {
            signal_parked_sync(main, false);
            // The main task cannot return from join just because its handler ran.
            assert!(lock_state().table.threads[&current_task()].joiner.is_some());
        });
        join(worker);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn mutex_and_cond_keep_ownership_and_notifications_across_handlers() {
    isolated(|| {
        install_handler(SIGUSR1, sync_handler, 0, 0);
        let main = current_task();
        for condition in [false, true] {
            for during_handler in [false, true] {
                HANDLERS.store(0, Ordering::SeqCst);
                SYNC_PHASE.store(usize::from(during_handler), Ordering::SeqCst);
                // Opaque keys: these modeled pthread entries never read a host object.
                let mutex = Box::into_raw(Box::new(0u64)) as usize;
                let cond = Box::into_raw(Box::new(0u64)) as usize;
                unsafe {
                    assert_eq!(patina_mutex_init(mutex as *mut _, std::ptr::null()), 0);
                    assert_eq!(patina_cond_init(cond as *mut _, std::ptr::null()), 0);
                    if condition {
                        assert_eq!(patina_mutex_lock(mutex as *mut _), 0);
                    }
                }
                let worker = spawn(move || unsafe {
                    assert_eq!(patina_mutex_lock(mutex as *mut _), 0);
                    if !condition {
                        delay();
                    }
                    signal_parked_sync(main, during_handler);
                    if condition {
                        // Move the semantic cond waiter to the still-owned mutex
                        // before releasing it: both registrations must survive.
                        assert_eq!(patina_cond_signal(cond as *mut _), 0);
                    }
                    assert_eq!(patina_mutex_unlock(mutex as *mut _), 0);
                    if during_handler {
                        SYNC_PHASE.store(3, Ordering::SeqCst);
                    }
                });
                unsafe {
                    if condition {
                        assert_eq!(patina_cond_wait(cond as *mut _, mutex as *mut _), 0);
                    } else {
                        delay();
                        assert_eq!(patina_mutex_lock(mutex as *mut _), 0);
                    }
                    assert_eq!(
                        lock_state().table.mutexes.get(&mutex).unwrap().owner,
                        Some(main)
                    );
                    assert_eq!(patina_mutex_unlock(mutex as *mut _), 0);
                }
                join(worker);
                assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
                unsafe {
                    assert_eq!(patina_cond_destroy(cond as *mut _), 0);
                    assert_eq!(patina_mutex_destroy(mutex as *mut _), 0);
                    drop(Box::from_raw(mutex as *mut u64));
                    drop(Box::from_raw(cond as *mut u64));
                }
            }
        }
    });
}

#[test]
fn interrupted_timed_cond_keeps_its_original_deadline() {
    isolated(|| unsafe {
        install_handler(SIGUSR1, sync_handler, 0, 0);
        let mut mutex = 0u64;
        let mut cond = 0u64;
        let mutex = (&mut mutex as *mut u64).cast();
        let cond = (&mut cond as *mut u64).cast();
        assert_eq!(patina_mutex_lock(mutex), 0);
        let main = current_task();
        let worker = spawn(move || signal_parked_sync(main, false));
        let deadline = with_context_raw(|context| context.now(ClockKind::Realtime)).unwrap() + 100;
        let time = CTimespec {
            tv_sec: (deadline / 1_000_000_000) as i64,
            tv_nsec: (deadline % 1_000_000_000) as i64,
        };
        assert_eq!(
            patina_cond_timedwait(cond, mutex, (&time as *const CTimespec).cast()),
            ETIMEDOUT
        );
        assert_eq!(
            with_context_raw(|context| context.now(ClockKind::Realtime)).unwrap(),
            deadline
        );
        assert_eq!(patina_mutex_unlock(mutex), 0);
        join(worker);
    });
}

#[test]
fn signal_after_mutex_grant_delivers_without_a_second_wake() {
    isolated(|| {
        action(false);
        let mutex = Box::into_raw(Box::new(0u64)) as usize;
        let me = current_task();
        let worker = spawn(move || unsafe {
            assert_eq!(patina_mutex_lock(mutex as *mut _), 0);
            delay();
            for _ in 0..100 {
                if parked_class(me) == Some(BlockClass::Sync) {
                    break;
                }
                sched_point().unwrap();
            }
            assert_eq!(parked_class(me), Some(BlockClass::Sync));
            assert_eq!(patina_mutex_unlock(mutex as *mut _), 0);
            generate(SIGUSR1);
            assert!(!lock_state().signals.interrupted.contains_key(&me));
        });
        delay();
        assert_eq!(unsafe { patina_mutex_lock(mutex as *mut _) }, 0);
        assert_eq!(HANDLERS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { patina_mutex_unlock(mutex as *mut _) }, 0);
        join(worker);
        unsafe {
            drop(Box::from_raw(mutex as *mut u64));
        }
    });
}

// Class pairing: deliver-and-resume Sync ownership must not absorb an inner wait.
#[test]
fn nested_pthread_wait_is_a_named_fatal_before_reparking() {
    use std::os::unix::process::ExitStatusExt;
    const DIAGNOSTIC: &str =
        "signal handler blocked on a pthread wait while interrupting one: not modeled";
    static TIMED: AtomicUsize = AtomicUsize::new(0);
    static GRANTED: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn blocking_handler(_: i32) {
        if GRANTED.load(Ordering::SeqCst) != 0 {
            for _ in 0..100 {
                if lock_state().table.threads[&current_task()].signal_resume == Some(true) {
                    break;
                }
                sched_point().unwrap();
            }
        }
        assert_eq!(
            lock_state().table.threads[&current_task()].signal_resume,
            Some(GRANTED.load(Ordering::SeqCst) != 0)
        );
        let mut mutex = 0u64;
        let mut cond = 0u64;
        unsafe {
            assert_eq!(patina_mutex_lock((&mut mutex as *mut u64).cast()), 0);
            if TIMED.load(Ordering::SeqCst) != 0 {
                let deadline = with_context_raw(|c| c.now(ClockKind::Realtime)).unwrap() + 100;
                let time = CTimespec {
                    tv_sec: (deadline / 1_000_000_000) as i64,
                    tv_nsec: (deadline % 1_000_000_000) as i64,
                };
                patina_cond_timedwait(
                    (&mut cond as *mut u64).cast(),
                    (&mut mutex as *mut u64).cast(),
                    (&time as *const CTimespec).cast(),
                );
            } else {
                patina_cond_wait(
                    (&mut cond as *mut u64).cast(),
                    (&mut mutex as *mut u64).cast(),
                );
            }
        }
        host(SYS_EXIT_GROUP, [99, 0, 0, 0, 0, 0]);
    }
    if let Ok(case) = std::env::var("PATINA_NESTED_SYNC") {
        TIMED.store(usize::from(case.contains("timed")), Ordering::SeqCst);
        GRANTED.store(usize::from(case.contains("granted")), Ordering::SeqCst);
        isolated(|| {
            install_handler(SIGUSR1, blocking_handler, 0, 0);
            let main = current_task();
            let worker = spawn(move || {
                assert_eq!(after_others_park(main), BlockClass::Sync);
                generate(SIGUSR1);
                if GRANTED.load(Ordering::SeqCst) == 0 {
                    delay(); // let the handler attempt its inner park before the grant
                }
            });
            join(worker);
        });
        return;
    }
    let mut failures = Vec::new();
    for case in ["plain", "timed", "plain-granted", "timed-granted"] {
        let output = reexec(&test_name(), &[("PATINA_NESTED_SYNC", case)]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.signal() != Some(6)
            || !stderr
                .lines()
                .any(|line| line == format!("patina native shim fatal: {DIAGNOSTIC}"))
        {
            failures.push(format!("{case}: {}: {stderr}", output.status));
        }
    }
    assert!(
        failures.is_empty(),
        "missing named nested Sync refusal:\n{}",
        failures.join("\n")
    );
}
