//! Class pairing: one CPU charge per guest call (`crate::charge`), attributed
//! to the calling thread's task, never for time parked, never in teardown.
use super::signals::tests::{isolated, join, spawn, task_of};
use super::*;
use patina_dst_abi::{ChargeClass, CpuCharge, STARTUP_CPU_CHARGE};

/// The charge `task` has, after this thread's counted calls are handed over.
fn charged(task: Option<TaskId>) -> CpuCharge {
    with_context_raw(|context| Ok(context.cpu_charge(task))).unwrap()
}

/// One clock-class door call: a monotonic read.
fn read_clock() {
    let mut now = 0;
    assert_eq!(unsafe { crate::patina_clock_now(1, &mut now) }, 0);
}

fn plus(base: CpuCharge, class: ChargeClass, calls: u64) -> CpuCharge {
    let cost = class.cost();
    CpuCharge::new(
        base.user_ns + cost.user_ns * calls,
        base.system_ns + cost.system_ns * calls,
    )
}

#[test]
fn the_startup_work_stays_with_the_thread_before_any_task() {
    isolated(|| {
        read_clock();
        assert_eq!(charged(None), STARTUP_CPU_CHARGE);
        assert_ne!(charged(Some(current_task())), CpuCharge::default());
    });
}

#[test]
fn a_door_is_charged_once_by_its_class_and_parking_costs_nothing() {
    isolated(|| {
        let me = Some(current_task());
        let before = charged(me);
        // A clock read is a clock-class door: one charge, whatever it calls
        // inside (a scheduling point, the runtime's recorded read).
        read_clock();
        let after_read = charged(me);
        assert_eq!(after_read, plus(before, ChargeClass::Clock, 1));
        // An hour asleep is one system call: virtual time parked is no CPU.
        let now = with_context_raw(|context| context.monotonic_now_unrecorded()).unwrap();
        assert_eq!(crate::patina_sleep_until(1, now + 3_600_000_000_000), 0);
        assert_eq!(charged(me), plus(after_read, ChargeClass::Syscall, 1));
    });
}

#[test]
fn a_threads_calls_are_charged_to_its_own_task() {
    isolated(|| {
        let me = Some(current_task());
        let worker = spawn(|| {
            for _ in 0..10 {
                read_clock();
            }
            // Flush this thread's calls into its own task.
            let _ = charged(None);
        });
        let task = task_of(worker);
        let before_join = charged(me);
        join(worker);
        // The join is the main thread's only call meanwhile.
        assert_eq!(charged(me), plus(before_join, ChargeClass::Syscall, 1));
        assert_eq!(
            charged(Some(task)),
            plus(CpuCharge::default(), ChargeClass::Clock, 10)
        );
    });
}

#[test]
fn every_charge_lands_on_a_reserved_task() {
    // The installing thread's task is reserved at install and every spawned
    // task at spawn: nothing is charged to an entry that would have to be
    // allocated (charging may run in a signal handler).
    isolated(|| {
        let worker = spawn(read_clock);
        join(worker);
        read_clock();
        let facts = with_context_raw(|context| Ok(context.run_facts())).unwrap();
        assert!(facts["cpu_charges"].get("unreserved").is_none(), "{facts}");
    });
}

#[test]
fn teardown_calls_are_not_charged() {
    isolated(|| {
        let me = Some(current_task());
        let before = charged(me);
        note_main_returned();
        for _ in 0..10 {
            read_clock();
        }
        assert_eq!(charged(me), before);
    });
}
