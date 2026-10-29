//! Tests for task scheduling, timer rescue, and schedule diagnostics.

use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::schedule::{SCAFFOLDING_YIELD_FLOOR, TaskCompletionCause};
use crate::{Context, DEFAULT_BOOT_ORIGIN_NANOS, RuntimeError};
use patina_dst_abi::{ClockKind, Operation, TaskId};

use crate::VirtualClock;
use crate::scheduler::{PctConfig, SchedulePolicy};
use patina_dst_trace::TraceBundle;

use tempfile::tempdir;

/// Drive a fixed multi-task cooperative schedule through a context, returning
/// the order in which `scheduler_next` selected tasks. Tasks all stay runnable
/// (yield, never park/complete until the end), so the policy fully controls
/// the order.
fn drive_schedule(context: &mut Context, n_workers: usize, rounds: usize) -> Vec<u64> {
    let mut workers = Vec::new();
    for index in 0..n_workers {
        workers.push(context.task_spawn(&format!("w{index}")).unwrap());
    }
    let mut order = Vec::new();
    for _ in 0..rounds {
        let task = context.scheduler_next().unwrap().unwrap();
        order.push(task.0);
        context.task_yield(task).unwrap();
    }
    drop(workers);
    // Drain: complete whatever task each decision selects until none remain.
    while let Some(task) = context.scheduler_next().unwrap() {
        context.task_complete(task).unwrap();
    }
    order
}

#[test]
fn pct_record_replay_reproduces_schedule_and_records_policy() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("pct.patina");
    let policy = SchedulePolicy {
        pct: Some(PctConfig {
            depth: 3,
            steps: 50,
        }),
    };
    let config = RuntimeConfig::record(11, &trace, "fp+pct").with_schedule_policy(policy);
    let mut record = Context::from_config(config).unwrap();
    let recorded = drive_schedule(&mut record, 4, 40);
    record.finish().unwrap();

    // The trace records the policy metadata authoritatively.
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let recorded_policy = bundle.metadata.schedule_policy.expect("policy recorded");
    assert_eq!(recorded_policy.pct.unwrap().depth, 3);

    // Replay WITHOUT re-supplying the policy reproduces the exact selection
    // order (decisions come from the recorded op-stream).
    let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp+pct")).unwrap();
    let replayed = drive_schedule(&mut replay, 4, 40);
    replay.finish().unwrap();
    assert_eq!(recorded, replayed);
    // A depth-3 PCT schedule over four always-runnable workers preempts, so
    // more than one task id appears.
    assert!(
        recorded
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1
    );
}

/// Drive the scheduler until `worker` completes, parking any other task that
/// is scheduled first and yielding the worker `yields` times before it runs
/// to completion. `yields == 0` models a worker whose whole body runs under a
/// single selection with no scheduling boundary.
fn run_worker(context: &mut Context, worker: TaskId, yields: u32) {
    let mut remaining = yields;
    loop {
        let selected = context.scheduler_next().unwrap().unwrap();
        if selected == worker {
            if remaining > 0 {
                remaining -= 1;
                context.task_yield(worker).unwrap();
            } else {
                context.task_complete(worker).unwrap();
                return;
            }
        } else {
            context.task_park(selected, "wait-for-worker").unwrap();
        }
    }
}

#[test]
fn only_a_concurrent_worker_that_never_yields_is_flagged_vacuous() {
    // RED: a spawned worker that runs from first scheduled to completion with
    // zero scheduling boundaries (like a lost-update race on an atomics-only
    // RwLock fast path) must be reported as vacuous.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let _main = context.task_spawn("main").unwrap();
    let worker = context.task_spawn("worker").unwrap();
    run_worker(&mut context, worker, 0);
    let diagnostics = context.schedule_diagnostics();
    assert!(diagnostics.had_concurrency());
    assert_eq!(diagnostics.vacuous, vec![worker]);
    let stat = diagnostics
        .tasks
        .iter()
        .find(|stat| stat.task == worker)
        .expect("worker recorded");
    assert_eq!(stat.boundaries, 0);
    assert!(stat.vacuous);

    // GREEN: a worker that clears the scaffolding floor with real scheduling
    // boundaries is explorable and must NOT be flagged.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let _main = context.task_spawn("main").unwrap();
    let worker = context.task_spawn("worker").unwrap();
    run_worker(&mut context, worker, SCAFFOLDING_YIELD_FLOOR as u32 + 1);
    let diagnostics = context.schedule_diagnostics();
    assert!(diagnostics.had_concurrency());
    assert!(diagnostics.vacuous.is_empty(), "{diagnostics:?}");

    // A run with only the initial task has no schedule to explore, so the
    // diagnostic stays silent.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let solo = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(solo));
    context.task_complete(solo).unwrap();
    let diagnostics = context.schedule_diagnostics();
    assert!(!diagnostics.had_concurrency());
    assert!(diagnostics.vacuous.is_empty());
}

#[test]
fn task_lifetime_and_completion_cause_are_annotated() {
    // A joined worker is reported `Completed` with a positive lifetime (it
    // spans at least its own spawn->complete steps); the initial thread of
    // control, still live at run end, is reported `LiveAtExit`.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let main = context.task_spawn("main").unwrap();
    let worker = context.task_spawn("worker").unwrap();
    run_worker(&mut context, worker, 2);

    let diagnostics = context.schedule_diagnostics();
    let worker_stat = diagnostics
        .tasks
        .iter()
        .find(|stat| stat.task == worker)
        .expect("worker recorded");
    assert_eq!(worker_stat.cause, TaskCompletionCause::Completed);
    assert!(
        worker_stat.lifetime > 0,
        "a completed worker spans at least one scheduling step: {worker_stat:?}"
    );

    let main_stat = diagnostics
        .tasks
        .iter()
        .find(|stat| stat.task == main)
        .expect("main recorded");
    assert_eq!(main_stat.cause, TaskCompletionCause::LiveAtExit);
}

/// Drive the runtime the way the shim does: spawn two tasks, park each with
/// a virtual-clock deadline, then let `scheduler_next` rescue the deadlock by
/// advancing time and waking the earliest-due task. Returns the observed wake
/// order and the virtual time at each wake.
fn timed_rescue(context: &mut Context) -> Result<Vec<(TaskId, u64)>, RuntimeError> {
    let start = context.now(ClockKind::Monotonic)?;
    let a = context.task_spawn("a")?;
    let b = context.task_spawn("b")?;
    // Park the first-selected task at 200 and the other at 100 so the wake
    // order is determined by deadline, not by spawn or selection order.
    let first = context.scheduler_next()?.expect("a task is runnable");
    context.task_park_timed(first, "wait", ClockKind::Monotonic, start + 200)?;
    let second = context.scheduler_next()?.expect("a task is runnable");
    context.task_park_timed(second, "wait", ClockKind::Monotonic, start + 100)?;
    let mut wakes = Vec::new();
    // Both tasks are parked; each `scheduler_next` now rescues in turn.
    for _ in 0..2 {
        let woken = context.scheduler_next()?.expect("a timer wakes a task");
        wakes.push((woken, context.now(ClockKind::Monotonic)? - start));
        context.task_complete(woken)?;
    }
    assert!(context.scheduler_next()?.is_none());
    let _ = (a, b);
    Ok(wakes)
}

#[test]
fn deadlock_rescue_advances_time_wakes_in_deadline_order_and_replays() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("timer.patina");
    let mut record = Context::from_config(RuntimeConfig::record(9, &path, "timer-v1")).unwrap();
    let wakes = timed_rescue(&mut record).unwrap();
    record.finish().unwrap();
    // The task parked at 100 wakes first at virtual time 100, then the task
    // parked at 200 wakes at 200: deadline order, not registration order.
    assert_eq!(wakes.len(), 2);
    assert_eq!(wakes[0].1, 100);
    assert_eq!(wakes[1].1, 200);
    assert_ne!(wakes[0].0, wakes[1].0);

    // Replay consumes every recorded SleepUntil/TaskWake/SchedulerNext event.
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "timer-v1")).unwrap();
    assert_eq!(timed_rescue(&mut replay).unwrap(), wakes);
    replay.finish().unwrap();
}

#[test]
fn realtime_deadlines_convert_through_the_clock_epoch() {
    // A clock whose realtime epoch is 1_000ns ahead of monotonic: a realtime
    // deadline of origin + 1_150 must rescue at monotonic origin + 150.
    let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .with_clock(VirtualClock::new(1_000))
        .build()
        .unwrap();
    let task = context.task_spawn("sleeper").unwrap();
    let running = context.scheduler_next().unwrap().unwrap();
    assert_eq!(running, task);
    context
        .task_park_timed(
            task,
            "sleep",
            ClockKind::Realtime,
            DEFAULT_BOOT_ORIGIN_NANOS + 1_150,
        )
        .unwrap();
    let woken = context.scheduler_next().unwrap().unwrap();
    assert_eq!(woken, task);
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + 150
    );
    assert_eq!(
        context.now(ClockKind::Realtime).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + 1_150
    );
    context.task_complete(task).unwrap();
    context.finish().unwrap();
}

/// Class pairing: the signals-family wake-order and timer-rescue obligations.
#[test]
fn signal_wake_records_task_wake_before_scheduler_next() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("signal-wake.patina");
    fn drive(mut context: Context) {
        let task = context.task_spawn("signal waiter").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        context.task_park(task, "pause").unwrap();
        context.task_wake(task).unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        context.task_complete(task).unwrap();
        context.finish().unwrap();
    }
    drive(Context::from_config(RuntimeConfig::record(1, &path, "signal-wake")).unwrap());
    let bundle = TraceBundle::load(&path).unwrap();
    let ops: Vec<_> = bundle.timelines[0]
        .decisions
        .iter()
        .map(|event| &event.operation)
        .collect();
    let park = ops
        .iter()
        .position(|op| matches!(op, Operation::TaskPark { .. }))
        .unwrap();
    assert!(matches!(ops[park + 1], Operation::TaskWake { .. }));
    assert!(matches!(ops[park + 2], Operation::SchedulerNext));
    drive(Context::from_config(RuntimeConfig::replay(&path, "signal-wake")).unwrap());
}

#[test]
fn early_signal_wake_deregisters_timed_sleep() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let a = context.task_spawn("a").unwrap();
    let b = context.task_spawn("b").unwrap();
    // `a` parks with an early deadline, then is woken by a "signal" before it
    // fires; only `b`'s later timer should drive a rescue.
    let first = context.scheduler_next().unwrap().unwrap();
    context
        .task_park_timed(
            first,
            "wait",
            ClockKind::Monotonic,
            DEFAULT_BOOT_ORIGIN_NANOS + 50,
        )
        .unwrap();
    let second = context.scheduler_next().unwrap().unwrap();
    context
        .task_park_timed(
            second,
            "wait",
            ClockKind::Monotonic,
            DEFAULT_BOOT_ORIGIN_NANOS + 500,
        )
        .unwrap();
    // Signal-wake `first` (deregisters its 50ns timer). It must not be woken
    // again by the rescue, which should advance straight to 500 for `second`.
    context.task_wake(first).unwrap();
    let resumed = context.scheduler_next().unwrap().unwrap();
    assert_eq!(
        resumed, first,
        "the signalled task runs without advancing time"
    );
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS
    );
    context.task_park(first, "again").unwrap();
    let rescued = context.scheduler_next().unwrap().unwrap();
    assert_eq!(rescued, second);
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + 500
    );
    let _ = (a, b);
}

#[test]
fn a_timed_park_whose_deadline_passed_expires_beside_a_runnable_peer() {
    // Class pairing: `expire_due_timers` runs at registration as well as at
    // every clock advance, so the registry never holds a reached deadline and
    // no expiry waits for every task to park (the deadlock rescue).
    let mut context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
    let peer = context.task_spawn("peer").unwrap();
    let waiter = context.task_spawn("waiter").unwrap();
    while context.scheduler_next().unwrap() != Some(waiter) {
        context.task_yield(peer).unwrap();
    }
    let now = context.now(ClockKind::Monotonic).unwrap();
    for deadline in [now, now - 1] {
        context
            .task_park_timed(waiter, "sleep", ClockKind::Monotonic, deadline)
            .unwrap();
        // The runnable peer does not hold the expiry back: the waiter is
        // selectable again without virtual time moving.
        let mut picked = Vec::new();
        for _ in 0..64 {
            let task = context.scheduler_next().unwrap().unwrap();
            picked.push(task);
            if task == waiter {
                break;
            }
            context.task_yield(task).unwrap();
        }
        assert_eq!(
            picked.last(),
            Some(&waiter),
            "expired waiter never ran: {picked:?}"
        );
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), now);
        assert_eq!(context.take_expired_timeouts(), vec![waiter]);
        assert!(!context.has_future_deadline(waiter));
    }
    // A future deadline stays registered until virtual time reaches it.
    context
        .task_park_timed(waiter, "sleep", ClockKind::Monotonic, now + 10)
        .unwrap();
    assert!(context.take_expired_timeouts().is_empty());
    assert!(context.has_future_deadline(waiter));
}
