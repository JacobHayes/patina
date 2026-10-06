//! Tests for progress watchdogs, spin rescue, cpu time, and compute stops.

use crate::config::{LivenessConfig, RuntimeConfig};
use crate::custom_op::CustomOpMode;
use crate::liveness::{
    LivenessKind, SPIN_CHURN_ABORT_RESCUES, SPIN_RESCUE_CLOCK_OPS, SPIN_RESCUE_TOKEN_MIN_NANOS,
    WatchdogArm, operation_is_progress,
};
use crate::{Context, DEFAULT_BOOT_ORIGIN_NANOS, FACTS_SCHEMA, RuntimeError};
use patina_dst_abi::{ClockKind, Fd, Operation, TaskId};

use patina_dst_trace::{BranchSession, Replayer, TraceBundle};
use std::fs;

use tempfile::tempdir;

/// The calibration busy-wait, reduced to its essence: read the monotonic
/// clock in a loop until `window` nanoseconds of it have gone by, doing
/// nothing else. This is the shape `fastant`/`minstant`/`quanta` run in a
/// pre-`main` constructor to measure the timestamp counter, and the shape
/// that hangs forever without advance-on-spin. Returns (reads, elapsed).
fn calibration_spin(context: &mut Context, window: u64) -> Result<(u64, u64), RuntimeError> {
    let start = context.now(ClockKind::Monotonic)?;
    let mut reads = 1u64;
    loop {
        let now = context.now(ClockKind::Monotonic)?;
        reads += 1;
        if now - start > window {
            return Ok((reads, now - start));
        }
    }
}

#[test]
fn advance_on_spin_converges_a_clock_busy_wait_in_tens_of_rescues() {
    // RED before advance-on-spin: this call never returns — virtual time only
    // moved through a recorded `SleepUntil`, and the loop issues none.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let (reads, elapsed) = calibration_spin(&mut context, 10_000_000).unwrap();

    // The token schedule pinned exactly (1 µs doubling to the 1 ms ceiling):
    // ten escalating rescues sum to 1_023_000 ns, then nine at the ceiling
    // carry the rest — 19 rescues for a 10 ms window, which is the brief's
    // "tens of rescues, not millions of loop iterations".
    assert_eq!(context.spin.rescues, 19);
    assert_eq!(elapsed, 10_023_000);
    assert_eq!(context.spin.advanced_nanos, 10_023_000);
    // Each rescue costs exactly `SPIN_RESCUE_CLOCK_OPS` reads, and the read
    // that observes the escaped deadline is the one that triggers the last.
    assert_eq!(reads, 19 * SPIN_RESCUE_CLOCK_OPS + 1);
    // Trace-size sanity: the recorded stream is one op per read plus one
    // `SleepUntil` per rescue, three orders of magnitude under the cap.
    assert!(reads + context.spin.rescues < patina_dst_trace::MAX_TIMELINE_EVENTS as u64);
    context.finish().unwrap();
}

#[test]
fn advance_on_spin_leaves_virtual_time_alone_below_the_trigger() {
    // The non-vacuity guard for the constant: one read short of the streak
    // must not move the clock by a nanosecond. This is what keeps every
    // existing recorded artifact byte-identical.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..SPIN_RESCUE_CLOCK_OPS {
        assert_eq!(
            context.now(ClockKind::Monotonic).unwrap(),
            DEFAULT_BOOT_ORIGIN_NANOS
        );
    }
    assert_eq!(context.spin.rescues, 0);
    // One more read crosses the streak and rescues.
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + SPIN_RESCUE_TOKEN_MIN_NANOS
    );
    assert_eq!(context.spin.rescues, 1);
    context.finish().unwrap();
}

#[test]
fn a_progress_op_ends_the_spin_episode_so_a_working_run_never_rescues() {
    // A guest that reads the clock hard but keeps doing real work: the
    // streak is broken by every genuine effect, so it never accumulates and
    // the clock never moves. An unbounded number of reads, zero rescues.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..8 {
        for _ in 0..SPIN_RESCUE_CLOCK_OPS {
            assert_eq!(
                context.now(ClockKind::Monotonic).unwrap(),
                DEFAULT_BOOT_ORIGIN_NANOS
            );
        }
        context.write_file("/work", b"x").unwrap();
    }
    assert_eq!(context.spin.rescues, 0);
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS
    );
    context.finish().unwrap();
}

#[test]
fn a_guest_sleep_ends_the_spin_episode_so_a_polling_loop_never_rescues() {
    // The other reset arm: virtual time moving for a reason the rescue did
    // not cause. A poll loop that sleeps between reads walks the clock on its
    // own and must never be rescued, however many reads it takes.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..4 {
        // One short of the streak, leaving room for `sleep_for`'s own
        // clock read: 1023 reads plus that one is exactly at the trigger,
        // not past it.
        for _ in 0..(SPIN_RESCUE_CLOCK_OPS - 1) {
            context.now(ClockKind::Monotonic).unwrap();
        }
        context.sleep_for(1).unwrap();
    }
    assert_eq!(context.spin.rescues, 0);
    // Exactly the four nanoseconds the guest itself slept.
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + 4
    );
    context.finish().unwrap();
}

#[test]
fn cpu_time_is_the_spin_rescues_charged_to_the_baton_holder() {
    // A sleep moves virtual time but computes nothing; a busy-wait computes
    // through every advance-on-spin rescue.
    // The process starts at its modeled startup cost, and a sleep moves
    // virtual time without charging it.
    const STARTUP: u64 = patina_dst_abi::STARTUP_CPU_NANOS;
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    assert_eq!(context.cpu_time_nanos(), STARTUP);
    context.sleep_for(5_000_000).unwrap();
    assert_eq!(context.cpu_time_nanos(), STARTUP);
    let (_, elapsed) = calibration_spin(&mut context, 10_000_000).unwrap();
    assert_eq!(context.cpu_time_nanos(), STARTUP + elapsed);
    // Before the embedder schedules a task, the main thread is `None`.
    assert_eq!(context.task_cpu_time_nanos(None), STARTUP + elapsed);
    let task = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(task));
    let (_, more) = calibration_spin(&mut context, 1_000_000).unwrap();
    assert_eq!(context.task_cpu_time_nanos(Some(task)), more);
    assert_eq!(context.cpu_time_nanos(), STARTUP + elapsed + more);
    context.finish().unwrap();
}

#[test]
fn the_spin_rescue_stops_at_an_alarm() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    context.set_alarm(Some(DEFAULT_BOOT_ORIGIN_NANOS + 1_500));
    // 1 µs, then the doubled 2 µs token is clamped to the alarm at 1.5 µs.
    let (_, elapsed) = calibration_spin(&mut context, 1_000).unwrap();
    assert_eq!(elapsed, 1_500);
    context.finish().unwrap();
}

/// Spin on the clock until `cpu` nanoseconds of CPU time are charged;
/// the rescues it took.
fn spin_for_cpu(context: &mut Context, cpu: u64) -> u64 {
    let start = context.cpu_time_nanos();
    while context.cpu_time_nanos() - start < cpu {
        context.now(ClockKind::Monotonic).unwrap();
    }
    context.spin.rescues
}

#[test]
fn a_cpu_alarm_is_reached_in_whole_rescues_without_the_ramp() {
    // An 11 ms CPU-time timer. Without an alarm the ramp takes ten
    // escalating rescues (1.023 ms) and ten more at the ceiling; toward a
    // declared CPU deadline each rescue is the ceiling or what is left,
    // and the last lands on the deadline exactly.
    const DEADLINE: u64 = 11_000_000;
    let mut ramp = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    assert_eq!(spin_for_cpu(&mut ramp, DEADLINE), 20);
    ramp.finish().unwrap();
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let start = context.cpu_time_nanos();
    context.set_cpu_alarm(Some(DEADLINE - 500_000));
    assert_eq!(spin_for_cpu(&mut context, DEADLINE - 500_000), 11);
    assert_eq!(context.cpu_time_nanos() - start, DEADLINE - 500_000);
    context.finish().unwrap();
}

#[test]
fn idle_time_advances_to_an_alarm_ahead_of_every_parked_deadline() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let task = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(task));
    // A runnable task: nothing is idle.
    let start = context.now(ClockKind::Monotonic).unwrap();
    assert!(!context.advance_idle_to(start + 100).unwrap());
    context
        .task_park_timed(task, "wait", ClockKind::Monotonic, start + 300)
        .unwrap();
    assert!(context.advance_idle_to(start + 100).unwrap());
    assert_eq!(context.now(ClockKind::Monotonic).unwrap() - start, 100);
    // Not behind the clock, not at or past a parked task's own deadline.
    assert!(!context.advance_idle_to(start + 100).unwrap());
    assert!(!context.advance_idle_to(start + 300).unwrap());
    // The parked task's deadline stays the deadlock rescue's.
    assert_eq!(context.scheduler_next().unwrap(), Some(task));
    assert_eq!(context.now(ClockKind::Monotonic).unwrap() - start, 300);
    context.finish().unwrap();
}

#[test]
fn advance_on_spin_records_and_replays_byte_identically() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("spin-a.patina");
    let second = directory.path().join("spin-b.patina");
    let mut recorded = Vec::new();
    for path in [&first, &second] {
        let mut record = Context::from_config(RuntimeConfig::record(9, path, "spin-v1")).unwrap();
        recorded.push(calibration_spin(&mut record, 100_000).unwrap());
        record.finish().unwrap();
    }
    // Same seed, two independent record runs: identical answers and bytes.
    assert_eq!(recorded[0], recorded[1]);
    assert_eq!(recorded[0].0, 7 * SPIN_RESCUE_CLOCK_OPS + 1);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    // Replay consumes the recorded `SleepUntil`/`ClockNow` stream in order:
    // the rescue re-fires at the same point because the spin state is a pure
    // function of that stream, not of anything the record run measured.
    let mut replay = Context::from_config(RuntimeConfig::replay(&first, "spin-v1")).unwrap();
    assert_eq!(calibration_spin(&mut replay, 100_000).unwrap(), recorded[0]);
    replay.finish().unwrap();
}

#[test]
fn compute_watchdog_uses_runnable_peers_not_live_tasks() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    assert_eq!(context.compute_watchdog_candidate(), None);
    let main = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(main));
    assert_eq!(context.compute_watchdog_candidate(), None);
    let peer = context.task_spawn("peer").unwrap();
    assert_eq!(
        context.compute_watchdog_candidate(),
        Some((context.steps(), main))
    );
    context.task_park(main, "condition").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(peer));
    assert_eq!(context.compute_watchdog_candidate(), None);
    context.task_wake(main).unwrap();
    assert_eq!(
        context.compute_watchdog_candidate(),
        Some((context.steps(), peer))
    );
    context.task_complete(peer).unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(main));
    assert_eq!(context.compute_watchdog_candidate(), None);
}

#[test]
fn compute_stop_emits_a_structured_runtime_limit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("compute-facts.json");
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_facts_path(&path)).unwrap();
    let task = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(task));
    context.task_spawn("runnable peer").unwrap();
    let steps = context.steps();
    assert_eq!(context.compute_watchdog_candidate(), Some((steps, task)));
    // No claim about what the baton holder is doing outside the boundary:
    // computation and untracked host blocking have the same runtime state.
    assert!(matches!(
        context.stop_compute_bound(task),
        RuntimeError::ComputeBound { task: stopped, steps: at }
            if stopped == task && at == steps
    ));
    let facts: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        facts,
        serde_json::json!({
            "schema": FACTS_SCHEMA,
            "runtime_findings": [{
                "source": "liveness", "kind": "liveness", "detail": "compute-bound",
                "known_limit": true, "task": task.0, "steps": steps,
            }],
        })
    );
    assert_eq!(context.steps(), steps);
}

#[test]
fn branch_sessions_do_not_arm_the_host_compute_detector() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("branch-compute.patina");
    let setup = |ctx: &mut Context| {
        let main = ctx.task_spawn("main").unwrap();
        assert_eq!(ctx.scheduler_next().unwrap(), Some(main));
        ctx.task_spawn("peer").unwrap();
    };
    let mut record =
        Context::from_config(RuntimeConfig::record(1, &path, "branch-compute-v1")).unwrap();
    setup(&mut record);
    assert!(record.compute_watchdog_candidate().is_some());
    record.finish().unwrap();
    let mut branch = Context::from_config(RuntimeConfig::branch(
        &path,
        "main",
        0,
        "branch",
        2,
        "branch-compute-v1",
    ))
    .unwrap();
    setup(&mut branch);
    assert!(branch.compute_watchdog_candidate().is_none());
}

#[test]
fn compute_stop_inside_an_open_custom_op_replays_only_the_committed_prefix() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("custom-compute.patina");
    let setup = |context: &mut Context| {
        let main = context.task_spawn("main").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(main));
        context.task_spawn("peer").unwrap();
        main
    };
    let mut record =
        Context::from_config(RuntimeConfig::record(1, &path, "custom-compute-v1")).unwrap();
    let main = setup(&mut record);
    let committed = record.steps();
    assert_eq!(
        record.custom_op_begin("perform", b"key", false).unwrap(),
        CustomOpMode::Record
    );
    assert_eq!(record.steps(), committed + 1);
    let stop = record.stop_compute_bound(main);
    let bundle = TraceBundle::load(&path).unwrap();
    assert_eq!(bundle.metadata.compute_stop.unwrap().steps, committed);
    assert_eq!(
        bundle.resolved_timeline("main").unwrap().len() as u64,
        committed
    );
    assert!(matches!(stop, RuntimeError::ComputeBound { steps, .. } if steps == committed));
    assert!(
        matches!(record.finish(), Err(RuntimeError::ComputeBound { steps, .. }) if steps == committed)
    );
    for finish in [false, true] {
        let mut replay =
            Context::from_config(RuntimeConfig::replay(&path, "custom-compute-v1")).unwrap();
        assert_eq!(setup(&mut replay), main);
        let error = if finish {
            replay.finish().unwrap_err()
        } else {
            // No outcome exists for this begin. The terminal fact must win
            // before Replayer::expect can request it (or perform can run).
            replay
                .custom_op_begin("perform", b"key", false)
                .unwrap_err()
        };
        assert!(
            matches!(error, RuntimeError::ComputeBound { task, steps } if task == main && steps == committed)
        );
    }
}

#[test]
fn compute_stop_replay_cannot_cross_the_recorded_prefix_or_finish_successfully() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("compute.patina");
    let setup = |context: &mut Context| {
        let main = context.task_spawn("main").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(main));
        context.task_spawn("peer").unwrap();
        main
    };
    let mut record = Context::from_config(RuntimeConfig::record(1, &path, "compute-v1")).unwrap();
    let task = setup(&mut record);
    let steps = record.steps();
    assert!(
        matches!(record.stop_compute_bound(task), RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == task && at == steps)
    );
    let original = fs::read(&path).unwrap();
    // The append-only native sink relies on exactly one flush.
    record.stop_compute_bound(task);
    assert_eq!(original, fs::read(&path).unwrap());
    for finish in [false, true] {
        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "compute-v1")).unwrap();
        assert_eq!(replay.compute_watchdog_candidate(), None);
        assert_eq!(setup(&mut replay), task);
        assert_eq!(
            replay.replay_compute_stop_due(),
            Some(patina_dst_trace::ComputeStop { task, steps })
        );
        let error = if finish {
            replay.finish().unwrap_err()
        } else {
            replay.task_yield(task).unwrap_err()
        };
        assert!(
            matches!(error, RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == task && at == steps)
        );
    }
    let mut wrong_task = TraceBundle::load(&path).unwrap();
    wrong_task.metadata.compute_stop.as_mut().unwrap().task = TaskId(99);
    let wrong_path = directory.path().join("wrong-task.patina");
    wrong_task.write_atomic(&wrong_path).unwrap();
    let mut replay =
        Context::from_config(RuntimeConfig::replay(&wrong_path, "compute-v1")).unwrap();
    setup(&mut replay);
    assert!(matches!(
        replay.finish(),
        Err(RuntimeError::ComputeStopState)
    ));
    let mut bundle = TraceBundle::load(&path).unwrap();
    bundle.metadata.compute_stop.as_mut().unwrap().steps += 1;
    assert!(Replayer::from_bundle(bundle, "compute-v1", "main").is_err());
    assert!(BranchSession::open(&path, "compute-v1", "main", 1, "branch", 2).is_err());
}

#[test]
fn frozen_clock_churn_aborts_a_loop_that_ignores_the_clock() {
    // A loop whose exit condition never depends on the clock value it reads:
    // no amount of advancing frees it, so the backstop must name it rather
    // than rescue it forever.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let mut reads = 0u64;
    let error = loop {
        match context.now(ClockKind::Monotonic) {
            Ok(_) => reads += 1,
            Err(error) => break error,
        }
    };
    let RuntimeError::FrozenClockChurn { detail } = error else {
        panic!("expected a frozen-clock-churn abort, got {error:?}");
    };
    // The marker rides the established liveness interface contract, so a
    // campaign consumer classifies it without a new rule, and names the
    // pattern and what the guest was doing.
    assert!(detail.starts_with("PATINA_VIOLATION liveness detail=frozen-clock-churn "));
    assert!(detail.contains(&format!("rescues={SPIN_CHURN_ABORT_RESCUES}")));
    // Ten escalating tokens (1_023_000 ns) plus 246 at the 1 ms ceiling.
    assert!(
        detail.contains("advanced_ns=247023000"),
        "marker was: {detail}"
    );
    assert_eq!(context.spin.rescues, SPIN_CHURN_ABORT_RESCUES);
    // The abort fires only once the spin PERSISTS past the last rescue:
    // a full further streak of reads bought nothing.
    assert_eq!(
        reads,
        (SPIN_CHURN_ABORT_RESCUES + 1) * SPIN_RESCUE_CLOCK_OPS
    );
    // The facts document carries the same finding as the line.
    let finding = &context.run_facts()["runtime_findings"][0];
    assert_eq!(finding["detail"], "frozen-clock-churn");
    assert_eq!(finding["rescues"], SPIN_CHURN_ABORT_RESCUES);
}

#[test]
fn the_liveness_watchdog_fires_first_on_a_spin_that_advance_on_spin_feeds() {
    // Before this slice the watchdog structurally could not fire on a clock
    // spin: its no-progress window is measured in virtual nanoseconds, and
    // virtual time did not move. Now the rescue feeds it, so a budget the
    // rescues walk past trips it — and it trips FIRST, long before the
    // frozen-clock backstop's 256 rescues. One mechanism, cleanly.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
            no_progress_budget_nanos: Some(5_000),
            converge_budget_nanos: None,
            heal_after_nanos: None,
        }))
        .unwrap();
    let error = loop {
        if let Err(error) = context.now(ClockKind::Monotonic) {
            break error;
        }
    };
    let RuntimeError::Liveness { kind, detail } = error else {
        panic!("expected the liveness watchdog to fire first, got {error:?}");
    };
    assert_eq!(kind, LivenessKind::NoProgress);
    assert!(detail.starts_with("PATINA_VIOLATION liveness detail=no-progress "));
    // Fired at the third rescue (1+2+4 = 7 µs past a 5 µs budget), so the
    // churn backstop was nowhere near its own trigger.
    assert_eq!(context.spin.rescues, 3);
    assert!(context.spin.rescues < SPIN_CHURN_ABORT_RESCUES);
}

// -- Liveness watchdog --------------------------------------------------

#[test]
fn operation_progress_classification_is_correct() {
    // Pure scheduling/time/wait ops are non-progress; genuine effects are.
    assert!(!operation_is_progress(&Operation::SchedulerNext));
    assert!(!operation_is_progress(&Operation::ClockNow {
        clock: ClockKind::Monotonic
    }));
    assert!(!operation_is_progress(&Operation::SleepUntil {
        clock: ClockKind::Monotonic,
        deadline_nanos: 1
    }));
    assert!(!operation_is_progress(&Operation::TaskParkTimed {
        task: TaskId(1),
        reason: "x".into(),
        deadline_nanos: 1
    }));
    assert!(operation_is_progress(&Operation::FsWrite {
        fd: Fd(1),
        bytes: vec![1]
    }));
    assert!(operation_is_progress(&Operation::TaskComplete {
        task: TaskId(1)
    }));
    assert!(operation_is_progress(&Operation::EntropyFill { len: 4 }));
}

#[test]
fn watchdog_arm_excuses_policy_deferral_windows() {
    // The CRITICAL COUPLING: while the scheduler reports a deliberate
    // deferral, no-progress must NOT accrue toward the budget — a starvation
    // interval or PCT priority deferral is never a liveness violation.
    let mut arm = WatchdogArm {
        kind: LivenessKind::NoProgress,
        arm_time_nanos: 0,
        budget_nanos: 1_000,
        armed: false,
        baseline_nanos: 0,
        stall_ops: 0,
    };
    // Virtual time races far past the budget, but every step is a policy
    // deferral, so the arm never fires and the baseline keeps advancing.
    for now in [500u64, 1_000, 5_000, 50_000, 500_000] {
        assert!(arm.observe(now, false, true).is_none());
    }
    // Once deferral stops, genuine no-progress accrues from the current time
    // and eventually trips the budget.
    assert!(arm.observe(500_500, false, false).is_none()); // stall 1
    assert!(arm.observe(501_000, false, false).is_none()); // stall 2
    assert!(arm.observe(501_400, false, false).is_none()); // stall 3
    // stall 4 and elapsed (501_600-500_000=1_600) > 1_000 -> fire.
    assert!(arm.observe(501_600, false, false).is_some());
}

#[test]
fn watchdog_arm_ignores_a_single_long_but_legitimate_sleep() {
    // One huge no-progress jump (a single legitimate sleep) must not trip the
    // watchdog: only genuine churn (>= LIVENESS_MIN_STALL_OPS non-progress
    // ops) can. A progress op then resets the clock.
    let mut arm = WatchdogArm {
        kind: LivenessKind::NoProgress,
        arm_time_nanos: 0,
        budget_nanos: 1_000,
        armed: false,
        baseline_nanos: 0,
        stall_ops: 0,
    };
    // A single sleep past the budget: only one stall op, below the floor.
    assert!(arm.observe(1_000_000, false, false).is_none());
    // Genuine progress resets.
    assert!(arm.observe(1_000_001, true, false).is_none());
    assert_eq!(arm.stall_ops, 0);
}

#[test]
fn liveness_watchdog_fires_on_virtual_time_no_progress_wedge() {
    // A single-task loop that only advances the virtual clock (sleep) with no
    // genuine effect is a pure-churn wedge: the watchdog fires deterministically
    // rather than letting virtual time march to a step budget silently.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
            no_progress_budget_nanos: Some(1_000),
            converge_budget_nanos: None,
            heal_after_nanos: None,
        }))
        .unwrap();
    let mut fired = None;
    for _ in 0..1_000 {
        if let Err(error) = context.sleep_for(500) {
            fired = Some(error);
            break;
        }
    }
    match fired {
        Some(RuntimeError::Liveness { kind, .. }) => {
            assert_eq!(kind, LivenessKind::NoProgress);
        }
        other => panic!("expected a liveness violation, got {other:?}"),
    }
}

#[test]
fn heal_then_converge_only_arms_after_the_fault_window() {
    // The converge arm arms at H (here 5_000 ns) and must not fire before then,
    // even though the guest is already wedged; after H it enforces the
    // convergence budget and fires.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
            no_progress_budget_nanos: None,
            converge_budget_nanos: Some(1_000),
            heal_after_nanos: Some(5_000),
        }))
        .unwrap();
    let mut fired_at_iter = None;
    for iteration in 0..1_000 {
        if let Err(RuntimeError::Liveness { kind, .. }) = context.sleep_for(500) {
            assert_eq!(kind, LivenessKind::HealThenConverge);
            fired_at_iter = Some(iteration);
            break;
        }
    }
    // sleep_for advances 500 ns/iteration, so ~10 iterations to reach H=5_000
    // and ~2 more (plus the min-stall floor) before the 1_000 ns budget trips.
    let fired = fired_at_iter.expect("converge watchdog must fire");
    assert!(
        fired >= 10,
        "must not fire before the fault window (H): {fired}"
    );
}

#[test]
fn liveness_watchdog_does_not_fire_on_a_run_that_makes_progress() {
    // A run that keeps doing genuine effects (writes) between sleeps never
    // trips the watchdog: each write resets the no-progress clock.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
            no_progress_budget_nanos: Some(1_000),
            converge_budget_nanos: None,
            heal_after_nanos: None,
        }))
        .unwrap();
    for index in 0..50 {
        context
            .write_file(&format!("/f{index}"), b"progress")
            .unwrap();
        context.sleep_for(10_000).unwrap();
    }
    context.finish().unwrap();
}

#[test]
fn liveness_watchdog_is_schedule_invariant_when_no_violation_fires() {
    // The schedule-invariance proof: recording a healthy run with the watchdog
    // enabled produces a byte-identical recorded op stream to recording it
    // without. The watchdog only ADDS a possible report; it never records a
    // boundary op nor perturbs selection. The metadata differs only by the
    // informational (non-fingerprinted) watchdog field.
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.patina");
    let watched = dir.path().join("watched.patina");
    let run = |path: &std::path::Path, liveness: LivenessConfig| {
        let mut context = Context::from_config(
            RuntimeConfig::record(7, path, "wd-invariance-v1").with_liveness(liveness),
        )
        .unwrap();
        context.write_file("/f", b"hello").unwrap();
        context.sleep_for(1_000).unwrap();
        let _ = context.read_file("/f").unwrap();
        context.finish().unwrap();
    };
    run(&plain, LivenessConfig::default());
    run(
        &watched,
        LivenessConfig {
            no_progress_budget_nanos: Some(10_000_000_000),
            converge_budget_nanos: Some(10_000_000_000),
            heal_after_nanos: None,
        },
    );
    let a = TraceBundle::load(&plain).unwrap();
    let b = TraceBundle::load(&watched).unwrap();
    assert_eq!(
        a.timelines, b.timelines,
        "the watchdog must not perturb the recorded op stream"
    );
    assert!(a.metadata.watchdog.is_none());
    let record = b.metadata.watchdog.expect("watchdog recorded");
    assert_eq!(record.no_progress_budget_nanos, Some(10_000_000_000));
    assert_eq!(record.converge_budget_nanos, Some(10_000_000_000));
    // Fingerprint is unchanged by the watchdog (schedule-invariant).
    assert_eq!(a.metadata.fingerprint, b.metadata.fingerprint);
}

#[test]
fn watchdog_config_is_recorded_and_replay_ignores_it() {
    // A watchdog trace replays against a build with no watchdog (informational
    // metadata, not reconciled fail-closed) — the op stream is authoritative.
    let dir = tempdir().unwrap();
    let path = dir.path().join("wd.patina");
    {
        let mut context = Context::from_config(
            RuntimeConfig::record(3, &path, "wd-replay-v1").with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(1_000_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }),
        )
        .unwrap();
        context.write_file("/f", b"data").unwrap();
        context.finish().unwrap();
    }
    // Replay with NO watchdog configured: must succeed (config not reconciled).
    // Re-issue the same recorded op stream (the write).
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "wd-replay-v1")).unwrap();
    replay.write_file("/f", b"data").unwrap();
    replay.finish().unwrap();
}
