//! Tests for progress watchdogs, poll escalation, charged time, and compute
//! stops.

use crate::config::{LivenessConfig, RuntimeConfig};
use crate::custom_op::CustomOpMode;
use crate::liveness::{
    CHURN_ABORT_ESCALATIONS, ESCALATION_POLLS, ESCALATION_TOKEN_MIN_NANOS, LivenessKind, Progress,
    WatchdogArm, outcome_is_progress, progress_of,
};
use crate::{Context, CpuAlarms, DEFAULT_BOOT_ORIGIN_NANOS, FACTS_SCHEMA, RuntimeError};
use patina_dst_abi::{
    ChargeClass, ChargeCounts, ClockKind, CpuCharge, Datagram, EffectError, ErrorCode, Fd,
    Operation, Outcome, STARTUP_CPU_CHARGE, SocketId, TaskId, TcpAccepted,
};

use patina_dst_trace::{BranchSession, Replayer, TraceBundle};
use std::fs;

use tempfile::tempdir;

/// The calibration busy-wait, reduced to its essence: read the monotonic
/// clock in a loop until `window` nanoseconds of it have gone by, doing
/// nothing else. This is the shape `fastant`/`minstant`/`quanta` run in a
/// pre-`main` constructor to measure the timestamp counter, and the shape
/// that hangs forever without escalation (this embedder charges no calls of
/// its own). Returns (reads, elapsed).
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

/// `calls` calls of `class`.
fn calls(class: ChargeClass, calls: u64) -> ChargeCounts {
    let mut counts = ChargeCounts::new();
    counts.add(class, calls);
    counts
}

#[test]
fn escalation_converges_a_clock_busy_wait_in_tens_of_escalations() {
    // RED without escalation: this call never returns. The loop makes no
    // call that is charged, so nothing else moves the clock.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let (reads, elapsed) = calibration_spin(&mut context, 10_000_000).unwrap();

    // The token schedule pinned exactly (1 µs doubling to the 1 ms ceiling):
    // ten escalating tokens sum to 1_023_000 ns, then nine at the ceiling
    // carry the rest: 19 escalations for a 10 ms window, tens of them, not
    // millions of loop iterations.
    assert_eq!(context.spin.escalations, 19);
    assert_eq!(elapsed, 10_023_000);
    assert_eq!(context.spin.charged_nanos, 10_023_000);
    // Each escalation takes exactly `ESCALATION_POLLS` reads, and the read
    // after the last observes the escaped window.
    assert_eq!(reads, 19 * ESCALATION_POLLS + 1);
    // The escalated reads are clock calls: user time, charged to the main
    // thread before any task.
    let charged = context.cpu_charge(None);
    assert_eq!(charged.user_ns - STARTUP_CPU_CHARGE.user_ns, elapsed);
    assert_eq!(charged.system_ns, STARTUP_CPU_CHARGE.system_ns);
    // Nothing is recorded but the reads themselves.
    assert!(reads < patina_dst_trace::MAX_TIMELINE_EVENTS as u64);
    context.finish().unwrap();
}

#[test]
fn escalation_leaves_virtual_time_alone_below_the_trigger() {
    // The non-vacuity guard for the constant: the polls of one streak all
    // observe the same time, and only the poll that completes it is
    // escalated, after its own observation.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..ESCALATION_POLLS {
        assert_eq!(
            context.now(ClockKind::Monotonic).unwrap(),
            DEFAULT_BOOT_ORIGIN_NANOS
        );
    }
    assert_eq!(context.spin.escalations, 1);
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + ESCALATION_TOKEN_MIN_NANOS
    );
    context.finish().unwrap();
}

#[test]
fn a_progress_op_ends_the_poll_episode_so_a_working_run_never_escalates() {
    // A guest that reads the clock hard but keeps doing real work: the
    // streak is broken by every genuine effect, so it never accumulates and
    // the clock never moves. An unbounded number of reads, no escalation.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..8 {
        for _ in 0..ESCALATION_POLLS - 1 {
            assert_eq!(
                context.now(ClockKind::Monotonic).unwrap(),
                DEFAULT_BOOT_ORIGIN_NANOS
            );
        }
        context.write_file("/work", b"x").unwrap();
    }
    assert_eq!(context.spin.escalations, 0);
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS
    );
    context.finish().unwrap();
}

#[test]
fn a_guest_sleep_ends_the_poll_episode_so_a_sleeping_loop_never_escalates() {
    // The other reset arm: an idle advance. A loop that sleeps between reads
    // waits for time itself and must never be escalated, however many reads
    // it takes.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    for _ in 0..4 {
        // Short of the streak with `sleep_for`'s own clock read.
        for _ in 0..(ESCALATION_POLLS - 2) {
            context.now(ClockKind::Monotonic).unwrap();
        }
        context.sleep_for(1).unwrap();
    }
    assert_eq!(context.spin.escalations, 0);
    // Exactly the four nanoseconds the guest itself slept.
    assert_eq!(
        context.now(ClockKind::Monotonic).unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS + 4
    );
    context.finish().unwrap();
}

#[test]
fn cpu_time_is_the_charged_calls_and_a_sleep_charges_none() {
    // The process starts at its modeled startup work; a sleep moves virtual
    // time without charging it; charged calls move both.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    assert_eq!(context.cpu_time(), STARTUP_CPU_CHARGE);
    let start = context.current_monotonic().unwrap();
    context.sleep_for(5_000_000).unwrap();
    assert_eq!(context.cpu_time(), STARTUP_CPU_CHARGE);
    assert_eq!(context.current_monotonic().unwrap() - start, 5_000_000);
    // Two system calls: user and system time, and the clock moves by both.
    context
        .charge_calls(None, calls(ChargeClass::Syscall, 2))
        .unwrap();
    assert_eq!(
        context.cpu_time(),
        CpuCharge::new(
            STARTUP_CPU_CHARGE.user_ns + 100,
            STARTUP_CPU_CHARGE.system_ns + 400
        )
    );
    assert_eq!(context.current_monotonic().unwrap() - start, 5_000_500);
    // Before the embedder schedules a task the main thread is `None`; once
    // it does, an escalation charges the task it selected.
    let task = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(task));
    let (_, elapsed) = calibration_spin(&mut context, 1_000_000).unwrap();
    assert_eq!(context.cpu_charge(Some(task)).user_ns, elapsed);
    assert_eq!(
        context.cpu_time().total_ns(),
        STARTUP_CPU_CHARGE.total_ns() + 500 + elapsed
    );
    context.finish().unwrap();
}

#[test]
fn a_charge_stops_at_the_earliest_deadline_and_carries_the_rest() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS;
    let sleeper = context.task_spawn("sleeper").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
    context
        .task_park_timed(sleeper, "sleep", ClockKind::Monotonic, origin + 300)
        .unwrap();
    let worker = context.task_spawn("worker").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(worker));
    // 500 ns of work crosses the sleeper's deadline: the clock stops there,
    // the park expires, and the rest is carried.
    context
        .charge_calls(Some(worker), calls(ChargeClass::Syscall, 2))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 300);
    assert_eq!(context.take_expired_timeouts(), vec![sleeper]);
    assert_eq!(context.cpu_charge(Some(worker)).total_ns(), 500);
    // The next charge shows the carried 200 ns and its own.
    context
        .charge_calls(Some(worker), calls(ChargeClass::Clock, 1))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 525);
    // An embedder's alarm stops the clock the same way, and stays a barrier
    // until its owner settles it: later charges wait behind it, so the owner
    // fires it at its own time and the timers after it at theirs.
    context.set_alarm(Some(origin + 600));
    context
        .charge_calls(Some(worker), calls(ChargeClass::Syscall, 1))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 600);
    context
        .charge_calls(Some(worker), calls(ChargeClass::Syscall, 1))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 600);
    // Settled: the owner publishes its next alarm, past the carry.
    context.set_alarm(Some(origin + 10_000));
    context
        .charge_calls(Some(worker), calls(ChargeClass::Sync, 1))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 1_045);
    context.finish().unwrap();
}

#[test]
fn time_stands_still_where_a_charge_is_carried() {
    // Inside an embedder section, and for an embedder that charges where it
    // may hold a wake decision (accrue_calls), nothing moves and nothing
    // expires until the carry is shown at a point that can settle it.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS;
    let sleeper = context.task_spawn("sleeper").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
    context
        .task_park_timed(sleeper, "sleep", ClockKind::Monotonic, origin + 300)
        .unwrap();
    let worker = context.task_spawn("worker").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(worker));
    context.accrue_calls(Some(worker), calls(ChargeClass::Syscall, 2));
    context.in_embedder_section(|context| {
        context
            .charge_calls(Some(worker), calls(ChargeClass::Syscall, 1))
            .unwrap();
        assert_eq!(context.current_monotonic().unwrap(), origin);
        assert!(context.take_expired_timeouts().is_empty());
    });
    assert_eq!(context.current_monotonic().unwrap(), origin);
    assert!(context.take_expired_timeouts().is_empty());
    // Shown: the clock stops at the deadline, the park expires there, and
    // the next show carries on past it.
    context.show_carry().unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 300);
    assert_eq!(context.take_expired_timeouts(), vec![sleeper]);
    context.show_carry().unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 750);
    context.finish().unwrap();
}

#[test]
fn an_idle_wait_covers_the_charged_time_still_to_show() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS;
    context.set_alarm(Some(origin + 100));
    context
        .charge_calls(None, calls(ChargeClass::Syscall, 2))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 100);
    // 400 ns carried; a 1 µs sleep from the observed time covers it.
    context.set_alarm(None);
    context
        .sleep_until(ClockKind::Monotonic, origin + 1_100)
        .unwrap();
    context
        .charge_calls(None, calls(ChargeClass::Clock, 1))
        .unwrap();
    assert_eq!(context.current_monotonic().unwrap(), origin + 1_125);
    context.finish().unwrap();
}

#[test]
fn escalation_reaches_an_alarm_in_one_step() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    context.set_alarm(Some(DEFAULT_BOOT_ORIGIN_NANOS + 1_500_000));
    // The first escalation charges the reads up to the alarm.
    let (reads, elapsed) = calibration_spin(&mut context, 1_000).unwrap();
    assert_eq!(elapsed, 1_500_000);
    assert_eq!(reads, ESCALATION_POLLS + 1);
    assert_eq!(context.spin.escalations, 1);
    context.finish().unwrap();
}

/// Class detector: every clock advance drains due timers through the shared
/// expiry path, even with a runnable task. Selection stays policy-driven.
fn spin_until_sleepers_run(context: &mut Context) {
    let deadline = DEFAULT_BOOT_ORIGIN_NANOS + 1_500;
    let mut sleepers = Vec::new();
    for _ in 0..2 {
        let sleeper = context.task_spawn("sleeper").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
        context
            .task_park_timed(sleeper, "sleep", ClockKind::Monotonic, deadline)
            .unwrap();
        sleepers.push(sleeper);
    }
    let spinner = context.task_spawn("spinner").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(spinner));
    while context.now(ClockKind::Monotonic).unwrap() < deadline {}
    // The escalation lands exactly on the deadline and wakes in registration
    // order, before another clock observation or scheduling decision can step
    // past it.
    assert_eq!(context.current_monotonic().unwrap(), deadline);
    assert_eq!(context.take_expired_timeouts(), sleepers);
    assert!(context.take_expired_timeouts().is_empty());
    let mut remaining = sleepers;
    let mut running = spinner;
    for _ in 0..100 {
        context.task_yield(running).unwrap();
        running = context.scheduler_next().unwrap().unwrap();
        if running != spinner {
            remaining.retain(|task| *task != running);
            context.task_complete(running).unwrap();
            running = context.scheduler_next().unwrap().unwrap();
        }
        if remaining.is_empty() {
            break;
        }
    }
    assert!(remaining.is_empty(), "timer-woken tasks must get a turn");
    context.task_complete(spinner).unwrap();
    assert_eq!(context.scheduler_next().unwrap(), None);
}

/// A poller of empty non-blocking receives waiting on a sleeping peer,
/// reading the clock between them when `read_clock`: the empty receives are
/// polls too, and the escalation brings virtual time to the sleeper's
/// deadline. Answers how many polls that took.
fn poll_until_the_sleeper_expires(context: &mut Context, read_clock: bool) -> u64 {
    let deadline = DEFAULT_BOOT_ORIGIN_NANOS + 1_000_000;
    let sleeper = context.task_spawn("sleeper").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
    context
        .task_park_timed(sleeper, "sleep", ClockKind::Monotonic, deadline)
        .unwrap();
    let poller = context.task_spawn("poller").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(poller));
    let socket = context.net_bind("poller").unwrap();
    let mut polls = 0;
    while context.take_expired_timeouts().is_empty() {
        assert!(context.net_recv(socket).unwrap().is_none());
        if read_clock {
            context.now(ClockKind::Monotonic).unwrap();
        }
        polls += 1;
        assert!(
            polls < 100_000,
            "empty polls kept virtual time from reaching the sleeper"
        );
    }
    assert_eq!(context.current_monotonic().unwrap(), deadline);
    polls
}

#[test]
fn an_empty_poll_loop_is_escalated_to_its_peers_deadline_and_replays() {
    for read_clock in [true, false] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("poll.patina");
        let mut record = Context::from_config(RuntimeConfig::record(3, &path, "poll-v1")).unwrap();
        let polls = poll_until_the_sleeper_expires(&mut record, read_clock);
        // One streak: the first escalation reaches the sleeper's deadline.
        assert!(polls <= ESCALATION_POLLS / 2, "{polls}");
        assert_eq!(record.spin.escalations, 1);
        record.finish().unwrap();
        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "poll-v1")).unwrap();
        assert_eq!(
            poll_until_the_sleeper_expires(&mut replay, read_clock),
            polls
        );
        replay.finish().unwrap();
    }
}

#[test]
fn escalation_wakes_due_sleepers_and_replays_their_turns() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("sleepers-a.patina");
    let second = directory.path().join("sleepers-b.patina");
    for path in [&first, &second] {
        let mut context =
            Context::from_config(RuntimeConfig::record(9, path, "sleepers-v1")).unwrap();
        spin_until_sleepers_run(&mut context);
        context.finish().unwrap();
    }
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let mut replay = Context::from_config(RuntimeConfig::replay(&first, "sleepers-v1")).unwrap();
    spin_until_sleepers_run(&mut replay);
    replay.finish().unwrap();
}

/// Spin on the clock until `cpu` nanoseconds of the process's CPU time
/// (`which` of it) are charged; the escalations it took.
fn spin_for_cpu(context: &mut Context, cpu: u64, which: fn(CpuCharge) -> u64) -> u64 {
    let start = which(context.cpu_time());
    while which(context.cpu_time()) - start < cpu {
        context.now(ClockKind::Monotonic).unwrap();
    }
    context.spin.escalations
}

#[test]
fn escalation_reaches_a_cpu_alarm_in_one_step_without_the_ramp() {
    // An 11 ms CPU-time timer. Without an alarm the ramp takes ten
    // escalating tokens (1.023 ms) and ten more at the ceiling; toward a
    // published CPU deadline, on either line, one escalation lands on it.
    const DEADLINE: u64 = 11_000_000;
    let total: fn(CpuCharge) -> u64 = |time| time.total_ns();
    let user: fn(CpuCharge) -> u64 = |time| time.user_ns;
    let mut ramp = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    assert_eq!(spin_for_cpu(&mut ramp, DEADLINE, total), 20);
    ramp.finish().unwrap();
    for (line, alarms) in [
        (
            total,
            CpuAlarms {
                user_ns: None,
                total_ns: Some(STARTUP_CPU_CHARGE.total_ns() + DEADLINE),
            },
        ),
        (
            user,
            CpuAlarms {
                user_ns: Some(STARTUP_CPU_CHARGE.user_ns + DEADLINE),
                total_ns: None,
            },
        ),
    ] {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        context.set_cpu_alarms(alarms);
        assert_eq!(spin_for_cpu(&mut context, DEADLINE, line), 1);
        assert_eq!(
            line(context.cpu_time()) - line(STARTUP_CPU_CHARGE),
            DEADLINE
        );
        context.finish().unwrap();
    }
}

#[test]
fn replay_names_a_charge_the_recording_did_not_make() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("charges.patina");
    let mut record = Context::from_config(RuntimeConfig::record(1, &path, "charges-v1")).unwrap();
    record
        .charge_calls(None, calls(ChargeClass::Syscall, 1))
        .unwrap();
    record.now(ClockKind::Monotonic).unwrap();
    record.finish().unwrap();
    // The same calls replay; a missed charge is a time-model divergence at
    // the first monotonic read.
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "charges-v1")).unwrap();
    replay
        .charge_calls(None, calls(ChargeClass::Syscall, 1))
        .unwrap();
    replay.now(ClockKind::Monotonic).unwrap();
    replay.finish().unwrap();
    let mut missed = Context::from_config(RuntimeConfig::replay(&path, "charges-v1")).unwrap();
    assert!(matches!(
        missed.now(ClockKind::Monotonic),
        Err(RuntimeError::TimeModel { .. })
    ));
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
fn escalation_records_and_replays_byte_identically() {
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
    assert_eq!(recorded[0].0, 7 * ESCALATION_POLLS + 1);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    // Nothing but the reads is recorded: the escalations replay with them.
    let bundle = TraceBundle::load(&first).unwrap();
    assert_eq!(
        bundle.resolved_timeline("main").unwrap().len() as u64,
        recorded[0].0
    );
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
fn compute_watchdog_stops_timed_peer_starvation_and_replays() {
    // Class pairing: the shared compute_starves_peer predicate validates both
    // observer eligibility and terminal export. A timed park needs virtual time
    // to move; a call-free baton holder prevents that just as it blocks a
    // runnable peer. Untimed parks remain exempt (the eligibility control above).
    let directory = tempdir().unwrap();
    let path = directory.path().join("timed-compute.patina");
    let setup = |context: &mut Context| {
        let sleeper = context.task_spawn("sleeper").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
        context
            .task_park_timed(
                sleeper,
                "sleep",
                ClockKind::Monotonic,
                DEFAULT_BOOT_ORIGIN_NANOS + 1_000_000,
            )
            .unwrap();
        let computing = context.task_spawn("computing").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(computing));
        computing
    };
    let mut record =
        Context::from_config(RuntimeConfig::record(1, &path, "timed-compute-v1")).unwrap();
    let task = setup(&mut record);
    let steps = record.steps();
    assert_eq!(record.compute_watchdog_candidate(), Some((steps, task)));
    assert!(matches!(
        record.stop_compute_bound(task),
        RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == task && at == steps
    ));
    assert_eq!(
        record.current_monotonic().unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS
    );
    let mut replay =
        Context::from_config(RuntimeConfig::replay(&path, "timed-compute-v1")).unwrap();
    assert_eq!(setup(&mut replay), task);
    assert_eq!(replay.compute_watchdog_candidate(), None);
    assert!(matches!(
        replay.finish(),
        Err(RuntimeError::ComputeBound { task: stopped, steps: at }) if stopped == task && at == steps
    ));
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
    // no amount of charging frees it, so the backstop must name it rather
    // than escalate it forever.
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
    // campaign consumer classifies it without a new rule.
    assert!(detail.starts_with("PATINA_VIOLATION liveness detail=frozen-clock-churn "));
    assert_eq!(context.spin.escalations, CHURN_ABORT_ESCALATIONS);
    // Ten escalating tokens (1_023_000 ns) plus 246 at the 1 ms ceiling.
    assert_eq!(context.spin.charged_nanos, 247_023_000);
    // The abort fires only once the poll PERSISTS past the last escalation:
    // a full further streak of reads bought nothing. The read that completes
    // it is the one refused.
    assert_eq!(reads, (CHURN_ABORT_ESCALATIONS + 1) * ESCALATION_POLLS - 1);
    // The facts document carries the same finding as the line.
    let finding = &context.run_facts()["runtime_findings"][0];
    assert_eq!(finding["detail"], "frozen-clock-churn");
    assert_eq!(finding["rescues"], CHURN_ABORT_ESCALATIONS);
    assert_eq!(finding["advanced_ns"], 247_023_000);
}

#[test]
fn the_liveness_watchdog_fires_first_on_a_poll_that_escalation_feeds() {
    // The watchdog's no-progress window is measured in virtual nanoseconds,
    // which escalation moves, so a budget the escalations walk past trips it,
    // and it trips FIRST, long before the frozen-clock backstop's 256.
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
    // Fired after the third escalation (1+2+4 = 7 µs past a 5 µs budget).
    assert_eq!(context.spin.escalations, 3);
    assert!(context.spin.escalations < CHURN_ABORT_ESCALATIONS);
}

// -- Liveness watchdog --------------------------------------------------

#[test]
fn operation_progress_classification_is_correct() {
    // Pure scheduling/time/wait ops are never progress; genuine effects
    // always are; a non-blocking network poll is decided by its outcome.
    for operation in [
        Operation::SchedulerNext,
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Operation::SleepUntil {
            clock: ClockKind::Monotonic,
            deadline_nanos: 1,
        },
        Operation::TaskParkTimed {
            task: TaskId(1),
            reason: "x".into(),
            deadline_nanos: 1,
        },
    ] {
        assert_eq!(progress_of(&operation), Progress::Never, "{operation:?}");
    }
    for operation in [
        Operation::FsWrite {
            fd: Fd(1),
            bytes: vec![1],
        },
        Operation::TaskComplete { task: TaskId(1) },
        Operation::EntropyFill { len: 4 },
    ] {
        assert_eq!(progress_of(&operation), Progress::Always, "{operation:?}");
    }
}

#[test]
fn an_empty_network_poll_is_not_progress_and_every_other_outcome_is() {
    let socket = SocketId(3);
    let recv = Operation::NetRecv {
        socket,
        now_nanos: 0,
    };
    let tcp_recv = Operation::NetTcpRecv {
        socket,
        max_len: 8,
        now_nanos: 0,
    };
    let accept = Operation::NetTcpAccept {
        listener: socket,
        now_nanos: 0,
    };
    for operation in [&recv, &tcp_recv, &accept] {
        assert_eq!(progress_of(operation), Progress::ByOutcome, "{operation:?}");
    }
    let refused = Outcome::Error(EffectError::new(ErrorCode::ConnectionReset, "reset"));
    let datagram = Datagram {
        packet_id: 1,
        from: "127.0.0.1:1".into(),
        to: "127.0.0.1:2".into(),
        bytes: b"ping".to_vec(),
        delivery_nanos: 0,
        dialed: String::new(),
        tos: 0,
    };
    let accepted = TcpAccepted {
        socket,
        peer: "127.0.0.1:1".into(),
    };
    let cases = [
        // Nothing to take: the poll changed nothing.
        (&recv, Outcome::Datagram(None), false),
        (&tcp_recv, Outcome::OptionalBytes(None), false),
        (&accept, Outcome::TcpAccepted(None), false),
        // Data, a stream's end of file, a connection, an error: progress.
        (&recv, Outcome::Datagram(Some(datagram)), true),
        (
            &tcp_recv,
            Outcome::OptionalBytes(Some(b"ok".to_vec())),
            true,
        ),
        (&tcp_recv, Outcome::OptionalBytes(Some(Vec::new())), true),
        (&accept, Outcome::TcpAccepted(Some(accepted)), true),
        (&recv, refused.clone(), true),
        (&tcp_recv, refused.clone(), true),
        (&accept, refused, true),
    ];
    for (operation, outcome, progress) in cases {
        assert_eq!(
            outcome_is_progress(operation, &outcome),
            progress,
            "{operation:?} -> {outcome:?}"
        );
    }
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
