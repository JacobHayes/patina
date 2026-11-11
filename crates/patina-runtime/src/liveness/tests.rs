//! Tests for progress watchdogs, poll escalation, charged time, and compute
//! stops.

use crate::config::{LivenessConfig, RuntimeConfig};
use crate::liveness::{CHURN_HORIZON_NANOS, ESCALATION_POLLS, LivenessKind, WatchdogArm};
use crate::{Context, CpuAlarms, DEFAULT_BOOT_ORIGIN_NANOS, FACTS_SCHEMA, RuntimeError};
use patina_dst_abi::{ChargeClass, ChargeCounts, ClockKind, CpuCharge, STARTUP_CPU_CHARGE, TaskId};

use patina_dst_trace::{Replayer, TraceBundle};
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
fn an_empty_poll_loop_reaches_its_peers_deadline_and_replays() {
    for read_clock in [true, false] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("poll.patina");
        let mut record = Context::from_config(RuntimeConfig::record(3, &path, "poll-v1")).unwrap();
        // The tokens walk virtual time to the sleeper's deadline, where the
        // clock stops (`poll_until_the_sleeper_expires` checks it): several
        // streaks of polls, not one that jumps there.
        let polls = poll_until_the_sleeper_expires(&mut record, read_clock);
        assert!(record.spin.escalations > 1);
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
fn work_that_reads_the_clock_does_not_reach_a_peers_deadline() {
    // A task parked for a minute, and another doing work that reads the
    // clock now and then with no other effect: the reads cost about a
    // microsecond each, and the minute does not pass because of them.
    const MINUTE: u64 = 60_000_000_000;
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let waiter = context.task_spawn("waiter").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(waiter));
    context
        .task_park_timed(
            waiter,
            "timeout",
            ClockKind::Monotonic,
            DEFAULT_BOOT_ORIGIN_NANOS + MINUTE,
        )
        .unwrap();
    let worker = context.task_spawn("worker").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(worker));
    let reads = 5_000;
    let mut last = 0;
    for _ in 0..reads {
        last = context.now(ClockKind::Monotonic).unwrap();
    }
    let elapsed = last - DEFAULT_BOOT_ORIGIN_NANOS;
    assert!(context.spin.escalations > 0, "the reads were a poll streak");
    assert!(elapsed < reads * 10_000, "{elapsed} ns for {reads} reads");
    assert!(context.take_expired_timeouts().is_empty());
    context.finish().unwrap();
}

#[test]
fn a_busy_wait_reaches_a_far_deadline_of_its_own_close_to_it() {
    // A loop whose only exit is the clock passing a time of its own, beyond
    // what the old fixed count of 1 ms tokens covered and minutes beyond it:
    // it ends, late by no more than half a percent of the wait, in a few
    // million reads, not the hundreds of millions a fixed token would take.
    // Nothing tells the runtime where the deadline is.
    for window in [300_000_000u64, 300_000_000_000] {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let (reads, elapsed) = calibration_spin(&mut context, window).unwrap();
        assert!(elapsed > window);
        assert!(
            elapsed - window <= (window / 200).max(1_000_000),
            "a {window} ns wait ended {} ns late",
            elapsed - window
        );
        assert!(reads < 4_000_000, "{reads} reads for a {window} ns wait");
        context.finish().unwrap();
    }
}

#[test]
fn escalation_wakes_due_sleepers_and_replays_their_turns() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("sleepers.patina");
    let mut context = Context::from_config(RuntimeConfig::record(9, &path, "sleepers-v1")).unwrap();
    spin_until_sleepers_run(&mut context);
    context.finish().unwrap();
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "sleepers-v1")).unwrap();
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
fn escalation_stops_the_clock_at_an_alarm_and_charges_no_further_than_a_cpu_timer() {
    // A wall alarm is a barrier like any pending deadline: the tokens walk
    // the clock up to it, and there it stops until its owner settles it.
    let alarm = DEFAULT_BOOT_ORIGIN_NANOS + 1_500_000;
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    context.set_alarm(Some(alarm));
    while context.now(ClockKind::Monotonic).unwrap() < alarm {}
    assert_eq!(context.current_monotonic().unwrap(), alarm);
    assert!(context.spin.escalations > 1);
    context.finish().unwrap();

    // CPU time is the charges themselves, with nothing to carry: without a
    // timer the token that passes 11 ms of it overshoots; toward a published
    // CPU-time deadline, on either line, the escalation that would pass it
    // charges exactly up to it.
    const DEADLINE: u64 = 11_000_000;
    let total: fn(CpuCharge) -> u64 = |time| time.total_ns();
    let user: fn(CpuCharge) -> u64 = |time| time.user_ns;
    let mut ramp = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    spin_for_cpu(&mut ramp, DEADLINE, total);
    assert!(total(ramp.cpu_time()) - total(STARTUP_CPU_CHARGE) > DEADLINE);
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
        spin_for_cpu(&mut context, DEADLINE, line);
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
fn escalation_records_only_the_reads_and_replays() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("spin.patina");
    let mut record = Context::from_config(RuntimeConfig::record(9, &path, "spin-v1")).unwrap();
    let recorded = calibration_spin(&mut record, 100_000).unwrap();
    record.finish().unwrap();
    assert_eq!(recorded.0, 7 * ESCALATION_POLLS + 1);
    // Nothing but the reads is recorded: the escalations replay with them.
    let bundle = TraceBundle::load(&path).unwrap();
    assert_eq!(
        bundle.resolved_timeline("main").unwrap().len() as u64,
        recorded.0
    );
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "spin-v1")).unwrap();
    assert_eq!(calibration_spin(&mut replay, 100_000).unwrap(), recorded);
    replay.finish().unwrap();
}

#[test]
fn compute_watchdog_watches_whichever_thread_runs_guest_code() {
    // A thread running guest code is a candidate with or without a peer:
    // the main thread before any task exists, a lone task, and a task beside
    // runnable or parked peers. Nothing runs guest code while the selected
    // task is parked.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let task_of = |context: &Context| context.compute_watchdog_candidate().map(|(_, task)| task);
    assert_eq!(task_of(&context), Some(None));
    let main = context.task_spawn("main").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(main));
    assert_eq!(task_of(&context), Some(Some(main)));
    let peer = context.task_spawn("peer").unwrap();
    assert_eq!(task_of(&context), Some(Some(main)));
    context.task_park(main, "condition").unwrap();
    assert_eq!(task_of(&context), None);
    assert_eq!(context.scheduler_next().unwrap(), Some(peer));
    assert_eq!(task_of(&context), Some(Some(peer)));
    context.task_wake(main).unwrap();
    context.task_complete(peer).unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(main));
    assert_eq!(task_of(&context), Some(Some(main)));
}

#[test]
fn compute_watchdog_stamp_ignores_yields_that_charge_nothing() {
    // What the observer compares between two looks. A yield and the decision
    // after it are what an instrumented build's edge hook takes: a guest
    // doing nothing else has made no call and moved no time, whichever task
    // the scheduler hands the baton to. A charged call or any other
    // operation is the guest reaching the runtime.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let stamp = |context: &Context| context.compute_watchdog_candidate().unwrap().0;
    let first = context.task_spawn("first").unwrap();
    context.task_spawn("second").unwrap();
    let mut running = context.scheduler_next().unwrap().unwrap();
    let idle = stamp(&context);
    let mut ran = std::collections::BTreeSet::new();
    for _ in 0..64 {
        ran.insert(running);
        context.task_yield(running).unwrap();
        running = context.scheduler_next().unwrap().unwrap();
        assert_eq!(stamp(&context), idle);
    }
    assert_eq!(ran.len(), 2, "both tasks took turns");
    context
        .charge_calls(Some(first), calls(ChargeClass::Sync, 1))
        .unwrap();
    let charged = stamp(&context);
    assert_ne!(charged, idle);
    context.now(ClockKind::Monotonic).unwrap();
    assert_ne!(stamp(&context), charged);
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
    let facts_path = directory.path().join("compute-facts.json");
    let mut record = crate::tests::with_facts_file(
        RuntimeConfig::record(1, &path, "timed-compute-v1"),
        &facts_path,
    );
    let task = setup(&mut record);
    let steps = record.steps();
    assert_eq!(
        record.compute_watchdog_candidate().map(|(_, task)| task),
        Some(Some(task))
    );
    assert!(matches!(
        record.stop_compute_bound(Some(task)),
        RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == Some(task) && at == steps
    ));
    assert_eq!(
        record.current_monotonic().unwrap(),
        DEFAULT_BOOT_ORIGIN_NANOS
    );
    // The stop is a structured known limit on the facts channel, with no claim
    // about what the baton holder was doing outside the boundary.
    let mut facts: serde_json::Value =
        serde_json::from_slice(&fs::read(&facts_path).unwrap()).unwrap();
    assert!(facts["context"].is_u64());
    facts.as_object_mut().unwrap().remove("context");
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
    let mut replay =
        Context::from_config(RuntimeConfig::replay(&path, "timed-compute-v1")).unwrap();
    assert_eq!(setup(&mut replay), task);
    assert_eq!(replay.compute_watchdog_candidate(), None);
    assert!(matches!(
        replay.finish(),
        Err(RuntimeError::ComputeBound { task: stopped, steps: at }) if stopped == Some(task) && at == steps
    ));
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
        matches!(record.stop_compute_bound(Some(task)), RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == Some(task) && at == steps)
    );
    let original = fs::read(&path).unwrap();
    // The append-only native sink relies on exactly one flush.
    record.stop_compute_bound(Some(task));
    assert_eq!(original, fs::read(&path).unwrap());
    for finish in [false, true] {
        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "compute-v1")).unwrap();
        assert_eq!(replay.compute_watchdog_candidate(), None);
        assert_eq!(setup(&mut replay), task);
        assert_eq!(
            replay.replay_compute_stop_due(),
            Some(patina_dst_trace::ComputeStop {
                task: Some(task),
                steps
            })
        );
        let error = if finish {
            replay.finish().unwrap_err()
        } else {
            replay.task_yield(task).unwrap_err()
        };
        assert!(
            matches!(error, RuntimeError::ComputeBound { task: stopped, steps: at } if stopped == Some(task) && at == steps)
        );
    }
    let mut wrong_task = TraceBundle::load(&path).unwrap();
    wrong_task.metadata.compute_stop.as_mut().unwrap().task = Some(TaskId(99));
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
    assert!(Replayer::from_bundle(bundle, "compute-v1").is_err());
}

#[test]
fn poll_churn_stops_a_loop_that_no_time_ends() {
    // A loop that reads the clock and goes round whatever it says: time
    // moves for it like for any poller, and no time ends it. It must become
    // a named stop, in a bounded number of reads, once it has polled away
    // the whole horizon.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let start = context.current_monotonic().unwrap();
    let mut reads = 0u64;
    let error = loop {
        match context.now(ClockKind::Monotonic) {
            Ok(_) => reads += 1,
            Err(error) => break error,
        }
    };
    let RuntimeError::PollChurn { detail } = error else {
        panic!("expected a poll-churn stop, got {error:?}");
    };
    // The marker rides the established liveness interface contract, so a
    // campaign consumer classifies it without a new rule.
    assert!(detail.starts_with("PATINA_VIOLATION liveness detail=poll-churn "));
    assert!(reads < 4_000_000, "{reads} reads to the stop");
    // The whole horizon went by, and the guest saw it go by.
    let charged = context.spin.charged_nanos;
    assert!(charged >= CHURN_HORIZON_NANOS);
    assert_eq!(context.current_monotonic().unwrap() - start, charged);
    // The facts document carries the same finding as the line.
    let finding = &context.run_facts()["runtime_findings"][0];
    assert_eq!(finding["detail"], "poll-churn");
    assert_eq!(finding["rescues"], context.spin.escalations);
    assert_eq!(finding["advanced_ns"], charged);
}

#[test]
fn a_loop_of_yields_is_a_poll_streak_too() {
    // A guest that only asks to yield is charged its calls and escalated
    // like one that only reads the clock: time passes for it, a sleeping
    // peer's deadline arrives, and with nothing to wait for it reaches the
    // same stop. The yields count while no other task is runnable. The embedder charges each call and applies the escalation
    // a call's poll earned as the call ends.
    let yield_once = |context: &mut Context, task| {
        context.accrue_calls(Some(task), calls(ChargeClass::Syscall, 1));
        context.yield_poll();
        let earned = context.take_poll_streak();
        context.show_carry()?;
        if earned {
            context.escalate_call(Some(task), ChargeClass::Syscall)?;
        }
        Ok::<_, RuntimeError>(())
    };
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS;
    let sleeper = context.task_spawn("sleeper").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(sleeper));
    context
        .task_park_timed(sleeper, "sleep", ClockKind::Monotonic, origin + 50_000_000)
        .unwrap();
    let spinner = context.task_spawn("spinner").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(spinner));
    let mut yields = 0u64;
    while context.take_expired_timeouts().is_empty() {
        yield_once(&mut context, spinner).unwrap();
        yields += 1;
    }
    // Reached by the tokens, well before the calls' own 250 ns each would
    // have got there.
    assert_eq!(context.current_monotonic().unwrap(), origin + 50_000_000);
    assert!(yields < 50_000_000 / 250 / 2, "{yields} yields");
    // A task alone that yields for good.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let spinner = context.task_spawn("spinner").unwrap();
    assert_eq!(context.scheduler_next().unwrap(), Some(spinner));
    let error = loop {
        if let Err(error) = yield_once(&mut context, spinner) {
            break error;
        }
    };
    assert!(matches!(error, RuntimeError::PollChurn { .. }), "{error:?}");
}

#[test]
fn a_yield_beside_a_runnable_peer_is_no_poll() {
    // A work-stealing pool's idle workers yield while a peer works: those
    // yields cost their calls and nothing more, however many there are.
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let worker = context.task_spawn("worker").unwrap();
    let idle = context.task_spawn("idle").unwrap();
    assert!(
        matches!(context.scheduler_next().unwrap(), Some(task) if task == worker || task == idle)
    );
    let running = context.charges.running.unwrap();
    for _ in 0..4 * ESCALATION_POLLS {
        context.accrue_calls(Some(running), calls(ChargeClass::Syscall, 1));
        context.yield_poll();
        assert!(!context.take_poll_streak());
    }
    assert_eq!(context.spin.polls, 0);
}

#[test]
fn the_liveness_watchdog_fires_first_on_a_poll_that_escalation_feeds() {
    // The watchdog's no-progress window is measured in virtual nanoseconds,
    // which escalation moves, so a budget the escalations walk past trips it,
    // and it trips FIRST, long before the churn stop's horizon.
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
    assert!(context.spin.charged_nanos < CHURN_HORIZON_NANOS);
}

// -- Liveness watchdog --------------------------------------------------

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
fn liveness_watchdog_is_schedule_invariant_and_replays_from_its_record() {
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

    // A replay adopts the recorded watchdog whatever it is configured with:
    // the watched trace replays with none configured.
    let mut replay =
        Context::from_config(RuntimeConfig::replay(&watched, "wd-invariance-v1")).unwrap();
    replay.write_file("/f", b"hello").unwrap();
    replay.sleep_for(1_000).unwrap();
    let _ = replay.read_file("/f").unwrap();
    replay.finish().unwrap();
}
