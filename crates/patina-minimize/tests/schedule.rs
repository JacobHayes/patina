//! End-to-end schedule reduction against a real runtime-produced trace.
//!
//! A multi-task run is recorded through the deterministic runtime, then
//! [`reduce_schedule`] is driven by an oracle that *replays* each candidate
//! against a fresh runtime. This exercises the real safety contract: the runtime
//! replays with strict operation matching, so a rewritten `SchedulerNext` forces
//! `scheduler.select` of a different task while the following recorded
//! `TaskYield` still names the original task, the replay mismatches, and the
//! oracle rejects the candidate. The reduced trace therefore still replays
//! cleanly and reproduces the recorded schedule, with no more context switches
//! than the original.

use std::sync::{Arc, Mutex};

use patina_dst_minimize::reduce_schedule;
use patina_dst_runtime::{Context, RuntimeBuilder, RuntimeConfig, RuntimeError, TraceTransport};
use patina_dst_trace::{TraceBundle, TraceError};

const FINGERPRINT: &str = "schedule-reduction-v1";

/// A cooperative two-task run: spawn two tasks, then repeatedly let the
/// scheduler pick a runnable task and yield it. The returned vector is the order
/// of task ids the scheduler chose, which is what the schedule reducer targets.
fn drive(context: &mut Context) -> Result<Vec<u64>, RuntimeError> {
    context.task_spawn("a")?;
    context.task_spawn("b")?;
    let mut order = Vec::new();
    for _ in 0..8 {
        let Some(task) = context.scheduler_next()? else {
            break;
        };
        order.push(task.0);
        context.task_yield(task)?;
    }
    Ok(order)
}

/// Replay a bundle's main timeline through a fresh runtime, returning the
/// observed schedule. Any structural mismatch (an illegal forced selection the
/// recorded operation stream still depends on) surfaces as an error.
fn replay_order(bundle: &TraceBundle) -> Result<Vec<u64>, RuntimeError> {
    let bytes = bundle.to_bytes().map_err(RuntimeError::Trace)?;
    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        FINGERPRINT,
    ))
    .with_default_drivers()
    .with_trace_transport(MemoryTransport::from_bytes(bytes))
    .build()?;
    let order = drive(&mut replay)?;
    replay.finish()?;
    Ok(order)
}

fn switch_count(order: &[u64]) -> usize {
    order.windows(2).filter(|pair| pair[0] != pair[1]).count()
}

/// Record the two-task run under the first seed whose scheduler actually
/// produces a context switch, so there is a ping-pong for the reducer to attack.
fn record_multi_task() -> (TraceBundle, Vec<u64>) {
    for seed in 0..64u64 {
        let transport = MemoryTransport::empty();
        let mut record = RuntimeBuilder::new(RuntimeConfig::record_transport(seed, FINGERPRINT))
            .with_default_drivers()
            .with_trace_transport(transport.clone())
            .build()
            .expect("record builder");
        let order = drive(&mut record).expect("record drive");
        record.finish().expect("record finish");
        if switch_count(&order) >= 1 {
            let bundle = TraceBundle::from_slice(&transport.stored()).expect("recorded bundle");
            return (bundle, order);
        }
    }
    panic!("no seed in 0..64 produced a context switch");
}

#[test]
fn schedule_reduction_preserves_a_real_multi_task_failure() {
    let (bundle, recorded_order) = record_multi_task();
    let original_switches = switch_count(&recorded_order);
    assert!(original_switches >= 1, "fixture must have a context switch");

    // The oracle replays each candidate and defines "failure preserved" as
    // reproducing the recorded schedule end-to-end. Under strict replay, any
    // rewritten selection breaks the following task-tagged yield, so every
    // proposed rewrite is rejected here - which is exactly the safety property
    // under test.
    let mut calls = 0u64;
    let mut oracle = |candidate: &TraceBundle| -> Result<bool, TraceError> {
        calls += 1;
        Ok(matches!(replay_order(candidate), Ok(order) if order == recorded_order))
    };
    let reduced = reduce_schedule(&bundle, &mut oracle).expect("reduce_schedule");

    // More than the single up-front check means real candidates were proposed
    // and judged by the replay oracle.
    assert!(
        calls > 1,
        "schedule candidates should have been proposed and replayed"
    );

    // The reduced trace still replays cleanly and reproduces the failure, with a
    // schedule no more complex than the original.
    let reduced_order = replay_order(&reduced).expect("reduced trace replays cleanly");
    assert_eq!(reduced_order, recorded_order, "failure preserved on replay");
    assert!(
        switch_count(&reduced_order) <= original_switches,
        "context switches never increase"
    );
}

/// An in-memory [`TraceTransport`] so record and replay need no filesystem.
#[derive(Clone)]
struct MemoryTransport {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl MemoryTransport {
    fn empty() -> Self {
        Self {
            bytes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
        }
    }

    fn stored(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }
}

impl TraceTransport for MemoryTransport {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Ok(self.stored())
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}
