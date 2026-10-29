//! A representative workload records one event per boundary operation, and
//! the recording replays.

use std::sync::{Arc, Mutex};

use patina_dst_abi::{ClockKind, OpenFlags};
use patina_dst_runtime::{
    Context, EntropyWait, RuntimeBuilder, RuntimeConfig, RuntimeError, TraceTransport,
};

const FINGERPRINT: &str = "patina-trace-growth-v1";

/// Holds the serialized trace bundle in memory, for measurement and replay.
#[derive(Clone, Default)]
struct CapturingTransport {
    bundle: Arc<Mutex<Vec<u8>>>,
}

impl CapturingTransport {
    fn bundle(&self) -> Vec<u8> {
        self.bundle.lock().unwrap().clone()
    }
}

impl TraceTransport for CapturingTransport {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Ok(self.bundle())
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        *self.bundle.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

/// One unit of work per iteration touching entropy, the clock, the
/// filesystem data plane and the scheduler.
fn workload(context: &mut Context, iterations: usize) -> Result<(), RuntimeError> {
    for index in 0..iterations {
        let bytes = context.entropy_bytes(16, EntropyWait::UntilReady)?;
        let _ = context.now(ClockKind::Monotonic)?;

        let path = format!("/bench/{index}");
        let fd = context.fs_open(&path, OpenFlags::create_truncate_write())?;
        context.fs_write(fd, &bytes)?;
        context.fs_sync(fd)?;
        context.fs_close(fd)?;

        let read = context.fs_open(&path, OpenFlags::read_only())?;
        let _ = context.fs_read(read, 64)?;
        context.fs_close(read)?;

        let task = context.task_spawn("bench")?;
        let _ = context.scheduler_next()?;
        context.task_complete(task)?;
    }
    Ok(())
}

/// The boundary-operation count of a seeded run.
fn seeded_ops(iterations: usize) -> u64 {
    let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .build()
        .unwrap();
    workload(&mut context, iterations).unwrap();
    let ops = context.steps();
    context.finish().unwrap();
    ops
}

/// A recording's event count and its bundle.
fn record(iterations: usize) -> (u64, CapturingTransport) {
    let transport = CapturingTransport::default();
    let mut context = RuntimeBuilder::new(RuntimeConfig::record_transport(1, FINGERPRINT))
        .with_trace_transport(transport.clone())
        .build()
        .unwrap();
    workload(&mut context, iterations).unwrap();
    let events = context.steps();
    context.finish().unwrap();
    (events, transport)
}

#[test]
fn recording_has_one_event_per_boundary_op() {
    let ops_one = seeded_ops(1);
    let ops_ten = seeded_ops(10);
    assert!(ops_one > 0);
    assert_eq!(ops_ten, ops_one * 10);
    assert_eq!(record(10).0, ops_ten);
}

#[test]
fn the_recorded_workload_replays() {
    let (_, transport) = record(200);

    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        FINGERPRINT,
    ))
    .with_trace_transport(transport)
    .build()
    .unwrap();
    workload(&mut replay, 200).unwrap();
    replay.finish().unwrap();
}
