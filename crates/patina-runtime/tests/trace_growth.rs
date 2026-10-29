//! Trace growth for a representative workload: one recorded event per
//! boundary operation, a serialized size linear in the work, and bytes per
//! event within a budget. The trace encoding alone decides these, so they hold
//! on every machine.

use std::sync::{Arc, Mutex};

use patina_dst_abi::{ClockKind, OpenFlags};
use patina_dst_runtime::{
    Context, EntropyWait, RuntimeBuilder, RuntimeConfig, RuntimeError, TraceTransport,
};

/// Maximum serialized bytes per recorded boundary event for the workload. The
/// workload measures about 124 bytes per event (compact JSON with base64 byte
/// payloads); the budget leaves headroom for minor encoding changes while
/// catching a blow-up such as a return to number arrays or pretty printing.
const MAX_TRACE_BYTES_PER_EVENT: f64 = 160.0;

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
        .with_default_drivers()
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
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()
        .unwrap();
    workload(&mut context, iterations).unwrap();
    let events = context.steps();
    context.finish().unwrap();
    (events, transport)
}

#[test]
fn recording_is_linear_with_one_event_per_boundary_op() {
    let ops_one = seeded_ops(1);
    let ops_ten = seeded_ops(10);
    assert!(ops_one > 0);
    assert_eq!(ops_ten, ops_one * 10);
    assert_eq!(record(10).0, ops_ten);

    let small = record(100).1.bundle().len();
    let large = record(200).1.bundle().len();
    let ratio = large as f64 / small as f64;
    assert!(
        (1.8..=2.2).contains(&ratio),
        "doubling the workload changed trace size by {ratio:.2}x, expected ~2x"
    );
}

/// The recording also replays, so a replay mismatch fails here too.
#[test]
fn trace_growth_stays_within_budget() {
    let (events, transport) = record(200);
    let bytes_per_event = transport.bundle().len() as f64 / events.max(1) as f64;
    assert!(
        bytes_per_event <= MAX_TRACE_BYTES_PER_EVENT,
        "trace grew to {bytes_per_event:.1} bytes/event, budget is {MAX_TRACE_BYTES_PER_EVENT:.0}"
    );

    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        FINGERPRINT,
    ))
    .with_default_drivers()
    .with_trace_transport(transport)
    .build()
    .unwrap();
    workload(&mut replay, 200).unwrap();
    replay.finish().unwrap();
}
