//! Performance qualification for the Patina runtime.
//!
//! This crate measures three qualities called out as release budgets in
//! `VALIDATION.md`:
//!
//! - **runtime overhead**: wall-clock cost per boundary operation in seeded
//!   execution, and the multiplier that record and replay add;
//! - **trace growth**: serialized bytes produced per recorded boundary event;
//! - **campaign performance**: throughput of running many independent seeded
//!   contexts, a proxy for a `cargo patina explore` seed campaign.
//!
//! It drives a fixed, representative workload across the default deterministic
//! drivers so the numbers are comparable run to run. The only machine-independent
//! quantity — trace growth — is enforced as a hard budget in the test suite;
//! the timing figures are reported for tracking and guarded by generous
//! sanity ceilings behind `#[ignore]` so shared CI runners do not flake.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use patina_dst_abi::{ClockKind, OpenFlags};
use patina_dst_runtime::{Context, RuntimeBuilder, RuntimeConfig, RuntimeError, TraceTransport};

/// Maximum serialized bytes per recorded boundary event for the representative
/// workload. This is deterministic given the trace encoding, so it is a real,
/// machine-independent budget. The workload measures ~123.6 bytes/event under
/// the format 3 encoding (compact JSON with base64 byte payloads), down from
/// ~344 under the previous pretty-JSON number-array encoding. The budget leaves
/// modest headroom for minor encoding changes while still catching a blow-up
/// such as a regression back to number arrays or pretty printing.
pub const MAX_TRACE_BYTES_PER_EVENT: f64 = 150.0;

/// A generous per-operation ceiling for seeded execution, in nanoseconds. Used
/// only by the opt-in timing guard; sized to catch pathological regressions
/// (orders of magnitude), not to police normal variance.
pub const MAX_SEEDED_NANOS_PER_OP: f64 = 50_000.0;

/// A generous ceiling on how many times slower record mode may be than seeded
/// mode. Recording appends one in-memory event per boundary op, so the ratio
/// is expected to stay small.
pub const MAX_RECORD_OVERHEAD_RATIO: f64 = 12.0;

/// Captures a serialized trace bundle in memory so trace growth can be measured
/// and replayed without touching the filesystem.
#[derive(Clone, Default)]
pub struct CapturingTransport {
    bundle: Arc<Mutex<Vec<u8>>>,
}

impl CapturingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// The serialized bundle written at record finalization.
    pub fn bundle(&self) -> Vec<u8> {
        self.bundle
            .lock()
            .expect("transport mutex poisoned")
            .clone()
    }
}

impl TraceTransport for CapturingTransport {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Ok(self.bundle())
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        *self.bundle.lock().expect("transport mutex poisoned") = bytes.to_vec();
        Ok(())
    }
}

/// The compatibility fingerprint used for record/replay qualification runs.
const FINGERPRINT: &str = "patina-dst-bench-v1";

/// Drive one representative unit of work touching entropy, the clock, the
/// filesystem data plane, and the scheduler. Returns the boundary-operation
/// count so callers can normalize timings.
fn workload(context: &mut Context, iterations: usize) -> Result<(), RuntimeError> {
    for index in 0..iterations {
        let bytes = context.entropy_bytes(16)?;
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

/// A completed qualification measurement.
#[derive(Clone, Debug)]
pub struct Report {
    pub iterations: usize,
    pub boundary_ops: u64,
    pub seeded_nanos: u128,
    pub record_nanos: u128,
    pub replay_nanos: u128,
    pub trace_bytes: usize,
    pub events: u64,
    pub campaign_runs: usize,
    pub campaign_nanos: u128,
}

impl Report {
    pub fn seeded_nanos_per_op(&self) -> f64 {
        self.seeded_nanos as f64 / self.boundary_ops.max(1) as f64
    }

    pub fn record_nanos_per_op(&self) -> f64 {
        self.record_nanos as f64 / self.boundary_ops.max(1) as f64
    }

    pub fn replay_nanos_per_op(&self) -> f64 {
        self.replay_nanos as f64 / self.boundary_ops.max(1) as f64
    }

    /// How many times slower recording is than seeded execution.
    pub fn record_overhead_ratio(&self) -> f64 {
        self.record_nanos as f64 / self.seeded_nanos.max(1) as f64
    }

    /// Serialized trace bytes per recorded boundary event.
    pub fn bytes_per_event(&self) -> f64 {
        self.trace_bytes as f64 / self.events.max(1) as f64
    }

    pub fn campaign_runs_per_sec(&self) -> f64 {
        self.campaign_runs as f64 / (self.campaign_nanos.max(1) as f64 / 1e9)
    }

    pub fn campaign_ops_per_sec(&self) -> f64 {
        (self.campaign_runs as u64 * self.boundary_ops) as f64
            / (self.campaign_nanos.max(1) as f64 / 1e9)
    }

    /// Render the report as a fixed, human-readable block.
    pub fn render(&self) -> String {
        format!(
            "Patina performance qualification\n\
             workload iterations      : {}\n\
             boundary ops per run     : {}\n\
             seeded ns/op             : {:.1}\n\
             record ns/op             : {:.1}\n\
             replay ns/op             : {:.1}\n\
             record overhead ratio    : {:.2}x\n\
             trace bytes              : {}\n\
             recorded events          : {}\n\
             trace bytes/event        : {:.1}  (budget {:.0})\n\
             campaign runs            : {}\n\
             campaign runs/sec        : {:.0}\n\
             campaign ops/sec         : {:.0}",
            self.iterations,
            self.boundary_ops,
            self.seeded_nanos_per_op(),
            self.record_nanos_per_op(),
            self.replay_nanos_per_op(),
            self.record_overhead_ratio(),
            self.trace_bytes,
            self.events,
            self.bytes_per_event(),
            MAX_TRACE_BYTES_PER_EVENT,
            self.campaign_runs,
            self.campaign_runs_per_sec(),
            self.campaign_ops_per_sec(),
        )
    }
}

fn seeded_context(seed: u64) -> Result<Context, RuntimeError> {
    RuntimeBuilder::new(RuntimeConfig::seeded(seed))
        .with_default_drivers()
        .build()
}

/// Measure seeded execution time and the boundary-operation count.
fn measure_seeded(iterations: usize) -> Result<(u128, u64), RuntimeError> {
    let mut context = seeded_context(1)?;
    let start = Instant::now();
    workload(&mut context, iterations)?;
    let elapsed = start.elapsed().as_nanos();
    let ops = context.steps();
    context.finish()?;
    Ok((elapsed, ops))
}

/// Measure record execution time, serialized trace size, and event count.
fn measure_record(iterations: usize) -> Result<(u128, usize, u64), RuntimeError> {
    let transport = CapturingTransport::new();
    let mut context = RuntimeBuilder::new(RuntimeConfig::record_transport(1, FINGERPRINT))
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()?;
    let start = Instant::now();
    workload(&mut context, iterations)?;
    let elapsed = start.elapsed().as_nanos();
    let events = context.steps();
    context.finish()?;
    let trace_bytes = transport.bundle().len();
    Ok((elapsed, trace_bytes, events))
}

/// Measure replay execution time over a freshly recorded bundle.
fn measure_replay(iterations: usize) -> Result<u128, RuntimeError> {
    let transport = CapturingTransport::new();
    let mut record = RuntimeBuilder::new(RuntimeConfig::record_transport(1, FINGERPRINT))
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()?;
    workload(&mut record, iterations)?;
    record.finish()?;

    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        FINGERPRINT,
    ))
    .with_default_drivers()
    .with_trace_transport(transport)
    .build()?;
    let start = Instant::now();
    workload(&mut replay, iterations)?;
    let elapsed = start.elapsed().as_nanos();
    replay.finish()?;
    Ok(elapsed)
}

/// Measure the time to run `runs` independent seeded contexts.
fn measure_campaign(runs: usize, iterations: usize) -> Result<u128, RuntimeError> {
    let start = Instant::now();
    for seed in 0..runs as u64 {
        let mut context = seeded_context(seed)?;
        workload(&mut context, iterations)?;
        context.finish()?;
    }
    Ok(start.elapsed().as_nanos())
}

/// Run the full qualification and collect a [`Report`].
pub fn qualify(iterations: usize, campaign_runs: usize) -> Result<Report, RuntimeError> {
    let (seeded_nanos, boundary_ops) = measure_seeded(iterations)?;
    let (record_nanos, trace_bytes, events) = measure_record(iterations)?;
    let replay_nanos = measure_replay(iterations)?;
    let campaign_nanos = measure_campaign(campaign_runs, iterations)?;
    Ok(Report {
        iterations,
        boundary_ops,
        seeded_nanos,
        record_nanos,
        replay_nanos,
        trace_bytes,
        events,
        campaign_runs,
        campaign_nanos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_boundary_op_count_scales_with_iterations() {
        // The workload must issue a stable number of boundary operations per
        // iteration so timing and trace-growth figures are comparable.
        let (_, ops_one) = measure_seeded(1).unwrap();
        let (_, ops_ten) = measure_seeded(10).unwrap();
        assert!(ops_one > 0);
        assert_eq!(ops_ten, ops_one * 10);
    }

    #[test]
    fn record_emits_exactly_one_event_per_boundary_op() {
        // Recording must not amplify: growth stays linear in boundary ops.
        let mut context = seeded_context(1).unwrap();
        workload(&mut context, 5).unwrap();
        let seeded_ops = context.steps();
        context.finish().unwrap();

        let (_, _, events) = measure_record(5).unwrap();
        assert_eq!(events, seeded_ops);
    }

    #[test]
    fn trace_growth_stays_within_budget() {
        // Deterministic, machine-independent budget gate.
        let report = qualify(200, 1).unwrap();
        let bytes_per_event = report.bytes_per_event();
        assert!(
            bytes_per_event <= MAX_TRACE_BYTES_PER_EVENT,
            "trace grew to {bytes_per_event:.1} bytes/event, budget is {MAX_TRACE_BYTES_PER_EVENT:.0}"
        );
    }

    #[test]
    fn trace_growth_is_linear_in_boundary_ops() {
        let (_, small, _) = measure_record(100).unwrap();
        let (_, large, _) = measure_record(200).unwrap();
        let ratio = large as f64 / small as f64;
        assert!(
            (1.8..=2.2).contains(&ratio),
            "doubling the workload changed trace size by {ratio:.2}x, expected ~2x"
        );
    }

    #[test]
    fn replay_reproduces_the_recorded_workload() {
        // Replay must complete without a mismatch, otherwise the timing figure
        // would be meaningless.
        assert!(measure_replay(50).is_ok());
    }

    // Timing guards are opt-in: they depend on the host and would flake as
    // hard CI gates. Run with `cargo test -p patina-dst-bench -- --ignored`.
    #[test]
    #[ignore = "machine-dependent timing guard"]
    fn seeded_overhead_within_sanity_ceiling() {
        let report = qualify(2000, 1).unwrap();
        assert!(
            report.seeded_nanos_per_op() <= MAX_SEEDED_NANOS_PER_OP,
            "{}",
            report.render()
        );
    }

    #[test]
    #[ignore = "machine-dependent timing guard"]
    fn record_overhead_within_sanity_ceiling() {
        let report = qualify(2000, 1).unwrap();
        assert!(
            report.record_overhead_ratio() <= MAX_RECORD_OVERHEAD_RATIO,
            "{}",
            report.render()
        );
    }
}
