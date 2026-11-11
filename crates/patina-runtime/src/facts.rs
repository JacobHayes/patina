//! Runtime-owned structured run facts (`patina.runfacts/v1`): the one machine
//! channel out of a run. The per-plane fault accounting, the runtime-detected
//! findings, the guest's verdicts, the cooperative-SUT site counters and the
//! exploration-policy accounting all travel here, built from the same report
//! structs the human `PATINA_*` stderr lines are formatted from. Those lines are
//! for a reader; nothing parses them back. `patina` folds the document
//! into the `patina.result/v2` envelope.
//!
//! The document is emitted only when the embedder installs an output channel
//! (`RuntimeBuilder::with_facts_sink`, which the native shim backs with the
//! [`ENV_FACTS_FD`](crate::ENV_FACTS_FD) descriptor), so a run that nobody asked
//! facts of behaves exactly as before.
//!
//! Field order is fixed (`serde_json::Map` is ordered), and every value is an
//! integer, boolean, or a stable token, so the same run emits byte-identical
//! facts on a repeat.

use std::io;

use serde_json::{Map, Value};

use crate::ScheduleDiagnostics;
use crate::liveness::LivenessViolation;
use patina_dst_abi::TaskId;

/// The stable schema identifier of the facts document.
pub const FACTS_SCHEMA: &str = "patina.runfacts/v1";

/// A byte channel the runtime writes its facts document to.
///
/// Exists for the same reason [`TraceTransport`](crate::TraceTransport) does:
/// inside the native shim the guest's ordinary file I/O is interposed, so the
/// document must travel over a supervisor-provided host descriptor written with
/// the shim's private host aliases rather than through `std::fs`.
pub trait FactsSink: Send {
    /// Write one complete, newline-terminated facts document. A run may write
    /// several, each superseding the last: an appending sink leaves the reader
    /// the final complete line.
    fn write_facts(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// The next process-unique context number for the facts channel.
pub(crate) fn next_context() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Build the facts document from the per-plane report structs and findings the
/// caller has already gathered. Pure, so the exact wire shape is unit-testable
/// without a run.
pub(crate) fn document(planes: Map<String, Value>, findings: Vec<Value>) -> Value {
    let mut root = Map::new();
    root.insert("schema".into(), Value::from(FACTS_SCHEMA));
    if !planes.is_empty() {
        root.insert("fault_reports".into(), Value::Object(planes));
    }
    if !findings.is_empty() {
        root.insert("runtime_findings".into(), Value::Array(findings));
    }
    Value::Object(root)
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

/// The per-operation-kind breakdown as an object, in `FsFaultOpKind::ALL` order.
/// An empty breakdown is an empty object (the line's `-` sentinel), never a
/// missing key: "this class landed nowhere" and "this class was not reported"
/// must stay distinguishable.
fn op_counts(counts: &patina_dst_driver_api::FsOpCounts) -> Value {
    let mut map = Map::new();
    for (kind, count) in counts.nonzero() {
        map.insert(kind.name().to_string(), Value::from(count));
    }
    Value::Object(map)
}

pub(crate) fn fs_plane(report: &patina_dst_driver_api::FsFaultReport) -> Value {
    object(vec![
        ("eligible_ops", Value::from(report.eligible_ops)),
        (
            "error_vacuity_diagnosable",
            Value::from(report.error_vacuity_diagnosable),
        ),
        ("errors_injected", Value::from(report.errors_injected)),
        ("errors_by_op", op_counts(&report.errors_by_op)),
        ("targets_missed", Value::from(report.targets_missed)),
        (
            "short_vacuity_diagnosable",
            Value::from(report.short_vacuity_diagnosable),
        ),
        ("shorts_applied", Value::from(report.shorts_applied)),
        ("shorts_by_op", op_counts(&report.shorts_by_op)),
        (
            "latency_vacuity_diagnosable",
            Value::from(report.latency_vacuity_diagnosable),
        ),
        ("latency_applied", Value::from(report.latency_applied)),
        ("vacuous", Value::from(report.is_vacuous())),
    ])
}

pub(crate) fn dns_plane(report: &patina_dst_driver_api::DnsFaultReport) -> Value {
    object(vec![
        ("resolutions", Value::from(report.resolutions)),
        (
            "fail_vacuity_diagnosable",
            Value::from(report.fail_vacuity_diagnosable),
        ),
        ("failures_injected", Value::from(report.failures_injected)),
        (
            "latency_vacuity_diagnosable",
            Value::from(report.latency_vacuity_diagnosable),
        ),
        ("latency_applied", Value::from(report.latency_applied)),
        ("vacuous", Value::from(report.is_vacuous())),
    ])
}

pub(crate) fn net_plane(report: &patina_dst_driver_api::NetFaultReport) -> Value {
    object(vec![
        ("send_ops", Value::from(report.send_ops)),
        (
            "drop_vacuity_diagnosable",
            Value::from(report.drop_vacuity_diagnosable),
        ),
        ("drops_applied", Value::from(report.drops_applied)),
        (
            "jitter_vacuity_diagnosable",
            Value::from(report.jitter_vacuity_diagnosable),
        ),
        ("jitter_applied", Value::from(report.jitter_applied)),
        (
            "latency_vacuity_diagnosable",
            Value::from(report.latency_vacuity_diagnosable),
        ),
        ("latency_applied", Value::from(report.latency_applied)),
        (
            "duplicate_vacuity_diagnosable",
            Value::from(report.duplicate_vacuity_diagnosable),
        ),
        ("duplicates_applied", Value::from(report.duplicates_applied)),
        ("connect_ops", Value::from(report.connect_ops)),
        (
            "connect_refuse_vacuity_diagnosable",
            Value::from(report.connect_refuse_vacuity_diagnosable),
        ),
        ("connects_refused", Value::from(report.connects_refused)),
        ("stream_ops", Value::from(report.stream_ops)),
        (
            "reset_vacuity_diagnosable",
            Value::from(report.reset_vacuity_diagnosable),
        ),
        ("resets_injected", Value::from(report.resets_injected)),
        (
            "partition_vacuity_diagnosable",
            Value::from(report.partition_vacuity_diagnosable),
        ),
        ("partition_blocks", Value::from(report.partition_blocks)),
        ("vacuous", Value::from(report.is_vacuous())),
    ])
}

pub(crate) fn entropy_plane(report: &patina_dst_driver_api::EntropyFaultReport) -> Value {
    object(vec![
        ("requests", Value::from(report.requests)),
        (
            "fail_vacuity_diagnosable",
            Value::from(report.fail_vacuity_diagnosable),
        ),
        ("failures_injected", Value::from(report.failures_injected)),
        ("vacuous", Value::from(report.is_vacuous())),
    ])
}

pub(crate) fn clock_plane(report: &patina_dst_driver_api::ClockFaultReport) -> Value {
    object(vec![
        ("reads", Value::from(report.reads)),
        (
            "jump_vacuity_diagnosable",
            Value::from(report.jump_vacuity_diagnosable),
        ),
        ("jumps_applied", Value::from(report.jumps_applied)),
        ("vacuous", Value::from(report.is_vacuous())),
    ])
}

pub(crate) fn swarm_plane(record: &patina_dst_trace::SwarmConfigRecord) -> Value {
    let selected = record.selected_classes.len();
    let classes: Vec<Value> = record
        .candidate_classes
        .iter()
        .map(|class| {
            object(vec![
                ("class", Value::from(class.clone())),
                ("selected", Value::from(!record.deselected(class))),
            ])
        })
        .collect();
    object(vec![
        ("candidates", Value::from(record.candidate_classes.len())),
        ("selected", Value::from(selected)),
        (
            "deselected",
            Value::from(record.candidate_classes.len() - selected),
        ),
        ("classes", Value::Array(classes)),
        ("vacuous", Value::from(record.is_vacuous())),
    ])
}

/// The verdicts the guest reported through the verdict ABI, in call order.
pub(crate) fn verdicts(records: &[crate::VerdictRecord]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|record| {
                object(vec![
                    ("seq", Value::from(record.seq)),
                    ("kind", Value::from(record.kind.as_str())),
                    ("label", Value::from(record.label.clone())),
                    ("detail", Value::from(record.detail.clone())),
                ])
            })
            .collect(),
    )
}

/// The cooperative-SUT (SDK) site accounting: the run-level buggify state, the
/// link-time declared sites, and every evaluated site's counters.
pub(crate) fn sdk(diag: &crate::BuggifyDiagnostics) -> Value {
    let declared: Vec<Value> = diag
        .declared_sites
        .iter()
        .map(|site| {
            object(vec![
                ("label", Value::from(site.label.clone())),
                ("kind", Value::from(site.kind.as_str())),
                ("site", Value::from(site.site.clone())),
            ])
        })
        .collect();
    let sites: Vec<Value> = diag
        .sites
        .iter()
        .map(|site| {
            object(vec![
                ("label", Value::from(site.label.clone())),
                ("kind", Value::from(site.kind.as_str())),
                ("site", Value::from(site.site.clone())),
                ("active", Value::from(site.active)),
                ("evals", Value::from(site.evals)),
                ("fires", Value::from(site.fires)),
                ("reachable", Value::from(site.reachable)),
                ("sometimes_satisfied", Value::from(site.sometimes_satisfied)),
                ("always_violated", Value::from(site.always_violated)),
                ("knob", site.knob.map_or(Value::Null, Value::from)),
            ])
        })
        .collect();
    object(vec![
        ("enabled", Value::from(diag.enabled)),
        ("swarm_deselected", Value::from(diag.swarm_deselected)),
        ("fire_permille", Value::from(diag.fire_permille)),
        ("activation_permille", Value::from(diag.activation_permille)),
        ("cutoff_nanos", Value::from(diag.cutoff_nanos)),
        ("cutoff_reached", Value::from(diag.cutoff_reached)),
        ("sites_registered", Value::from(diag.sites_registered)),
        ("sites_activated", Value::from(diag.sites_activated)),
        ("total_firings", Value::from(diag.total_firings)),
        ("cutoff_suppressed", Value::from(diag.cutoff_suppressed)),
        ("after_setup", Value::from(diag.after_setup)),
        ("setup_complete", Value::from(diag.setup_complete)),
        ("declared_sites", Value::Array(declared)),
        ("sites", Value::Array(sites)),
    ])
}

/// The exploration-policy (PCT) accounting, with the bug-depth
/// estimate a found failure is annotated with.
pub(crate) fn schedule_policy(report: &crate::scheduler::SchedulePolicyReport) -> Value {
    object(vec![
        ("pct", Value::from(report.pct)),
        ("pct_depth", Value::from(report.pct_depth)),
        ("pct_change_points", Value::from(report.pct_change_points)),
        (
            "pct_change_points_hit",
            Value::from(report.pct_change_points_hit),
        ),
        ("decisions", Value::from(report.decisions)),
        ("bug_depth", Value::from(report.bug_depth())),
    ])
}

/// The schedule plane. `vacuous` mirrors the loud vacuous-schedule warning's
/// condition, so the plane answers "was this run's concurrency explorable?"
/// with the same bit the human diagnostic uses.
pub(crate) fn schedule_plane(diagnostics: &ScheduleDiagnostics) -> Value {
    let tasks: Vec<Value> = diagnostics
        .tasks
        .iter()
        .map(|stat| {
            object(vec![
                ("task", Value::from(stat.task.0)),
                ("yields", Value::from(stat.yields)),
                ("parks", Value::from(stat.parks)),
                ("boundaries", Value::from(stat.boundaries)),
                ("lifetime", Value::from(stat.lifetime)),
                ("cause", Value::from(stat.cause.as_str())),
                ("vacuous", Value::from(stat.vacuous)),
            ])
        })
        .collect();
    object(vec![
        ("tasks_spawned", Value::from(diagnostics.tasks_spawned)),
        ("max_concurrent", Value::from(diagnostics.max_concurrent)),
        (
            "total_boundaries",
            Value::from(diagnostics.total_boundaries),
        ),
        ("vacuous_threads", Value::from(diagnostics.vacuous.len())),
        ("tasks", Value::Array(tasks)),
        ("vacuous", Value::from(!diagnostics.vacuous.is_empty())),
    ])
}

/// A liveness/converge watchdog finding, carrying the same fields as the
/// `PATINA_VIOLATION liveness|converge` interface-contract line.
pub(crate) fn liveness_finding(violation: &LivenessViolation) -> Value {
    object(vec![
        ("source", Value::from("liveness")),
        ("kind", Value::from(violation.kind.as_str())),
        ("detail", Value::from(violation.kind.reason())),
        ("vtime_ns", Value::from(violation.vtime_ns)),
        ("budget_ns", Value::from(violation.budget_ns)),
        (
            "last_fault_vtime_ns",
            Value::from(violation.last_fault_vtime_ns),
        ),
    ])
}

/// A terminal native runtime limitation, explicitly not a guest bug verdict.
#[derive(serde::Serialize)]
struct ComputeBoundFinding {
    source: &'static str,
    kind: &'static str,
    detail: &'static str,
    known_limit: bool,
    /// `null` for the main thread of a run that had no task yet.
    task: Option<u64>,
    steps: u64,
}

/// The sole wire shape, serialized into the caller's fixed storage. No Value,
/// String, Vec, or finish-time enrichment on the asynchronous stop path.
pub(crate) fn write_compute_bound_facts(
    context: u64,
    stop: patina_dst_trace::ComputeStop,
    writer: impl io::Write,
) -> serde_json::Result<()> {
    #[derive(serde::Serialize)]
    struct Envelope {
        schema: &'static str,
        context: u64,
        runtime_findings: [ComputeBoundFinding; 1],
    }
    serde_json::to_writer(
        writer,
        &Envelope {
            schema: FACTS_SCHEMA,
            context,
            runtime_findings: [ComputeBoundFinding {
                source: "liveness",
                kind: "liveness",
                detail: "compute-bound",
                known_limit: true,
                task: stop.task.map(|task| task.0),
                steps: stop.steps,
            }],
        },
    )
}

/// The compute budget's finding: the guest charged `compute_ns` of metered
/// computation, past `budget_ns`, with no operation but scheduling points in
/// between. Carries the fields of the `PATINA_STOP compute_bound` line.
pub(crate) fn compute_budget_finding(
    task: Option<TaskId>,
    compute_ns: u64,
    budget_ns: u64,
) -> Value {
    object(vec![
        ("source", Value::from("compute")),
        ("kind", Value::from("compute_bound")),
        ("detail", Value::from("compute-budget")),
        ("known_limit", Value::from(false)),
        ("task", task.map_or(Value::Null, |task| Value::from(task.0))),
        ("compute_ns", Value::from(compute_ns)),
        ("budget_ns", Value::from(budget_ns)),
    ])
}

/// The vacuous-schedule finding: spawned workers whose interleavings were
/// unreachable at any seed. Same condition as the loud stderr warning.
pub(crate) fn vacuous_schedule_finding(diagnostics: &ScheduleDiagnostics) -> Value {
    let tasks: Vec<Value> = diagnostics
        .vacuous
        .iter()
        .map(|task| Value::from(task.0))
        .collect();
    object(vec![
        ("source", Value::from("schedule")),
        ("kind", Value::from("vacuous_schedule")),
        ("detail", Value::from("unschedulable-worker")),
        ("tasks", Value::Array(tasks)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_facts_fit_fixed_storage_even_at_maximum_integers() {
        let mut bytes = [0u8; 512];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        write_compute_bound_facts(
            u64::MAX,
            patina_dst_trace::ComputeStop {
                task: Some(patina_dst_abi::TaskId(u64::MAX)),
                steps: u64::MAX,
            },
            &mut cursor,
        )
        .unwrap();
        let length = cursor.position() as usize;
        let value: Value = serde_json::from_slice(&bytes[..length]).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"schema": FACTS_SCHEMA, "context": u64::MAX, "runtime_findings": [{
                "source": "liveness", "kind": "liveness", "detail": "compute-bound",
                "known_limit": true, "task": u64::MAX, "steps": u64::MAX,
            }]})
        );
        assert!(length < bytes.len()); // leaves space for the line terminator
    }
}
