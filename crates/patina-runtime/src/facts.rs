//! Runtime-owned structured run facts (`patina.runfacts/v1`).
//!
//! Every end-of-run diagnostic the runtime prints to stderr as a
//! `PATINA_*_REPORT` line is *also* available as a structured document, built
//! from the same report structs the lines are formatted from — never by parsing
//! a line back. `cargo patina` reads the document and folds it into the
//! `patina.result/v1` envelope's `fault_reports` / `runtime_findings` fields, so
//! a consumer that wants the facts machine-readably never has to re-derive them
//! from human text.
//!
//! The document is emitted only when the embedder installs an output channel
//! (`RuntimeConfig::with_facts_path`, `RuntimeBuilder::with_facts_sink`, or the
//! [`ENV_FACTS`](crate::ENV_FACTS) / [`ENV_FACTS_FD`](crate::ENV_FACTS_FD)
//! control-plane variables), so a run that nobody asked facts of behaves exactly
//! as before.
//!
//! Deliberately independent of the report-suppression knobs
//! ([`ReportConfig`](crate::ReportConfig)): those decide what *prints*, and the
//! facts channel is not printing. A consumer must not be able to blind the
//! structured channel by silencing a human diagnostic.
//!
//! Field order is fixed (`serde_json::Map` is ordered), and every value is an
//! integer, boolean, or a stable token, so the same run emits byte-identical
//! facts on a repeat.

use std::io;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::{LivenessViolation, ScheduleDiagnostics};

/// The stable schema identifier of the facts document.
pub const FACTS_SCHEMA: &str = "patina.runfacts/v1";

/// A byte channel the runtime writes its facts document to.
///
/// Exists for the same reason [`TraceTransport`](crate::TraceTransport) does:
/// inside the native shim the guest's ordinary file I/O is interposed, so the
/// document must travel over a supervisor-provided host descriptor written with
/// the shim's private host aliases rather than through `std::fs`.
pub trait FactsSink: Send {
    /// Write the complete facts document. Called at most once per run.
    fn write_facts(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// Where a run's facts document goes: a path the runtime writes with `std::fs`
/// (the cargo family and in-process embedders such as the WASI host), or an
/// embedder-installed byte sink (the native shim's host descriptor).
pub(crate) enum FactsOutput {
    Path(PathBuf),
    Sink(Box<dyn FactsSink>),
}

impl FactsOutput {
    pub(crate) fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            FactsOutput::Path(path) => std::fs::write(path, bytes),
            FactsOutput::Sink(sink) => sink.write_facts(bytes),
        }
    }
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

/// The frozen-clock-churn finding: advance-on-spin fed a spinning guest
/// `rescues` token advances totalling `advanced_ns` of virtual time and it still
/// made no genuine progress. Carries the same fields as the
/// `PATINA_VIOLATION liveness detail=frozen-clock-churn` line.
pub(crate) fn frozen_clock_churn_finding(
    vtime_ns: u64,
    rescues: u64,
    advanced_ns: u64,
    clock_ops_per_rescue: u64,
) -> Value {
    object(vec![
        ("source", Value::from("liveness")),
        ("kind", Value::from("liveness")),
        ("detail", Value::from("frozen-clock-churn")),
        ("vtime_ns", Value::from(vtime_ns)),
        ("rescues", Value::from(rescues)),
        ("advanced_ns", Value::from(advanced_ns)),
        ("clock_ops_per_rescue", Value::from(clock_ops_per_rescue)),
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

/// The vacuous-starvation finding: scheduling decisions that would have starved
/// every runnable task and were forced to schedule anyway.
pub(crate) fn vacuous_starvation_finding(starve_vacuous: u64) -> Value {
    object(vec![
        ("source", Value::from("schedule")),
        ("kind", Value::from("vacuous_starvation")),
        ("detail", Value::from("starves-only-runnable-task")),
        ("decisions", Value::from(starve_vacuous)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_carries_only_the_schema() {
        let value = document(Map::new(), Vec::new());
        assert_eq!(value["schema"], FACTS_SCHEMA);
        assert!(value.get("fault_reports").is_none());
        assert!(value.get("runtime_findings").is_none());
    }

    #[test]
    fn fs_plane_carries_the_line_fields_including_the_breakdowns() {
        let mut report = patina_dst_driver_api::FsFaultReport {
            eligible_ops: 40,
            error_vacuity_diagnosable: true,
            errors_injected: 3,
            ..Default::default()
        };
        report
            .errors_by_op
            .record(patina_dst_driver_api::FsFaultOpKind::Open);
        report
            .errors_by_op
            .record(patina_dst_driver_api::FsFaultOpKind::Read);
        report
            .errors_by_op
            .record(patina_dst_driver_api::FsFaultOpKind::Read);
        let value = fs_plane(&report);
        assert_eq!(value["eligible_ops"], 40);
        assert_eq!(value["error_vacuity_diagnosable"], true);
        assert_eq!(value["errors_injected"], 3);
        assert_eq!(value["errors_by_op"]["open"], 1);
        assert_eq!(value["errors_by_op"]["read"], 2);
        // An empty breakdown is an empty object, never a missing key.
        assert_eq!(value["shorts_by_op"], serde_json::json!({}));
        assert_eq!(value["vacuous"], false);
    }

    #[test]
    fn fs_plane_reports_the_vacuity_bit_the_line_reports() {
        let report = patina_dst_driver_api::FsFaultReport {
            eligible_ops: 40,
            error_vacuity_diagnosable: true,
            errors_injected: 0,
            ..Default::default()
        };
        assert_eq!(fs_plane(&report)["vacuous"], true);
    }

    #[test]
    fn the_schedule_plane_and_its_finding_report_unschedulable_workers() {
        let diagnostics = ScheduleDiagnostics {
            tasks_spawned: 3,
            max_concurrent: 3,
            total_boundaries: 17,
            tasks: vec![crate::TaskScheduleStat {
                task: patina_dst_abi::TaskId(2),
                yields: 4,
                parks: 0,
                boundaries: 4,
                lifetime: 12,
                cause: crate::TaskCompletionCause::Completed,
                vacuous: true,
            }],
            vacuous: vec![patina_dst_abi::TaskId(2), patina_dst_abi::TaskId(3)],
        };
        let plane = schedule_plane(&diagnostics);
        assert_eq!(plane["tasks_spawned"], 3);
        assert_eq!(plane["vacuous_threads"], 2);
        assert_eq!(plane["vacuous"], true);
        assert_eq!(plane["tasks"][0]["cause"], "completed");
        assert_eq!(plane["tasks"][0]["vacuous"], true);

        let finding = vacuous_schedule_finding(&diagnostics);
        assert_eq!(finding["source"], "schedule");
        assert_eq!(finding["kind"], "vacuous_schedule");
        assert_eq!(finding["tasks"], serde_json::json!([2, 3]));

        // A run whose workers all yielded is not vacuous, and reports no finding.
        let explored = ScheduleDiagnostics {
            vacuous: Vec::new(),
            ..diagnostics
        };
        assert_eq!(schedule_plane(&explored)["vacuous"], false);
    }

    #[test]
    fn the_liveness_finding_carries_the_violation_lines_fields() {
        let finding = liveness_finding(&LivenessViolation {
            kind: crate::LivenessKind::HealThenConverge,
            vtime_ns: 400,
            budget_ns: 300,
            last_fault_vtime_ns: 10,
        });
        assert_eq!(finding["source"], "liveness");
        assert_eq!(finding["kind"], "converge");
        assert_eq!(finding["detail"], "did-not-converge");
        assert_eq!(finding["vtime_ns"], 400);
        assert_eq!(finding["budget_ns"], 300);
        assert_eq!(finding["last_fault_vtime_ns"], 10);
    }

    #[test]
    fn document_serializes_byte_identically_on_a_repeat() {
        let build = || {
            let mut planes = Map::new();
            planes.insert(
                "entropy".into(),
                entropy_plane(&patina_dst_driver_api::EntropyFaultReport {
                    requests: 40,
                    fail_vacuity_diagnosable: true,
                    failures_injected: 0,
                }),
            );
            planes.insert(
                "clock".into(),
                clock_plane(&patina_dst_driver_api::ClockFaultReport {
                    reads: 12,
                    jump_vacuity_diagnosable: false,
                    jumps_applied: 0,
                }),
            );
            serde_json::to_string(&document(planes, vec![vacuous_starvation_finding(4)])).unwrap()
        };
        assert_eq!(build(), build());
        let value: Value = serde_json::from_str(&build()).unwrap();
        assert_eq!(value["fault_reports"]["entropy"]["vacuous"], true);
        assert_eq!(value["runtime_findings"][0]["kind"], "vacuous_starvation");
        assert_eq!(value["runtime_findings"][0]["decisions"], 4);
    }
}
