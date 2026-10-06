//! Shared semantic view of a recorded trace.
//!
//! This module is the read-only decode layer behind both the HTML renderer and
//! the `cargo patina trace` inspection commands. It owns the scheduler-cursor
//! lane attribution walk, virtual-time reconstruction, operation categories,
//! one-line event summaries, notable-event detection, and the operation-kind
//! registry used for filter validation.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::Operation;
#[cfg(test)]
use patina_dst_abi::Outcome;
use patina_dst_trace::{LifecycleEvent, LifecycleEventKind, TraceBundle, TraceError};
use serde_json::Value;

mod summary;
pub use summary::*;
mod kinds;
pub use kinds::*;
#[cfg(test)]
mod fixtures;

#[cfg(test)]
pub(crate) use fixtures::representative_events_for_all_op_kinds;

/// The category a boundary operation falls into for lane coloring and rollups.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Schedule,
    Sleep,
    Net,
    Fs,
    Crash,
    Entropy,
    Clock,
    Other,
}

impl Category {
    pub fn of_kind(kind: &str) -> Self {
        op_kind_category(kind).unwrap_or_else(|| match kind {
            "fs_crash" | "lifecycle_crash" | "lifecycle_restart" => Category::Crash,
            "sleep_until" => Category::Sleep,
            "clock_now" => Category::Clock,
            "entropy_fill" => Category::Entropy,
            "scheduler_next" => Category::Schedule,
            _ if kind.starts_with("task_") => Category::Schedule,
            _ if kind.starts_with("net_") => Category::Net,
            _ if kind.starts_with("fs_") => Category::Fs,
            _ => Category::Other,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Schedule => "scheduling",
            Category::Sleep => "sleep",
            Category::Net => "network",
            Category::Fs => "filesystem",
            Category::Crash => "crash",
            Category::Entropy => "entropy",
            Category::Clock => "clock",
            Category::Other => "other",
        }
    }

    /// A stable CSS class suffix (also the color key in the renderer's stylesheet).
    pub fn css(self) -> &'static str {
        match self {
            Category::Schedule => "sched",
            Category::Sleep => "sleep",
            Category::Net => "net",
            Category::Fs => "fs",
            Category::Crash => "crash",
            Category::Entropy => "entropy",
            Category::Clock => "clock",
            Category::Other => "other",
        }
    }

    pub const ALL: [Category; 8] = [
        Category::Schedule,
        Category::Sleep,
        Category::Net,
        Category::Fs,
        Category::Crash,
        Category::Entropy,
        Category::Clock,
        Category::Other,
    ];

    pub fn parse_label(label: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.label() == label)
    }
}

/// A task lane in the flattened event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKey {
    /// Events attributed to no scheduled task (single-threaded runs and ops
    /// before the first scheduler decision).
    Main,
    Task(u64),
}

impl LaneKey {
    pub fn label(self) -> String {
        match self {
            LaneKey::Main => "main".to_string(),
            LaneKey::Task(id) => format!("task {id}"),
        }
    }

    pub fn json_value(self) -> Value {
        match self {
            LaneKey::Main => Value::from("main"),
            LaneKey::Task(id) => Value::from(id),
        }
    }
}

/// Why an event is notable enough to surface outside an aggregated timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notable {
    Error { code: String, message: String },
    Crash,
    Drop { to: String, reason: String },
}

impl Notable {
    pub fn kind(&self) -> &'static str {
        match self {
            Notable::Error { .. } => "error",
            Notable::Crash => "crash",
            Notable::Drop { .. } => "drop",
        }
    }

    pub fn human(&self) -> String {
        match self {
            Notable::Error { code, message } => format!("error {code}: {message}"),
            Notable::Crash => "filesystem crash injected".to_string(),
            Notable::Drop { to, reason } => format!("datagram to {to} dropped ({reason})"),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Notable::Error { code, message } => serde_json::json!({
                "kind": "error",
                "code": code,
                "message": message,
            }),
            Notable::Crash => serde_json::json!({ "kind": "crash" }),
            Notable::Drop { to, reason } => serde_json::json!({
                "kind": "drop",
                "to": to,
                "reason": reason,
            }),
        }
    }
}

/// Whether a flattened row came from a boundary operation or a v5 lifecycle marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlatEventSource {
    Operation,
    Lifecycle,
}

/// One strict-loaded event flattened for inspection.
#[derive(Clone, Debug)]
pub struct FlatEvent {
    /// Operation sequence for operation rows; lifecycle rows use their global order
    /// as a stable display/filter value because they do not consume an operation sequence.
    pub seq: u64,
    pub order: u64,
    pub incarnation: Option<u64>,
    pub source: FlatEventSource,
    pub lane: LaneKey,
    pub category: Category,
    pub kind: String,
    pub detail: String,
    pub vtime: Option<u64>,
    pub notable: Option<Notable>,
    pub operation: Value,
    pub outcome: Value,
}

/// Per-task rollup for the summary table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskStat {
    pub ops: u64,
    pub yields: u64,
    pub parks: u64,
    pub completed: bool,
    pub label: Option<String>,
    pub first_seq: Option<u64>,
    pub last_seq: u64,
}

/// Per-operation-kind rollup shared with the later stats surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KindStat {
    pub count: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// One strict-loaded, resolved timeline flattened for inspection.
#[derive(Clone, Debug, Default)]
pub struct FlatTrace {
    pub events: Vec<FlatEvent>,
    pub lanes: BTreeMap<LaneKey, TaskStat>,
    pub kind_counts: BTreeMap<String, KindStat>,
    pub category_counts: BTreeMap<Category, u64>,
    pub vt_min: Option<u64>,
    pub vt_max: Option<u64>,
    pub notable: Vec<FlatEvent>,
}

/// Flatten one resolved timeline, sharing the same semantic walk between the
/// renderer and CLI inspection surfaces.
pub fn flatten(
    bundle: &TraceBundle,
    _raw: &Value,
    timeline: &str,
) -> Result<FlatTrace, TraceError> {
    let resolved = bundle.resolved_timeline(timeline)?;
    let lifecycle = bundle.resolved_lifecycle(timeline)?;
    let total = resolved.len() + lifecycle.len();
    let mut current = LaneKey::Main;
    let mut vtime: Option<u64> = None;
    let mut vt_min: Option<u64> = None;
    let mut vt_max: Option<u64> = None;
    let mut events = Vec::with_capacity(total);
    let mut lanes: BTreeMap<LaneKey, TaskStat> = BTreeMap::new();
    let mut kind_counts: BTreeMap<String, KindStat> = BTreeMap::new();
    let mut category_counts: BTreeMap<Category, u64> = BTreeMap::new();
    let mut notable = Vec::new();

    enum Row<'a> {
        Operation(&'a patina_dst_trace::TraceEvent),
        Lifecycle(&'a LifecycleEvent),
    }

    let mut rows: Vec<Row<'_>> = resolved.iter().map(Row::Operation).collect();
    rows.extend(lifecycle.iter().map(Row::Lifecycle));
    rows.sort_by_key(|row| match row {
        Row::Operation(event) => (event.order, 0u8),
        Row::Lifecycle(event) => (event.order, 1u8),
    });

    for row in rows {
        let flat = match row {
            Row::Operation(event) => {
                let op = serde_json::to_value(&event.operation).unwrap_or(Value::Null);
                let out = serde_json::to_value(&event.outcome).unwrap_or(Value::Null);
                let kind = op
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                debug_assert_eq!(operation_kind(&event.operation), kind.as_str());
                let category = Category::of_kind(&kind);

                // Advance the virtual-time cursor from any absolute reading on this event.
                if kind == "clock_now"
                    && let Some(n) = outcome_u64(&out)
                {
                    vtime = Some(n);
                }
                if let Some(n) = op.get("now_nanos").and_then(Value::as_u64) {
                    vtime = Some(n);
                }
                if let Some(n) = vtime {
                    vt_min = Some(vt_min.map_or(n, |m| m.min(n)));
                    vt_max = Some(vt_max.map_or(n, |m| m.max(n)));
                }

                // SchedulerNext re-points the current lane; ops before the first decision
                // (or in a single-threaded run) stay on `main`.
                if kind == "scheduler_next"
                    && let Some(id) = out.get("value").and_then(Value::as_u64)
                {
                    current = LaneKey::Task(id);
                }

                let lane = match &kind[..] {
                    // Spawn is issued by the current task; keep the row on the spawner.
                    "task_spawn" => current,
                    k if k.starts_with("task_") => op
                        .get("task")
                        .and_then(Value::as_u64)
                        .map(LaneKey::Task)
                        .unwrap_or(current),
                    _ => current,
                };

                let stat = lanes.entry(lane).or_default();
                stat.ops += 1;
                stat.first_seq.get_or_insert(event.sequence);
                stat.last_seq = event.sequence;
                if kind == "task_yield" {
                    stat.yields += 1;
                }
                if kind == "task_park" || kind == "task_park_timed" {
                    stat.parks += 1;
                }
                if kind == "task_spawn"
                    && let Some(id) = outcome_task(&out)
                {
                    let child = lanes.entry(LaneKey::Task(id)).or_default();
                    if child.label.is_none() {
                        child.label = op.get("label").and_then(Value::as_str).map(str::to_string);
                    }
                }
                if kind == "task_complete"
                    && let Some(id) = op.get("task").and_then(Value::as_u64)
                {
                    lanes.entry(LaneKey::Task(id)).or_default().completed = true;
                }

                let detail = summarize(&kind, &op, &out);
                let note = detect_notable(&kind, &op, &out);
                FlatEvent {
                    seq: event.sequence,
                    order: event.order,
                    incarnation: Some(event.incarnation),
                    source: FlatEventSource::Operation,
                    lane,
                    category,
                    kind,
                    detail,
                    vtime,
                    notable: note,
                    operation: op,
                    outcome: out,
                }
            }
            Row::Lifecycle(marker) => {
                let (kind, incarnation, detail, note) = lifecycle_summary(marker);
                let category = Category::of_kind(&kind);
                FlatEvent {
                    seq: marker.order,
                    order: marker.order,
                    incarnation,
                    source: FlatEventSource::Lifecycle,
                    lane: LaneKey::Main,
                    category,
                    kind,
                    detail,
                    vtime,
                    notable: note,
                    operation: Value::Null,
                    outcome: Value::Null,
                }
            }
        };

        *category_counts.entry(flat.category).or_insert(0) += 1;
        let stat = kind_counts.entry(flat.kind.clone()).or_default();
        stat.count += 1;
        if flat.outcome.get("kind").and_then(Value::as_str) == Some("error") {
            stat.errors += 1;
        }
        stat.bytes_in += bytes_in(&flat.operation) as u64;
        stat.bytes_out += bytes_out(&flat.outcome) as u64;
        if flat.notable.is_some() {
            notable.push(flat.clone());
        }
        events.push(flat);
    }

    Ok(FlatTrace {
        events,
        lanes,
        kind_counts,
        category_counts,
        vt_min,
        vt_max,
        notable,
    })
}

fn lifecycle_summary(marker: &LifecycleEvent) -> (String, Option<u64>, String, Option<Notable>) {
    match &marker.kind {
        LifecycleEventKind::Start { incarnation } => (
            "lifecycle_start".to_string(),
            Some(*incarnation),
            format!("incarnation={incarnation}"),
            None,
        ),
        LifecycleEventKind::Crash {
            incarnation,
            snapshot_digest,
        } => (
            "lifecycle_crash".to_string(),
            Some(*incarnation),
            format!("incarnation={incarnation} snapshot={snapshot_digest}"),
            Some(Notable::Crash),
        ),
        LifecycleEventKind::Restart {
            from_incarnation,
            to_incarnation,
            snapshot_digest,
        } => (
            "lifecycle_restart".to_string(),
            Some(*to_incarnation),
            format!("{from_incarnation}->{to_incarnation} snapshot={snapshot_digest}"),
            Some(Notable::Crash),
        ),
        LifecycleEventKind::End { incarnation } => (
            "lifecycle_end".to_string(),
            Some(*incarnation),
            format!("incarnation={incarnation}"),
            None,
        ),
    }
}

fn outcome_u64(out: &Value) -> Option<u64> {
    match out.get("kind").and_then(Value::as_str)? {
        "u64" | "usize" => out.get("value").and_then(Value::as_u64),
        _ => None,
    }
}

fn outcome_task(out: &Value) -> Option<u64> {
    match out.get("kind").and_then(Value::as_str)? {
        "task" => out.get("value").and_then(Value::as_u64),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
