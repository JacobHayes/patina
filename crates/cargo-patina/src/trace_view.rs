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
use patina_dst_trace::{TraceBundle, TraceError};
use serde_json::Value;

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
            "fs_crash" => Category::Crash,
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

/// One strict-loaded event flattened for inspection.
#[derive(Clone, Debug)]
pub struct FlatEvent {
    pub seq: u64,
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
    let total = resolved.len();
    let mut current = LaneKey::Main;
    let mut vtime: Option<u64> = None;
    let mut vt_min: Option<u64> = None;
    let mut vt_max: Option<u64> = None;
    let mut events = Vec::with_capacity(total);
    let mut lanes: BTreeMap<LaneKey, TaskStat> = BTreeMap::new();
    let mut kind_counts: BTreeMap<String, KindStat> = BTreeMap::new();
    let mut category_counts: BTreeMap<Category, u64> = BTreeMap::new();
    let mut notable = Vec::new();

    for event in &resolved {
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
        if kind == "clock_now" {
            if let Some(n) = outcome_u64(&out) {
                vtime = Some(n);
            }
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
        if kind == "scheduler_next" {
            if let Some(id) = out.get("value").and_then(Value::as_u64) {
                current = LaneKey::Task(id);
            }
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
        if kind == "task_spawn" {
            if let Some(id) = outcome_task(&out) {
                let child = lanes.entry(LaneKey::Task(id)).or_default();
                if child.label.is_none() {
                    child.label = op.get("label").and_then(Value::as_str).map(str::to_string);
                }
            }
        }
        if kind == "task_complete" {
            if let Some(id) = op.get("task").and_then(Value::as_u64) {
                lanes.entry(LaneKey::Task(id)).or_default().completed = true;
            }
        }
        *category_counts.entry(category).or_insert(0) += 1;

        let stat = kind_counts.entry(kind.clone()).or_default();
        stat.count += 1;
        if out.get("kind").and_then(Value::as_str) == Some("error") {
            stat.errors += 1;
        }
        stat.bytes_in += bytes_in(&op) as u64;
        stat.bytes_out += bytes_out(&out) as u64;

        let detail = summarize(&kind, &op, &out);
        let note = detect_notable(&kind, &op, &out);

        let flat = FlatEvent {
            seq: event.sequence,
            lane,
            category,
            kind,
            detail,
            vtime,
            notable: note,
            operation: op,
            outcome: out,
        };
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

/// A one-line human summary of an event, avoiding raw byte payloads (shown as a
/// length instead). Reads fields generically from JSON so it never panics on an
/// unfamiliar operation shape.
pub fn summarize(kind: &str, op: &Value, out: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in [
        "path",
        "from",
        "to",
        "target",
        "link_path",
        "address",
        "label",
        "reason",
        "clock",
        "fd",
        "socket",
        "listener",
        "task",
        "offset",
        "len",
        "max_len",
        "deadline_nanos",
        "now_nanos",
        "backlog",
        "how",
    ] {
        if let Some(v) = op.get(key) {
            if let Some(text) = scalar(v) {
                parts.push(format!("{key}={text}"));
            }
        }
    }
    for key in ["bytes"] {
        if let Some(Value::String(s)) = op.get(key) {
            parts.push(format!("bytes≈{}", base64_len(s)));
        }
    }
    if let Some(k) = out.get("kind").and_then(Value::as_str) {
        match k {
            "unit" => {}
            "error" => {
                if let Some(v) = out.get("value") {
                    let code = v
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_string();
                    parts.push(format!("→ error:{code}"));
                }
            }
            "bytes" => {
                if let Some(Value::String(s)) = out.get("value") {
                    parts.push(format!("→ {} bytes", base64_len(s)));
                }
            }
            "optional_task" | "task" => {
                if let Some(v) = out.get("value") {
                    parts.push(format!(
                        "→ task {}",
                        scalar(v).unwrap_or_else(|| "-".into())
                    ));
                }
            }
            "handle" | "socket" | "u64" | "usize" | "optional_u64" => {
                if let Some(v) = out.get("value") {
                    if let Some(text) = scalar(v) {
                        parts.push(format!("→ {text}"));
                    }
                }
            }
            "send_report" => {
                if let Some(v) = out.get("value") {
                    let disp = v
                        .get("disposition")
                        .and_then(Value::as_str)
                        .unwrap_or("queued");
                    parts.push(format!("→ {disp}"));
                }
            }
            "datagram" => {
                let present = out.get("value").map(|v| !v.is_null()).unwrap_or(false);
                parts.push(if present {
                    "→ datagram".into()
                } else {
                    "→ none".into()
                });
            }
            other => parts.push(format!("→ {other}")),
        }
    }
    let _ = kind;
    parts.join(" ")
}

pub fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn base64_len(s: &str) -> usize {
    let padding = s.bytes().rev().take_while(|&b| b == b'=').count();
    (s.len() / 4).saturating_mul(3).saturating_sub(padding)
}

fn bytes_in(op: &Value) -> usize {
    op.get("bytes")
        .and_then(Value::as_str)
        .map(base64_len)
        .unwrap_or(0)
}

fn bytes_out(out: &Value) -> usize {
    match out.get("kind").and_then(Value::as_str) {
        Some("bytes") => out
            .get("value")
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        Some("optional_bytes") => out
            .get("value")
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        Some("datagram") => out
            .get("value")
            .and_then(|value| value.get("bytes"))
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        _ => 0,
    }
}

pub fn detect_notable(kind: &str, op: &Value, out: &Value) -> Option<Notable> {
    if kind == "fs_crash" {
        return Some(Notable::Crash);
    }
    if out.get("kind").and_then(Value::as_str) == Some("error") {
        let v = out.get("value")?;
        return Some(Notable::Error {
            code: v
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_string(),
            message: v
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    if out.get("kind").and_then(Value::as_str) == Some("send_report") {
        let disp = out
            .get("value")
            .and_then(|v| v.get("disposition"))
            .and_then(Value::as_str)
            .unwrap_or("queued");
        if disp != "queued" {
            return Some(Notable::Drop {
                to: op
                    .get("to")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                reason: disp.to_string(),
            });
        }
    }
    None
}

/// Render a nanosecond count in a compact human unit.
pub fn human_nanos(n: u64) -> String {
    if n == 0 {
        return "0 ns".to_string();
    }
    const UNITS: [(u64, &str); 5] = [
        (1_000_000_000 * 60, "min"),
        (1_000_000_000, "s"),
        (1_000_000, "ms"),
        (1_000, "µs"),
        (1, "ns"),
    ];
    for (scale, unit) in UNITS {
        if n >= scale {
            let whole = n / scale;
            let frac = (n % scale) * 100 / scale;
            if frac == 0 {
                return format!("{whole} {unit}");
            }
            return format!("{whole}.{frac:02} {unit}");
        }
    }
    format!("{n} ns")
}

/// The complete operation-kind registry. The companion [`operation_kind`] match
/// has no wildcard arm, so adding an ABI operation fails the build until the
/// new tag is consciously registered here.
pub const OP_KINDS: &[(&str, Category)] = &[
    ("entropy_fill", Category::Entropy),
    ("clock_now", Category::Clock),
    ("sleep_until", Category::Sleep),
    ("fs_open", Category::Fs),
    ("fs_read", Category::Fs),
    ("fs_write", Category::Fs),
    ("fs_read_at", Category::Fs),
    ("fs_write_at", Category::Fs),
    ("fs_close", Category::Fs),
    ("fs_dup", Category::Fs),
    ("fs_seek", Category::Fs),
    ("fs_metadata", Category::Fs),
    ("fs_fd_metadata", Category::Fs),
    ("fs_create_directory", Category::Fs),
    ("fs_remove_file", Category::Fs),
    ("fs_sync", Category::Fs),
    ("fs_set_length", Category::Fs),
    ("fs_set_times", Category::Fs),
    ("fs_set_times_by_path", Category::Fs),
    ("fs_read_directory", Category::Fs),
    ("fs_remove_directory", Category::Fs),
    ("fs_rename", Category::Fs),
    ("fs_link", Category::Fs),
    ("fs_symlink", Category::Fs),
    ("fs_read_link", Category::Fs),
    ("fs_crash", Category::Crash),
    ("task_spawn", Category::Schedule),
    ("task_yield", Category::Schedule),
    ("task_park", Category::Schedule),
    ("task_park_timed", Category::Schedule),
    ("task_wake", Category::Schedule),
    ("task_complete", Category::Schedule),
    ("scheduler_next", Category::Schedule),
    ("net_bind", Category::Net),
    ("net_send", Category::Net),
    ("net_recv", Category::Net),
    ("net_close", Category::Net),
    ("net_next_delivery", Category::Net),
    ("net_tcp_listen", Category::Net),
    ("net_tcp_accept", Category::Net),
    ("net_tcp_connect", Category::Net),
    ("net_tcp_send", Category::Net),
    ("net_tcp_recv", Category::Net),
    ("net_tcp_shutdown", Category::Net),
];

pub fn valid_op_kinds() -> BTreeSet<&'static str> {
    OP_KINDS.iter().map(|(kind, _)| *kind).collect()
}

pub fn valid_category_labels() -> BTreeSet<&'static str> {
    Category::ALL.into_iter().map(Category::label).collect()
}

pub fn op_kind_category(kind: &str) -> Option<Category> {
    OP_KINDS
        .iter()
        .find_map(|(candidate, category)| (*candidate == kind).then_some(*category))
}

pub fn operation_kind(operation: &Operation) -> &'static str {
    match operation {
        Operation::EntropyFill { .. } => "entropy_fill",
        Operation::ClockNow { .. } => "clock_now",
        Operation::SleepUntil { .. } => "sleep_until",
        Operation::FsOpen { .. } => "fs_open",
        Operation::FsRead { .. } => "fs_read",
        Operation::FsWrite { .. } => "fs_write",
        Operation::FsReadAt { .. } => "fs_read_at",
        Operation::FsWriteAt { .. } => "fs_write_at",
        Operation::FsClose { .. } => "fs_close",
        Operation::FsDup { .. } => "fs_dup",
        Operation::FsSeek { .. } => "fs_seek",
        Operation::FsMetadata { .. } => "fs_metadata",
        Operation::FsFdMetadata { .. } => "fs_fd_metadata",
        Operation::FsCreateDirectory { .. } => "fs_create_directory",
        Operation::FsRemoveFile { .. } => "fs_remove_file",
        Operation::FsSync { .. } => "fs_sync",
        Operation::FsSetLength { .. } => "fs_set_length",
        Operation::FsSetTimes { .. } => "fs_set_times",
        Operation::FsSetTimesByPath { .. } => "fs_set_times_by_path",
        Operation::FsReadDirectory { .. } => "fs_read_directory",
        Operation::FsRemoveDirectory { .. } => "fs_remove_directory",
        Operation::FsRename { .. } => "fs_rename",
        Operation::FsLink { .. } => "fs_link",
        Operation::FsSymlink { .. } => "fs_symlink",
        Operation::FsReadLink { .. } => "fs_read_link",
        Operation::FsCrash => "fs_crash",
        Operation::TaskSpawn { .. } => "task_spawn",
        Operation::TaskYield { .. } => "task_yield",
        Operation::TaskPark { .. } => "task_park",
        Operation::TaskParkTimed { .. } => "task_park_timed",
        Operation::TaskWake { .. } => "task_wake",
        Operation::TaskComplete { .. } => "task_complete",
        Operation::SchedulerNext => "scheduler_next",
        Operation::NetBind { .. } => "net_bind",
        Operation::NetSend { .. } => "net_send",
        Operation::NetRecv { .. } => "net_recv",
        Operation::NetClose { .. } => "net_close",
        Operation::NetNextDelivery { .. } => "net_next_delivery",
        Operation::NetTcpListen { .. } => "net_tcp_listen",
        Operation::NetTcpAccept { .. } => "net_tcp_accept",
        Operation::NetTcpConnect { .. } => "net_tcp_connect",
        Operation::NetTcpSend { .. } => "net_tcp_send",
        Operation::NetTcpRecv { .. } => "net_tcp_recv",
        Operation::NetTcpShutdown { .. } => "net_tcp_shutdown",
    }
}

#[cfg(test)]
pub(crate) fn representative_events_for_all_op_kinds() -> Vec<(Operation, Outcome)> {
    use patina_dst_abi::{
        ClockKind, Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata,
        OpenFlags, SeekWhence, SendDisposition, SendReport, ShutdownHow, SocketId, TaskId,
        TcpAccepted,
    };

    let metadata = FsMetadata {
        kind: FsEntryKind::File,
        len: 12,
        ino: 1,
        nlink: 1,
        atime_nanos: 0,
        mtime_nanos: 0,
    };
    let datagram = Datagram {
        packet_id: 1,
        from: "127.0.0.1:1".into(),
        to: "127.0.0.1:2".into(),
        bytes: vec![9, 8, 7],
        delivery_nanos: 5,
    };
    vec![
        (
            Operation::EntropyFill { len: 4 },
            Outcome::Bytes(vec![1, 2, 3, 4]),
        ),
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(1_000_000),
        ),
        (
            Operation::SleepUntil {
                clock: ClockKind::Monotonic,
                deadline_nanos: 2_000_000,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsOpen {
                path: "/missing".into(),
                flags: OpenFlags::read_only(),
            },
            Outcome::Error(EffectError::new(ErrorCode::NotFound, "missing")),
        ),
        (
            Operation::FsRead {
                fd: Fd(3),
                max_len: 8,
            },
            Outcome::Bytes(vec![1, 2]),
        ),
        (
            Operation::FsWrite {
                fd: Fd(3),
                bytes: vec![1, 2, 3],
            },
            Outcome::Usize(3),
        ),
        (
            Operation::FsReadAt {
                fd: Fd(3),
                offset: 4,
                max_len: 8,
            },
            Outcome::Bytes(vec![4, 5]),
        ),
        (
            Operation::FsWriteAt {
                fd: Fd(3),
                offset: 4,
                bytes: vec![6, 7],
            },
            Outcome::Usize(2),
        ),
        (Operation::FsClose { fd: Fd(3) }, Outcome::Unit),
        (Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4))),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 0,
                whence: SeekWhence::Start,
            },
            Outcome::U64(0),
        ),
        (
            Operation::FsMetadata {
                path: "/file".into(),
            },
            Outcome::Metadata(metadata),
        ),
        (
            Operation::FsFdMetadata { fd: Fd(3) },
            Outcome::Metadata(metadata),
        ),
        (
            Operation::FsCreateDirectory { path: "/d".into() },
            Outcome::Unit,
        ),
        (
            Operation::FsRemoveFile {
                path: "/file".into(),
            },
            Outcome::Unit,
        ),
        (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
        (Operation::FsSetLength { fd: Fd(3), len: 9 }, Outcome::Unit),
        (
            Operation::FsSetTimes {
                fd: Fd(3),
                atime_nanos: Some(1),
                mtime_nanos: Some(2),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetTimesByPath {
                path: "/file".into(),
                atime_nanos: Some(1),
                mtime_nanos: Some(2),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsReadDirectory { path: "/d".into() },
            Outcome::DirectoryEntries(vec![FsDirectoryEntry {
                name: "file".into(),
                kind: FsEntryKind::File,
            }]),
        ),
        (
            Operation::FsRemoveDirectory { path: "/d".into() },
            Outcome::Unit,
        ),
        (
            Operation::FsRename {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsLink {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSymlink {
                target: "/target".into(),
                link_path: "/link".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsReadLink {
                path: "/link".into(),
            },
            Outcome::Bytes(b"/target".to_vec()),
        ),
        (Operation::FsCrash, Outcome::Unit),
        (
            Operation::TaskSpawn {
                label: "worker".into(),
            },
            Outcome::Task(TaskId(1)),
        ),
        (Operation::TaskYield { task: TaskId(1) }, Outcome::Unit),
        (
            Operation::TaskPark {
                task: TaskId(1),
                reason: "wait".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::TaskParkTimed {
                task: TaskId(1),
                reason: "timer".into(),
                deadline_nanos: 3_000_000,
            },
            Outcome::Unit,
        ),
        (Operation::TaskWake { task: TaskId(1) }, Outcome::Unit),
        (Operation::TaskComplete { task: TaskId(1) }, Outcome::Unit),
        (
            Operation::SchedulerNext,
            Outcome::OptionalTask(Some(TaskId(1))),
        ),
        (
            Operation::NetBind {
                address: "127.0.0.1:1".into(),
            },
            Outcome::Socket(SocketId(1)),
        ),
        (
            Operation::NetSend {
                socket: SocketId(1),
                to: "127.0.0.1:2".into(),
                bytes: vec![1, 2, 3],
                now_nanos: 4_000_000,
            },
            Outcome::SendReport(SendReport {
                written: 0,
                copies: 0,
                delivery_nanos: vec![],
                disposition: SendDisposition::DroppedByFault,
            }),
        ),
        (
            Operation::NetRecv {
                socket: SocketId(1),
                now_nanos: 4_000_001,
            },
            Outcome::Datagram(Some(datagram)),
        ),
        (
            Operation::NetClose {
                socket: SocketId(1),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetNextDelivery {
                socket: SocketId(1),
                now_nanos: 4_000_002,
            },
            Outcome::OptionalU64(Some(4_100_000)),
        ),
        (
            Operation::NetTcpListen {
                address: "127.0.0.1:10".into(),
                backlog: 16,
            },
            Outcome::Socket(SocketId(2)),
        ),
        (
            Operation::NetTcpAccept {
                listener: SocketId(2),
                now_nanos: 4_000_003,
            },
            Outcome::TcpAccepted(Some(TcpAccepted {
                socket: SocketId(3),
                peer: "127.0.0.1:11".into(),
            })),
        ),
        (
            Operation::NetTcpConnect {
                address: "127.0.0.1:11".into(),
                to: "127.0.0.1:10".into(),
                now_nanos: 4_000_004,
            },
            Outcome::Socket(SocketId(4)),
        ),
        (
            Operation::NetTcpSend {
                socket: SocketId(4),
                bytes: vec![1, 2],
                now_nanos: 4_000_005,
            },
            Outcome::Usize(2),
        ),
        (
            Operation::NetTcpRecv {
                socket: SocketId(4),
                max_len: 8,
                now_nanos: 4_000_006,
            },
            Outcome::OptionalBytes(Some(vec![5, 6])),
        ),
        (
            Operation::NetTcpShutdown {
                socket: SocketId(4),
                how: ShutdownHow::Both,
            },
            Outcome::Unit,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_trace::{RunMetadata, TraceBundle, TraceEvent};

    fn bundle_with(events: Vec<(Operation, Outcome)>) -> TraceBundle {
        let decisions = events
            .into_iter()
            .enumerate()
            .map(|(i, (operation, outcome))| TraceEvent {
                sequence: i as u64,
                operation,
                outcome,
            })
            .collect();
        TraceBundle::new(RunMetadata::new(7, "fp-test"), decisions)
    }

    fn registry_coverage(registry: &[(&str, Category)]) -> Result<(), String> {
        let registered: BTreeMap<&str, Category> = registry.iter().copied().collect();
        for (operation, _) in representative_events_for_all_op_kinds() {
            let tag = operation_kind(&operation);
            if !registered.contains_key(tag) {
                return Err(format!("operation tag {tag:?} is missing from OP_KINDS"));
            }
            let encoded = serde_json::to_value(&operation).unwrap();
            assert_eq!(encoded["kind"], tag, "operation_kind must match serde tag");
        }
        Ok(())
    }

    #[test]
    fn op_kind_registry_covers_every_operation_variant() {
        registry_coverage(OP_KINDS).unwrap();
    }

    #[test]
    fn every_op_tag_gate_selftest_fires_on_planted_missing_tag() {
        if std::env::var_os("PATINA_TRACE_VIEW_PLANT_MISSING_TAG").is_none() {
            return;
        }
        let planted: Vec<_> = OP_KINDS
            .iter()
            .copied()
            .filter(|(tag, _)| *tag != "net_tcp_shutdown")
            .collect();
        registry_coverage(&planted).unwrap();
    }

    #[test]
    fn flatten_round_trips_every_operation_json_and_counts_kinds() {
        let bundle = bundle_with(representative_events_for_all_op_kinds());
        let raw = serde_json::to_value(&bundle).unwrap();
        let flat = flatten(&bundle, &raw, "main").unwrap();
        assert_eq!(flat.events.len(), OP_KINDS.len());
        assert!(flat.notable.iter().any(|event| event.kind == "fs_open"));
        assert!(flat.notable.iter().any(|event| event.kind == "fs_crash"));
        assert!(flat.notable.iter().any(|event| event.kind == "net_send"));
        for (event, recorded) in flat.events.iter().zip(&bundle.timelines[0].decisions) {
            assert_eq!(
                event.operation,
                serde_json::to_value(&recorded.operation).unwrap()
            );
            assert_eq!(
                event.outcome,
                serde_json::to_value(&recorded.outcome).unwrap()
            );
        }
        let total: u64 = flat.kind_counts.values().map(|stat| stat.count).sum();
        assert_eq!(total, flat.events.len() as u64);
        for (tag, _) in OP_KINDS {
            assert_eq!(flat.kind_counts.get(*tag).map(|stat| stat.count), Some(1));
        }
    }
}
