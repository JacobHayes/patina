//! Self-contained single-file HTML rendering of a recorded Patina trace.
//!
//! This module is a *read-only consumer* of trace/runtime semantics: it loads a
//! [`TraceBundle`] plus the raw trace JSON and emits a standalone HTML timeline.
//! It never records, replays, or mutates a trace, so rendering can never perturb
//! replay hashes (the render path only reads the file and writes a separate
//! `.html`).
//!
//! Forward-compatibility with concurrent runtime work is deliberate: operations
//! are categorized by their serde `kind` tag *prefix* rather than by an
//! exhaustive `match` on the [`patina_abi::Operation`] enum, and the metadata
//! panel is rendered generically from the raw JSON object. A new operation
//! variant or a new metadata field therefore surfaces in the render with no code
//! change here — it lands in the "other" lane / an extra metadata row rather than
//! breaking the build or being silently dropped.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use patina_trace::{TraceBundle, TraceError};
use serde_json::Value;

/// Above this many events the per-event timeline is aggregated into density
/// buckets (with a visible banner) instead of drawing one mark per event, so a
/// multi-hundred-thousand-event trace still renders a bounded, openable file.
/// Notable events (crashes, errors, drops) are always listed in full regardless.
const PER_EVENT_CAP: usize = 3000;

/// Everything the renderer needs about the run being visualized. Borrowed so the
/// caller keeps ownership of the loaded bundle and parsed JSON.
pub struct RenderInput<'a> {
    pub bundle: &'a TraceBundle,
    /// The full parsed trace JSON, used to render the metadata panel generically
    /// (so fields added by concurrent work surface without a code change).
    pub raw: &'a Value,
    pub trace_path: &'a str,
    pub artifact: &'a str,
    /// Target family label: `native`, `wasi`, or `cargo`.
    pub family: &'a str,
    /// The resolved timeline id being rendered (usually `main`).
    pub timeline: &'a str,
    /// Present when the run ended in a violation/failure; rendered as a prominent
    /// summary section at the top of the report.
    pub failure: Option<FailureSummary>,
}

/// A machine-and-human summary of why a run failed, rendered at the top of a
/// per-failure report. Kept generic (label/value pairs plus free-form lines) so
/// the caller can populate it from any family's result/violation output.
#[derive(Clone, Debug, Default)]
pub struct FailureSummary {
    /// The runner's terminal result line (e.g. a `RAFT_VIOLATION ...` or
    /// `trace operation mismatch ...` line).
    pub result_line: String,
    /// A short classification token (e.g. `operation-mismatch`,
    /// `fingerprint-mismatch`, `nonzero-exit`).
    pub classification: String,
    /// The process exit code the run produced.
    pub exit_code: i32,
    /// Labeled facts about the failure (fired markers, final state, hashes).
    pub facts: Vec<(String, String)>,
    /// Free-form diagnostic lines (captured markers, stderr excerpts).
    pub messages: Vec<String>,
}

/// The category a boundary operation falls into for lane coloring and stats.
/// Derived from the operation's serde `kind` tag prefix so it stays exhaustive
/// over future additions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
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
    fn of_kind(kind: &str) -> Self {
        match kind {
            "fs_crash" => Category::Crash,
            "sleep_until" => Category::Sleep,
            "clock_now" => Category::Clock,
            "entropy_fill" => Category::Entropy,
            "scheduler_next" => Category::Schedule,
            _ if kind.starts_with("task_") => Category::Schedule,
            _ if kind.starts_with("net_") => Category::Net,
            _ if kind.starts_with("fs_") => Category::Fs,
            _ => Category::Other,
        }
    }

    fn label(self) -> &'static str {
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

    /// A stable CSS class suffix (also the color key in the stylesheet).
    fn css(self) -> &'static str {
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

    const ALL: [Category; 8] = [
        Category::Schedule,
        Category::Sleep,
        Category::Net,
        Category::Fs,
        Category::Crash,
        Category::Entropy,
        Category::Clock,
        Category::Other,
    ];
}

/// One event flattened for rendering: which lane owns it, its category, a short
/// human label, an optional virtual-time reading, and whether it is "notable"
/// (an error, crash, or dropped datagram surfaced in full).
struct Ev {
    seq: u64,
    lane: LaneKey,
    category: Category,
    kind: String,
    detail: String,
    vtime: Option<u64>,
    notable: Option<Notable>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LaneKey {
    /// Events attributed to no scheduled task (e.g. a single-threaded run with no
    /// scheduler decisions, or ops before the first `SchedulerNext`).
    Main,
    Task(u64),
}

impl LaneKey {
    fn label(self) -> String {
        match self {
            LaneKey::Main => "main".to_string(),
            LaneKey::Task(id) => format!("task {id}"),
        }
    }
}

enum Notable {
    Error { code: String, message: String },
    Crash,
    Drop { to: String, reason: String },
}

/// Per-task rollup for the summary table.
#[derive(Default)]
struct TaskStat {
    ops: u64,
    yields: u64,
    parks: u64,
    completed: bool,
    label: Option<String>,
    first_seq: Option<u64>,
    last_seq: u64,
}

/// Load a trace from disk and render it to a standalone HTML document.
///
/// The raw JSON is parsed a second time (cheaply, it is already size-limited by
/// [`TraceBundle::load`]) so the metadata panel can show any field, including
/// ones this build's typed `RunMetadata` does not know about.
pub fn render_trace_file(
    trace_path: &str,
    artifact: &str,
    family: &str,
    timeline: &str,
    failure: Option<FailureSummary>,
) -> Result<String, TraceError> {
    let bundle = TraceBundle::load(trace_path)?;
    let bytes = std::fs::read(trace_path).map_err(|source| TraceError::Io {
        action: format!("read trace {trace_path} for rendering"),
        source,
    })?;
    let raw: Value = serde_json::from_slice(&bytes).map_err(|source| TraceError::Parse {
        path: std::path::PathBuf::from(trace_path),
        source,
    })?;
    Ok(render(&RenderInput {
        bundle: &bundle,
        raw: &raw,
        trace_path,
        artifact,
        family,
        timeline,
        failure,
    }))
}

/// Render a loaded bundle to a self-contained HTML string. Pure and
/// filesystem-free, so it is unit-testable on a hand-built bundle.
pub fn render(input: &RenderInput<'_>) -> String {
    let events = input
        .bundle
        .resolved_timeline(input.timeline)
        .unwrap_or_default();
    let total = events.len();

    // Walk the event stream once, tracking the currently-running task (chosen by
    // the most recent SchedulerNext) and a virtual-time cursor reconstructed from
    // clock reads and the `now_nanos` fields carried by net ops.
    let mut current = LaneKey::Main;
    let mut vtime: Option<u64> = None;
    let mut vt_min: Option<u64> = None;
    let mut vt_max: Option<u64> = None;
    let mut flat: Vec<Ev> = Vec::with_capacity(total);
    let mut lanes: BTreeMap<LaneKey, TaskStat> = BTreeMap::new();
    let mut cat_counts: BTreeMap<Category, u64> = BTreeMap::new();
    let mut notable: Vec<Ev> = Vec::new();

    for event in &events {
        let op = serde_json::to_value(&event.operation).unwrap_or(Value::Null);
        let out = serde_json::to_value(&event.outcome).unwrap_or(Value::Null);
        let kind = op
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
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

        // Task attribution: SchedulerNext re-points the current lane; ops before
        // the first decision (or in a single-threaded run) stay on `main`.
        if kind == "scheduler_next" {
            // OptionalTask(Some(id)) re-points the current lane; OptionalTask(None)
            // (no runnable task) keeps it.
            if let Some(id) = out.get("value").and_then(Value::as_u64) {
                current = LaneKey::Task(id);
            }
        }

        let lane = match &kind[..] {
            // Lifecycle ops name their *target* task; attribute the row to that
            // task's lane so its birth/yield/park/wake/completion sit together.
            "task_spawn" => {
                // Spawn is issued by the current task; the child id is in the
                // outcome. Keep the row on the spawner's lane.
                current
            }
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
            // Record the child lane's label eagerly so a task that never runs a
            // boundary op of its own still appears with its spawn label.
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
        *cat_counts.entry(category).or_insert(0) += 1;

        let detail = summarize(&kind, &op, &out);
        let note = detect_notable(&kind, &op, &out);

        let ev = Ev {
            seq: event.sequence,
            lane,
            category,
            kind: kind.clone(),
            detail,
            vtime,
            notable: note,
        };
        if ev.notable.is_some() {
            notable.push(Ev {
                seq: ev.seq,
                lane: ev.lane,
                category: ev.category,
                kind: ev.kind.clone(),
                detail: ev.detail.clone(),
                vtime: ev.vtime,
                notable: detect_notable(&kind, &op, &out),
            });
        }
        flat.push(ev);
    }

    // Ensure every lane discovered via lifecycle also owns a stat row.
    let lane_order: Vec<LaneKey> = lanes.keys().copied().collect();

    let mut html = String::with_capacity(64 * 1024);
    write_head(&mut html, input);
    write_body_open(&mut html);
    write_header(&mut html, input, total, &lane_order, vt_min, vt_max);
    if let Some(failure) = &input.failure {
        write_failure(&mut html, failure);
    }
    write_metadata(&mut html, input);
    write_stat_tiles(&mut html, total, &lane_order, &cat_counts, vt_min, vt_max);
    write_timeline(&mut html, &flat, &lane_order, total);
    write_task_table(&mut html, &lanes);
    write_notable(&mut html, &notable);
    write_legend(&mut html, &cat_counts);
    write_data_note(&mut html, input);
    write_body_close(&mut html);
    html
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
/// length instead). Reads fields generically from the JSON so it never panics on
/// an unfamiliar operation shape.
fn summarize(kind: &str, op: &Value, out: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    // A curated set of the most useful scalar fields, in a stable order.
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
    // Byte payloads: show length only.
    for key in ["bytes"] {
        if let Some(Value::String(s)) = op.get(key) {
            parts.push(format!("bytes≈{}", base64_len(s)));
        }
    }
    // Outcome summary.
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
    let _ = kind; // kind already drives the row label elsewhere
    parts.join(" ")
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn base64_len(s: &str) -> usize {
    // Approximate decoded length of a padded base64 string.
    let padding = s.bytes().rev().take_while(|&b| b == b'=').count();
    (s.len() / 4).saturating_mul(3).saturating_sub(padding)
}

fn detect_notable(kind: &str, op: &Value, out: &Value) -> Option<Notable> {
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

// ---------------------------------------------------------------------------
// HTML emission. All CSS/JS is inlined; no external assets or network access.
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn write_head(html: &mut String, input: &RenderInput<'_>) {
    let title = format!("Patina trace — {}", esc(input.artifact));
    let _ = writeln!(
        html,
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg:#ffffff; --fg:#1a1a1a; --muted:#666; --border:#ddd; --accent:#8a5a2b;
  --pass:#1a7f37; --fail:#b42318; --pending:#9a6700; --card:#f7f5f2;
  --sched:#3b82f6; --sleep:#8b5cf6; --net:#0d9488; --fs:#8a5a2b;
  --crash:#b42318; --entropy:#a16207; --clock:#64748b; --other:#94a3b8;
  color-scheme: light dark;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#16130f; --fg:#e8e4de; --muted:#a39a8e; --border:#3a342c; --accent:#d1a05a;
    --pass:#4ade80; --fail:#f87171; --pending:#fbbf24; --card:#211c16;
    --sched:#60a5fa; --sleep:#a78bfa; --net:#2dd4bf; --fs:#d1a05a;
    --crash:#f87171; --entropy:#fbbf24; --clock:#94a3b8; --other:#64748b; }}
}}
body {{ margin:0 auto; max-width:74rem; padding:2rem 1.25rem 4rem;
  font:15px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--fg); }}
h1 {{ font-size:1.6rem; margin-bottom:.15rem; }}
h2 {{ font-size:1.2rem; margin-top:2.2rem; border-bottom:1px solid var(--border); padding-bottom:.3rem; }}
.subtitle {{ color:var(--muted); margin-top:0; }}
table {{ border-collapse:collapse; width:100%; margin:1rem 0; font-size:.88rem; }}
th,td {{ border:1px solid var(--border); padding:.4rem .55rem; text-align:left; vertical-align:top; }}
th {{ background:var(--card); }}
code,pre {{ font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:.86em; }}
pre {{ background:var(--card); border:1px solid var(--border); border-radius:6px; padding:.7rem .9rem; overflow-x:auto; }}
.tiles {{ display:flex; flex-wrap:wrap; gap:.75rem; margin:1rem 0; }}
.tile {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:.6rem .9rem; min-width:7rem; }}
.tile .n {{ font-size:1.4rem; font-weight:650; }}
.tile .k {{ color:var(--muted); font-size:.8rem; }}
.note {{ background:var(--card); border-left:3px solid var(--accent); padding:.6rem .9rem; border-radius:0 6px 6px 0; margin:1rem 0; }}
.fail-box {{ background:var(--card); border-left:4px solid var(--fail); padding:.8rem 1rem; border-radius:0 8px 8px 0; margin:1.2rem 0; }}
.fail-box h2 {{ border:0; margin-top:0; color:var(--fail); }}
.muted {{ color:var(--muted); }}
.legend {{ display:flex; flex-wrap:wrap; gap:.6rem 1rem; margin:.5rem 0 1rem; }}
.legend span {{ display:inline-flex; align-items:center; gap:.35rem; font-size:.85rem; }}
.swatch {{ width:.85rem; height:.85rem; border-radius:2px; display:inline-block; }}
.timeline-wrap {{ overflow-x:auto; border:1px solid var(--border); border-radius:8px; padding:.5rem; background:var(--card); }}
.lane-name {{ font-size:.8rem; fill:var(--muted); }}
.grid-line {{ stroke:var(--border); stroke-width:1; }}
.sw-sched{{background:var(--sched)}} .sw-sleep{{background:var(--sleep)}} .sw-net{{background:var(--net)}}
.sw-fs{{background:var(--fs)}} .sw-crash{{background:var(--crash)}} .sw-entropy{{background:var(--entropy)}}
.sw-clock{{background:var(--clock)}} .sw-other{{background:var(--other)}}
</style>
</head>"#
    );
}

fn write_body_open(html: &mut String) {
    html.push_str("<body>\n");
}

fn write_body_close(html: &mut String) {
    html.push_str("</body>\n</html>\n");
}

fn write_header(
    html: &mut String,
    input: &RenderInput<'_>,
    total: usize,
    lanes: &[LaneKey],
    vt_min: Option<u64>,
    vt_max: Option<u64>,
) {
    let span = match (vt_min, vt_max) {
        (Some(a), Some(b)) => format!("{} of virtual time", human_nanos(b.saturating_sub(a))),
        _ => "no virtual-time samples".to_string(),
    };
    let _ = writeln!(
        html,
        "<h1>Patina trace timeline</h1>\n<p class=\"subtitle\">{} · <code>{}</code> · timeline <code>{}</code> · {} events across {} lanes · {}</p>",
        esc(input.family),
        esc(input.artifact),
        esc(input.timeline),
        total,
        lanes.len().max(1),
        esc(&span),
    );
}

fn write_failure(html: &mut String, failure: &FailureSummary) {
    html.push_str("<div class=\"fail-box\">\n<h2>Run failed</h2>\n");
    let _ = writeln!(
        html,
        "<p><strong>{}</strong> · exit code {}</p>",
        esc(&failure.classification),
        failure.exit_code
    );
    if !failure.result_line.is_empty() {
        let _ = writeln!(html, "<pre>{}</pre>", esc(&failure.result_line));
    }
    if !failure.facts.is_empty() {
        html.push_str("<table>\n");
        for (k, v) in &failure.facts {
            let _ = writeln!(
                html,
                "<tr><th>{}</th><td><code>{}</code></td></tr>",
                esc(k),
                esc(v)
            );
        }
        html.push_str("</table>\n");
    }
    if !failure.messages.is_empty() {
        let joined = failure
            .messages
            .iter()
            .map(|m| esc(m))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = writeln!(html, "<pre>{joined}</pre>");
    }
    html.push_str("</div>\n");
}

fn write_metadata(html: &mut String, input: &RenderInput<'_>) {
    html.push_str("<h2>Run metadata</h2>\n<table>\n");
    let _ = writeln!(
        html,
        "<tr><th>trace</th><td><code>{}</code></td></tr>\n<tr><th>format_version</th><td><code>{}</code></td></tr>",
        esc(input.trace_path),
        input.bundle.format_version
    );
    // Render every metadata key generically from the raw JSON so fields this
    // build's typed model does not know about still appear.
    if let Some(meta) = input.raw.get("metadata").and_then(Value::as_object) {
        for (key, value) in meta {
            let rendered = render_json_scalarish(value);
            let _ = writeln!(
                html,
                "<tr><th>{}</th><td><code>{}</code></td></tr>",
                esc(key),
                esc(&rendered)
            );
        }
    }
    html.push_str("</table>\n");
}

/// Render a JSON metadata value compactly: scalars verbatim, small
/// objects/arrays as compact JSON. Keeps the metadata panel readable while still
/// showing structured fault/buggify config and any unknown additions.
fn render_json_scalarish(value: &Value) -> String {
    match value {
        Value::Null => "—".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "?".to_string()),
    }
}

fn write_stat_tiles(
    html: &mut String,
    total: usize,
    lanes: &[LaneKey],
    cat_counts: &BTreeMap<Category, u64>,
    vt_min: Option<u64>,
    vt_max: Option<u64>,
) {
    html.push_str("<div class=\"tiles\">\n");
    tile(html, "events", &total.to_string());
    tile(html, "lanes", &lanes.len().max(1).to_string());
    for cat in Category::ALL {
        let n = cat_counts.get(&cat).copied().unwrap_or(0);
        if n > 0 {
            tile(html, cat.label(), &n.to_string());
        }
    }
    if let (Some(a), Some(b)) = (vt_min, vt_max) {
        tile(html, "virtual span", &human_nanos(b.saturating_sub(a)));
    }
    html.push_str("</div>\n");
}

fn tile(html: &mut String, k: &str, n: &str) {
    let _ = writeln!(
        html,
        "<div class=\"tile\"><div class=\"n\">{}</div><div class=\"k\">{}</div></div>",
        esc(n),
        esc(k)
    );
}

fn write_timeline(html: &mut String, flat: &[Ev], lanes: &[LaneKey], total: usize) {
    html.push_str("<h2>Timeline</h2>\n");
    let lane_index: BTreeMap<LaneKey, usize> = if lanes.is_empty() {
        [(LaneKey::Main, 0)].into_iter().collect()
    } else {
        lanes.iter().enumerate().map(|(i, l)| (*l, i)).collect()
    };
    let lane_count = lane_index.len().max(1);

    // Layout constants.
    let left = 90u32; // lane-label gutter
    let row = 26u32;
    let top = 24u32;
    let height = top + row * lane_count as u32 + 12;

    let aggregated = total > PER_EVENT_CAP;
    let columns = if aggregated {
        PER_EVENT_CAP
    } else {
        total.max(1)
    };
    let colw = if aggregated { 3u32 } else { 6u32 };
    let width = left + colw * columns as u32 + 20;

    if aggregated {
        let per = total.div_ceil(PER_EVENT_CAP);
        let _ = writeln!(
            html,
            "<div class=\"note\"><strong>Aggregated view.</strong> {total} events exceed the {PER_EVENT_CAP}-event per-event cap, so each column below aggregates ≈{per} events (colored by the densest category). Nothing is dropped: every crash, error, and dropped datagram is still listed in full in the Notable events section below.</div>"
        );
    }

    html.push_str("<div class=\"timeline-wrap\">\n");
    let _ = writeln!(
        html,
        "<svg width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"per-task event timeline\">"
    );
    // Lane labels + baselines.
    for (lane, idx) in &lane_index {
        let y = top + row * (*idx as u32) + row / 2;
        let _ = writeln!(
            html,
            "<text class=\"lane-name\" x=\"4\" y=\"{}\" dominant-baseline=\"middle\">{}</text>",
            y,
            esc(&lane.label())
        );
        let _ = writeln!(
            html,
            "<line class=\"grid-line\" x1=\"{left}\" y1=\"{y}\" x2=\"{}\" y2=\"{y}\" opacity=\"0.35\"/>",
            left + colw * columns as u32
        );
    }

    if aggregated {
        // Bucket events into columns; pick the densest non-clock category so
        // rare-but-important marks (crash/net) are not hidden by clock spam.
        let per = total.div_ceil(PER_EVENT_CAP).max(1);
        // (lane_idx, col) -> (category -> count)
        let mut cells: BTreeMap<(usize, usize), BTreeMap<Category, u64>> = BTreeMap::new();
        for (i, ev) in flat.iter().enumerate() {
            let col = i / per;
            let li = *lane_index.get(&ev.lane).unwrap_or(&0);
            *cells
                .entry((li, col))
                .or_default()
                .entry(ev.category)
                .or_insert(0) += 1;
        }
        for ((li, col), cats) in &cells {
            let dominant = cats
                .iter()
                .max_by_key(|(cat, n)| (cat_priority(**cat), **n))
                .map(|(c, _)| *c)
                .unwrap_or(Category::Other);
            let total_here: u64 = cats.values().sum();
            let x = left + colw * (*col as u32);
            let y = top + row * (*li as u32) + 3;
            let title = format!(
                "col {col}: {total_here} events (densest: {})",
                dominant.label()
            );
            let _ = writeln!(
                html,
                "<rect x=\"{x}\" y=\"{y}\" width=\"{colw}\" height=\"{}\" fill=\"var(--{})\"><title>{}</title></rect>",
                row - 6,
                dominant.css(),
                esc(&title)
            );
        }
    } else {
        for (i, ev) in flat.iter().enumerate() {
            let li = *lane_index.get(&ev.lane).unwrap_or(&0);
            let x = left + colw * (i as u32);
            let y = top + row * (li as u32) + 3;
            let vt = ev
                .vtime
                .map(|n| format!(" @ {}", human_nanos(n)))
                .unwrap_or_default();
            let title = format!("#{} {}{} — {}", ev.seq, ev.kind, vt, ev.detail);
            let h = if ev.category == Category::Crash {
                row - 2
            } else {
                row - 6
            };
            let _ = writeln!(
                html,
                "<rect x=\"{x}\" y=\"{y}\" width=\"{}\" height=\"{h}\" rx=\"1\" fill=\"var(--{})\"><title>{}</title></rect>",
                colw - 1,
                ev.category.css(),
                esc(&title)
            );
        }
    }
    html.push_str("</svg>\n</div>\n");
    html.push_str("<p class=\"muted\">Hover any mark for its sequence number, kind, virtual time, and detail. Columns are ordered by trace sequence; lanes are scheduler tasks (the <code>main</code> lane holds ops issued before any scheduling decision or in a single-threaded run).</p>\n");
}

/// Crash and network marks win ties over high-frequency clock/scheduling marks
/// when choosing a bucket's representative color.
fn cat_priority(c: Category) -> u8 {
    match c {
        Category::Crash => 6,
        Category::Net => 5,
        Category::Fs => 4,
        Category::Sleep => 3,
        Category::Entropy => 2,
        Category::Schedule => 1,
        Category::Clock => 0,
        Category::Other => 1,
    }
}

fn write_task_table(html: &mut String, lanes: &BTreeMap<LaneKey, TaskStat>) {
    if lanes.is_empty() {
        return;
    }
    html.push_str("<h2>Tasks</h2>\n<table>\n<tr><th>lane</th><th>label</th><th>ops</th><th>yields</th><th>parks</th><th>seq span</th><th>completion</th></tr>\n");
    for (lane, stat) in lanes {
        let span = match stat.first_seq {
            Some(first) => format!("{first}–{}", stat.last_seq),
            None => "—".to_string(),
        };
        let completion = if stat.completed {
            "completed"
        } else {
            "live-at-exit"
        };
        let _ = writeln!(
            html,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            esc(&lane.label()),
            esc(stat.label.as_deref().unwrap_or("—")),
            stat.ops,
            stat.yields,
            stat.parks,
            esc(&span),
            completion,
        );
    }
    html.push_str("</table>\n");
}

fn write_notable(html: &mut String, notable: &[Ev]) {
    html.push_str("<h2>Notable events</h2>\n");
    if notable.is_empty() {
        html.push_str("<p class=\"muted\">No crashes, boundary errors, or dropped datagrams were recorded.</p>\n");
        return;
    }
    html.push_str("<table>\n<tr><th>seq</th><th>lane</th><th>kind</th><th>what</th></tr>\n");
    for ev in notable {
        let what = match &ev.notable {
            Some(Notable::Crash) => "filesystem crash injected".to_string(),
            Some(Notable::Error { code, message }) => format!("error {code}: {message}"),
            Some(Notable::Drop { to, reason }) => format!("datagram to {to} dropped ({reason})"),
            None => ev.detail.clone(),
        };
        let _ = writeln!(
            html,
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
            ev.seq,
            esc(&ev.lane.label()),
            esc(&ev.kind),
            esc(&what)
        );
    }
    html.push_str("</table>\n");
}

fn write_legend(html: &mut String, cat_counts: &BTreeMap<Category, u64>) {
    html.push_str("<h2>Legend</h2>\n<div class=\"legend\">\n");
    for cat in Category::ALL {
        if cat_counts.get(&cat).copied().unwrap_or(0) == 0 {
            continue;
        }
        let _ = writeln!(
            html,
            "<span><i class=\"swatch sw-{}\"></i>{}</span>",
            cat.css(),
            esc(cat.label())
        );
    }
    html.push_str("</div>\n");
}

fn write_data_note(html: &mut String, input: &RenderInput<'_>) {
    let has_buggify = input
        .raw
        .get("metadata")
        .and_then(|m| m.get("buggify"))
        .map(|b| !b.is_null())
        .unwrap_or(false);
    html.push_str("<h2>What this trace records</h2>\n<div class=\"note\">\n");
    html.push_str("<p>The timeline above is reconstructed from the recorded boundary-operation stream. A few effects are configured in metadata rather than emitted as per-event records, so they are shown from the <em>Run metadata</em> panel, not as timeline marks:</p>\n<ul>\n");
    html.push_str("<li><strong>Buggify firings &amp; lifecycle</strong> are deterministic functions of the seed and are re-derived on replay, not recorded per evaluation. ");
    if has_buggify {
        html.push_str("This run's buggify config, active sites, and knob picks appear in the metadata panel.</li>\n");
    } else {
        html.push_str("This run recorded no buggify config.</li>\n");
    }
    html.push_str("<li><strong>Fault injection</strong> (crash point, torn-write granularity, net drop/jitter/latency, sleep jitter) is seed-driven config in <code>faults</code>; its effects surface as <code>fs_crash</code> marks and dropped-datagram outcomes on the timeline.</li>\n");
    html.push_str("<li><strong>Restarts</strong> under crash-recovery appear as an <code>fs_crash</code> mark followed by re-open activity in the same lane.</li>\n");
    html.push_str("</ul>\n</div>\n");
}

/// Render a nanosecond count in a compact human unit.
fn human_nanos(n: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use patina_abi::{ClockKind, Fd, Operation, Outcome, SocketId, TaskId};
    use patina_trace::{RunMetadata, TraceBundle, TraceEvent};

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

    fn render_bundle(bundle: &TraceBundle) -> String {
        let raw = serde_json::to_value(bundle).unwrap();
        render(&RenderInput {
            bundle,
            raw: &raw,
            trace_path: "run.patina",
            artifact: "demo",
            family: "native",
            timeline: "main",
            failure: None,
        })
    }

    #[test]
    fn renders_wellformed_standalone_html() {
        let bundle = bundle_with(vec![
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
        ]);
        let html = render_bundle(&bundle);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.trim_end().ends_with("</html>"));
        // Fully self-contained: no external references.
        assert!(!html.contains("http://") && !html.contains("https://"));
        assert!(!html.contains("<script"));
        // Event count surfaces.
        assert!(html.contains("2 events"));
    }

    #[test]
    fn attributes_ops_to_scheduled_task_lanes() {
        let bundle = bundle_with(vec![
            (
                Operation::TaskSpawn {
                    label: "worker".into(),
                },
                Outcome::Task(TaskId(1)),
            ),
            (
                Operation::SchedulerNext,
                Outcome::OptionalTask(Some(TaskId(1))),
            ),
            (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
            (Operation::TaskComplete { task: TaskId(1) }, Outcome::Unit),
        ]);
        let html = render_bundle(&bundle);
        assert!(html.contains("task 1"));
        assert!(html.contains("worker"));
        assert!(html.contains("completed"));
    }

    #[test]
    fn surfaces_crash_error_and_drop_as_notable() {
        use patina_abi::{EffectError, ErrorCode, SendDisposition, SendReport};
        let bundle = bundle_with(vec![
            (Operation::FsCrash, Outcome::Unit),
            (
                Operation::FsOpen {
                    path: "/x".into(),
                    flags: patina_abi::OpenFlags::read_only(),
                },
                Outcome::Error(EffectError::new(ErrorCode::NotFound, "missing")),
            ),
            (
                Operation::NetSend {
                    socket: SocketId(1),
                    to: "127.0.0.1:9".into(),
                    bytes: vec![0; 8],
                    now_nanos: 5,
                },
                Outcome::SendReport(SendReport {
                    written: 0,
                    copies: 0,
                    delivery_nanos: vec![],
                    disposition: SendDisposition::DroppedByFault,
                }),
            ),
        ]);
        let html = render_bundle(&bundle);
        assert!(html.contains("filesystem crash injected"));
        assert!(html.contains("error not_found: missing"));
        assert!(html.contains("dropped"));
    }

    #[test]
    fn aggregates_large_traces_with_visible_banner() {
        let events: Vec<_> = (0..(PER_EVENT_CAP + 500))
            .map(|_| {
                (
                    Operation::ClockNow {
                        clock: ClockKind::Monotonic,
                    },
                    Outcome::U64(1),
                )
            })
            .collect();
        let bundle = bundle_with(events);
        let html = render_bundle(&bundle);
        assert!(html.contains("Aggregated view"));
        assert!(html.contains("Nothing is dropped"));
    }

    #[test]
    fn renders_unknown_metadata_fields_generically() {
        // Simulate a future/unknown metadata field by editing the raw JSON the
        // metadata panel renders from.
        let bundle = bundle_with(vec![(Operation::FsCrash, Outcome::Unit)]);
        let mut raw = serde_json::to_value(&bundle).unwrap();
        raw["metadata"]["future_knob_from_another_wave"] = serde_json::json!("surfaced");
        let html = render(&RenderInput {
            bundle: &bundle,
            raw: &raw,
            trace_path: "run.patina",
            artifact: "demo",
            family: "native",
            timeline: "main",
            failure: None,
        });
        assert!(html.contains("future_knob_from_another_wave"));
        assert!(html.contains("surfaced"));
    }

    #[test]
    fn includes_failure_summary_when_present() {
        let bundle = bundle_with(vec![(Operation::FsCrash, Outcome::Unit)]);
        let raw = serde_json::to_value(&bundle).unwrap();
        let html = render(&RenderInput {
            bundle: &bundle,
            raw: &raw,
            trace_path: "run.patina",
            artifact: "demo",
            family: "native",
            timeline: "main",
            failure: Some(FailureSummary {
                result_line: "RAFT_VIOLATION two-leaders term=4".into(),
                classification: "violation".into(),
                exit_code: 1,
                facts: vec![("applied_hash".into(), "deadbeef".into())],
                messages: vec!["PATINA_SCHEDULE_REPORT tasks_spawned=3".into()],
            }),
        });
        assert!(html.contains("Run failed"));
        assert!(html.contains("RAFT_VIOLATION"));
        assert!(html.contains("applied_hash"));
    }
}
