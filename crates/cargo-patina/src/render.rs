//! Self-contained single-file HTML rendering of a recorded Patina trace.
//!
//! This module is a *read-only consumer* of trace/runtime semantics: it loads a
//! [`TraceBundle`] plus the raw trace JSON and emits a standalone HTML timeline.
//! It never records, replays, or mutates a trace, so rendering can never perturb
//! replay hashes (the render path only reads the file and writes a separate
//! `.html`).
//!
//! Event decoding is shared with the `trace` CLI through `trace_view`, including
//! the operation-kind registry that fails the build when a new ABI operation is
//! not consciously made inspectable. The metadata panel is still rendered
//! generically from the raw JSON object, so a new metadata field surfaces with no
//! renderer change.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use patina_dst_trace::{TraceBundle, TraceError};
use serde_json::Value;

use crate::trace_view::{self, Category, FlatEvent as Ev, LaneKey, Notable, TaskStat, human_nanos};

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
    /// The runner's terminal result line (e.g. a guest violation marker or
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
    let flat = trace_view::flatten(input.bundle, input.raw, input.timeline).unwrap_or_default();
    let total = flat.events.len();

    // Ensure every lane discovered via lifecycle also owns a stat row.
    let lane_order: Vec<LaneKey> = flat.lanes.keys().copied().collect();

    let mut html = String::with_capacity(64 * 1024);
    write_head(&mut html, input);
    write_body_open(&mut html);
    write_header(
        &mut html,
        input,
        total,
        &lane_order,
        flat.vt_min,
        flat.vt_max,
    );
    if let Some(failure) = &input.failure {
        write_failure(&mut html, failure);
    }
    write_metadata(&mut html, input);
    write_stat_tiles(
        &mut html,
        total,
        &lane_order,
        &flat.category_counts,
        flat.vt_min,
        flat.vt_max,
    );
    write_timeline(&mut html, &flat.events, &lane_order, total);
    write_task_table(&mut html, &flat.lanes);
    write_notable(&mut html, &flat.notable);
    write_legend(&mut html, &flat.category_counts);
    write_data_note(&mut html, input);
    write_body_close(&mut html);
    html
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
        let what = ev
            .notable
            .as_ref()
            .map(Notable::human)
            .unwrap_or_else(|| ev.detail.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_abi::{ClockKind, Fd, Operation, Outcome, SocketId, TaskId};
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
        use patina_dst_abi::{EffectError, ErrorCode, SendDisposition, SendReport};
        let bundle = bundle_with(vec![
            (Operation::FsCrash, Outcome::Unit),
            (
                Operation::FsOpen {
                    path: "/x".into(),
                    flags: patina_dst_abi::OpenFlags::read_only(),
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
    fn renders_every_registered_operation_kind() {
        let bundle = bundle_with(crate::trace_view::representative_events_for_all_op_kinds());
        let html = render_bundle(&bundle);
        for (kind, _) in crate::trace_view::OP_KINDS {
            assert!(
                html.contains(kind),
                "render should surface operation kind {kind}"
            );
        }
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
                result_line: "GUEST_VIOLATION two-leaders term=4".into(),
                classification: "violation".into(),
                exit_code: 1,
                facts: vec![("applied_hash".into(), "deadbeef".into())],
                messages: vec!["PATINA_SCHEDULE_REPORT tasks_spawned=3".into()],
            }),
        });
        assert!(html.contains("Run failed"));
        assert!(html.contains("GUEST_VIOLATION"));
        assert!(html.contains("applied_hash"));
    }
}
