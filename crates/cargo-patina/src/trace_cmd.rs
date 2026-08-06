//! `cargo patina trace` inspection commands.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use patina_dst_trace::{TraceBundle, TraceError};
use serde_json::{Map, Value};

use crate::CliError;
use crate::output::{self, OutputFormat};
use crate::trace_view::{self, Category, FlatEvent, FlatTrace, LaneKey, Notable};

pub(crate) const INFO_SCHEMA: &str = "patina.trace.info/v1";
pub(crate) const EVENTS_SCHEMA: &str = "patina.trace.events/v1";
pub(crate) const STATS_SCHEMA: &str = "patina.trace.stats/v1";
pub(crate) const DIFF_SCHEMA: &str = "patina.trace.diff/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TraceInvocation {
    Info(TraceInfo),
    Events(TraceEvents),
    Stats(TraceStats),
    Diff(TraceDiff),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceInfo {
    pub(crate) path: PathBuf,
    pub(crate) timeline: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceEvents {
    pub(crate) path: PathBuf,
    pub(crate) timeline: String,
    pub(crate) filters: EventFilters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceStats {
    pub(crate) path: PathBuf,
    pub(crate) timeline: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceDiff {
    pub(crate) a: PathBuf,
    pub(crate) b: PathBuf,
    pub(crate) timeline: String,
    pub(crate) context: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EventFilters {
    pub(crate) op_kinds: BTreeSet<String>,
    pub(crate) categories: BTreeSet<Category>,
    pub(crate) tasks: BTreeSet<LaneKey>,
    pub(crate) seq: Option<(u64, u64)>,
    pub(crate) first: Option<u64>,
    pub(crate) last: Option<u64>,
    pub(crate) notable: bool,
}

impl EventFilters {
    pub(crate) fn matches(&self, event: &FlatEvent) -> bool {
        if !(self.op_kinds.is_empty() && self.categories.is_empty())
            && !self.op_kinds.contains(&event.kind)
            && !self.categories.contains(&event.category)
        {
            return false;
        }
        if !self.tasks.is_empty() && !self.tasks.contains(&event.lane) {
            return false;
        }
        if let Some((start, end)) = self.seq {
            if event.seq < start || event.seq > end {
                return false;
            }
        }
        if self.notable && event.notable.is_none() {
            return false;
        }
        true
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        if !self.op_kinds.is_empty() || !self.categories.is_empty() {
            let mut kinds: Vec<Value> = self.op_kinds.iter().cloned().map(Value::from).collect();
            kinds.extend(
                self.categories
                    .iter()
                    .map(|category| Value::from(category.label())),
            );
            map.insert("kind".into(), Value::Array(kinds));
        }
        if !self.tasks.is_empty() {
            map.insert(
                "task".into(),
                Value::Array(self.tasks.iter().map(|task| task.json_value()).collect()),
            );
        }
        if let Some((start, end)) = self.seq {
            map.insert(
                "seq".into(),
                serde_json::json!({ "start": start, "end": end }),
            );
        }
        if let Some(first) = self.first {
            map.insert("first".into(), Value::from(first));
        }
        if let Some(last) = self.last {
            map.insert("last".into(), Value::from(last));
        }
        if self.notable {
            map.insert("notable".into(), Value::from(true));
        }
        Value::Object(map)
    }
}

pub(crate) fn execute(invocation: TraceInvocation) -> Result<i32, CliError> {
    reject_render_report()?;
    match invocation {
        TraceInvocation::Info(info) => execute_info(&info),
        TraceInvocation::Events(events) => execute_events(&events),
        TraceInvocation::Stats(stats) => execute_stats(&stats),
        TraceInvocation::Diff(diff) => execute_diff(&diff),
    }
}

fn reject_render_report() -> Result<(), CliError> {
    let opts = output::options();
    if opts.render.is_some() || opts.report.is_some() {
        return Err(CliError::usage(
            "trace inspection is read-only and does not accept --render/--report; use `cargo patina trace events` for textual inspection or run/replay --render when executing a guest",
        ));
    }
    Ok(())
}

fn execute_info(info: &TraceInfo) -> Result<i32, CliError> {
    let (bundle, raw) = load_trace(&info.path)?;
    let facts = info_value(&info.path, &info.timeline, &bundle, &raw)?;
    match output::options().format {
        OutputFormat::Human => print_info_human(&facts),
        OutputFormat::Json => println!("{}", compact_json(&info_envelope(facts))?),
    }
    Ok(0)
}

fn execute_stats(stats: &TraceStats) -> Result<i32, CliError> {
    let (bundle, raw) = load_trace(&stats.path)?;
    let flat = trace_view::flatten(&bundle, &raw, &stats.timeline)
        .map_err(|error| trace_error(&stats.path, error))?;
    let payload = stats_value(&stats.path, &stats.timeline, &flat);
    match output::options().format {
        OutputFormat::Human => print_stats_human(&payload),
        OutputFormat::Json => println!("{}", compact_json(&stats_envelope(payload))?),
    }
    Ok(0)
}

fn execute_diff(diff: &TraceDiff) -> Result<i32, CliError> {
    let (a_bundle, a_raw) = load_trace(&diff.a)?;
    let (b_bundle, b_raw) = load_trace(&diff.b)?;
    let a_flat = trace_view::flatten(&a_bundle, &a_raw, &diff.timeline)
        .map_err(|error| trace_error(&diff.a, error))?;
    let b_flat = trace_view::flatten(&b_bundle, &b_raw, &diff.timeline)
        .map_err(|error| trace_error(&diff.b, error))?;
    let report = diff_report(
        &diff.a,
        &diff.b,
        &diff.timeline,
        &a_bundle,
        &b_bundle,
        &a_raw,
        &b_raw,
        &a_flat,
        &b_flat,
        diff.context,
    );
    let exit_code = if report.identical { 0 } else { 1 };
    match output::options().format {
        OutputFormat::Human => print_diff_human(&report),
        OutputFormat::Json => println!(
            "{}",
            compact_json(&diff_envelope(report.to_json(), exit_code))?
        ),
    }
    Ok(exit_code)
}

fn execute_events(events: &TraceEvents) -> Result<i32, CliError> {
    let (bundle, raw) = load_trace(&events.path)?;
    let flat = trace_view::flatten(&bundle, &raw, &events.timeline)
        .map_err(|error| trace_error(&events.path, error))?;
    debug_assert_eq!(
        flat.kind_counts
            .values()
            .map(|stat| stat.count)
            .sum::<u64>(),
        flat.events.len() as u64
    );
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match output::options().format {
        OutputFormat::Human => write_events_human(
            &mut out,
            &events.path,
            &events.timeline,
            &flat,
            &events.filters,
        )?,
        OutputFormat::Json => write_events_jsonl(
            &mut out,
            &events.path,
            &events.timeline,
            &flat,
            &events.filters,
        )?,
    }
    Ok(0)
}

fn load_trace(path: &Path) -> Result<(TraceBundle, Value), CliError> {
    let bundle = TraceBundle::load(path).map_err(|error| trace_error(path, error))?;
    let bytes = std::fs::read(path)
        .map_err(|error| CliError(format!("failed to read trace {}: {error}", path.display())))?;
    let raw = serde_json::from_slice(&bytes).map_err(|source| {
        trace_error(
            path,
            TraceError::Parse {
                path: path.to_path_buf(),
                source,
            },
        )
    })?;
    Ok((bundle, raw))
}

fn trace_error(path: &Path, error: TraceError) -> CliError {
    CliError(format!("failed to load trace {}: {error}", path.display()))
}

fn info_envelope(facts: Value) -> Value {
    trace_envelope("info", "ok", 0, "trace_info", facts)
}

fn stats_envelope(stats: Value) -> Value {
    trace_envelope("stats", "ok", 0, "trace_stats", stats)
}

fn diff_envelope(diff: Value, exit_code: i32) -> Value {
    let result = diff
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("diverged")
        .to_string();
    trace_envelope("diff", &result, exit_code, "trace_diff", diff)
}

fn trace_envelope(
    subcommand: &str,
    result: &str,
    exit_code: i32,
    payload_key: &str,
    payload: Value,
) -> Value {
    let mut map = Map::new();
    map.insert("schema".into(), Value::from(output::ENVELOPE_SCHEMA));
    map.insert("verb".into(), Value::from("trace"));
    map.insert("subcommand".into(), Value::from(subcommand));
    map.insert("result".into(), Value::from(result));
    map.insert("exit_code".into(), Value::from(exit_code));
    map.insert(payload_key.into(), payload);
    Value::Object(map)
}

fn compact_json(value: &Value) -> Result<String, CliError> {
    serde_json::to_string(value)
        .map_err(|error| CliError(format!("failed to encode trace JSON: {error}")))
}

pub(crate) fn info_value(
    path: &Path,
    timeline: &str,
    bundle: &TraceBundle,
    raw: &Value,
) -> Result<Value, CliError> {
    let events = raw_resolved_events(raw, timeline)?;
    let (vt_min, vt_max) = vtime_span(&events);
    let timelines: Vec<Value> = bundle
        .timelines
        .iter()
        .map(|timeline| {
            serde_json::json!({
                "id": timeline.id,
                "parent": timeline.parent,
                "from_sequence": timeline.from_sequence,
                "branch_seed": timeline.branch_seed,
                "events": timeline.decisions.len(),
            })
        })
        .collect();
    let metadata = raw
        .get("metadata")
        .cloned()
        .unwrap_or_else(|| serde_json::to_value(&bundle.metadata).unwrap_or(Value::Null));
    let vtime = match (vt_min, vt_max) {
        (Some(min), Some(max)) => serde_json::json!({
            "min_nanos": min,
            "max_nanos": max,
            "span_nanos": max.saturating_sub(min),
        }),
        _ => Value::Null,
    };
    Ok(serde_json::json!({
        "schema": INFO_SCHEMA,
        "path": path.to_string_lossy(),
        "format_version": bundle.format_version,
        "fingerprint": bundle.metadata.fingerprint,
        "root_seed": bundle.metadata.root_seed,
        "decision_policy": bundle.metadata.decision_policy,
        "guest_argv": bundle.metadata.guest_argv,
        "timeline": timeline,
        "timelines": timelines,
        "resolved_events": events.len(),
        "vtime": vtime,
        "metadata": metadata,
    }))
}

fn raw_resolved_events<'a>(raw: &'a Value, id: &str) -> Result<Vec<&'a Value>, CliError> {
    let timelines = raw
        .get("timelines")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("trace JSON is missing a timelines array".into()))?;
    let index = timelines
        .iter()
        .position(|timeline| timeline.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| CliError(format!("trace has no timeline named {id:?}")))?;
    raw_resolved_events_by_index(timelines, index)
}

fn raw_resolved_events_by_index(
    timelines: &[Value],
    index: usize,
) -> Result<Vec<&Value>, CliError> {
    let timeline = &timelines[index];
    let decisions = timeline
        .get("decisions")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("trace timeline is missing a decisions array".into()))?;
    let Some(parent) = timeline.get("parent").and_then(Value::as_str) else {
        return Ok(decisions.iter().collect());
    };
    let parent_index = timelines[..index]
        .iter()
        .position(|candidate| candidate.get("id").and_then(Value::as_str) == Some(parent))
        .ok_or_else(|| CliError(format!("trace has no timeline named {parent:?}")))?;
    let mut resolved = raw_resolved_events_by_index(timelines, parent_index)?;
    let from = timeline
        .get("from_sequence")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    resolved.truncate(from);
    resolved.extend(decisions.iter());
    Ok(resolved)
}

fn vtime_span(events: &[&Value]) -> (Option<u64>, Option<u64>) {
    let mut current: Option<u64> = None;
    let mut min: Option<u64> = None;
    let mut max: Option<u64> = None;
    for event in events {
        let op = event.get("operation").unwrap_or(&Value::Null);
        let out = event.get("outcome").unwrap_or(&Value::Null);
        let kind = op.get("kind").and_then(Value::as_str);
        if kind == Some("clock_now") {
            if let Some(value) = outcome_u64(out) {
                current = Some(value);
            }
        }
        if let Some(value) = op.get("now_nanos").and_then(Value::as_u64) {
            current = Some(value);
        }
        if let Some(value) = current {
            min = Some(min.map_or(value, |old| old.min(value)));
            max = Some(max.map_or(value, |old| old.max(value)));
        }
    }
    (min, max)
}

fn outcome_u64(out: &Value) -> Option<u64> {
    match out.get("kind").and_then(Value::as_str)? {
        "u64" | "usize" => out.get("value").and_then(Value::as_u64),
        _ => None,
    }
}

fn print_info_human(facts: &Value) {
    println!("trace: {}", facts["path"].as_str().unwrap_or("?"));
    println!("format_version: {}", facts["format_version"]);
    println!(
        "fingerprint: {}",
        facts["fingerprint"].as_str().unwrap_or("?")
    );
    println!("root_seed: {}", facts["root_seed"]);
    println!(
        "decision_policy: {}",
        facts["decision_policy"].as_str().unwrap_or("?")
    );
    if !facts["guest_argv"].is_null() {
        println!("guest_argv: {}", compact_json_lossy(&facts["guest_argv"]));
    }
    let timeline_summary = facts["timelines"]
        .as_array()
        .map(|timelines| {
            timelines
                .iter()
                .map(|timeline| {
                    let id = timeline["id"].as_str().unwrap_or("?");
                    let events = timeline["events"].as_u64().unwrap_or(0);
                    if timeline["parent"].is_null() {
                        format!("{id} ({events} events)")
                    } else {
                        format!(
                            "{} (parent {} @ {}, seed {}, {} events)",
                            id,
                            timeline["parent"].as_str().unwrap_or("?"),
                            timeline["from_sequence"].as_u64().unwrap_or(0),
                            timeline["branch_seed"].as_u64().unwrap_or(0),
                            events
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default();
    println!("timelines: {timeline_summary}");
    println!(
        "events: {} (resolved {})",
        facts["resolved_events"],
        facts["timeline"].as_str().unwrap_or("main")
    );
    if facts["vtime"].is_null() {
        println!("virtual time: no samples");
    } else {
        let min = facts["vtime"]["min_nanos"].as_u64().unwrap_or(0);
        let max = facts["vtime"]["max_nanos"].as_u64().unwrap_or(min);
        let span = facts["vtime"]["span_nanos"].as_u64().unwrap_or(0);
        println!(
            "virtual time: {} .. {} (span {})",
            trace_view::human_nanos(min),
            trace_view::human_nanos(max),
            trace_view::human_nanos(span)
        );
    }
    let metadata = &facts["metadata"];
    print_optional_metadata(metadata, "faults", "faults");
    if metadata
        .get("buggify")
        .is_some_and(|value| !value.is_null())
    {
        println!(
            "buggify: {} (per-evaluation firings are re-derived from the seed, not recorded)",
            compact_json_lossy(&metadata["buggify"])
        );
    }
    print_optional_metadata(metadata, "schedule_policy", "schedule_policy");
    print_swarm_metadata(metadata);
    print_optional_metadata(metadata, "watchdog", "watchdog");
    if metadata.get("sud").and_then(Value::as_bool) == Some(true) {
        println!("sud: armed");
    }
    println!(
        "next: `cargo patina trace events {}` for the event stream",
        facts["path"].as_str().unwrap_or("<TRACE>")
    );
}

/// Render the swarm record with its selection spelled out rather than as raw
/// JSON the reader has to diff by eye. The deselected list is the whole point of
/// the record: a class named there was requested and dropped by this generation's
/// seed, which is why the trace carries no `buggify`/fault config for it and why
/// its fingerprint component is absent. A class the operator never enabled is in
/// neither list.
fn print_swarm_metadata(metadata: &Value) {
    let Some(swarm) = metadata.get("swarm").filter(|value| !value.is_null()) else {
        return;
    };
    let classes = |key: &str| -> Vec<&str> {
        swarm
            .get(key)
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    };
    let candidates = classes("candidate_classes");
    let selected = classes("selected_classes");
    let deselected: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|class| !selected.contains(class))
        .collect();
    let list = |values: &[&str]| -> String {
        if values.is_empty() {
            "(none)".to_string()
        } else {
            values.join(",")
        }
    };
    println!(
        "swarm: candidates={} selected={} deselected={}",
        list(&candidates),
        list(&selected),
        list(&deselected)
    );
}

fn print_optional_metadata(metadata: &Value, key: &str, label: &str) {
    if let Some(value) = metadata.get(key) {
        if !value.is_null() {
            println!("{label}: {}", compact_json_lossy(value));
        }
    }
}

fn compact_json_lossy(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "?".to_string())
}

pub(crate) fn write_events_human<W: std::io::Write>(
    out: &mut W,
    _path: &Path,
    _timeline: &str,
    flat: &FlatTrace,
    filters: &EventFilters,
) -> Result<(), CliError> {
    let mut matched = 0u64;
    let mut emitted = 0u64;
    match (filters.first, filters.last) {
        (Some(limit), None) => {
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                if emitted < limit {
                    write_human_event(out, event)?;
                    emitted += 1;
                }
            }
        }
        (None, Some(limit)) => {
            let mut ring: VecDeque<&FlatEvent> = VecDeque::new();
            let cap = usize::try_from(limit).map_err(|_| {
                CliError::usage(format!(
                    "--last value {limit} is too large for this platform"
                ))
            })?;
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                if ring.len() == cap {
                    ring.pop_front();
                }
                ring.push_back(event);
            }
            for event in ring {
                write_human_event(out, event)?;
                emitted += 1;
            }
        }
        (None, None) => {
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                write_human_event(out, event)?;
                emitted += 1;
            }
        }
        (Some(_), Some(_)) => unreachable!("parser rejects --first with --last"),
    }
    let _ = (matched, emitted);
    Ok(())
}

fn write_human_event<W: std::io::Write>(out: &mut W, event: &FlatEvent) -> Result<(), CliError> {
    writeln!(out, "{}", human_event_line(event))
        .map_err(|error| CliError(format!("failed to write trace events: {error}")))
}

fn human_event_line(event: &FlatEvent) -> String {
    let vtime = event
        .vtime
        .map(|n| format!(" @ {}", trace_view::human_nanos(n)))
        .unwrap_or_default();
    let notable = event
        .notable
        .as_ref()
        .map(|note| format!("  [notable: {}]", note.kind()))
        .unwrap_or_default();
    format!(
        "#{:06}  {:<8} {:<18} {}{}{}",
        event.seq,
        event.lane.label(),
        event.kind,
        event.detail,
        vtime,
        notable
    )
}

pub(crate) fn write_events_jsonl<W: std::io::Write>(
    out: &mut W,
    path: &Path,
    timeline: &str,
    flat: &FlatTrace,
    filters: &EventFilters,
) -> Result<(), CliError> {
    write_json_line(
        out,
        &serde_json::json!({
            "schema": EVENTS_SCHEMA,
            "path": path.to_string_lossy(),
            "timeline": timeline,
            "total_events": flat.events.len(),
            "filters": filters.to_json(),
        }),
    )?;

    let mut matched = 0u64;
    let mut emitted = 0u64;
    match (filters.first, filters.last) {
        (Some(limit), None) => {
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                if emitted < limit {
                    write_json_event(out, event)?;
                    emitted += 1;
                }
            }
        }
        (None, Some(limit)) => {
            let mut ring: VecDeque<&FlatEvent> = VecDeque::new();
            let cap = usize::try_from(limit).map_err(|_| {
                CliError::usage(format!(
                    "--last value {limit} is too large for this platform"
                ))
            })?;
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                if ring.len() == cap {
                    ring.pop_front();
                }
                ring.push_back(event);
            }
            for event in ring {
                write_json_event(out, event)?;
                emitted += 1;
            }
        }
        (None, None) => {
            for event in &flat.events {
                if !filters.matches(event) {
                    continue;
                }
                matched += 1;
                write_json_event(out, event)?;
                emitted += 1;
            }
        }
        (Some(_), Some(_)) => unreachable!("parser rejects --first with --last"),
    }

    write_json_line(
        out,
        &serde_json::json!({
            "matched": matched,
            "emitted": emitted,
        }),
    )
}

fn write_json_event<W: std::io::Write>(out: &mut W, event: &FlatEvent) -> Result<(), CliError> {
    write_json_line(out, &event_value(event))
}

fn event_value(event: &FlatEvent) -> Value {
    let mut map = Map::new();
    map.insert("seq".into(), Value::from(event.seq));
    map.insert("task".into(), event.lane.json_value());
    map.insert("kind".into(), Value::from(event.kind.clone()));
    map.insert("category".into(), Value::from(event.category.label()));
    map.insert(
        "vtime_nanos".into(),
        event.vtime.map(Value::from).unwrap_or(Value::Null),
    );
    if let Some(notable) = &event.notable {
        map.insert("notable".into(), notable.to_json());
    }
    map.insert("operation".into(), event.operation.clone());
    map.insert("outcome".into(), event.outcome.clone());
    Value::Object(map)
}

fn write_json_line<W: std::io::Write>(out: &mut W, value: &Value) -> Result<(), CliError> {
    serde_json::to_writer(&mut *out, value)
        .map_err(|error| CliError(format!("failed to encode trace events JSON: {error}")))?;
    writeln!(out).map_err(|error| CliError(format!("failed to write trace events: {error}")))
}

const HISTOGRAM_BUCKETS: usize = 20;

fn stats_value(path: &Path, timeline: &str, flat: &FlatTrace) -> Value {
    let notable = notable_counts(flat);
    let vtime = histogram_value(flat);
    let mut kinds = Map::new();
    for (kind, stat) in &flat.kind_counts {
        kinds.insert(
            kind.clone(),
            serde_json::json!({
                "count": stat.count,
                "errors": stat.errors,
                "bytes_in": stat.bytes_in,
                "bytes_out": stat.bytes_out,
            }),
        );
    }
    let mut categories = Map::new();
    for category in Category::ALL {
        categories.insert(
            category.label().to_string(),
            Value::from(flat.category_counts.get(&category).copied().unwrap_or(0)),
        );
    }
    let tasks: Vec<Value> = flat
        .lanes
        .iter()
        .map(|(lane, stat)| task_stat_value(*lane, stat))
        .collect();
    serde_json::json!({
        "schema": STATS_SCHEMA,
        "path": path.to_string_lossy(),
        "timeline": timeline,
        "totals": {
            "events": flat.events.len(),
            "lanes": flat.lanes.len(),
            "virtual_time_span_nanos": flat.vt_min.zip(flat.vt_max).map(|(min, max)| max.saturating_sub(min)),
            "notable": flat.notable.len(),
        },
        "kinds": Value::Object(kinds),
        "categories": Value::Object(categories),
        "tasks": tasks,
        "vtime": vtime,
        "notable": {
            "crashes": notable.crashes,
            "errors": notable.errors,
            "drops": notable.drops,
        },
    })
}

fn task_stat_value(lane: LaneKey, stat: &trace_view::TaskStat) -> Value {
    serde_json::json!({
        "lane": lane.json_value(),
        "label": stat.label.clone(),
        "ops": stat.ops,
        "yields": stat.yields,
        "parks": stat.parks,
        "first_seq": stat.first_seq,
        "last_seq": stat.first_seq.map(|_| stat.last_seq),
        "completed": stat.completed,
        "completion": if stat.completed { "completed" } else { "live-at-exit" },
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NotableCounts {
    crashes: u64,
    errors: u64,
    drops: u64,
}

fn notable_counts(flat: &FlatTrace) -> NotableCounts {
    let mut counts = NotableCounts::default();
    for event in &flat.notable {
        match event.notable.as_ref() {
            Some(Notable::Crash) => counts.crashes += 1,
            Some(Notable::Error { .. }) => counts.errors += 1,
            Some(Notable::Drop { .. }) => counts.drops += 1,
            None => {}
        }
    }
    counts
}

fn histogram_value(flat: &FlatTrace) -> Value {
    let Some(buckets) = histogram_buckets(flat) else {
        return Value::Null;
    };
    serde_json::json!({
        "min_nanos": flat.vt_min,
        "max_nanos": flat.vt_max,
        "buckets": buckets.into_iter().map(|bucket| serde_json::json!({
            "start_nanos": bucket.start,
            "end_nanos": bucket.end,
            "events": bucket.events,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistogramBucket {
    start: u64,
    end: u64,
    events: u64,
}

fn histogram_buckets(flat: &FlatTrace) -> Option<Vec<HistogramBucket>> {
    let (min, max) = flat.vt_min.zip(flat.vt_max)?;
    let range = u128::from(max) - u128::from(min) + 1;
    let mut buckets = Vec::with_capacity(HISTOGRAM_BUCKETS);
    for index in 0..HISTOGRAM_BUCKETS {
        let start_offset = range * index as u128 / HISTOGRAM_BUCKETS as u128;
        let end_exclusive_offset = range * (index as u128 + 1) / HISTOGRAM_BUCKETS as u128;
        let start = u64::try_from(u128::from(min) + start_offset).unwrap_or(max);
        let end = if end_exclusive_offset == 0 {
            start
        } else {
            u64::try_from(u128::from(min) + end_exclusive_offset - 1).unwrap_or(max)
        };
        buckets.push(HistogramBucket {
            start: start.min(max),
            end: end.min(max),
            events: 0,
        });
    }
    for event in &flat.events {
        let Some(vtime) = event.vtime else {
            continue;
        };
        let offset = u128::from(vtime.saturating_sub(min));
        let bucket = ((offset * HISTOGRAM_BUCKETS as u128) / range)
            .min(HISTOGRAM_BUCKETS as u128 - 1) as usize;
        buckets[bucket].events += 1;
    }
    Some(buckets)
}

fn print_stats_human(stats: &Value) {
    println!("trace stats: {}", stats["path"].as_str().unwrap_or("?"));
    println!("timeline: {}", stats["timeline"].as_str().unwrap_or("main"));
    println!("\nTotals");
    println!("events: {}", stats["totals"]["events"]);
    println!("lanes: {}", stats["totals"]["lanes"]);
    if stats["totals"]["virtual_time_span_nanos"].is_null() {
        println!("virtual time: no samples");
    } else {
        let span = stats["totals"]["virtual_time_span_nanos"]
            .as_u64()
            .unwrap_or(0);
        println!("virtual time span: {}", trace_view::human_nanos(span));
    }
    println!(
        "notable: crashes={} errors={} drops={}",
        stats["notable"]["crashes"], stats["notable"]["errors"], stats["notable"]["drops"]
    );

    let total = stats["totals"]["events"].as_u64().unwrap_or(0).max(1);
    println!("\nPer-kind");
    println!(
        "{:<22} {:>8} {:>8} {:>8} {:>10} {:>10}",
        "kind", "count", "share", "errors", "bytes_in", "bytes_out"
    );
    if let Some(kinds) = stats["kinds"].as_object() {
        for (kind, stat) in kinds {
            let count = stat["count"].as_u64().unwrap_or(0);
            let share = count as f64 * 100.0 / total as f64;
            println!(
                "{:<22} {:>8} {:>7.2}% {:>8} {:>10} {:>10}",
                kind,
                count,
                share,
                stat["errors"].as_u64().unwrap_or(0),
                stat["bytes_in"].as_u64().unwrap_or(0),
                stat["bytes_out"].as_u64().unwrap_or(0)
            );
        }
    }

    println!("\nPer-category");
    println!("{:<12} {:>8}", "category", "count");
    if let Some(categories) = stats["categories"].as_object() {
        for category in Category::ALL {
            let label = category.label();
            println!(
                "{:<12} {:>8}",
                label,
                categories.get(label).and_then(Value::as_u64).unwrap_or(0)
            );
        }
    }

    println!("\nPer-task");
    println!(
        "{:<10} {:<18} {:>8} {:>8} {:>8} {:<17} completion",
        "lane", "label", "ops", "yields", "parks", "seq span"
    );
    if let Some(tasks) = stats["tasks"].as_array() {
        for task in tasks {
            let lane = task["lane"]
                .as_str()
                .map(str::to_string)
                .or_else(|| task["lane"].as_u64().map(|id| format!("task {id}")))
                .unwrap_or_else(|| "?".into());
            let span = match (task["first_seq"].as_u64(), task["last_seq"].as_u64()) {
                (Some(first), Some(last)) => format!("{first}..{last}"),
                _ => "—".to_string(),
            };
            println!(
                "{:<10} {:<18} {:>8} {:>8} {:>8} {:<17} {}",
                lane,
                task["label"].as_str().unwrap_or("—"),
                task["ops"].as_u64().unwrap_or(0),
                task["yields"].as_u64().unwrap_or(0),
                task["parks"].as_u64().unwrap_or(0),
                span,
                task["completion"].as_str().unwrap_or("?")
            );
        }
    }

    println!("\nVirtual-time histogram");
    if let Some(vtime) = stats["vtime"].as_object() {
        let buckets = vtime["buckets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let max_events = buckets
            .iter()
            .filter_map(|bucket| bucket["events"].as_u64())
            .max()
            .unwrap_or(1)
            .max(1);
        for bucket in buckets {
            let events = bucket["events"].as_u64().unwrap_or(0);
            let bar_len = ((events * 40) / max_events) as usize;
            println!(
                "{:>12} .. {:<12} {:>8} {}",
                trace_view::human_nanos(bucket["start_nanos"].as_u64().unwrap_or(0)),
                trace_view::human_nanos(bucket["end_nanos"].as_u64().unwrap_or(0)),
                events,
                "#".repeat(bar_len)
            );
        }
    } else {
        println!("no virtual-time samples");
    }
}

#[derive(Clone, Debug)]
struct MetadataDiff {
    field: String,
    a: Value,
    b: Value,
}

#[derive(Clone, Debug)]
struct Divergence {
    seq: u64,
    class: &'static str,
    a_event: Option<FlatEvent>,
    b_event: Option<FlatEvent>,
    a_context: Vec<FlatEvent>,
    b_context: Vec<FlatEvent>,
}

#[derive(Clone, Debug)]
struct DiffReport {
    a_path: String,
    b_path: String,
    timeline: String,
    a_events: usize,
    b_events: usize,
    a_final_vtime: Option<u64>,
    b_final_vtime: Option<u64>,
    metadata_diff: Vec<MetadataDiff>,
    aligned_prefix: usize,
    divergence: Option<Divergence>,
    identical: bool,
}

impl DiffReport {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "schema": DIFF_SCHEMA,
            "a": {
                "path": self.a_path,
                "timeline": self.timeline,
                "events": self.a_events,
                "final_vtime_nanos": self.a_final_vtime,
            },
            "b": {
                "path": self.b_path,
                "timeline": self.timeline,
                "events": self.b_events,
                "final_vtime_nanos": self.b_final_vtime,
            },
            "result": if self.identical { "identical" } else { "diverged" },
            "metadata_diff": self.metadata_diff.iter().map(|diff| serde_json::json!({
                "field": diff.field,
                "a": diff.a,
                "b": diff.b,
            })).collect::<Vec<_>>(),
            "aligned_prefix": self.aligned_prefix,
            "divergence": self.divergence.as_ref().map(divergence_value),
            "tails": {
                "a": {
                    "events": self.a_events.saturating_sub(self.aligned_prefix),
                    "final_vtime_nanos": self.a_final_vtime,
                },
                "b": {
                    "events": self.b_events.saturating_sub(self.aligned_prefix),
                    "final_vtime_nanos": self.b_final_vtime,
                },
            },
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn diff_report(
    a_path: &Path,
    b_path: &Path,
    timeline: &str,
    a_bundle: &TraceBundle,
    b_bundle: &TraceBundle,
    a_raw: &Value,
    b_raw: &Value,
    a_flat: &FlatTrace,
    b_flat: &FlatTrace,
    context: usize,
) -> DiffReport {
    let metadata_diff = metadata_diff(a_bundle, b_bundle, a_raw, b_raw);
    let (aligned_prefix, divergence) = event_divergence(a_flat, b_flat, context);
    let identical = metadata_diff.is_empty() && divergence.is_none();
    DiffReport {
        a_path: a_path.to_string_lossy().into_owned(),
        b_path: b_path.to_string_lossy().into_owned(),
        timeline: timeline.to_string(),
        a_events: a_flat.events.len(),
        b_events: b_flat.events.len(),
        a_final_vtime: final_vtime(a_flat),
        b_final_vtime: final_vtime(b_flat),
        metadata_diff,
        aligned_prefix,
        divergence,
        identical,
    }
}

fn metadata_diff(
    a_bundle: &TraceBundle,
    b_bundle: &TraceBundle,
    a_raw: &Value,
    b_raw: &Value,
) -> Vec<MetadataDiff> {
    let mut diffs = Vec::new();
    if a_bundle.format_version != b_bundle.format_version {
        diffs.push(MetadataDiff {
            field: "format_version".into(),
            a: Value::from(a_bundle.format_version),
            b: Value::from(b_bundle.format_version),
        });
    }
    let a_meta = a_raw
        .get("metadata")
        .cloned()
        .unwrap_or_else(|| serde_json::to_value(&a_bundle.metadata).unwrap_or(Value::Null));
    let b_meta = b_raw
        .get("metadata")
        .cloned()
        .unwrap_or_else(|| serde_json::to_value(&b_bundle.metadata).unwrap_or(Value::Null));
    match (a_meta.as_object(), b_meta.as_object()) {
        (Some(a), Some(b)) => {
            let keys: BTreeSet<String> = a.keys().chain(b.keys()).cloned().collect();
            for key in keys {
                let av = a.get(&key).cloned().unwrap_or(Value::Null);
                let bv = b.get(&key).cloned().unwrap_or(Value::Null);
                if av != bv {
                    diffs.push(MetadataDiff {
                        field: key,
                        a: av,
                        b: bv,
                    });
                }
            }
        }
        _ if a_meta != b_meta => diffs.push(MetadataDiff {
            field: "metadata".into(),
            a: a_meta,
            b: b_meta,
        }),
        _ => {}
    }
    diffs
}

fn event_divergence(
    a_flat: &FlatTrace,
    b_flat: &FlatTrace,
    context: usize,
) -> (usize, Option<Divergence>) {
    let min_len = a_flat.events.len().min(b_flat.events.len());
    let mut aligned = 0usize;
    for index in 0..min_len {
        let a = &a_flat.events[index];
        let b = &b_flat.events[index];
        if a.operation != b.operation {
            return (
                aligned,
                Some(make_divergence(
                    "operation-mismatch",
                    index,
                    Some(a),
                    Some(b),
                    &a_flat.events,
                    &b_flat.events,
                    context,
                )),
            );
        }
        if a.outcome != b.outcome {
            return (
                aligned,
                Some(make_divergence(
                    "outcome-mismatch",
                    index,
                    Some(a),
                    Some(b),
                    &a_flat.events,
                    &b_flat.events,
                    context,
                )),
            );
        }
        aligned += 1;
    }
    if a_flat.events.len() != b_flat.events.len() {
        return (
            aligned,
            Some(make_divergence(
                "length",
                min_len,
                a_flat.events.get(min_len),
                b_flat.events.get(min_len),
                &a_flat.events,
                &b_flat.events,
                context,
            )),
        );
    }
    (aligned, None)
}

fn make_divergence(
    class: &'static str,
    index: usize,
    a_event: Option<&FlatEvent>,
    b_event: Option<&FlatEvent>,
    a_events: &[FlatEvent],
    b_events: &[FlatEvent],
    context: usize,
) -> Divergence {
    let seq = a_event
        .or(b_event)
        .map(|event| event.seq)
        .unwrap_or(index as u64);
    Divergence {
        seq,
        class,
        a_event: a_event.cloned(),
        b_event: b_event.cloned(),
        a_context: context_events(a_events, index, context),
        b_context: context_events(b_events, index, context),
    }
}

fn context_events(events: &[FlatEvent], index: usize, context: usize) -> Vec<FlatEvent> {
    if events.is_empty() {
        return Vec::new();
    }
    if index >= events.len() {
        let start = events.len().saturating_sub(context);
        return events[start..].to_vec();
    }
    let start = index.saturating_sub(context);
    let end = (index + context + 1).min(events.len());
    events[start..end].to_vec()
}

fn divergence_value(divergence: &Divergence) -> Value {
    serde_json::json!({
        "seq": divergence.seq,
        "class": divergence.class,
        "a_event": divergence.a_event.as_ref().map(event_value),
        "b_event": divergence.b_event.as_ref().map(event_value),
        "a_context": divergence.a_context.iter().map(event_value).collect::<Vec<_>>(),
        "b_context": divergence.b_context.iter().map(event_value).collect::<Vec<_>>(),
    })
}

fn final_vtime(flat: &FlatTrace) -> Option<u64> {
    flat.events.iter().rev().find_map(|event| event.vtime)
}

fn print_diff_human(report: &DiffReport) {
    println!("trace diff:");
    println!("a: {}", report.a_path);
    println!("b: {}", report.b_path);
    println!("timeline: {}", report.timeline);
    println!("\nMetadata diff");
    if report.metadata_diff.is_empty() {
        println!("metadata: identical");
    } else {
        for diff in &report.metadata_diff {
            println!(
                "{}: {} -> {}",
                diff.field,
                compact_json_lossy(&diff.a),
                compact_json_lossy(&diff.b)
            );
        }
    }
    println!("\nAligned prefix: {} events", report.aligned_prefix);
    match &report.divergence {
        None if report.identical => println!("Result: identical"),
        None => println!("Result: metadata-only divergence; event streams are identical"),
        Some(divergence) => {
            println!(
                "First divergence: {} at sequence {}",
                divergence.class, divergence.seq
            );
            println!(
                "a: {}",
                divergence
                    .a_event
                    .as_ref()
                    .map(human_event_line)
                    .unwrap_or_else(|| "<missing>".to_string())
            );
            println!(
                "b: {}",
                divergence
                    .b_event
                    .as_ref()
                    .map(human_event_line)
                    .unwrap_or_else(|| "<missing>".to_string())
            );
            println!("\nContext a:");
            for event in &divergence.a_context {
                println!("{}", human_event_line(event));
            }
            println!("Context b:");
            for event in &divergence.b_context {
                println!("{}", human_event_line(event));
            }
        }
    }
    println!("\nTail summary");
    println!(
        "a: remaining_events={} final_vtime={}",
        report.a_events.saturating_sub(report.aligned_prefix),
        report
            .a_final_vtime
            .map(trace_view::human_nanos)
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "b: remaining_events={} final_vtime={}",
        report.b_events.saturating_sub(report.aligned_prefix),
        report
            .b_final_vtime
            .map(trace_view::human_nanos)
            .unwrap_or_else(|| "none".into())
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_abi::{ClockKind, Fd, Operation, Outcome, TaskId};
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

    fn sample_flat() -> FlatTrace {
        let bundle = bundle_with(vec![
            (
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(10),
            ),
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
        let raw = serde_json::to_value(&bundle).unwrap();
        trace_view::flatten(&bundle, &raw, "main").unwrap()
    }

    fn jsonl_lines(flat: &FlatTrace, filters: &EventFilters) -> Vec<Value> {
        let mut bytes = Vec::new();
        write_events_jsonl(&mut bytes, Path::new("run.patina"), "main", flat, filters).unwrap();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn events_jsonl_parses_and_round_trips_raw_operation_outcome() {
        let flat = sample_flat();
        let lines = jsonl_lines(&flat, &EventFilters::default());
        assert_eq!(lines.first().unwrap()["schema"], EVENTS_SCHEMA);
        assert_eq!(lines.last().unwrap()["matched"], flat.events.len() as u64);
        let event_lines = &lines[1..lines.len() - 1];
        assert_eq!(event_lines.len(), flat.events.len());
        for (line, event) in event_lines.iter().zip(&flat.events) {
            assert_eq!(line["operation"], event.operation);
            assert_eq!(line["outcome"], event.outcome);
        }
    }

    #[test]
    fn event_filters_are_and_composed_subsets() {
        let flat = sample_flat();
        let mut kind = EventFilters::default();
        kind.op_kinds.insert("fs_sync".into());
        let kind_lines = jsonl_lines(&flat, &kind);
        assert_eq!(kind_lines.last().unwrap()["matched"], 1);

        let seq = EventFilters {
            seq: Some((2, 4)),
            ..EventFilters::default()
        };
        let seq_matched = jsonl_lines(&flat, &seq).last().unwrap()["matched"]
            .as_u64()
            .unwrap();
        assert_eq!(seq_matched, 3);

        let mut both = kind.clone();
        both.seq = Some((2, 4));
        let both_matched = jsonl_lines(&flat, &both).last().unwrap()["matched"]
            .as_u64()
            .unwrap();
        assert!(both_matched <= kind_lines.last().unwrap()["matched"].as_u64().unwrap());
        assert!(both_matched <= seq_matched);
    }

    #[test]
    fn first_and_last_apply_after_filtering() {
        let flat = sample_flat();
        let filters = EventFilters {
            first: Some(2),
            ..EventFilters::default()
        };
        let lines = jsonl_lines(&flat, &filters);
        assert_eq!(lines.last().unwrap()["matched"], flat.events.len() as u64);
        assert_eq!(lines.last().unwrap()["emitted"], 2);
        assert_eq!(lines[1]["seq"], 0);
        assert_eq!(lines[2]["seq"], 1);

        let filters = EventFilters {
            last: Some(2),
            ..EventFilters::default()
        };
        let lines = jsonl_lines(&flat, &filters);
        assert_eq!(lines.last().unwrap()["emitted"], 2);
        assert_eq!(lines[1]["seq"], 3);
        assert_eq!(lines[2]["seq"], 4);
    }

    #[test]
    fn stats_counts_sum_to_totals_and_histogram_counts_vtime_events() {
        let flat = sample_flat();
        let stats = stats_value(Path::new("run.patina"), "main", &flat);
        assert_eq!(stats["schema"], STATS_SCHEMA);
        assert_eq!(stats["totals"]["events"], flat.events.len() as u64);
        let kind_sum: u64 = stats["kinds"]
            .as_object()
            .unwrap()
            .values()
            .map(|stat| stat["count"].as_u64().unwrap())
            .sum();
        assert_eq!(kind_sum, flat.events.len() as u64);
        let category_sum: u64 = stats["categories"]
            .as_object()
            .unwrap()
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum();
        assert_eq!(category_sum, flat.events.len() as u64);
        let buckets = stats["vtime"]["buckets"].as_array().unwrap();
        assert_eq!(buckets.len(), HISTOGRAM_BUCKETS);
        let bucket_sum: u64 = buckets
            .iter()
            .map(|bucket| bucket["events"].as_u64().unwrap())
            .sum();
        assert_eq!(
            bucket_sum,
            flat.events
                .iter()
                .filter(|event| event.vtime.is_some())
                .count() as u64
        );
    }

    fn flat_for(bundle: &TraceBundle) -> (serde_json::Value, FlatTrace) {
        let raw = serde_json::to_value(bundle).unwrap();
        let flat = trace_view::flatten(bundle, &raw, "main").unwrap();
        (raw, flat)
    }

    fn diff_for(a: &TraceBundle, b: &TraceBundle, context: usize) -> DiffReport {
        let (a_raw, a_flat) = flat_for(a);
        let (b_raw, b_flat) = flat_for(b);
        diff_report(
            Path::new("a.patina"),
            Path::new("b.patina"),
            "main",
            a,
            b,
            &a_raw,
            &b_raw,
            &a_flat,
            &b_flat,
            context,
        )
    }

    #[test]
    fn diff_reports_identical_metadata_operation_outcome_and_length_classes() {
        let one = bundle_with(vec![(
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(1),
        )]);
        let identical = diff_for(&one, &one, 1);
        assert!(identical.identical);
        assert_eq!(identical.aligned_prefix, 1);
        assert!(identical.divergence.is_none());
        assert_eq!(identical.to_json()["result"], "identical");

        let mut metadata_only = one.clone();
        metadata_only.metadata.root_seed = 99;
        let metadata = diff_for(&one, &metadata_only, 1);
        assert!(!metadata.identical);
        assert!(metadata.divergence.is_none());
        assert_eq!(metadata.metadata_diff[0].field, "root_seed");

        let op_changed = bundle_with(vec![(Operation::FsSync { fd: Fd(3) }, Outcome::Unit)]);
        let operation = diff_for(&one, &op_changed, 1);
        assert_eq!(
            operation.divergence.as_ref().unwrap().class,
            "operation-mismatch"
        );
        assert_eq!(operation.aligned_prefix, 0);

        let outcome_changed = bundle_with(vec![(
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(2),
        )]);
        let outcome = diff_for(&one, &outcome_changed, 1);
        assert_eq!(
            outcome.divergence.as_ref().unwrap().class,
            "outcome-mismatch"
        );
        assert_eq!(outcome.aligned_prefix, 0);

        let longer = bundle_with(vec![
            (
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(1),
            ),
            (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
        ]);
        let length = diff_for(&one, &longer, 1);
        assert_eq!(length.divergence.as_ref().unwrap().class, "length");
        assert_eq!(length.aligned_prefix, 1);
        assert!(length.divergence.as_ref().unwrap().a_event.is_none());
        assert!(length.divergence.as_ref().unwrap().b_event.is_some());
    }

    #[test]
    fn info_counts_resolved_branch_and_vtime_from_raw_json() {
        let main = vec![TraceEvent {
            sequence: 0,
            operation: Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            outcome: Outcome::U64(5),
        }];
        let mut bundle = TraceBundle::new(RunMetadata::new(9, "fp"), main);
        bundle.timelines.push(patina_dst_trace::Timeline {
            id: "b1".into(),
            parent: Some("main".into()),
            from_sequence: Some(1),
            branch_seed: Some(11),
            decisions: vec![TraceEvent {
                sequence: 1,
                operation: Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                outcome: Outcome::U64(20),
            }],
        });
        let raw = serde_json::to_value(&bundle).unwrap();
        let info = info_value(Path::new("run.patina"), "b1", &bundle, &raw).unwrap();
        assert_eq!(info["resolved_events"], 2);
        assert_eq!(info["vtime"]["min_nanos"], 5);
        assert_eq!(info["vtime"]["max_nanos"], 20);
    }
}
