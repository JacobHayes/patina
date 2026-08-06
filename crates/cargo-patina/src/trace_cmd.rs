//! `cargo patina trace` inspection commands.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use patina_dst_trace::{TraceBundle, TraceError};
use serde_json::{Map, Value};

use crate::CliError;
use crate::output::{self, OutputFormat};
use crate::trace_view::{self, Category, FlatEvent, FlatTrace, LaneKey};

pub(crate) const INFO_SCHEMA: &str = "patina.trace.info/v1";
pub(crate) const EVENTS_SCHEMA: &str = "patina.trace.events/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TraceInvocation {
    Info(TraceInfo),
    Events(TraceEvents),
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
    serde_json::json!({
        "schema": output::ENVELOPE_SCHEMA,
        "verb": "trace",
        "subcommand": "info",
        "result": "ok",
        "exit_code": 0,
        "trace_info": facts,
    })
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
    print_optional_metadata(metadata, "swarm", "swarm");
    print_optional_metadata(metadata, "watchdog", "watchdog");
    if metadata.get("sud").and_then(Value::as_bool) == Some(true) {
        println!("sud: armed");
    }
    println!(
        "next: `cargo patina trace events {}` for the event stream",
        facts["path"].as_str().unwrap_or("<TRACE>")
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
    let vtime = event
        .vtime
        .map(|n| format!(" @ {}", trace_view::human_nanos(n)))
        .unwrap_or_default();
    let notable = event
        .notable
        .as_ref()
        .map(|note| format!("  [notable: {}]", note.kind()))
        .unwrap_or_default();
    writeln!(
        out,
        "#{:06}  {:<8} {:<18} {}{}{}",
        event.seq,
        event.lane.label(),
        event.kind,
        event.detail,
        vtime,
        notable
    )
    .map_err(|error| CliError(format!("failed to write trace events: {error}")))
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
    write_json_line(out, &Value::Object(map))
}

fn write_json_line<W: std::io::Write>(out: &mut W, value: &Value) -> Result<(), CliError> {
    serde_json::to_writer(&mut *out, value)
        .map_err(|error| CliError(format!("failed to encode trace events JSON: {error}")))?;
    writeln!(out).map_err(|error| CliError(format!("failed to write trace events: {error}")))
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
