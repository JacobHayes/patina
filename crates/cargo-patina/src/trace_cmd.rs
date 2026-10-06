//! `cargo patina trace` inspection commands.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use patina_dst_trace::{TraceBundle, TraceError};
use serde_json::{Map, Value};

use crate::CliError;
use crate::output::{self, OutputFormat};
use crate::trace_view::{self, Category, FlatEvent, FlatTrace, LaneKey, Notable};

mod diff;
mod events;
mod info;
mod stats;

use diff::diff_report;
use diff::print_diff_human;
pub(crate) use events::EventFilters;
use events::event_value;
use events::human_event_line;
pub(crate) use events::write_events_human;
pub(crate) use events::write_events_jsonl;
use info::compact_json_lossy;
pub(crate) use info::info_value;
use info::print_info_human;
use stats::print_stats_human;
use stats::stats_value;

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

#[cfg(test)]
mod tests;
