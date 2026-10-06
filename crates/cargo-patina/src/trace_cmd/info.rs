//! Trace metadata and information reports.

use super::*;

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
        if kind == Some("clock_now")
            && let Some(value) = outcome_u64(out)
        {
            current = Some(value);
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

pub(super) fn print_info_human(facts: &Value) {
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
    if let Some(value) = metadata.get(key)
        && !value.is_null()
    {
        println!("{label}: {}", compact_json_lossy(value));
    }
}

pub(super) fn compact_json_lossy(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "?".to_string())
}

#[cfg(test)]
mod tests;
