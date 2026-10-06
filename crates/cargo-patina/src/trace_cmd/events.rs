//! Trace event filters and stream rendering.

use super::*;

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

pub(super) fn human_event_line(event: &FlatEvent) -> String {
    let vtime = event
        .vtime
        .map(|n| format!(" @ {}", trace_view::human_nanos(n)))
        .unwrap_or_default();
    let notable = event
        .notable
        .as_ref()
        .map(|note| format!("  [notable: {}]", note.kind()))
        .unwrap_or_default();
    let incarnation = event
        .incarnation
        .map(|id| format!(" i{id}"))
        .unwrap_or_default();
    format!(
        "#{:06} o={:<6}{} {:<8} {:<18} {}{}{}",
        event.seq,
        event.order,
        incarnation,
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

pub(super) fn event_value(event: &FlatEvent) -> Value {
    let mut map = Map::new();
    map.insert("seq".into(), Value::from(event.seq));
    map.insert("order".into(), Value::from(event.order));
    map.insert(
        "incarnation".into(),
        event.incarnation.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert(
        "source".into(),
        Value::from(match event.source {
            trace_view::FlatEventSource::Operation => "operation",
            trace_view::FlatEventSource::Lifecycle => "lifecycle",
        }),
    );
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

#[cfg(test)]
mod tests;
