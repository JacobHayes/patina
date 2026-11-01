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
        if let Some((start, end)) = self.seq
            && (event.seq < start || event.seq > end)
        {
            return false;
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

/// Writes a stream of flattened events as `trace events` prints them: each
/// event that passes the filters, cut to the first or last N when asked, with
/// a JSON header and trailer around them in JSON. It holds no event it has
/// written, so its memory is bounded by `--last`'s window, not the trace.
pub(crate) struct EventWriter<'a, W> {
    out: &'a mut W,
    format: OutputFormat,
    filters: &'a EventFilters,
    /// The `--last` window, when one was asked for.
    ring: Option<(usize, VecDeque<FlatEvent>)>,
    matched: u64,
    emitted: u64,
}

impl<'a, W: std::io::Write> EventWriter<'a, W> {
    /// Start writing a timeline of `total_events` events.
    pub(crate) fn new(
        out: &'a mut W,
        format: OutputFormat,
        path: &Path,
        timeline: &str,
        total_events: usize,
        filters: &'a EventFilters,
    ) -> Result<Self, CliError> {
        let ring = match (filters.first, filters.last) {
            (Some(_), Some(_)) => unreachable!("parser rejects --first with --last"),
            (_, Some(limit)) => {
                let cap = usize::try_from(limit).map_err(|_| {
                    CliError::usage(format!(
                        "--last value {limit} is too large for this platform"
                    ))
                })?;
                // `--last 0` has always printed every match, as no window does.
                (cap > 0).then(|| (cap, VecDeque::new()))
            }
            (_, None) => None,
        };
        if format == OutputFormat::Json {
            write_json_line(
                out,
                &serde_json::json!({
                    "schema": EVENTS_SCHEMA,
                    "path": path.to_string_lossy(),
                    "timeline": timeline,
                    "total_events": total_events,
                    "filters": filters.to_json(),
                }),
            )?;
        }
        Ok(Self {
            out,
            format,
            filters,
            ring,
            matched: 0,
            emitted: 0,
        })
    }

    /// Take the timeline's next event.
    pub(crate) fn push(&mut self, event: FlatEvent) -> Result<(), CliError> {
        if !self.filters.matches(&event) {
            return Ok(());
        }
        self.matched += 1;
        if let Some((cap, ring)) = &mut self.ring {
            if ring.len() == *cap {
                ring.pop_front();
            }
            ring.push_back(event);
            return Ok(());
        }
        if self.filters.first.is_none_or(|limit| self.emitted < limit) {
            self.write(&event)?;
        }
        Ok(())
    }

    /// Write what `--last` kept and, in JSON, the trailer.
    pub(crate) fn finish(mut self) -> Result<(), CliError> {
        if let Some((_, ring)) = self.ring.take() {
            for event in ring {
                self.write(&event)?;
            }
        }
        if self.format == OutputFormat::Json {
            write_json_line(
                self.out,
                &serde_json::json!({
                    "matched": self.matched,
                    "emitted": self.emitted,
                }),
            )?;
        }
        Ok(())
    }

    fn write(&mut self, event: &FlatEvent) -> Result<(), CliError> {
        self.emitted += 1;
        match self.format {
            OutputFormat::Human => write_human_event(self.out, event),
            OutputFormat::Json => write_json_line(self.out, &event_value(event)),
        }
    }
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
