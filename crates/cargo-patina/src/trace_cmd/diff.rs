//! Trace comparison and divergence reports.

use super::*;

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
pub(crate) struct DiffReport {
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
    pub(crate) identical: bool,
}

impl DiffReport {
    pub(crate) fn to_json(&self) -> Value {
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
pub(super) fn diff_report(
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

pub(super) fn print_diff_human(report: &DiffReport) {
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
mod tests;
