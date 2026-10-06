//! Trace statistics and histograms.

use super::*;

const HISTOGRAM_BUCKETS: usize = 20;

pub(super) fn stats_value(path: &Path, timeline: &str, flat: &FlatTrace) -> Value {
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

pub(super) fn print_stats_human(stats: &Value) {
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

#[cfg(test)]
mod tests;
