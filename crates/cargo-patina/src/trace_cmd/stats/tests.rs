//! Regression tests for stats.

use super::*;

use super::super::tests::*;

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
