//! Regression tests for events.

use super::*;

use super::super::tests::*;

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
    assert_eq!(lines[1]["order"], 0);
    assert_eq!(lines[2]["order"], 1);

    let filters = EventFilters {
        last: Some(2),
        ..EventFilters::default()
    };
    let lines = jsonl_lines(&flat, &filters);
    assert_eq!(lines.last().unwrap()["emitted"], 2);
    assert_eq!(lines[1]["order"], 5);
    assert_eq!(lines[2]["order"], 6);
}
