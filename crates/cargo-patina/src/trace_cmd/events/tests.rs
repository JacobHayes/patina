//! Regression tests for events.

use super::*;

use super::super::tests::*;

fn jsonl_lines(flat: &FlatTrace, filters: &EventFilters) -> Vec<Value> {
    let mut bytes = Vec::new();
    let mut writer = EventWriter::new(
        &mut bytes,
        OutputFormat::Json,
        Path::new("run.patina"),
        "main",
        flat.events.len(),
        filters,
    )
    .unwrap();
    for event in &flat.events {
        writer.push(event.clone()).unwrap();
    }
    writer.finish().unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn events_jsonl_round_trips_and_filters_compose() {
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
    // --first/--last apply after filtering.
    {
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
    // Unfiltered, every event's raw operation and outcome round-trips.
    {
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
}

/// `trace events` streams a trace file to exactly what writing its in-memory
/// flattening produces, lifecycle markers between decisions included.
#[test]
fn streamed_events_match_the_flattened_trace() {
    use patina_dst_abi::CrashKind;
    use patina_dst_trace::{LifecycleEvent, LifecycleEventKind};

    let mut bundle = bundle_with(trace_view::representative_events_for_all_op_kinds());
    // Crash and restart after the third decision.
    let digest = format!("sha256:{}", "cd".repeat(32));
    let timeline = &mut bundle.timelines[0];
    for event in &mut timeline.decisions[3..] {
        event.order += 3;
        event.incarnation = 1;
    }
    let end = timeline.decisions.last().unwrap().order + 1;
    timeline.lifecycle = vec![
        LifecycleEvent {
            order: 0,
            kind: LifecycleEventKind::Start { incarnation: 0 },
        },
        LifecycleEvent {
            order: 4,
            kind: LifecycleEventKind::Crash {
                incarnation: 0,
                crash_kind: CrashKind::Process,
                snapshot_digest: digest.clone(),
            },
        },
        LifecycleEvent {
            order: 5,
            kind: LifecycleEventKind::Restart {
                from_incarnation: 0,
                to_incarnation: 1,
                snapshot_digest: digest,
            },
        },
        LifecycleEvent {
            order: 6,
            kind: LifecycleEventKind::Start { incarnation: 1 },
        },
        LifecycleEvent {
            order: end,
            kind: LifecycleEventKind::End { incarnation: 1 },
        },
    ];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("run.patina");
    bundle.write_atomic(&path).unwrap();
    let flat = trace_view::flatten(&bundle, &Value::Null, MAIN_TIMELINE).unwrap();

    let write = |format, filters: &EventFilters, streamed: bool| {
        let mut bytes = Vec::new();
        let mut writer = EventWriter::new(
            &mut bytes,
            format,
            &path,
            MAIN_TIMELINE,
            flat.events.len(),
            filters,
        )
        .unwrap();
        if streamed {
            let mut stream = TraceStream::open(&path).unwrap();
            trace_view::for_each_flat_event(&mut stream, MAIN_TIMELINE, |event| writer.push(event))
                .unwrap()
                .unwrap();
        } else {
            for event in &flat.events {
                writer.push(event.clone()).unwrap();
            }
        }
        writer.finish().unwrap();
        bytes
    };
    let filters = [
        EventFilters::default(),
        EventFilters {
            last: Some(3),
            ..EventFilters::default()
        },
        EventFilters {
            first: Some(4),
            ..EventFilters::default()
        },
        EventFilters {
            notable: true,
            ..EventFilters::default()
        },
    ];
    for format in [OutputFormat::Human, OutputFormat::Json] {
        for filters in &filters {
            assert_eq!(
                String::from_utf8(write(format, filters, true)).unwrap(),
                String::from_utf8(write(format, filters, false)).unwrap(),
                "{format:?} {filters:?}"
            );
        }
    }
    assert!(
        flat.events
            .iter()
            .any(|event| event.kind == "lifecycle_crash")
    );
}
