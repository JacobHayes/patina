//! Regression tests for trace_view.

use super::*;

use patina_dst_trace::{RunMetadata, TraceBundle, TraceEvent};

pub(super) fn bundle_with(events: Vec<(Operation, Outcome)>) -> TraceBundle {
    let decisions = events
        .into_iter()
        .enumerate()
        .map(|(i, (operation, outcome))| TraceEvent::new(i as u64, operation, outcome))
        .collect();
    TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), decisions)
}

#[test]
fn flatten_round_trips_every_operation_json_and_counts_kinds() {
    let bundle = bundle_with(representative_events_for_all_op_kinds());
    let raw = serde_json::to_value(&bundle).unwrap();
    let flat = flatten(&bundle, &raw, "main").unwrap();
    assert_eq!(
        flat.events.len(),
        OP_KINDS.len() + bundle.timelines[0].lifecycle.len()
    );
    assert!(flat.notable.iter().any(|event| event.kind == "fs_open"));
    assert!(flat.notable.iter().any(|event| event.kind == "fs_crash"));
    assert!(flat.notable.iter().any(|event| event.kind == "net_send"));
    let operation_events: Vec<_> = flat
        .events
        .iter()
        .filter(|event| event.source == FlatEventSource::Operation)
        .collect();
    for (event, recorded) in operation_events.iter().zip(&bundle.timelines[0].decisions) {
        assert_eq!(
            event.operation,
            serde_json::to_value(&recorded.operation).unwrap()
        );
        assert_eq!(
            event.outcome,
            serde_json::to_value(&recorded.outcome).unwrap()
        );
    }
    let total: u64 = flat.kind_counts.values().map(|stat| stat.count).sum();
    assert_eq!(total, flat.events.len() as u64);
    assert_eq!(
        flat.kind_counts
            .get("lifecycle_start")
            .map(|stat| stat.count),
        Some(1)
    );
    assert_eq!(
        flat.kind_counts.get("lifecycle_end").map(|stat| stat.count),
        Some(1)
    );
    for (tag, _) in OP_KINDS {
        assert_eq!(flat.kind_counts.get(*tag).map(|stat| stat.count), Some(1));
    }
}

#[test]
fn flatten_branch_lifecycle_continues_inherited_incarnation_without_duplicate_start() {
    let main = vec![TraceEvent::new(
        0,
        Operation::ClockNow {
            clock: patina_dst_abi::ClockKind::Monotonic,
        },
        Outcome::U64(5),
    )];
    let mut branch_event = TraceEvent::new(
        1,
        Operation::EntropyFill { len: 1 },
        Outcome::Bytes(vec![9]),
    );
    branch_event.order = 3;
    let mut bundle = TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), main);
    bundle.timelines.push(patina_dst_trace::Timeline {
        id: "branch".into(),
        parent: Some("main".into()),
        from_sequence: Some(1),
        branch_seed: Some(99),
        lifecycle: vec![
            LifecycleEvent {
                order: 2,
                kind: LifecycleEventKind::Start { incarnation: 0 },
            },
            LifecycleEvent {
                order: 4,
                kind: LifecycleEventKind::End { incarnation: 0 },
            },
        ],
        decisions: vec![branch_event],
    });
    let raw = serde_json::to_value(&bundle).unwrap();
    let flat = flatten(&bundle, &raw, "branch").unwrap();
    assert_eq!(
        flat.events
            .iter()
            .map(|event| event.order)
            .collect::<Vec<_>>(),
        vec![0, 1, 3, 4]
    );
    assert_eq!(
        flat.events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "lifecycle_start",
            "clock_now",
            "entropy_fill",
            "lifecycle_end",
        ]
    );
    assert_eq!(
        flat.events
            .iter()
            .filter(|event| event.kind == "lifecycle_start")
            .count(),
        1,
        "resolved branch rendering must not duplicate inherited Start(0)"
    );
    assert!(
        flat.events
            .iter()
            .all(|event| event.incarnation.is_none_or(|incarnation| incarnation == 0))
    );
}

#[test]
fn flatten_merges_lifecycle_and_operations_by_global_order() {
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let bundle = TraceBundle {
        format_version: patina_dst_trace::TRACE_FORMAT_VERSION,
        metadata: RunMetadata::new(7, "fp-test+crash-restart", 0, "patina"),
        timelines: vec![patina_dst_trace::Timeline {
            id: "main".into(),
            parent: None,
            from_sequence: None,
            branch_seed: None,
            lifecycle: vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 2,
                    kind: LifecycleEventKind::Crash {
                        incarnation: 0,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 3,
                    kind: LifecycleEventKind::Restart {
                        from_incarnation: 0,
                        to_incarnation: 1,
                        snapshot_digest: digest.into(),
                    },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::Start { incarnation: 1 },
                },
                LifecycleEvent {
                    order: 6,
                    kind: LifecycleEventKind::End { incarnation: 1 },
                },
            ],
            decisions: vec![
                TraceEvent {
                    sequence: 0,
                    order: 1,
                    incarnation: 0,
                    operation: Operation::FsWrite {
                        fd: patina_dst_abi::Fd(3),
                        bytes: b"trigger".to_vec(),
                    },
                    outcome: Outcome::Usize(7),
                },
                TraceEvent {
                    sequence: 1,
                    order: 5,
                    incarnation: 1,
                    operation: Operation::ClockNow {
                        clock: patina_dst_abi::ClockKind::Monotonic,
                    },
                    outcome: Outcome::U64(11),
                },
            ],
        }],
    };
    let raw = serde_json::to_value(&bundle).unwrap();
    let flat = flatten(&bundle, &raw, "main").unwrap();
    assert_eq!(
        flat.events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "lifecycle_start",
            "fs_write",
            "lifecycle_crash",
            "lifecycle_restart",
            "lifecycle_start",
            "clock_now",
            "lifecycle_end",
        ]
    );
    assert_eq!(
        flat.events
            .iter()
            .map(|event| event.order)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5, 6]
    );
    assert_eq!(flat.events[1].incarnation, Some(0));
    assert_eq!(flat.events[5].incarnation, Some(1));
    assert!(
        flat.notable
            .iter()
            .any(|event| event.kind == "lifecycle_crash")
    );
    assert!(
        flat.notable
            .iter()
            .any(|event| event.kind == "lifecycle_restart")
    );
}
