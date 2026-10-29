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
    for (tag, _) in OP_KINDS {
        assert_eq!(flat.kind_counts.get(*tag).map(|stat| stat.count), Some(1));
    }
    // A realtime clock read never moves the virtual-time cursor.
    {
        let bundle = bundle_with(events_with_a_realtime_read());
        let raw = serde_json::to_value(&bundle).unwrap();
        let flat = flatten(&bundle, &raw, "main").unwrap();
        assert_eq!((flat.vt_min, flat.vt_max), (Some(1_000), Some(20_000_000)));
        let stamps: Vec<_> = flat
            .events
            .iter()
            .filter(|event| event.source == FlatEventSource::Operation)
            .map(|event| event.vtime)
            .collect();
        assert_eq!(stamps, [Some(1_000), Some(1_000), Some(20_000_000)]);
    }
}

#[test]
fn flatten_orders_lifecycle_and_operations_globally() {
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
                        crash_kind: patina_dst_abi::CrashKind::Machine,
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
    // A resolved branch continues the inherited incarnation without a duplicate Start.
    {
        let main = vec![TraceEvent::new(
            0,
            Operation::ClockNow {
                clock: patina_dst_abi::ClockKind::Monotonic,
            },
            Outcome::U64(5),
        )];
        let mut branch_event = TraceEvent::new(
            1,
            Operation::EntropyFill {
                len: 1,
                wait: patina_dst_abi::EntropyWait::UntilReady,
            },
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
}

/// A monotonic read, a realtime read (epoch-scale), then another monotonic
/// read: the guest's elapsed virtual time is the monotonic span alone.
fn events_with_a_realtime_read() -> Vec<(Operation, Outcome)> {
    use patina_dst_abi::ClockKind;
    vec![
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(1_000),
        ),
        (
            Operation::ClockNow {
                clock: ClockKind::Realtime,
            },
            Outcome::U64(patina_dst_abi::DEFAULT_REALTIME_EPOCH_NANOS + 1_500),
        ),
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(20_000_000),
        ),
    ]
}
