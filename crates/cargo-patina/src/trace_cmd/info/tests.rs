//! Regression tests for info.

use super::*;
use patina_dst_abi::{ClockKind, Operation, Outcome};
use patina_dst_trace::{RunMetadata, TraceBundle, TraceEvent};

#[test]
fn info_counts_resolved_branch_and_monotonic_vtime() {
    let main = vec![TraceEvent::new(
        0,
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Outcome::U64(5),
    )];
    let mut bundle = TraceBundle::new(RunMetadata::new(9, "fp", 0, "patina"), main);
    bundle.timelines.push(patina_dst_trace::Timeline {
        id: "b1".into(),
        parent: Some("main".into()),
        from_sequence: Some(1),
        branch_seed: Some(11),
        lifecycle: vec![
            patina_dst_trace::LifecycleEvent {
                order: 2,
                kind: patina_dst_trace::LifecycleEventKind::Start { incarnation: 0 },
            },
            patina_dst_trace::LifecycleEvent {
                order: 4,
                kind: patina_dst_trace::LifecycleEventKind::End { incarnation: 0 },
            },
        ],
        decisions: vec![{
            let mut event = TraceEvent::new(
                1,
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(20),
            );
            event.order = 3;
            event
        }],
    });
    let raw = serde_json::to_value(&bundle).unwrap();
    let info = info_value(Path::new("run.patina"), "b1", &bundle, &raw).unwrap();
    assert_eq!(info["resolved_events"], 2);
    assert_eq!(info["vtime"]["min_nanos"], 5);
    assert_eq!(info["vtime"]["max_nanos"], 20);
    // The vtime span ignores realtime clock reads.
    {
        let events = vec![
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
                Outcome::U64(patina_dst_abi::DEFAULT_REALTIME_EPOCH_NANOS),
            ),
            (
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(20_000_000),
            ),
        ];
        let decisions = events
            .into_iter()
            .enumerate()
            .map(|(i, (operation, outcome))| TraceEvent::new(i as u64, operation, outcome))
            .collect();
        let bundle = TraceBundle::new(RunMetadata::new(9, "fp", 0, "patina"), decisions);
        let raw = serde_json::to_value(&bundle).unwrap();
        let info = info_value(Path::new("run.patina"), "main", &bundle, &raw).unwrap();
        assert_eq!(info["vtime"]["min_nanos"], 1_000);
        assert_eq!(info["vtime"]["max_nanos"], 20_000_000);
    }
}
