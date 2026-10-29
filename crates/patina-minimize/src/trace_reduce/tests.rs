//! Timeline deletion, branch preservation, and fixed-point tests.

use super::*;
use crate::tests::{clock_event, test_timeline};
use patina_dst_abi::{ClockKind, Operation, Outcome};
use patina_dst_trace::{RunMetadata, TraceEvent};
use std::convert::Infallible;

#[test]
fn delta_debugging_preserves_only_the_failure_inducing_decision() {
    let mut decisions = (0..10)
        .map(|sequence| {
            TraceEvent::new(
                sequence,
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(sequence),
            )
        })
        .collect::<Vec<_>>();
    decisions[6].outcome = Outcome::U64(999);
    let bundle = TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), decisions);
    let mut calls = 0;
    let minimized = minimize_main(&bundle, &mut |candidate: &TraceBundle| {
        calls += 1;
        Ok::<_, Infallible>(
            candidate.timelines[0]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999)),
        )
    })
    .unwrap();
    assert!(calls > 1);
    assert_eq!(minimized.timelines[0].decisions.len(), 1);
    assert_eq!(minimized.timelines[0].decisions[0].sequence, 0);
    assert_eq!(
        minimized.timelines[0].decisions[0].outcome,
        Outcome::U64(999)
    );
    // Tree minimization of a single timeline reaches the same result.
    let tree = minimize_branch_tree(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(
            candidate.timelines[0]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999)),
        )
    })
    .unwrap();
    assert_eq!(tree, minimized);
}

#[test]
fn minimizes_a_leaf_branch_without_changing_its_inherited_prefix() {
    let main = (0..3)
        .map(|sequence| {
            TraceEvent::new(
                sequence,
                Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                Outcome::U64(sequence),
            )
        })
        .collect::<Vec<_>>();
    let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), main.clone());
    bundle.timelines.push(test_timeline(
        "failure",
        "main",
        2,
        9,
        (2..8)
            .map(|sequence| {
                TraceEvent::new(
                    sequence,
                    Operation::ClockNow {
                        clock: ClockKind::Monotonic,
                    },
                    Outcome::U64(if sequence == 6 { 999 } else { sequence }),
                )
            })
            .collect(),
    ));
    let minimized = minimize_timeline(&bundle, "failure", &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(
            candidate.timelines[1]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999)),
        )
    })
    .unwrap();
    assert_eq!(minimized.timelines[0].decisions, main);
    assert_eq!(minimized.timelines[1].decisions.len(), 1);
    assert_eq!(minimized.timelines[1].decisions[0].sequence, 2);
    assert_eq!(minimized.resolved_timeline("failure").unwrap().len(), 3);
}

#[test]
fn refuses_a_timeline_with_children_or_an_original_that_does_not_fail() {
    let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), Vec::new());
    bundle
        .timelines
        .push(test_timeline("parent", "main", 0, 2, Vec::new()));
    bundle
        .timelines
        .push(test_timeline("child", "parent", 0, 3, Vec::new()));
    let error = minimize_timeline(&bundle, "parent", &mut |_candidate: &TraceBundle| {
        Ok::<_, Infallible>(true)
    })
    .unwrap_err();
    assert!(matches!(error, MinimizeError::TimelineHasChildren(_)));

    let bundle = TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), Vec::new());
    let result = minimize_main(&bundle, &mut |_candidate: &TraceBundle| {
        Ok::<_, Infallible>(false)
    });
    assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
}

#[test]
fn tree_minimization_preserves_a_non_leaf_protected_prefix_and_shrinks_its_suffix() {
    // A three-level chain main -> mid -> leaf. `mid` is a non-leaf timeline
    // that `leaf` branches from at sequence 4, so mid's first two decisions
    // (sequences 2 and 3) are an inherited, protected prefix, and mid's
    // remaining decisions (sequences 4..8) are a reducible suffix no
    // descendant depends on. The failure marker sits in the protected prefix.
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![clock_event(0, 0), clock_event(1, 1)],
    );
    bundle.timelines.push(test_timeline(
        "mid",
        "main",
        2,
        7,
        vec![
            clock_event(2, 999),
            clock_event(3, 3),
            clock_event(4, 4),
            clock_event(5, 5),
            clock_event(6, 6),
            clock_event(7, 7),
        ],
    ));
    bundle.timelines.push(test_timeline(
        "leaf",
        "mid",
        4,
        11,
        vec![clock_event(4, 40), clock_event(5, 50)],
    ));
    let mid_protected = bundle.timelines[1].decisions[..2].to_vec();
    let leaf_inherited = bundle.resolved_timeline("leaf").unwrap()[..4].to_vec();

    // The failure is present when leaf's inherited prefix still carries the
    // 999 marker; nothing in any reducible suffix matters.
    let minimized = minimize_branch_tree(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(
            candidate
                .resolved_timeline("leaf")
                .unwrap()
                .iter()
                .take(4)
                .any(|event| event.outcome == Outcome::U64(999)),
        )
    })
    .unwrap();

    // main is entirely inherited by mid, so it is untouched.
    assert_eq!(
        minimized.timelines[0].decisions,
        vec![clock_event(0, 0), clock_event(1, 1)]
    );
    // mid's protected prefix survives byte-for-byte while its suffix shrank.
    let mid = &minimized.timelines[1];
    assert_eq!(mid.decisions[..2].to_vec(), mid_protected);
    assert_eq!(mid.decisions[0].outcome, Outcome::U64(999));
    assert!(mid.decisions.len() >= 2 && mid.decisions.len() < 6);
    // The recorded branch point stays valid and leaf's inherited prefix is
    // unchanged after its parent shrank.
    assert_eq!(minimized.timelines[2].from_sequence, Some(4));
    minimized.validate().unwrap();
    assert_eq!(
        minimized.resolved_timeline("leaf").unwrap()[..4].to_vec(),
        leaf_inherited
    );
}

fn branched_bundle() -> TraceBundle {
    // main -> keeper (carries the 999 marker) and main -> disposable, plus
    // disposable -> grandchild so pruning must drop a whole subtree.
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![clock_event(0, 0), clock_event(1, 1)],
    );
    bundle.timelines.push(test_timeline(
        "keeper",
        "main",
        2,
        7,
        vec![clock_event(2, 999)],
    ));
    bundle.timelines.push(test_timeline(
        "disposable",
        "main",
        2,
        8,
        vec![clock_event(2, 2), clock_event(3, 3)],
    ));
    bundle.timelines.push(test_timeline(
        "grandchild",
        "disposable",
        3,
        9,
        vec![clock_event(3, 30)],
    ));
    bundle
}

#[test]
fn prune_branches_drops_exactly_the_subtrees_the_failure_does_not_need() {
    let bundle = branched_bundle();
    // The failure lives only in `keeper`; the `disposable` subtree is dead
    // weight and should be removed together with its `grandchild`.
    let pruned = prune_branches(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(candidate.timelines.iter().any(|timeline| {
            timeline
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999))
        }))
    })
    .unwrap();
    let ids: Vec<&str> = pruned.timelines.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["main", "keeper"]);
    pruned.validate().unwrap();

    // The failure now depends on `grandchild`, so neither it nor its parent
    // `disposable` may be dropped; `keeper` still goes.
    let pruned = prune_branches(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(candidate.timelines.iter().any(|t| t.id == "grandchild"))
    })
    .unwrap();
    let ids: Vec<&str> = pruned.timelines.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["main", "disposable", "grandchild"]);
    pruned.validate().unwrap();
}

#[test]
fn minimize_branches_prunes_then_shrinks_surviving_suffixes() {
    let mut bundle = branched_bundle();
    // Give `keeper` a long removable suffix after its marker so the combined
    // pass both drops `disposable`/`grandchild` and shrinks `keeper`.
    bundle.timelines[1].decisions = vec![
        clock_event(2, 999),
        clock_event(3, 3),
        clock_event(4, 4),
        clock_event(5, 5),
    ];
    let start_order = bundle.timelines[1].lifecycle[0].order;
    for (index, event) in bundle.timelines[1].decisions.iter_mut().enumerate() {
        event.order = start_order.saturating_add(1).saturating_add(index as u64);
    }
    bundle.timelines[1].lifecycle =
        linear_lifecycle_from_start(start_order, &bundle.timelines[1].decisions);
    let minimized = minimize_branches(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(candidate.timelines.iter().any(|timeline| {
            timeline
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999))
        }))
    })
    .unwrap();
    let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["main", "keeper"]);
    assert_eq!(minimized.timelines[1].decisions.len(), 1);
    assert_eq!(
        minimized.timelines[1].decisions[0].outcome,
        Outcome::U64(999)
    );
    minimized.validate().unwrap();
}

/// A crash-restart trace shrinks in both incarnations, and the decision the
/// crash follows survives every candidate: the oracle fails only while the
/// crash stays on that decision, as a replay that crashes elsewhere diverges.
#[test]
fn a_crash_restart_trace_shrinks_each_incarnation_around_the_crash() {
    use patina_dst_trace::{CrashRestartSegments, Sha256Digest};
    let metadata = RunMetadata::new(1, "fixture", 0, "patina");
    let segment = |incarnation, values: std::ops::Range<u64>| {
        TraceBundle::linear(
            metadata.clone(),
            incarnation,
            values
                .enumerate()
                .map(|(index, value)| clock_event(index as u64, value))
                .collect(),
        )
    };
    let join = |crashed, restarted| {
        CrashRestartSegments {
            crashed,
            snapshot_digest: Sha256Digest([7; 32]),
            restarted,
        }
        .join()
        .unwrap()
    };
    let values_of = |bundle: &TraceBundle, incarnation| -> Vec<u64> {
        bundle.timelines[0]
            .decisions
            .iter()
            .filter(|event| event.incarnation == incarnation)
            .map(|event| match event.outcome {
                Outcome::U64(value) => value,
                ref other => panic!("{other:?}"),
            })
            .collect()
    };
    // Incarnation 0 needs 3 and crashes after 9; incarnation 1 needs 15. The
    // oracle does not ask for 9: the crash's decision survives because every
    // entry point keeps it, not because the failure needs it.
    let bundle = join(segment(0, 0..10), segment(1, 10..20));
    let fails = |candidate: &TraceBundle| {
        Ok::<_, Infallible>(
            values_of(candidate, 0).contains(&3) && values_of(candidate, 1).contains(&15),
        )
    };
    let entry_points: [(&str, TraceBundle); 4] = [
        (
            "main",
            minimize_main(&bundle, &mut |c: &TraceBundle| fails(c)).unwrap(),
        ),
        (
            "timeline",
            minimize_timeline(&bundle, "main", &mut |c: &TraceBundle| fails(c)).unwrap(),
        ),
        (
            "branch tree",
            minimize_branch_tree(&bundle, &mut |c: &TraceBundle| fails(c)).unwrap(),
        ),
        (
            "branches",
            minimize_branches(&bundle, &mut |c: &TraceBundle| fails(c)).unwrap(),
        ),
    ];
    for (entry, minimized) in &entry_points {
        assert_eq!(values_of(minimized, 0), [3, 9], "{entry}");
        assert_eq!(values_of(minimized, 1), [15], "{entry}");
    }
    // A lone removable decision on either side of the crash still goes.
    let lone = join(segment(0, 2..4), segment(1, 14..15));
    let minimized = minimize_main(&lone, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(values_of(candidate, 0).last() == Some(&3))
    })
    .unwrap();
    assert_eq!(values_of(&minimized, 0), [3]);
    assert!(values_of(&minimized, 1).is_empty());
    let segments = entry_points[0].1.crash_restart_segments().unwrap().unwrap();
    assert_eq!(segments.snapshot_digest, Sha256Digest([7; 32]));
}
