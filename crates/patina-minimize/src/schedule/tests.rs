//! Schedule canonicalization and protected-prefix tests.

use super::*;
use crate::tests::{sched_event, selected_tasks, switch_count, test_timeline};
use patina_dst_trace::RunMetadata;
use std::convert::Infallible;

#[test]
fn schedule_reduction_collapses_a_ping_pong_into_longer_runs() {
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![
            sched_event(0, 1),
            sched_event(1, 2),
            sched_event(2, 1),
            sched_event(3, 2),
        ],
    );
    assert_eq!(switch_count(&selected_tasks(&bundle.timelines[0])), 3);
    // Order-independent marker: both tasks must still be scheduled somewhere,
    // so the reducer can batch runs but cannot drop a task entirely.
    let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
        let tasks = selected_tasks(&candidate.timelines[0]);
        Ok::<_, Infallible>(tasks.contains(&1) && tasks.contains(&2))
    })
    .unwrap();
    let tasks = selected_tasks(&reduced.timelines[0]);
    assert!(tasks.contains(&1) && tasks.contains(&2), "marker preserved");
    assert!(
        switch_count(&tasks) < 3,
        "context switches reduced from a ping-pong: {tasks:?}"
    );
    // Positions and count never change; only scheduler outcomes are rewritten.
    assert_eq!(reduced.timelines[0].decisions.len(), 4);
    reduced.validate().unwrap();
}

#[test]
fn schedule_reduction_prefers_the_lowest_task_id() {
    // The higher id is scheduled first; an id- and order-independent marker
    // (two scheduling decisions) lets canonicalization pull every point down
    // to the lowest observed id, overriding switch-collapsing's own bias
    // toward extending the earlier - here higher - task's run.
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![sched_event(0, 2), sched_event(1, 1)],
    );
    let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(selected_tasks(&candidate.timelines[0]).len() == 2)
    })
    .unwrap();
    assert_eq!(selected_tasks(&reduced.timelines[0]), vec![1, 1]);
}

#[test]
fn schedule_reduction_never_rewrites_a_protected_prefix() {
    // main is a non-leaf timeline; `child` branches at sequence 2, so main's
    // first two scheduling points are an inherited, protected prefix that must
    // survive byte-for-byte even though the all-accepting marker would
    // tolerate rewriting them.
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![
            sched_event(0, 2),
            sched_event(1, 2),
            sched_event(2, 2),
            sched_event(3, 1),
        ],
    );
    bundle.timelines.push(test_timeline(
        "child",
        "main",
        2,
        5,
        vec![sched_event(2, 2)],
    ));
    let protected_before = bundle.timelines[0].decisions[..2].to_vec();
    let reduced = reduce_schedule(&bundle, &mut |_candidate: &TraceBundle| {
        Ok::<_, Infallible>(true)
    })
    .unwrap();
    // The protected prefix is untouched...
    assert_eq!(
        reduced.timelines[0].decisions[..2].to_vec(),
        protected_before
    );
    // ...while the reducible suffix was canonicalized toward the lowest id.
    assert_eq!(
        selected_tasks(&reduced.timelines[0])[2..].to_vec(),
        vec![1, 1]
    );
    reduced.validate().unwrap();
}

#[test]
fn schedule_reduction_leaves_the_bundle_unchanged_when_every_rewrite_is_rejected() {
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![sched_event(0, 1), sched_event(1, 2), sched_event(2, 1)],
    );
    // The oracle demands the exact original schedule, so the up-front check
    // passes but no rewrite is ever accepted.
    let original = selected_tasks(&bundle.timelines[0]);
    let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
        Ok::<_, Infallible>(selected_tasks(&candidate.timelines[0]) == original)
    })
    .unwrap();
    assert_eq!(reduced, bundle);
}

#[test]
fn schedule_reduction_reaches_a_fixed_point() {
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![
            sched_event(0, 1),
            sched_event(1, 2),
            sched_event(2, 1),
            sched_event(3, 2),
        ],
    );
    let mut marker = |candidate: &TraceBundle| {
        let tasks = selected_tasks(&candidate.timelines[0]);
        Ok::<_, Infallible>(tasks.contains(&1) && tasks.contains(&2))
    };
    let once = reduce_schedule(&bundle, &mut marker).unwrap();
    let twice = reduce_schedule(&once, &mut marker).unwrap();
    assert_eq!(
        once, twice,
        "a second pass changes nothing at the fixed point"
    );
}

#[test]
fn schedule_reduction_rejects_an_input_that_does_not_fail() {
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![sched_event(0, 1)],
    );
    let result = reduce_schedule(&bundle, &mut |_c: &TraceBundle| Ok::<_, Infallible>(false));
    assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
}
