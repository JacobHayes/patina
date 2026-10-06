//! Regression tests for minimize.

use super::*;

pub(super) fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

pub(super) fn clock_event(sequence: u64, value: u64) -> patina_dst_trace::TraceEvent {
    patina_dst_trace::TraceEvent::new(
        sequence,
        patina_dst_abi::Operation::ClockNow {
            clock: patina_dst_abi::ClockKind::Monotonic,
        },
        patina_dst_abi::Outcome::U64(value),
    )
}

#[test]
fn executes_trace_minimization_with_an_external_oracle() {
    use patina_dst_abi::Outcome;
    use patina_dst_trace::RunMetadata;

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.patina");
    let output = directory.path().join("output.patina");
    let decisions = (0..6)
        .map(|sequence| clock_event(sequence, if sequence == 4 { 999 } else { sequence }))
        .collect();
    TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), decisions)
        .write_atomic(&input)
        .unwrap();
    execute_trace(TraceMinimize {
        trace: input,
        output: output.clone(),
        timeline: None,
        prune: false,
        jobs: Some(1),
        oracle: strings(&[
            "sh",
            "-c",
            "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
        ]),
    })
    .unwrap();
    let minimized = TraceBundle::load(output).unwrap();
    assert_eq!(minimized.timelines[0].decisions.len(), 1);
    assert_eq!(
        minimized.timelines[0].decisions[0].outcome,
        Outcome::U64(999)
    );
}

#[test]
fn an_oracle_with_inverted_exit_polarity_is_refused_rather_than_obeyed() {
    use patina_dst_trace::RunMetadata;

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.patina");
    let output = directory.path().join("output.patina");
    let decisions = (0..6)
        .map(|sequence| clock_event(sequence, if sequence == 4 { 999 } else { sequence }))
        .collect();
    TraceBundle::new(RunMetadata::new(1, "fixture", 0, "patina"), decisions)
        .write_atomic(&input)
        .unwrap();
    // The same oracle as above with its exits swapped — the footgun a
    // reader writes by accident, because "found the failure" reads like
    // success. Every verdict is backwards, so the search would "succeed" by
    // deleting the entire trace.
    let error = execute_trace(TraceMinimize {
        trace: input,
        output: output.clone(),
        timeline: None,
        prune: false,
        jobs: Some(1),
        oracle: strings(&[
            "sh",
            "-c",
            "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 0; exit 1",
        ]),
    })
    .unwrap_err();
    assert!(
        error.0.contains("inverted exit polarity"),
        "unexpected error: {}",
        error.0
    );
    assert!(
        !output.exists(),
        "a refused minimization must not write an output trace"
    );
}

pub(super) fn branch_lifecycle(
    start_order: u64,
    decisions: &[patina_dst_trace::TraceEvent],
) -> Vec<patina_dst_trace::LifecycleEvent> {
    let end_order = decisions
        .last()
        .map(|event| event.order.saturating_add(1))
        .unwrap_or(start_order.saturating_add(1));
    vec![
        patina_dst_trace::LifecycleEvent {
            order: start_order,
            kind: patina_dst_trace::LifecycleEventKind::Start { incarnation: 0 },
        },
        patina_dst_trace::LifecycleEvent {
            order: end_order,
            kind: patina_dst_trace::LifecycleEventKind::End { incarnation: 0 },
        },
    ]
}

pub(super) fn branched_input(path: &Path) {
    use patina_dst_trace::{RunMetadata, Timeline};
    // main -> keeper (holds the 999 marker plus a removable suffix) and
    // main -> disposable (dead weight the oracle never needs).
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        vec![clock_event(0, 0)],
    );
    let mut keeper = vec![clock_event(1, 999), clock_event(2, 2), clock_event(3, 3)];
    for (index, event) in keeper.iter_mut().enumerate() {
        event.order = 3 + index as u64;
    }
    bundle.timelines.push(Timeline {
        id: "keeper".into(),
        parent: Some("main".into()),
        from_sequence: Some(1),
        branch_seed: Some(7),
        lifecycle: branch_lifecycle(2, &keeper),
        decisions: keeper,
    });
    let mut disposable = vec![clock_event(1, 11), clock_event(2, 12)];
    for (index, event) in disposable.iter_mut().enumerate() {
        event.order = 3 + index as u64;
    }
    bundle.timelines.push(Timeline {
        id: "disposable".into(),
        parent: Some("main".into()),
        from_sequence: Some(1),
        branch_seed: Some(8),
        lifecycle: branch_lifecycle(2, &disposable),
        decisions: disposable,
    });
    bundle.write_atomic(path).unwrap();
}

#[test]
fn executes_non_leaf_branch_tree_minimization_automatically() {
    use patina_dst_abi::Outcome;

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.patina");
    let output = directory.path().join("output.patina");
    branched_input(&input);

    // A branched bundle with no --timeline automatically uses the branch-tree
    // policy: each timeline's safe suffix shrinks, but no subtree is dropped.
    execute_trace(TraceMinimize {
        trace: input,
        output: output.clone(),
        timeline: None,
        prune: false,
        jobs: Some(1),
        oracle: strings(&[
            "sh",
            "-c",
            "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
        ]),
    })
    .unwrap();

    let minimized = TraceBundle::load(output).unwrap();
    let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["main", "keeper", "disposable"]);
    assert_eq!(minimized.timelines[1].decisions.len(), 1);
    assert_eq!(
        minimized.timelines[1].decisions[0].outcome,
        Outcome::U64(999)
    );
    minimized.validate().unwrap();
}

#[test]
fn executes_branch_pruning_dropping_and_shrinking() {
    use patina_dst_abi::Outcome;

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.patina");
    let output = directory.path().join("output.patina");
    branched_input(&input);

    execute_trace(TraceMinimize {
        trace: input,
        output: output.clone(),
        timeline: None,
        prune: true,
        jobs: Some(1),
        oracle: strings(&[
            "sh",
            "-c",
            "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
        ]),
    })
    .unwrap();

    let minimized = TraceBundle::load(output).unwrap();
    let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, vec!["main", "keeper"]);
    assert_eq!(minimized.timelines[1].decisions.len(), 1);
    assert_eq!(
        minimized.timelines[1].decisions[0].outcome,
        Outcome::U64(999)
    );
}

#[test]
fn executes_scenario_minimization_shrinking_seed_and_params() {
    // Smoke-check the scenario reducer end to end through a real oracle:
    // the failure needs seed >= 3 and the `keep` parameter present, both
    // read from the PATINA_* environment protocol.
    let invocation = ScenarioMinimize {
        seed: 9,
        params: [("keep", "1"), ("drop", "5")]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        seed_budget: 64,
        oracle: strings(&[
            "sh",
            "-c",
            "test \"$PATINA_SEED\" -ge 3 \
                 && printf '%s' \"$PATINA_PARAMS_JSON\" | grep -q '\"keep\"' && exit 1; exit 0",
        ]),
    };
    assert_eq!(execute_scenario(invocation).unwrap(), 0);
}

pub(super) fn verdict(kind: &str, label: &str) -> VerdictFacts {
    VerdictFacts {
        kind: kind.to_string(),
        label: label.to_string(),
    }
}
