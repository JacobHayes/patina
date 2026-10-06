//! Argument parsing regression tests.

use super::*;
use crate::minimize;
use crate::tests::strings;
use std::path::PathBuf;

fn trace_invocation(values: &[&str]) -> minimize::TraceMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Trace(invocation)) => invocation,
        _ => panic!("expected trace minimization"),
    }
}

fn scenario_invocation(values: &[&str]) -> minimize::ScenarioMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Scenario(invocation)) => invocation,
        _ => panic!("expected scenario minimization"),
    }
}

#[test]
fn parses_trace_minimization_with_an_external_oracle() {
    let invocation = trace_invocation(&[
        "minimize",
        "failure.patina",
        "--output",
        "small.patina",
        "--timeline",
        "failure",
        "--",
        "./oracle",
        "--exact",
    ]);
    assert_eq!(invocation.trace, PathBuf::from("failure.patina"));
    assert_eq!(invocation.output, PathBuf::from("small.patina"));
    assert_eq!(invocation.timeline.as_deref(), Some("failure"));
    assert!(!invocation.prune);
    assert_eq!(invocation.oracle, strings(&["./oracle", "--exact"]));
    assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
}

#[test]
fn parses_branch_pruning_and_rejects_timeline_combo() {
    let invocation = trace_invocation(&[
        "minimize",
        "failure.patina",
        "--output",
        "small.patina",
        "--prune-branches",
        "--",
        "./oracle",
    ]);
    assert!(invocation.prune);
    assert_eq!(invocation.timeline, None);
    // --prune-branches and --timeline are mutually exclusive.
    assert!(
        parse(strings(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--prune-branches",
            "--timeline",
            "leaf",
            "--",
            "./oracle",
        ]))
        .is_err()
    );
}

#[test]
fn parses_scenario_minimization_with_seed_and_params() {
    let invocation = scenario_invocation(&[
        "minimize",
        "--scenario",
        "--seed",
        "12",
        "--param",
        "zone=a",
        "--seed-budget",
        "16",
        "--",
        "./oracle",
        "--flag",
    ]);
    assert_eq!(invocation.seed, 12);
    assert_eq!(invocation.seed_budget, 16);
    assert_eq!(invocation.params.get("zone").map(String::as_str), Some("a"));
    assert_eq!(invocation.oracle, strings(&["./oracle", "--flag"]));
    // --scenario requires a seed and an oracle after `--`.
    assert!(parse(strings(&["minimize", "--scenario", "--", "./oracle"])).is_err());
    assert!(parse(strings(&["minimize", "--scenario", "--seed", "1"])).is_err());
    // trace-only options are rejected in scenario mode.
    assert!(
        parse(strings(&[
            "minimize",
            "--scenario",
            "--seed",
            "1",
            "--timeline",
            "leaf",
            "--",
            "./oracle",
        ]))
        .is_err()
    );
}

#[test]
fn minimize_locates_the_trace_after_options() {
    // `minimize --output out.patina trace.patina -- oracle`: the trace follows
    // the option, like the other verbs (previously the option was mistaken for
    // the trace path).
    match parse(strings(&[
        "minimize",
        "--output",
        "out.patina",
        "trace.patina",
        "--",
        "oracle",
    ]))
    .unwrap()
    {
        ParseResult::Minimize(minimize::MinimizeInvocation::Trace(trace)) => {
            assert_eq!(trace.trace, PathBuf::from("trace.patina"));
            assert_eq!(trace.output, PathBuf::from("out.patina"));
            assert_eq!(trace.oracle, strings(&["oracle"]));
        }
        _ => panic!("expected a trace minimization"),
    }
}
