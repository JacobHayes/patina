//! Argument parsing regression tests.

use super::*;
use crate::minimize;
use crate::tests::strings;

fn scenario_invocation(values: &[&str]) -> minimize::ScenarioMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Scenario(invocation)) => invocation,
        _ => panic!("expected scenario minimization"),
    }
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
    // Generation-only options are rejected in scenario mode.
    assert!(
        parse(strings(&[
            "minimize",
            "--scenario",
            "--seed",
            "1",
            "--marker",
            "x",
            "--",
            "./oracle",
        ]))
        .is_err()
    );
}

#[test]
fn minimize_without_a_selector_is_refused() {
    assert!(parse(strings(&["minimize", "failure.patina", "--", "./oracle"])).is_err());
    assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
}
