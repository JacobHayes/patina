//! Regression tests for knobs.

use super::*;

#[test]
fn knobs_split_on_the_run_registry_arity_not_on_leading_dashes() {
    let flags = vec![
        "--swarm".to_string(),
        "--fs-short-permille".to_string(),
        "122".to_string(),
        "--fs-crash-at".to_string(),
        "write:3".to_string(),
        "--dns-entry".to_string(),
        "workq-server=127.0.0.1".to_string(),
    ];
    let knobs = split_knobs(&flags).unwrap();
    assert_eq!(
        knobs.iter().map(Knob::render).collect::<Vec<_>>(),
        vec![
            "--swarm",
            "--fs-short-permille 122",
            "--fs-crash-at write:3",
            "--dns-entry workq-server=127.0.0.1",
        ]
    );
}

#[test]
fn an_unregistered_recorded_flag_is_refused_rather_than_guessed() {
    let error = split_knobs(&["--not-a-run-flag".to_string()]).unwrap_err();
    assert!(
        error.0.contains("is not a `run` flag"),
        "unexpected error: {}",
        error.0
    );
}
