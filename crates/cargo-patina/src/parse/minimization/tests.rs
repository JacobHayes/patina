//! Argument parsing regression tests.

use super::*;
use crate::minimize;
use crate::tests::strings;

fn params_invocation(values: &[&str]) -> minimize::ParamsMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Params(invocation)) => invocation,
        _ => panic!("expected parameter minimization"),
    }
}

#[test]
fn params_minimization_lifts_the_commands_own_params_out() {
    let invocation = params_invocation(&[
        "minimize",
        "--params",
        "--",
        "cargo",
        "patina",
        "run",
        "./guest",
        "--param",
        "zone=a",
        "--seed",
        "3",
        "--param=clients=4",
        "--",
        "--param",
        "guest=arg",
    ]);
    assert_eq!(
        invocation.params,
        BTreeMap::from([
            ("clients".to_owned(), "4".to_owned()),
            ("zone".to_owned(), "a".to_owned()),
        ])
    );
    assert_eq!(
        invocation.head,
        strings(&["cargo", "patina", "run", "./guest", "--seed", "3"])
    );
    // The guest's own arguments stay the guest's.
    assert_eq!(invocation.tail, strings(&["--", "--param", "guest=arg"]));
}

#[test]
fn params_minimization_needs_a_command_with_params() {
    for argv in [
        &["minimize", "--params"][..],
        &["minimize", "--params", "--", "./oracle"],
        &[
            "minimize", "--params", "--", "./oracle", "--", "--param", "k=v",
        ],
        &[
            "minimize", "--params", "--", "./oracle", "--param", "novalue",
        ],
        &[
            "minimize",
            "--params",
            "--",
            "./o",
            "--param",
            "k=1",
            "--param=k=2",
        ],
        // Generation-only options are rejected in parameter mode.
        &[
            "minimize", "--params", "--marker", "x", "--", "./o", "--param", "k=v",
        ],
    ] {
        assert!(parse(strings(argv)).is_err(), "{argv:?}");
    }
}

#[test]
fn minimize_without_a_selector_is_refused() {
    assert!(parse(strings(&["minimize", "failure.patina", "--", "./oracle"])).is_err());
    assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
}
