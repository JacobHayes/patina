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
    // A recorded flag `run` does not register is refused rather than guessed.
    assert!(split_knobs(&["--not-a-run-flag".to_string()]).is_err());
}

/// A knob candidate is held to the unreduced run's refusal class, never to the
/// guest's own exit code.
#[test]
fn a_knob_candidate_is_held_to_the_refusal_class_not_the_exit_code() {
    let ended = |code: i32, refusal: Option<&str>| {
        let facts = crate::campaign::RunFacts {
            exit_code: code,
            guest_exit_code: Some(code),
            refusal: refusal.map(str::to_string),
            ..Default::default()
        };
        RunEnd {
            exit: facts.exit_status(),
            refusal: facts.refusal,
        }
    };
    let original = ended(4, None);
    // The fault is gone and the guest exits otherwise, still showing the bug.
    assert!(candidate_counts(
        &ended(3, None),
        false,
        true,
        Some(&original)
    ));
    // The guest showed the bug, then patina refused the run.
    let refused = ended(134, Some("shim_fatal"));
    assert!(!candidate_counts(&refused, false, true, Some(&original)));
    // A generation that ended under a refusal is held to that refusal.
    assert!(candidate_counts(
        &refused,
        false,
        true,
        Some(&ended(134, Some("shim_fatal")))
    ));
    assert!(!candidate_counts(
        &ended(3, None),
        false,
        true,
        Some(&refused)
    ));
    // The unreduced run itself is held to nothing but the target.
    assert!(candidate_counts(&refused, false, true, None));
    assert!(!candidate_counts(&original, true, true, Some(&original)));
    assert!(!candidate_counts(&original, false, false, Some(&original)));
}
