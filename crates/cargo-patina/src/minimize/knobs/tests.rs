//! Regression tests for knobs.

use super::*;

#[test]
fn knobs_split_on_the_run_registry_arity_not_on_leading_dashes() {
    let flags = vec![
        "--swarm".to_string(),
        "--fs-short-permille".to_string(),
        "122".to_string(),
        "--machine-crash-permille".to_string(),
        "5".to_string(),
        "--dns-entry".to_string(),
        "workq-server=127.0.0.1".to_string(),
    ];
    let knobs = split_knobs(&flags).unwrap();
    assert_eq!(
        knobs.iter().map(Knob::render).collect::<Vec<_>>(),
        vec![
            "--swarm",
            "--fs-short-permille 122",
            "--machine-crash-permille 5",
            "--dns-entry workq-server=127.0.0.1",
        ]
    );
    // A recorded flag `run` does not register is refused rather than guessed.
    assert!(split_knobs(&["--not-a-run-flag".to_string()]).is_err());
}

/// A knob candidate is held to the stop patina ended the unreduced run under,
/// if any; how the guest itself exited is not part of what is compared.
#[test]
fn a_knob_candidate_is_held_to_the_stop_the_unreduced_run_ended_under() {
    let ended = |refusal: Option<&str>| RunEnd {
        refusal: refusal.map(str::to_string),
    };
    let original = ended(None);
    // The fault is gone and the guest still shows the bug.
    assert!(candidate_counts(&ended(None), false, true, Some(&original)));
    // The guest showed the bug, then patina stopped the run.
    let refused = ended(Some("shim_fatal"));
    assert!(!candidate_counts(&refused, false, true, Some(&original)));
    // A generation that ended under a stop of patina's is held to that stop.
    assert!(candidate_counts(
        &refused,
        false,
        true,
        Some(&ended(Some("shim_fatal")))
    ));
    assert!(!candidate_counts(&ended(None), false, true, Some(&refused)));
    // The unreduced run itself is held to nothing but the target.
    assert!(candidate_counts(&refused, false, true, None));
    assert!(!candidate_counts(&original, true, true, Some(&original)));
    assert!(!candidate_counts(&original, false, false, Some(&original)));
}
