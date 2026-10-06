//! Regression tests for oracle.

use super::*;

use super::super::tests::*;

/// A candidate that reported `verdicts` and nothing else on either stream.
fn reported(verdicts: &[VerdictFacts]) -> CandidateOutcome<'_> {
    CandidateOutcome {
        stdout: "",
        stderr: "",
        verdicts,
    }
}

#[test]
fn a_marker_matches_any_alternative_and_needs_a_clean_replay() {
    let target = Target::Marker(
        Marker::parse("GUEST_VIOLATION|GUEST_ABORT final-wal wal corruption").unwrap(),
    );
    let saw = |stderr: &str| {
        target.preserved(&CandidateOutcome {
            stdout: "",
            stderr,
            verdicts: &[],
        })
    };
    assert!(saw("boom: GUEST_VIOLATION no-loss"));
    assert!(saw("GUEST_ABORT final-wal wal corruption"));
    assert!(!saw("clean run"));
    // The fail-open direction the probe named: the marker is present, but
    // the replay diverged after printing it.
    assert!(!saw(
        "GUEST_VIOLATION no-loss\npatina native shim fatal: trace operation mismatch"
    ));
}

#[test]
fn an_empty_marker_is_refused() {
    assert!(Marker::parse("").is_err());
    assert!(Marker::parse("|").is_err());
}

#[test]
fn a_verdict_target_captures_only_the_failure_verdicts_deduplicated() {
    // A generation's recorded stream: the same violation reported twice (the
    // ABI aggregates by label, so repeats are normal), a second violation,
    // an abort intent, and a pass.
    let target = VerdictTarget::capture(&[
        verdict("violation", "durability"),
        verdict("pass", "queue-drained"),
        verdict("violation", "durability"),
        verdict("abort_intent", "final-wal"),
        verdict("violation", "wal-integrity"),
    ])
    .expect("a generation with violations has a target");
    assert_eq!(
        target.render(),
        "abort_intent:final-wal,violation:durability,violation:wal-integrity"
    );
}

#[test]
fn a_generation_whose_only_verdicts_are_passes_has_no_target() {
    assert!(
        VerdictTarget::capture(&[verdict("pass", "queue-drained")]).is_none(),
        "a `pass` reports that a property HELD; there is no failure in it to preserve"
    );
    assert!(VerdictTarget::capture(&[]).is_none());
}

#[test]
fn a_verdict_target_is_containment_on_kind_and_label_not_equality() {
    let target = VerdictTarget::capture(&[
        verdict("violation", "durability"),
        verdict("violation", "wal-integrity"),
    ])
    .unwrap();
    let target = Target::Verdicts(target);

    // Exactly the target: preserved.
    assert!(target.preserved(&reported(&[
        verdict("violation", "durability"),
        verdict("violation", "wal-integrity"),
    ])));
    // Extra verdicts are free — including a PASS the seed run never had, and
    // one the reduction dropped. Only the targeted failure decides.
    assert!(target.preserved(&reported(&[
        verdict("pass", "queue-drained"),
        verdict("violation", "wal-integrity"),
        verdict("violation", "durability"),
        verdict("violation", "some-other-invariant"),
    ])));
    // A candidate that reproduces only half the failure reproduces a
    // different, weaker failure.
    assert!(!target.preserved(&reported(&[verdict("violation", "durability")])));
    // Same label, different kind: not the same verdict.
    assert!(!target.preserved(&reported(&[
        verdict("violation", "durability"),
        verdict("abort_intent", "wal-integrity"),
    ])));
    // Nothing reported at all — a candidate patina refused to replay.
    assert!(!target.preserved(&reported(&[])));
}

#[test]
fn a_verdict_target_still_needs_a_clean_replay() {
    let target =
        Target::Verdicts(VerdictTarget::capture(&[verdict("violation", "no-loss")]).unwrap());
    let verdicts = [verdict("violation", "no-loss")];
    assert!(target.preserved(&reported(&verdicts)));
    // The same fail-open direction the marker path closes: the guest reported
    // the violation, then the replay diverged, so the candidate never
    // actually reproduced the failure.
    assert!(!target.preserved(&CandidateOutcome {
        stdout: "",
        stderr: "patina native shim fatal: trace operation mismatch",
        verdicts: &verdicts,
    }));
}
