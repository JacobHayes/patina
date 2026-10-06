//! Regression tests for generation.

use super::*;

use super::super::tests::*;

fn repro_with(class: &str, verdicts: Vec<VerdictFacts>) -> crate::campaign::GenerationRepro {
    crate::campaign::GenerationRepro {
        artifact: PathBuf::from("guest"),
        seed: 7,
        flags: Vec::new(),
        pinned: Vec::new(),
        guest_args: Vec::new(),
        timeout_secs: 30,
        class: class.to_string(),
        verdicts,
    }
}

#[test]
fn an_explicit_marker_overrides_the_recorded_verdicts() {
    let repro = repro_with("VIOLATION", vec![verdict("violation", "durability")]);
    let target = generation_target(Some("GUEST_TORN"), 14, &repro).unwrap();
    assert_eq!(target.render(), "marker[GUEST_TORN]");
}

#[test]
fn a_generation_with_verdicts_targets_them_without_a_marker() {
    let repro = repro_with(
        "VIOLATION",
        vec![
            verdict("violation", "durability"),
            verdict("pass", "queue-drained"),
        ],
    );
    let target = generation_target(None, 14, &repro).unwrap();
    assert_eq!(target.render(), "verdicts[violation:durability]");
}

#[test]
fn a_generation_with_no_failure_verdict_and_no_marker_is_refused_naming_both_options() {
    // The classes that do not travel on the verdict channel at all: a
    // liveness wedge is a runtime finding, not a guest verdict.
    let error = generation_target(None, 14, &repro_with("LIVENESS", Vec::new())).unwrap_err();
    assert!(
        error.0.contains("no failure verdict to target")
            && error.0.contains("reported no verdict at all"),
        "unexpected error: {}",
        error.0
    );
    assert!(
        error.0.contains("patina_dst::verdict") && error.0.contains("--marker"),
        "the refusal must name BOTH ways forward: {}",
        error.0
    );

    // A guest that reports only successes is refused for its own reason,
    // rather than being minimized against a `pass`.
    let passes = generation_target(
        None,
        14,
        &repro_with("UNCLASSIFIED", vec![verdict("pass", "queue-drained")]),
    )
    .unwrap_err();
    assert!(
        passes.0.contains("pass:queue-drained") && passes.0.contains("HELD"),
        "unexpected error: {}",
        passes.0
    );
}
