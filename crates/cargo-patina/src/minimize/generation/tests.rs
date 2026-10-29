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
        cross_run: crate::campaign::CampaignClass::ALL
            .iter()
            .any(|known| known.as_str() == class && known.is_cross_run()),
        verdicts,
    }
}

/// A cross-run class is refused whatever target a single run could offer:
/// its own recorded verdicts, or a marker the operator typed.
#[test]
fn a_cross_run_generation_is_refused_even_with_a_target() {
    let repro = repro_with("NONDETERMINISM", vec![verdict("violation", "durability")]);
    assert!(generation_target(None, 14, &repro).is_err());
    assert!(generation_target(Some("GUEST_TORN"), 14, &repro).is_err());
}

/// Without a marker a generation targets its own failure verdicts; an
/// explicit marker overrides them.
#[test]
fn a_generation_targets_its_failure_verdicts_unless_a_marker_overrides_them() {
    let repro = repro_with(
        "VIOLATION",
        vec![
            verdict("violation", "durability"),
            verdict("pass", "queue-drained"),
        ],
    );
    let target = generation_target(None, 14, &repro).unwrap();
    assert_eq!(target.render(), "verdicts[violation:durability]");
    let target = generation_target(Some("GUEST_TORN"), 14, &repro).unwrap();
    assert_eq!(target.render(), "marker[GUEST_TORN]");
}

#[test]
fn a_generation_with_no_failure_verdict_and_no_marker_is_refused_refused() {
    // The classes that do not travel on the verdict channel at all: a
    // liveness wedge is a runtime finding, not a guest verdict.
    let error = generation_target(None, 14, &repro_with("LIVENESS", Vec::new())).unwrap_err();
    assert!(error.0.contains("--marker"), "{}", error.0);

    // A guest that reports only successes is refused for its own reason,
    // rather than being minimized against a `pass`.
    let passes = generation_target(
        None,
        14,
        &repro_with("UNCLASSIFIED", vec![verdict("pass", "queue-drained")]),
    )
    .unwrap_err();
    assert!(
        passes.0.contains("queue-drained"),
        "unexpected error: {}",
        passes.0
    );
}
