//! Native audit findings and containment-note rendering tests.

use super::*;
use crate::NativeEscape;
use crate::provenance::NativeProvenance;
use crate::tests::instruction_finding;

#[test]
fn cpu_nondeterminism_note_names_allowability_and_trappability() {
    // No instruction findings: no note (a by-name cpu-nondeterminism import
    // is answered by the ordinary symbol machinery).
    let by_name = NativeEscape::new(
        "sched_getcpu".into(),
        "cpu-nondeterminism",
        vec![NativeProvenance::unknown()],
    );
    assert!(render_cpu_nondeterminism_note(&[by_name]).is_none());

    // A blocked timestamp read: say it is trappable elsewhere, and that
    // --allow cannot clear an instruction finding.
    let note =
        render_cpu_nondeterminism_note(&[instruction_finding("cpu-nondeterminism", "rdtscp")])
            .expect("a blocked instruction finding must carry a note");
    assert!(note.contains("--allow <symbol> cannot clear one"), "{note}");
    assert!(note.contains("rdtscp"), "{note}");
    assert!(note.contains("PR_SET_TSC"), "{note}");

    // A blocked entropy read: say it is untrappable anywhere, so the operator
    // is not sent hunting for a platform that would run it.
    let note = render_cpu_nondeterminism_note(&[
        instruction_finding("cpu-nondeterminism", "rdrand"),
        instruction_finding("cpu-nondeterminism", "cntvct"),
    ])
    .expect("a blocked instruction finding must carry a note");
    assert!(note.contains("untrappable anywhere"), "{note}");
    assert!(note.contains("cntvct/rdrand"), "{note}");
    assert!(!note.contains("PR_SET_TSC"), "{note}");
}
