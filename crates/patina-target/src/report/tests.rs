//! Native audit findings and containment-note rendering tests.

use super::*;
use crate::NativeEscape;
use crate::provenance::NativeProvenance;
use crate::tests::instruction_finding;

#[test]
fn cpu_nondeterminism_note_names_the_blocked_instructions() {
    // No instruction findings: no note (a by-name cpu-nondeterminism import
    // is answered by the ordinary symbol machinery).
    let by_name = NativeEscape::new(
        "sched_getcpu".into(),
        "cpu-nondeterminism",
        vec![NativeProvenance::unknown()],
    );
    assert!(render_cpu_nondeterminism_note(&[by_name]).is_none());

    // A blocked instruction finding carries a note naming the instruction.
    let note =
        render_cpu_nondeterminism_note(&[instruction_finding("cpu-nondeterminism", "rdtscp")])
            .expect("a blocked instruction finding must carry a note");
    assert!(note.contains("rdtscp"), "{note}");

    // Every blocked instruction is named.
    let note = render_cpu_nondeterminism_note(&[
        instruction_finding("cpu-nondeterminism", "rdrand"),
        instruction_finding("cpu-nondeterminism", "cntvct"),
    ])
    .expect("a blocked instruction finding must carry a note");
    assert!(note.contains("cntvct") && note.contains("rdrand"), "{note}");
}
