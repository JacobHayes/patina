//! Regression tests for diff.

use super::*;
use patina_dst_abi::{ClockKind, Fd, Operation, Outcome};
use patina_dst_trace::TraceBundle;

use super::super::tests::*;

fn flat_for(bundle: &TraceBundle) -> (serde_json::Value, FlatTrace) {
    let raw = serde_json::to_value(bundle).unwrap();
    let flat = trace_view::flatten(bundle, &raw, "main").unwrap();
    (raw, flat)
}

fn diff_for(a: &TraceBundle, b: &TraceBundle, context: usize) -> DiffReport {
    let (a_raw, a_flat) = flat_for(a);
    let (b_raw, b_flat) = flat_for(b);
    diff_report(
        Path::new("a.patina"),
        Path::new("b.patina"),
        "main",
        a,
        b,
        &a_raw,
        &b_raw,
        &a_flat,
        &b_flat,
        context,
    )
}

#[test]
fn diff_reports_identical_metadata_operation_outcome_and_length_classes() {
    let one = bundle_with(vec![(
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Outcome::U64(1),
    )]);
    let identical = diff_for(&one, &one, 1);
    assert!(identical.identical);
    assert_eq!(identical.aligned_prefix, 3);
    assert!(identical.divergence.is_none());
    assert_eq!(identical.to_json()["result"], "identical");

    let mut metadata_only = one.clone();
    metadata_only.metadata.root_seed = 99;
    let metadata = diff_for(&one, &metadata_only, 1);
    assert!(!metadata.identical);
    assert!(metadata.divergence.is_none());
    assert_eq!(metadata.metadata_diff[0].field, "root_seed");

    let op_changed = bundle_with(vec![(Operation::FsSync { fd: Fd(3) }, Outcome::Unit)]);
    let operation = diff_for(&one, &op_changed, 1);
    assert_eq!(
        operation.divergence.as_ref().unwrap().class,
        "operation-mismatch"
    );
    assert_eq!(operation.aligned_prefix, 1);

    let outcome_changed = bundle_with(vec![(
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Outcome::U64(2),
    )]);
    let outcome = diff_for(&one, &outcome_changed, 1);
    assert_eq!(
        outcome.divergence.as_ref().unwrap().class,
        "outcome-mismatch"
    );
    assert_eq!(outcome.aligned_prefix, 1);

    let longer = bundle_with(vec![
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(1),
        ),
        (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
    ]);
    let length = diff_for(&one, &longer, 1);
    assert_eq!(
        length.divergence.as_ref().unwrap().class,
        "operation-mismatch"
    );
    assert_eq!(length.aligned_prefix, 2);
    assert!(length.divergence.as_ref().unwrap().a_event.is_some());
    assert!(length.divergence.as_ref().unwrap().b_event.is_some());
}
