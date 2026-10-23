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
    // A differing record names the member that differs; a record on one side only is reported
    // whole.
    {
        use patina_dst_trace::{NativeIdentityRecord, Sha256Digest};

        let identity = NativeIdentityRecord {
            executable_sha256: Sha256Digest([1; 32]),
            supervisor_sha256: Sha256Digest([3; 32]),
            patina_version: "1.0.0".into(),
            shim_bundle_sha256: Sha256Digest([2; 32]),
            target: "x86_64-unknown-linux-gnu".into(),
        };
        let mut a = bundle_with(Vec::new());
        a.metadata.native = Some(identity.clone());
        let mut b = a.clone();
        b.metadata.native = Some(NativeIdentityRecord {
            executable_sha256: Sha256Digest([3; 32]),
            ..identity
        });
        let report = diff_for(&a, &b, 1);
        let fields: Vec<&str> = report
            .metadata_diff
            .iter()
            .map(|diff| diff.field.as_str())
            .collect();
        assert_eq!(fields, ["native.executable_sha256"]);
        assert_eq!(
            report.metadata_diff[0].b,
            serde_json::json!(Sha256Digest([3; 32]).to_string())
        );

        // A record present on one side only is reported whole.
        b.metadata.native = None;
        let report = diff_for(&a, &b, 1);
        assert_eq!(report.metadata_diff[0].field, "native");
    }
}
