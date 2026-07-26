//! Trace schema migration policy: current bundles load, every supported prior
//! format upgrades in memory and then passes the same structural oracle as a
//! natively current bundle, and unknown or malformed inputs are rejected with
//! the typed error taxonomy.

use std::path::PathBuf;

use patina_abi::{ClockKind, Operation, Outcome};
use patina_trace::{Replayer, TRACE_FORMAT_VERSION, TraceBundle, TraceError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn expected_operations() -> Vec<Operation> {
    vec![
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Operation::EntropyFill { len: 4 },
    ]
}

#[test]
fn current_format_fixture_parses_validates_and_is_canonically_encoded() {
    let bundle = TraceBundle::load(fixture("format-4.patina")).unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    bundle.validate().unwrap();
    // A pre-metadata run records no fault configuration; the field is absent
    // from the canonical form rather than an explicit empty object.
    assert_eq!(bundle.metadata.faults, None);
    let main = bundle.resolved_timeline("main").unwrap();
    assert_eq!(main.len(), 2);
    assert_eq!(main[0].outcome, Outcome::U64(1000));
    assert_eq!(main[1].outcome, Outcome::Bytes(vec![1, 2, 3, 4]));

    // The current-format fixture is exactly what the writer emits: compact,
    // single-line JSON with base64 byte payloads. This both documents the
    // on-disk encoding and guards against the fixture drifting from the writer.
    let reencoded = bundle.to_bytes().unwrap();
    assert_eq!(
        std::fs::read(fixture("format-4.patina")).unwrap(),
        reencoded
    );
    let text = String::from_utf8(reencoded).unwrap();
    assert!(
        text.contains("\"value\":\"AQIDBA==\""),
        "bytes not base64: {text}"
    );
    assert_eq!(
        text.lines().count(),
        1,
        "current encoding must be single-line"
    );
}

#[test]
fn every_prior_format_migrates_to_an_equivalent_current_bundle() {
    // Both supported prior formats upgrade to a bundle byte-for-byte equivalent
    // to the hand-written current-format fixture: current version, a single
    // unbranched `main` timeline, and absent branch metadata.
    let current = TraceBundle::load(fixture("format-4.patina")).unwrap();
    for prior in ["format-1.patina", "format-2.patina", "format-3.patina"] {
        let migrated = TraceBundle::load(fixture(prior)).unwrap();
        assert_eq!(
            migrated, current,
            "{prior} did not migrate to the current bundle"
        );
        assert_eq!(migrated.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(migrated.timelines.len(), 1);
        let main = &migrated.timelines[0];
        assert_eq!(main.id, "main");
        assert_eq!(main.parent, None);
        assert_eq!(main.from_sequence, None);
        assert_eq!(main.branch_seed, None);

        // The migrated bundle passes the normal oracle and replays identically.
        migrated.validate().unwrap();
        assert_eq!(
            migrated.resolved_timeline("main").unwrap(),
            current.resolved_timeline("main").unwrap()
        );

        let mut replay = Replayer::from_bundle(migrated, "fixture-fingerprint", "main").unwrap();
        assert_eq!(replay.root_seed(), 42);
        for operation in expected_operations() {
            replay.expect(&operation).unwrap();
        }
        replay.finish().unwrap();
    }
}

#[test]
fn migration_never_rewrites_the_source_file() {
    for prior in ["format-1.patina", "format-2.patina", "format-3.patina"] {
        let path = fixture(prior);
        let before = std::fs::read(&path).unwrap();
        TraceBundle::load(&path).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "loading {prior} must not rewrite the on-disk trace"
        );
    }
}

#[test]
fn migration_output_is_still_subject_to_structural_validation() {
    // A prior-format bundle whose sequence numbers are non-contiguous migrates
    // structurally, then fails the oracle exactly as a current-format bundle
    // with the same defect would - at every supported prior version.
    for prior in [
        "format-1-noncontiguous.patina",
        "format-2-noncontiguous.patina",
    ] {
        let error = TraceBundle::load(fixture(prior)).unwrap_err();
        assert!(
            matches!(error, TraceError::Invalid(_)),
            "expected structural rejection of {prior}, got {error:?}"
        );
    }
}

#[test]
fn newer_unsupported_version_is_rejected_with_typed_error() {
    let error = TraceBundle::load(fixture("format-99-unsupported.patina")).unwrap_err();
    assert!(
        matches!(
            error,
            TraceError::UnsupportedVersion {
                found: 99,
                supported
            } if supported == TRACE_FORMAT_VERSION
        ),
        "expected UnsupportedVersion, got {error:?}"
    );
}

#[test]
fn version_below_the_supported_floor_is_rejected_with_typed_error() {
    let error = TraceBundle::load(fixture("format-0-unsupported.patina")).unwrap_err();
    assert!(
        matches!(error, TraceError::UnsupportedVersion { found: 0, .. }),
        "expected UnsupportedVersion, got {error:?}"
    );
}

#[test]
fn malformed_fixture_is_rejected_as_a_parse_error() {
    let error = TraceBundle::load(fixture("malformed.patina")).unwrap_err();
    assert!(
        matches!(error, TraceError::Parse { .. }),
        "expected Parse, got {error:?}"
    );
}

#[test]
fn migration_is_reachable_through_the_in_memory_transport_path() {
    // The same decode path backs `from_slice`, so transported prior-format
    // bundles migrate identically to file loads.
    let current = TraceBundle::load(fixture("format-4.patina")).unwrap();
    for prior in ["format-1.patina", "format-2.patina", "format-3.patina"] {
        let bytes = std::fs::read(fixture(prior)).unwrap();
        let migrated = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(
            migrated, current,
            "{prior} did not migrate through from_slice"
        );
    }
}
