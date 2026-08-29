//! Trace schema migration policy: current bundles load, every supported prior
//! format upgrades in memory and then passes the same structural oracle as a
//! natively current bundle, and unknown or malformed inputs are rejected with
//! the typed error taxonomy.

use std::path::PathBuf;

use patina_dst_abi::{ClockKind, Operation, Outcome};
use patina_dst_trace::{Replayer, TRACE_FORMAT_VERSION, TraceBundle, TraceError};

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
    let bundle = TraceBundle::load(fixture("format-7.patina")).unwrap();
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
        std::fs::read(fixture("format-7.patina")).unwrap(),
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
fn current_crash_restart_fixture_parses_validates_and_is_canonical() {
    let bundle = TraceBundle::load(fixture("format-7-crash-restart.patina")).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    assert_eq!(bundle.timelines[0].lifecycle.len(), 5);
    assert_eq!(bundle.timelines[0].decisions[0].order, 1);
    assert_eq!(bundle.timelines[0].decisions[1].incarnation, 1);
    assert_eq!(
        std::fs::read(fixture("format-7-crash-restart.patina")).unwrap(),
        bundle.to_bytes().unwrap()
    );
}

#[test]
fn every_prior_format_migrates_to_an_equivalent_current_bundle() {
    // Every supported non-crash prior format upgrades to a bundle byte-for-byte
    // equivalent to the hand-written current-format fixture: current version, a single
    // unbranched `main` timeline, and absent branch metadata.
    let current = TraceBundle::load(fixture("format-7.patina")).unwrap();
    for prior in [
        "format-1.patina",
        "format-2.patina",
        "format-3.patina",
        "format-4.patina",
        "format-5.patina",
        "format-6.patina",
    ] {
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

/// The v5→v6 step writes in the creation mode the recorded run behaved as if it
/// had asked for: a format-5 recorder dropped the caller's argument and the
/// driver minted every new entry at the fixed umasked default for its kind, and
/// `0o666`/`0o777` are exactly the requests those defaults come from. A
/// non-creating `open` gets `0` — the argument POSIX says the kernel never
/// reads. RED without the step: the bundle fails to deserialize at all, because
/// `mode` is a required field of both operations.
#[test]
fn the_mode_migration_reconstructs_the_request_a_format_5_run_made() {
    let bundle = TraceBundle::load(fixture("format-5-modes.patina")).unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    bundle.validate().unwrap();
    let main = bundle.resolved_timeline("main").unwrap();
    assert_eq!(
        main[0].operation,
        Operation::FsCreateDirectory {
            path: "/state".into(),
            mode: 0o777,
        }
    );
    let Operation::FsOpen { flags, .. } = &main[1].operation else {
        panic!("expected a creating fs_open, got {:?}", main[1].operation);
    };
    assert!(flags.create);
    assert_eq!(flags.mode, 0o666);
    let Operation::FsOpen { flags, .. } = &main[2].operation else {
        panic!("expected a read-only fs_open, got {:?}", main[2].operation);
    };
    assert!(!flags.create);
    assert_eq!(flags.mode, 0, "a non-creating open records no mode");
}

/// The v6→v7 step gives every recorded open the flag the format-6 recorder
/// behaved as if it had: format 6 had no `O_PATH` in its vocabulary at all, so
/// every open it recorded opened the entry. RED without the step: the bundle
/// fails to deserialize, because `path_only` is a required field of `OpenFlags`.
#[test]
fn the_path_only_migration_marks_every_prior_open_as_opening_the_entry() {
    let bundle = TraceBundle::load(fixture("format-6-path-only.patina")).unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    bundle.validate().unwrap();
    let main = bundle.resolved_timeline("main").unwrap();
    for event in &main[1..] {
        let Operation::FsOpen { flags, .. } = &event.operation else {
            panic!("expected an fs_open, got {:?}", event.operation);
        };
        assert!(
            !flags.path_only,
            "a format-6 open always opened the entry: {flags:?}"
        );
        assert!(
            flags.read || flags.write,
            "and therefore always carried an access mode: {flags:?}"
        );
    }
}

#[test]
fn migration_never_rewrites_the_source_file() {
    for prior in [
        "format-1.patina",
        "format-2.patina",
        "format-3.patina",
        "format-4.patina",
        "format-5.patina",
        "format-6.patina",
    ] {
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
fn legacy_crash_traces_fail_closed_with_named_semantics_error() {
    for version in [1u32, 2, 3, 4] {
        let value = if version == 1 {
            serde_json::json!({
                "format_version": 1,
                "metadata": {
                    "root_seed": 42,
                    "decision_policy": "splitmix64-v1",
                    "fingerprint": "fixture-fingerprint"
                },
                "decisions": [{
                    "sequence": 0,
                    "operation": {"kind": "fs_crash"},
                    "outcome": {"kind": "unit"}
                }]
            })
        } else {
            serde_json::json!({
                "format_version": version,
                "metadata": {
                    "root_seed": 42,
                    "decision_policy": "splitmix64-v1",
                    "fingerprint": "fixture-fingerprint"
                },
                "timelines": [{
                    "id": "main",
                    "parent": null,
                    "from_sequence": null,
                    "branch_seed": null,
                    "decisions": [{
                        "sequence": 0,
                        "operation": {"kind": "fs_crash"},
                        "outcome": {"kind": "unit"}
                    }]
                }]
            })
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        let error = TraceBundle::from_slice(&bytes).unwrap_err();
        assert!(
            matches!(error, TraceError::LegacyCrashSemantics { format_version } if format_version == version),
            "version {version} should fail as LegacyCrashSemantics, got {error:?}"
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
    let current = TraceBundle::load(fixture("format-7.patina")).unwrap();
    for prior in [
        "format-1.patina",
        "format-2.patina",
        "format-3.patina",
        "format-4.patina",
        "format-5.patina",
        "format-6.patina",
    ] {
        let bytes = std::fs::read(fixture(prior)).unwrap();
        let migrated = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(
            migrated, current,
            "{prior} did not migrate through from_slice"
        );
    }
}
