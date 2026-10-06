//! Tests for trace events, timelines, bundle validation and persistence.

use super::*;
use crate::tests::operation;
use crate::{
    MAX_TIMELINE_EVENTS, MAX_TRACE_BYTES, Recorder, Replayer, RunMetadata, TRACE_FORMAT_VERSION,
    TraceError,
};
use patina_dst_abi::{Fd, Operation, Outcome};
use std::fs;
use tempfile::tempdir;

#[test]
fn byte_encoding_round_trips_and_matches_files() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    recorder.observe(Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4)));
    let bundle = recorder.into_bundle().unwrap();
    let bytes = bundle.to_bytes().unwrap();
    bundle.write_atomic(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let parsed = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(parsed, bundle);
    let mut replay = Replayer::from_bundle(parsed, "fingerprint", "main").unwrap();
    assert_eq!(replay.expect(&operation()).unwrap(), Outcome::U64(10));
    assert_eq!(
        replay.expect(&Operation::FsDup { fd: Fd(3) }).unwrap(),
        Outcome::Handle(Fd(4))
    );
    replay.finish().unwrap();

    assert!(matches!(
        TraceBundle::from_slice(b"not json"),
        Err(TraceError::Parse { .. })
    ));
}

/// A writer that dies mid-write leaves its scratch file behind, and a
/// scratch name derived from the pid is the name the next process given
/// that pid picks. Red while scratch names were `.<trace>.tmp-<pid>-<n>`
/// opened with `create_new`: these leftovers refused the write.
#[test]
fn a_dead_writers_scratch_file_does_not_block_a_write() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    for counter in 0..1024 {
        let name = format!(".run.patina.tmp-{}-{counter}", std::process::id());
        File::create(directory.path().join(name)).unwrap();
    }
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    recorder.finish(&path).unwrap();
    TraceBundle::load(&path).unwrap();
}

/// A write sweeps the scratch files beside its trace that no writer holds
/// and spares one a live writer holds.
#[test]
fn a_write_sweeps_dead_scratch_and_spares_live_scratch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let (live, _held) = create_scratch(&path).unwrap();
    let dead = directory.path().join(".run.patina.tmp.dead");
    File::create(&dead).unwrap();
    let other_trace = directory.path().join(".run.patina2.tmp.dead");
    File::create(&other_trace).unwrap();

    TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new())
        .write_atomic(&path)
        .unwrap();
    assert!(!dead.exists(), "a dead writer's scratch is swept");
    assert!(live.exists(), "a live writer's scratch is spared");
    assert!(other_trace.exists(), "another trace's scratch is not swept");
}

#[test]
fn save_paths_reject_serialized_trace_that_exceeds_byte_limit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("oversized.patina");
    let event = TraceEvent::new(0, operation(), Outcome::U64(10));
    let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), vec![event]);
    let serialized_len = {
        let mut bytes = serde_json::to_vec(&bundle).unwrap();
        bytes.push(b'\n');
        bytes.len() as u64
    };
    let limit = serialized_len - 1;

    let error = bundle.to_bytes_with_limit(limit).unwrap_err();
    assert!(
        matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
        "unexpected error: {error}"
    );

    let error = bundle.write_atomic_with_limit(&path, limit).unwrap_err();
    assert!(
        matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
        "unexpected error: {error}"
    );
    assert!(
        !path.exists(),
        "save-time refusal must not leave a trace file"
    );
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        0,
        "save-time refusal must not leave a temporary file"
    );

    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    let error = recorder.finish_with_limit(&path, limit).unwrap_err();
    assert!(
        matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
        "unexpected error: {error}"
    );
    assert!(!path.exists(), "Recorder::finish must fail before writing");
}

#[test]
fn buggify_fingerprint_requires_buggify_metadata() {
    // Class-level pairing for SDK buggify value-form point pins: a trace whose
    // fingerprint declares `+buggify` must carry the authoritative buggify
    // config, or the run is vacuous and replay cannot reproduce SDK decisions.
    let invalid = serde_json::json!({
        "format_version": TRACE_FORMAT_VERSION,
        "metadata": {
            "root_seed": 7,
            "decision_policy": "splitmix64-v1",
            "fingerprint": "fingerprint+buggify",
            "realtime_epoch_nanos": 0,
            "boot_origin_nanos": 1000,
            "hostname": "patina"
        },
        "timelines": [{
            "id": MAIN_TIMELINE,
            "parent": null,
            "from_sequence": null,
            "branch_seed": null,
            "lifecycle": [
                {"order": 0, "kind": "start", "incarnation": 0},
                {"order": 1, "kind": "end", "incarnation": 0}
            ],
            "decisions": []
        }]
    });
    let bytes = serde_json::to_vec(&invalid).unwrap();
    let error = TraceBundle::from_slice(&bytes).expect_err("missing buggify config must fail");
    assert!(
        error
            .to_string()
            .contains("fingerprint declares +buggify but trace metadata has no buggify config"),
        "{error}"
    );
}

#[test]
fn rejects_non_contiguous_sequences() {
    let mut bundle = TraceBundle::new(
        RunMetadata::new(1, "fingerprint", 0, "patina"),
        vec![TraceEvent::new(4, operation(), Outcome::U64(0))],
    );
    bundle.timelines[0].decisions[0].sequence = 4;
    assert!(matches!(bundle.validate(), Err(TraceError::Invalid(_))));
}

#[test]
fn rejects_malformed_incomplete_and_unsupported_trace_files() {
    let directory = tempdir().unwrap();
    let malformed = directory.path().join("malformed.patina");
    fs::write(&malformed, b"not json").unwrap();
    assert!(matches!(
        TraceBundle::load(&malformed),
        Err(TraceError::Parse { .. })
    ));

    let empty = directory.path().join("empty.patina");
    fs::write(&empty, b"").unwrap();
    let error = TraceBundle::load(&empty).unwrap_err();
    assert!(
        matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("empty trace")),
        "unexpected error: {error}"
    );

    let truncated = directory.path().join("truncated.patina");
    fs::write(
        &truncated,
        format!("{{\"format_version\":{TRACE_FORMAT_VERSION},"),
    )
    .unwrap();
    let error = TraceBundle::load(&truncated).unwrap_err();
    assert!(
        matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("truncated JSON")),
        "unexpected error: {error}"
    );

    let incomplete_metadata = directory.path().join("incomplete-metadata.patina");
    fs::write(
        &incomplete_metadata,
        format!(
            r#"{{"format_version":{TRACE_FORMAT_VERSION},"metadata":{{"root_seed":1,"decision_policy":"splitmix64-v1"}},"timelines":[]}}"#
        ),
    )
    .unwrap();
    let error = TraceBundle::load(&incomplete_metadata).unwrap_err();
    assert!(
        matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("trace metadata") && reason.contains("fingerprint")),
        "unexpected error: {error}"
    );

    assert!(matches!(
        TraceBundle::from_slice(b""),
        Err(TraceError::Incomplete { .. })
    ));

    let unsupported = directory.path().join("unsupported.patina");
    let mut bundle = TraceBundle::new(RunMetadata::new(1, "fingerprint", 0, "patina"), Vec::new());
    bundle.format_version = TRACE_FORMAT_VERSION + 1;
    fs::write(&unsupported, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(matches!(
        TraceBundle::load(&unsupported),
        Err(TraceError::UnsupportedVersion { .. })
    ));

    let oversized = directory.path().join("oversized.patina");
    File::create(&oversized)
        .unwrap()
        .set_len(MAX_TRACE_BYTES + 1)
        .unwrap();
    assert!(matches!(
        TraceBundle::load(&oversized),
        Err(TraceError::ResourceLimit { .. })
    ));
}

/// A budget refusal must be distinguishable from a broken trace WITHOUT
/// string matching, and must carry the two numbers a diagnostic reports.
/// The native shim keeps a run's verdict on the budget refusal and aborts
/// on every other one, so this is the seam that decision rests on.
#[test]
fn a_budget_refusal_is_classifiable_and_carries_its_numbers() {
    let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let serialized_len = bundle.to_bytes().unwrap().len() as u64;
    let limit = serialized_len - 1;

    let error = bundle.to_bytes_with_limit(limit).unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    assert_eq!(error.resource_limit_bytes(), Some((serialized_len, limit)));

    let mut oversized =
        TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    oversized.timelines[0].decisions =
        vec![TraceEvent::new(0, operation(), Outcome::U64(0)); MAX_TIMELINE_EVENTS + 1];
    let error = oversized.validate().unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    assert_eq!(
        error.resource_limit_bytes(),
        None,
        "an event-count budget has no byte figures to report"
    );

    let broken = TraceError::Invalid("something is wrong".into());
    assert!(!broken.is_resource_limit());
}
