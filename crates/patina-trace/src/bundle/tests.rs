//! Tests for trace events, timelines, bundle validation and persistence.

use super::*;
use crate::tests::operation;
use crate::{
    MAX_TIMELINE_EVENTS, MAX_TRACE_BYTES, Recorder, RunMetadata, TRACE_FORMAT_VERSION, TraceError,
};
use patina_dst_abi::Outcome;
use std::fs;
use tempfile::tempdir;

/// A write sweeps the scratch files beside its trace that no writer holds
/// and spares one a live writer holds. Leftover scratch from dead writers,
/// even under names a pid-derived scheme would pick again, never blocks it.
#[test]
fn a_write_sweeps_dead_scratch_and_spares_live_scratch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    for counter in 0..1024 {
        let name = format!(".run.patina.tmp-{}-{counter}", std::process::id());
        File::create(directory.path().join(name)).unwrap();
    }
    let (live, _held) = create_scratch(&path).unwrap();
    let dead = directory.path().join(".run.patina.tmp.dead");
    File::create(&dead).unwrap();
    let other_trace = directory.path().join(".run.patina2.tmp.dead");
    File::create(&other_trace).unwrap();

    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    recorder.finish(&path).unwrap();
    TraceBundle::load(&path).unwrap();
    assert!(!dead.exists(), "a dead writer's scratch is swept");
    assert!(live.exists(), "a live writer's scratch is spared");
    assert!(other_trace.exists(), "another trace's scratch is not swept");
}

/// Every save path refuses a trace over its byte budget before writing
/// anything, and the refusal is classifiable as a budget refusal WITHOUT
/// string matching, carrying the two numbers a diagnostic reports. The native
/// shim keeps a run's verdict on the budget refusal and aborts on every other
/// one, so this is the seam that decision rests on.
#[test]
fn save_paths_refuse_an_over_budget_trace_classifiably_and_write_nothing() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("oversized.patina");
    let event = TraceEvent::new(0, operation(), Outcome::U64(10));
    let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), vec![event]);
    let serialized_len = bundle.to_bytes().unwrap().len() as u64;
    let limit = serialized_len - 1;

    let error = bundle.to_bytes_with_limit(limit).unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    assert_eq!(error.resource_limit_bytes(), Some((serialized_len, limit)));
    let error = bundle.write_atomic_with_limit(&path, limit).unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    let error = recorder.finish_with_limit(&path, limit).unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        0,
        "a save-time refusal must leave neither a trace nor a temporary file"
    );

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
    assert!(!TraceError::Invalid("something is wrong".into()).is_resource_limit());
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
            "fingerprint": "fingerprint+buggify",
            "faults": {},
            "realtime_epoch_nanos": 0,
            "boot_origin_nanos": 1000,
            "hostname": "patina",
            "cpus": patina_dst_abi::DEFAULT_CPUS,
            "time_model": patina_dst_abi::TIME_MODEL
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
    assert!(matches!(error, TraceError::Invalid(_)), "{error}");
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
fn rejects_malformed_incomplete_and_oversized_trace_files() {
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
            r#"{{"format_version":{TRACE_FORMAT_VERSION},"metadata":{{"root_seed":1}},"timelines":[]}}"#
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
