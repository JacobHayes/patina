//! Tests for run metadata and recorded configuration.

use super::*;
use crate::{Replayer, TraceBundle};
use std::collections::BTreeMap;

#[test]
fn run_facts_round_trip_through_the_metadata() {
    let metadata = RunMetadata::new(7, "fingerprint", 1_000_000_000, "db-1");
    let bundle = TraceBundle::new(metadata, Vec::new());
    let reloaded = TraceBundle::from_slice(&bundle.to_bytes().unwrap()).unwrap();
    assert_eq!(reloaded.metadata.realtime_epoch_nanos, 1_000_000_000);
    assert_eq!(reloaded.metadata.hostname, "db-1");
    let replay = Replayer::from_bundle(reloaded, "fingerprint", "main").unwrap();
    assert_eq!(replay.realtime_epoch_nanos(), 1_000_000_000);
    assert_eq!(replay.hostname(), "db-1");
}

#[test]
fn fault_config_metadata_round_trips_and_omits_defaults() {
    let faults = FaultConfigRecord {
        crash_at: Some(CrashPointRecord {
            op: FaultCrashOp::Write,
            ordinal: 34,
        }),
        torn_granularity: TornGranularity::Byte,
        fs_error_permille: 100,
        fs_short_permille: 200,
        net_drop_permille: 250,
        ..FaultConfigRecord::default()
    };
    let metadata =
        RunMetadata::new(7, "fingerprint", 0, "patina").with_faults(Some(faults.clone()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let bytes = bundle.to_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    // Enum tags serialize by name, and inert knobs are omitted entirely.
    assert!(text.contains("\"op\":\"write\""), "{text}");
    assert!(text.contains("\"torn_granularity\":\"byte\""), "{text}");
    assert!(text.contains("\"fs_error_permille\":100"), "{text}");
    assert!(text.contains("\"fs_short_permille\":200"), "{text}");
    assert!(!text.contains("sleep_jitter_nanos"), "{text}");
    assert!(!text.contains("net_latency_nanos"), "{text}");

    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded.metadata.faults, Some(faults));

    // A fault-free run records a compact empty object, still distinct from a
    // pre-metadata trace whose field is absent (None).
    let empty = TraceBundle::new(
        RunMetadata::new(7, "fingerprint", 0, "patina")
            .with_faults(Some(FaultConfigRecord::default())),
        Vec::new(),
    );
    let text = String::from_utf8(empty.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"faults\":{}"), "{text}");
}

#[test]
fn buggify_config_metadata_round_trips_and_is_additive() {
    let mut knobs = BTreeMap::new();
    knobs.insert("commit-batch".to_string(), 42);
    let buggify = BuggifyConfigRecord {
        fire_permille: 250,
        activation_permille: 250,
        cutoff_nanos: 300_000_000_000,
        after_setup: true,
        active_sites: vec!["commit-early-return".to_string()],
        knobs,
    };
    let metadata =
        RunMetadata::new(7, "fingerprint+buggify", 0, "patina").with_buggify(Some(buggify.clone()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let bytes = bundle.to_bytes().unwrap();
    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded.metadata.buggify, Some(buggify));

    // A trace recorded without buggify keeps the field absent, so an old
    // trace and a buggify-disabled run are indistinguishable (both None).
    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("buggify"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.buggify, None);
}

#[test]
fn schedule_policy_metadata_round_trips_and_is_additive() {
    let policy = SchedulePolicyRecord {
        pct: Some(PctPolicyRecord {
            depth: 3,
            steps: 512,
        }),
        starvation: Some(StarvationPolicyRecord {
            intervals: 2,
            max_len: 64,
            window: 256,
        }),
    };
    let metadata = RunMetadata::new(7, "fingerprint+pct+starve", 0, "patina")
        .with_schedule_policy(Some(policy));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let bytes = bundle.to_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"depth\":3"), "{text}");
    assert!(text.contains("\"intervals\":2"), "{text}");
    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded.metadata.schedule_policy, Some(policy));
    assert!(reloaded.metadata.schedule_policy.unwrap().is_active());

    // A default-policy run keeps the field absent, indistinguishable from an
    // old trace (both None).
    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("schedule_policy"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.schedule_policy, None);
}

#[test]
fn swarm_config_metadata_round_trips_and_is_additive() {
    let swarm = SwarmConfigRecord {
        candidate_classes: vec![
            "crash".to_string(),
            "net_drop".to_string(),
            "sleep_jitter".to_string(),
        ],
        selected_classes: vec!["crash".to_string(), "sleep_jitter".to_string()],
    };
    let metadata =
        RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(swarm.clone()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let bytes = bundle.to_bytes().unwrap();
    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded.metadata.swarm, Some(swarm));

    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("swarm"), "{text}");
}

/// The candidate/selected lists are the machine-readable record of what swarm
/// dropped, so consumers derive deselection as their complement. Prove the
/// derivation and the validation that keeps it meaningful.
#[test]
fn swarm_record_partitions_candidates_into_selected_and_deselected() {
    let swarm = SwarmConfigRecord {
        candidate_classes: vec![
            "crash".to_string(),
            "net_drop".to_string(),
            "buggify".to_string(),
        ],
        selected_classes: vec!["crash".to_string()],
    };
    assert_eq!(swarm.deselected_classes(), vec!["net_drop", "buggify"]);
    assert!(swarm.deselected("buggify"));
    assert!(!swarm.deselected("crash"));
    // A class the operator never enabled is in neither list: it was not a
    // candidate, so it was not "deselected" either. That distinction is the
    // whole point — it separates "swarm dropped it" from "never requested".
    assert!(!swarm.was_candidate("fs_error"));
    assert!(!swarm.deselected("fs_error"));
    TraceBundle::new(
        RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(swarm)),
        Vec::new(),
    )
    .validate()
    .expect("a clean partition validates");

    // RED: a selection that is not a subset of the candidates would make the
    // complement nonsense, so the trace is refused.
    let broken = SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string()],
        selected_classes: vec!["buggify".to_string()],
    };
    let error = TraceBundle::new(
        RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(broken)),
        Vec::new(),
    )
    .validate()
    .expect_err("a selection outside the candidates must be refused");
    assert!(
        format!("{error}").contains("was not a candidate"),
        "{error}"
    );

    // RED: a duplicated class would double-count in any accumulation.
    let duplicated = SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string(), "crash".to_string()],
        selected_classes: Vec::new(),
    };
    let error = TraceBundle::new(
        RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(duplicated)),
        Vec::new(),
    )
    .validate()
    .expect_err("a duplicated candidate must be refused");
    assert!(format!("{error}").contains("more than once"), "{error}");
}

/// A swarm draw over an empty candidate set is the inert-knob signature: the
/// operator asked for `--swarm` and the run had nothing to select from.
/// Dropping every candidate of a non-empty set is the opposite — a legitimate
/// draw — so the two must not collapse into one predicate.
#[test]
fn swarm_record_is_vacuous_exactly_when_there_were_no_candidates() {
    assert!(SwarmConfigRecord::default().is_vacuous());
    let all_dropped = SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string(), "buggify".to_string()],
        selected_classes: Vec::new(),
    };
    assert!(!all_dropped.is_vacuous());
    let all_kept = SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string()],
        selected_classes: vec!["crash".to_string()],
    };
    assert!(!all_kept.is_vacuous());
}

#[test]
fn sud_metadata_round_trips_and_is_additive() {
    // An armed run records `sud:true` and round-trips.
    let metadata = RunMetadata::new(7, "fingerprint", 0, "patina").with_sud(Some(true));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"sud\":true"), "{text}");
    let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded.metadata.sud, Some(true));

    // Every other run (macOS, non-SUD kernel, standalone, pre-SUD trace)
    // records nothing: the field is omitted, so old and new traces are
    // byte-identical.
    let plain = TraceBundle::new(
        RunMetadata::new(7, "fingerprint", 0, "patina").with_sud(None),
        Vec::new(),
    );
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("sud"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.sud, None);
}

#[test]
fn tsc_metadata_round_trips_and_is_additive() {
    // A run that armed the timestamp-counter trap records `tsc:true` and
    // round-trips, independently of the SUD field.
    let metadata = RunMetadata::new(7, "fingerprint", 0, "patina").with_tsc(Some(true));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"tsc\":true"), "{text}");
    let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded.metadata.tsc, Some(true));
    assert_eq!(reloaded.metadata.sud, None);

    // Every run that did not arm it records nothing, so a trace taken before
    // the trap existed stays byte-identical.
    let plain = TraceBundle::new(
        RunMetadata::new(7, "fingerprint", 0, "patina").with_tsc(None),
        Vec::new(),
    );
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("tsc"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.tsc, None);
}

#[test]
fn guest_argv_metadata_round_trips_and_is_additive() {
    // A recorded argument list round-trips exactly, including order.
    let argv = vec!["--replay-commands".to_string(), "3,1,2".to_string()];
    let metadata =
        RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_argv(Some(argv.clone()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let bytes = bundle.to_bytes().unwrap();
    let reloaded = TraceBundle::from_slice(&bytes).unwrap();
    assert_eq!(reloaded.metadata.guest_argv, Some(argv));

    // An empty argument list is recorded as `Some([])` and stays distinct
    // from an old trace's absent field: a zero-argument run must reproduce
    // zero arguments on replay, not inherit whatever the command line gives.
    let empty = TraceBundle::new(
        RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_argv(Some(Vec::new())),
        Vec::new(),
    );
    let text = String::from_utf8(empty.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"guest_argv\":[]"), "{text}");
    let reloaded_empty = TraceBundle::from_slice(empty.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_empty.metadata.guest_argv, Some(Vec::new()));

    // A trace recorded before argv capture keeps the field absent, so it and
    // the "no arguments recorded" case are distinguishable (None vs Some([])).
    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("guest_argv"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.guest_argv, None);
}

#[test]
fn guest_cwd_metadata_round_trips_and_is_additive() {
    let metadata =
        RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_cwd(Some("/work".into()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"guest_cwd\":\"/work\""), "{text}");
    let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded.metadata.guest_cwd.as_deref(), Some("/work"));

    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("guest_cwd"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.guest_cwd, None);
}

#[test]
fn guest_env_metadata_round_trips_and_is_additive() {
    let env = BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]);
    let metadata =
        RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_env(Some(env.clone()));
    let bundle = TraceBundle::new(metadata, Vec::new());
    let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
    assert!(text.contains("\"guest_env\":{"), "{text}");
    assert!(text.contains("\"RUST_LOG\":\"debug\""), "{text}");
    let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded.metadata.guest_env, Some(env));

    let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("guest_env"), "{text}");
    let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(reloaded_plain.metadata.guest_env, None);
}
