//! Tests for run metadata and recorded configuration.

use super::*;
use crate::{Replayer, TraceBundle};
use std::collections::BTreeMap;

fn reload(metadata: RunMetadata) -> (String, RunMetadata) {
    let bytes = TraceBundle::new(metadata, Vec::new()).to_bytes().unwrap();
    let reloaded = TraceBundle::from_slice(&bytes).unwrap().metadata;
    (String::from_utf8(bytes).unwrap(), reloaded)
}

/// Every recorded configuration round-trips exactly, and a run that sets none
/// of the optional ones writes none of those fields, so it reloads as `None`
/// everywhere. An empty-but-present `guest_argv: []` stays distinct from an
/// absent one: a zero-argument run must replay zero arguments.
#[test]
fn recorded_configuration_round_trips_and_is_omitted_when_unset() {
    let full = RunMetadata::new(
        7,
        "fingerprint+buggify+pct+starve+swarm",
        1_000_000_000,
        "db-1",
    )
    .with_faults(FaultConfigRecord {
        crash_permille: 34,
        crash_kind: patina_dst_abi::CrashKind::Process,
        fs_error_permille: 100,
        net_drop_permille: 250,
        ..FaultConfigRecord::default()
    })
    .with_buggify(Some(BuggifyConfigRecord {
        fire_permille: 250,
        activation_permille: 250,
        cutoff_nanos: 300_000_000_000,
        after_setup: true,
        active_sites: vec!["commit-early-return".to_string()],
        knobs: BTreeMap::from([("commit-batch".to_string(), 42)]),
    }))
    .with_schedule_policy(Some(SchedulePolicyRecord {
        pct: Some(PctPolicyRecord {
            depth: 3,
            steps: 512,
        }),
        starvation: Some(StarvationPolicyRecord {
            intervals: 2,
            max_len: 64,
            window: 256,
        }),
        yield_stride: 16,
    }))
    .with_swarm(Some(SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string(), "net_drop".to_string()],
        selected_classes: vec!["crash".to_string()],
    }))
    .with_sud(Some(true))
    .with_tsc(Some(true))
    .with_guest_argv(Some(vec!["--replay-commands".into(), "3,1,2".into()]))
    .with_guest_cwd(Some("/work".into()))
    .with_guest_env(Some(BTreeMap::from([(
        "RUST_LOG".to_string(),
        "debug".to_string(),
    )])));
    let (_, reloaded) = reload(full.clone());
    assert_eq!(reloaded, full);
    let replay = Replayer::from_bundle(
        TraceBundle::new(reloaded, Vec::new()),
        "fingerprint+buggify+pct+starve+swarm",
        "main",
    )
    .unwrap();
    assert_eq!(replay.realtime_epoch_nanos(), 1_000_000_000);
    assert_eq!(replay.hostname(), "db-1");

    let plain = RunMetadata::new(7, "fingerprint", 0, "patina");
    let (text, reloaded) = reload(plain.clone());
    assert_eq!(reloaded, plain);
    for field in [
        "buggify",
        "schedule_policy",
        "swarm",
        "sud",
        "tsc",
        "guest_argv",
        "guest_cwd",
        "guest_env",
    ] {
        assert!(!text.contains(field), "{field} written when unset: {text}");
    }

    let empty = plain.with_guest_argv(Some(Vec::new()));
    let (_, reloaded) = reload(empty.clone());
    assert_eq!(reloaded, empty);
}

/// The candidate/selected lists are the machine-readable record of what swarm
/// dropped, so consumers derive deselection as their complement: a class never
/// enabled is not "deselected", and an empty candidate set is the vacuous
/// signature while dropping every candidate is a legitimate draw. A selection
/// outside the candidates or a duplicated class is refused.
#[test]
fn swarm_record_partitions_candidates_and_validates_the_partition() {
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
    assert!(!swarm.was_candidate("fs_error"));
    assert!(!swarm.deselected("fs_error"));
    assert!(SwarmConfigRecord::default().is_vacuous());
    assert!(
        !SwarmConfigRecord {
            selected_classes: Vec::new(),
            ..swarm.clone()
        }
        .is_vacuous()
    );
    let validate = |swarm| {
        TraceBundle::new(
            RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(swarm)),
            Vec::new(),
        )
        .validate()
    };
    validate(swarm).expect("a clean partition validates");
    validate(SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string()],
        selected_classes: vec!["buggify".to_string()],
    })
    .expect_err("a selection outside the candidates must be refused");
    validate(SwarmConfigRecord {
        candidate_classes: vec!["crash".to_string(), "crash".to_string()],
        selected_classes: Vec::new(),
    })
    .expect_err("a duplicated candidate must be refused");
}
