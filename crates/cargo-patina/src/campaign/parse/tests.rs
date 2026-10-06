//! Tests for campaign invocation parsing and continuation controls.

use super::super::selftest::declared_rules_fixture;
use super::super::spec::{
    DEFAULT_PLATEAU_AFTER, DEFAULT_PROGRESS_EVERY, classify_rules_to_json, json_classify_rules,
};
use super::super::{AllowUnmetSometimes, CampaignSpec, FAULT_SCALE_FULL, STARVE_SCALE_FULL};
use super::*;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

/// A `--spec` file and individual flags layer with the flag on top, in
/// EITHER argument order, and an absent switch never undoes the spec.
#[test]
fn flags_override_the_spec_in_either_order_and_absence_overrides_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    fs::write(
        &path,
        br#"{"generations": 7, "buggify": true, "watchdog_nanos": 11}"#,
    )
    .expect("write spec");
    let spec = path.display().to_string();
    let argv = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

    // Spec alone.
    let only_spec = parse(argv(&["art.wasm", "--spec", &spec])).unwrap().spec;
    assert_eq!(only_spec.generations, 7);
    assert!(
        only_spec.buggify,
        "an absent --buggify must not undo the spec"
    );
    assert_eq!(only_spec.watchdog_nanos, Some(11));

    // A flag wins over the spec whether it precedes or follows `--spec`.
    for args in [
        vec![
            "art.wasm",
            "--spec",
            &spec,
            "--gens",
            "3",
            "--liveness-watchdog",
            "22",
        ],
        vec![
            "art.wasm",
            "--gens",
            "3",
            "--liveness-watchdog",
            "22",
            "--spec",
            &spec,
        ],
    ] {
        let spec = parse(argv(&args)).unwrap().spec;
        assert_eq!(spec.generations, 3, "flag beats spec for {args:?}");
        assert_eq!(
            spec.watchdog_nanos,
            Some(22),
            "flag beats spec for {args:?}"
        );
        assert!(spec.buggify, "the spec's own knobs survive for {args:?}");
    }
}

#[test]
fn declared_rules_are_grammar_validated_and_loud() {
    for bad in [
        serde_json::json!([]),
        serde_json::json!({"nonsense": {}}),
        serde_json::json!({"patterns": {"NOT_A_CLASS": ["x"]}}),
        serde_json::json!({"patterns": {"OK": ["x"]}}),
        serde_json::json!({"patterns": {"VIOLATION": []}}),
        serde_json::json!({"patterns": {"VIOLATION": [""]}}),
        serde_json::json!({"patterns": {"VIOLATION": [7]}}),
        serde_json::json!({"exit_codes": {"VIOLATION": ["3"]}}),
        serde_json::json!({"exit_codes": {"VIOLATION": {}}}),
    ] {
        assert!(
            json_classify_rules(&bad).is_err(),
            "malformed classify rules must be refused: {bad}"
        );
    }
    let rules = declared_rules_fixture();
    assert_eq!(
        classify_rules_to_json(&rules),
        serde_json::json!({
            "patterns": {"VIOLATION": ["checksum mismatch"]},
            "exit_codes": {"VIOLATION": [3]},
        })
    );
}

/// The bound and the precedence, on both the JSON and the flag path — the
/// same contract [`the_fault_scale_is_bounded_and_the_flag_beats_the_spec_file`]
/// holds the fault dial to: a spec file cannot ask for a scale ABOVE the
/// tuned policy (it dampens, it never amplifies), and an explicit flag
/// overrides a spec file's value.
#[test]
fn the_starve_scale_is_bounded_and_the_flag_beats_the_spec_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();

    fs::write(&path, br#"{"starve": true, "starve_scale_permille": 1001}"#).expect("write");
    let error = parse(args(&["art", "--spec", &spec_flag]))
        .expect_err("a scale above full intensity must be refused")
        .to_string();
    assert!(
        error.contains("starve_scale_permille") && error.contains("[0, 1000]"),
        "the refusal must name the key and its bound: {error}"
    );

    fs::write(&path, br#"{"starve": true, "starve_scale_permille": 250}"#).expect("write");
    let from_spec = parse(args(&["art", "--spec", &spec_flag])).expect("spec parses");
    assert_eq!(from_spec.spec.starve_scale_permille, 250);
    let overridden = parse(args(&[
        "art",
        "--spec",
        &spec_flag,
        "--starve-scale-permille",
        "100",
    ]))
    .expect("flag parses");
    assert_eq!(overridden.spec.starve_scale_permille, 100);
    // Absent flag, absent spec key: the default is full intensity.
    assert_eq!(
        parse(args(&["art", "--starve"]))
            .expect("parses")
            .spec
            .starve_scale_permille,
        STARVE_SCALE_FULL
    );
}

/// The bound and the precedence, on both the JSON and the flag path: a spec
/// file cannot ask for a scale ABOVE the tuned bands (it dampens, it never
/// amplifies), and an explicit flag overrides a spec file's value.
#[test]
fn the_fault_scale_is_bounded_and_the_flag_beats_the_spec_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();

    fs::write(&path, br#"{"faults": true, "fault_scale_permille": 1001}"#).expect("write");
    let error = parse(args(&["art", "--spec", &spec_flag]))
        .expect_err("a scale above full intensity must be refused")
        .to_string();
    assert!(
        error.contains("fault_scale_permille") && error.contains("[0, 1000]"),
        "the refusal must name the key and its bound: {error}"
    );

    fs::write(&path, br#"{"faults": true, "fault_scale_permille": 250}"#).expect("write");
    let from_spec = parse(args(&["art", "--spec", &spec_flag])).expect("spec parses");
    assert_eq!(from_spec.spec.fault_scale_permille, 250);
    let overridden = parse(args(&[
        "art",
        "--spec",
        &spec_flag,
        "--fault-scale-permille",
        "10",
    ]))
    .expect("flag parses");
    assert_eq!(overridden.spec.fault_scale_permille, 10);
    // Absent flag, absent spec key: the default is full intensity.
    assert_eq!(
        parse(args(&["art", "--faults"]))
            .expect("parses")
            .spec
            .fault_scale_permille,
        FAULT_SCALE_FULL
    );
}

#[test]
fn renamed_flags_parse_and_old_spellings_error() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    // New spellings parse and set the right fields; the `=VALUE` form works too.
    let inv = parse(args(&[
        "art",
        "--sched-pct",
        "--seed-start",
        "7",
        "--out-dir",
        "d",
        "--gens=3",
    ]))
    .unwrap();
    assert!(inv.spec.pct);
    assert_eq!(inv.spec.seed_base, 7);
    assert_eq!(inv.out_dir, PathBuf::from("d"));
    assert_eq!(inv.spec.generations, 3);

    // Old spellings are unknown-flag errors (no aliases).
    for old in [
        &["art", "--pct"][..],
        &["art", "--out", "d"][..],
        &["art", "--seed-base", "1"][..],
    ] {
        assert!(parse(args(old)).is_err(), "old spelling {old:?} must error");
    }

    // A leading flag (no artifact) fails closed with the unsupported-option
    // usage error, not a later "failed to read artifact --nonsense".
    assert!(parse(args(&["--nonsense"])).is_err());
    assert!(parse(args(&["--gens", "3"])).is_err());
}

#[test]
fn campaign_locates_the_artifact_around_options() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    // Options may lead the artifact, in any form/order, matching the leading
    // spelling exactly.
    let base = parse(args(&["art.wasm", "--gens", "5", "--seed-start", "2"])).unwrap();
    for spelling in [
        &["--gens", "5", "--seed-start", "2", "art.wasm"][..],
        &["--gens=5", "art.wasm", "--seed-start=2"][..],
    ] {
        let got = parse(args(spelling)).unwrap();
        assert_eq!(got.artifact, base.artifact);
        assert_eq!(got.spec, base.spec);
        assert_eq!(got.out_dir, base.out_dir);
    }
    // A leading UNKNOWN flag with no artifact is the unsupported-option error
    // naming the flag (campaign has no Cargo family to forward to).
    let error = |values: &[&str]| match parse(args(values)) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a usage error for {values:?}"),
    };
    assert!(error(&["--frob"]).contains("--frob"));
    // A real compiled artifact stranded behind an unknown flag is a loud
    // routing error naming both, never a confusing later "failed to read".
    let dir = tempfile::tempdir().unwrap();
    let module = dir.path().join("app.wasm");
    std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
    let m = module.to_str().unwrap();
    let message = error(&["--frob", m]);
    assert!(message.contains("--frob"), "{message}");
    assert!(message.contains(m), "{message}");
}

#[test]
fn progress_every_and_plateau_parse_and_default() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    // Default when unset.
    let inv = parse(args(&["art"])).unwrap();
    assert_eq!(inv.progress_every, DEFAULT_PROGRESS_EVERY);
    assert_eq!(inv.spec.plateau_after, DEFAULT_PLATEAU_AFTER);
    // Both value forms parse; 0 and 1 are accepted (silent / full-stream).
    assert_eq!(
        parse(args(&["art", "--progress-every", "0"]))
            .unwrap()
            .progress_every,
        0
    );
    assert_eq!(
        parse(args(&["art", "--progress-every=1"]))
            .unwrap()
            .progress_every,
        1
    );
    assert_eq!(
        parse(args(&["art", "--plateau-after", "0"]))
            .unwrap()
            .spec
            .plateau_after,
        0
    );
    assert_eq!(
        parse(args(&["art", "--plateau-after=17"]))
            .unwrap()
            .spec
            .plateau_after,
        17
    );
    // Duplicate is rejected (set_once), non-integer is rejected.
    assert!(parse(args(&["art", "--progress-every=1", "--progress-every=2"])).is_err());
    assert!(parse(args(&["art", "--progress-every", "nope"])).is_err());
    assert!(parse(args(&["art", "--plateau-after=1", "--plateau-after=2"])).is_err());
    assert!(parse(args(&["art", "--plateau-after", "nope"])).is_err());
}

#[test]
fn allow_unmet_sometimes_parses_flag_and_spec_shapes() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let bare = parse(args(&["art", "--allow-unmet-sometimes"])).unwrap();
    assert_eq!(
        bare.spec.allow_unmet_sometimes,
        Some(AllowUnmetSometimes::Always)
    );
    let threshold = parse(args(&["art", "--allow-unmet-sometimes=10"])).unwrap();
    assert_eq!(
        threshold.spec.allow_unmet_sometimes,
        Some(AllowUnmetSometimes::BelowGenerations(10))
    );
    assert!(parse(args(&["art", "--allow-unmet-sometimes=0"])).is_err());
    assert!(
        parse(args(&[
            "art",
            "--allow-unmet-sometimes=1",
            "--allow-unmet-sometimes=2",
        ]))
        .is_err()
    );

    let mut spec = CampaignSpec::default();
    spec.apply_json(&serde_json::json!({"allow_unmet_sometimes": true}))
        .unwrap();
    assert_eq!(
        spec.allow_unmet_sometimes,
        Some(AllowUnmetSometimes::Always)
    );
    spec.apply_json(&serde_json::json!({"allow_unmet_sometimes": 7}))
        .unwrap();
    assert_eq!(
        spec.allow_unmet_sometimes,
        Some(AllowUnmetSometimes::BelowGenerations(7))
    );
    for bad in [
        serde_json::json!({"allow_unmet_sometimes": false}),
        serde_json::json!({"allow_unmet_sometimes": 0}),
        serde_json::json!({"allow_unmet_sometimes": "yes"}),
    ] {
        assert!(CampaignSpec::default().apply_json(&bad).is_err());
    }
}

#[test]
fn continuation_modes_parse_and_reject_resupplied_spec() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let extend = parse(args(&["--extend", "7", "--out-dir", "d"])).unwrap();
    assert_eq!(extend.artifact, None);
    assert_eq!(extend.mode, CampaignMode::Extend { additional: 7 });
    assert_eq!(extend.out_dir, PathBuf::from("d"));
    let resume = parse(args(&[
        "--resume",
        "--timeout-secs",
        "120",
        "--progress-every",
        "2",
    ]))
    .unwrap();
    assert_eq!(resume.mode, CampaignMode::Resume);
    assert_eq!(resume.timeout_secs_override, Some(120));
    assert_eq!(resume.progress_every, 2);

    assert!(parse(args(&["--extend", "0"])).is_err());
    assert!(parse(args(&["--extend", "1", "--resume"])).is_err());
    assert!(parse(args(&["guest", "--extend", "1"])).is_err());
    assert!(parse(args(&["--extend", "1", "--", "guest-arg"])).is_err());
    for flag in [
        "--gens",
        "--seed-start",
        "--spec",
        "--buggify",
        "--swarm",
        "--sched-pct",
        "--faults",
        "--liveness-watchdog",
        "--converge-within",
        "--heal-after",
        "--report-failures",
        "--allow-unmet-sometimes",
    ] {
        let values: Vec<&str> = match flag {
            "--buggify"
            | "--swarm"
            | "--sched-pct"
            | "--faults"
            | "--report-failures"
            | "--allow-unmet-sometimes" => vec!["--extend", "1", flag],
            _ => vec!["--extend", "1", flag, "1"],
        };
        let message = parse(args(&values)).unwrap_err().to_string();
        assert!(
            message.contains("out-dir's recorded spec is authoritative"),
            "{message}"
        );
        assert!(message.contains(flag), "{message}");
    }
}

#[test]
fn the_native_invocation_flags_parse_into_the_spec() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let inv = parse(args(&[
        "art",
        "--harness",
        "--allow",
        "dlsym",
        "--allow",
        "semaphore_wait",
        "--allow-unsupported-symbols",
        "all",
    ]))
    .unwrap();
    assert!(inv.spec.harness);
    assert_eq!(inv.spec.allow_symbols, ["dlsym", "semaphore_wait"]);
    assert_eq!(inv.spec.allow_unsupported_symbols.as_deref(), Some("all"));
    // The value grammars are the registry's, enforced at parse time.
    assert!(parse(args(&["art", "--allow-unsupported-symbols", ""])).is_err());
    assert!(parse(args(&["art", "--allow"])).is_err());
    // They describe the campaign's shape, so a continuation cannot change them.
    for flag in [
        "--harness",
        "--allow=dlsym",
        "--allow-unsupported-symbols=all",
    ] {
        let error = parse(args(&["--resume", flag])).unwrap_err().to_string();
        assert!(
            error.contains("recorded spec is authoritative"),
            "{flag} must be refused on a continuation, got {error}"
        );
    }
}
