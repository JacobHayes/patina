//! Tests for campaign invocation parsing and continuation controls.

use super::super::selftest::declared_rules_fixture;
use super::super::spec::{classify_rules_to_json, json_classify_rules};
use super::super::{
    AllowUnmetSometimes, CampaignClass, CampaignSpec, FAULT_PLANE_NAMES, FAULT_SCALE_FULL,
    FaultPlanes, STARVE_SCALE_FULL,
};
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
    let only_spec = parse(argv(&["art", "--spec", &spec])).unwrap().spec;
    assert_eq!(only_spec.generations, 7);
    assert!(
        only_spec.buggify,
        "an absent --buggify must not undo the spec"
    );
    assert_eq!(only_spec.watchdog_nanos, Some(11));

    // A flag wins over the spec whether it precedes or follows `--spec`.
    for args in [
        vec![
            "art",
            "--spec",
            &spec,
            "--gens",
            "3",
            "--liveness-watchdog",
            "22",
        ],
        vec![
            "art",
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
    let cross_run = CampaignClass::ALL
        .iter()
        .find(|class| class.is_cross_run())
        .unwrap();
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
        // No rule over one run's output can say that run would not reproduce.
        serde_json::json!({"patterns": {cross_run.as_str(): ["token"]}}),
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

/// The bound and the precedence of both scale dials, on the JSON and the flag
/// path: a spec file cannot ask for a scale ABOVE the tuned policy (it
/// dampens, it never amplifies), an explicit flag overrides a spec file's
/// value, and with neither the default is full intensity.
#[test]
fn the_scale_dials_are_bounded_and_the_flag_beats_the_spec_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    type Field = fn(&CampaignSpec) -> u64;
    let dials: [(&str, &str, &str, Field, u64); 2] = [
        (
            "faults",
            "fault_scale_permille",
            "--fault-scale-permille",
            |spec| spec.fault_scale_permille,
            FAULT_SCALE_FULL,
        ),
        (
            "starve",
            "starve_scale_permille",
            "--starve-scale-permille",
            |spec| spec.starve_scale_permille,
            STARVE_SCALE_FULL,
        ),
    ];
    for (switch, key, flag, field, full) in dials {
        fs::write(&path, format!(r#"{{"{switch}": true, "{key}": 1001}}"#)).expect("write");
        let error = parse(args(&["art", "--spec", &spec_flag]))
            .expect_err("a scale above full intensity must be refused")
            .to_string();
        assert!(error.contains(key), "the refusal must name {key}: {error}");

        fs::write(&path, format!(r#"{{"{switch}": true, "{key}": 250}}"#)).expect("write");
        let from_spec = parse(args(&["art", "--spec", &spec_flag])).expect("spec parses");
        assert_eq!(field(&from_spec.spec), 250);
        let overridden =
            parse(args(&["art", "--spec", &spec_flag, flag, "10"])).expect("flag parses");
        assert_eq!(field(&overridden.spec), 10);
        let default = parse(args(&["art", &format!("--{switch}")])).expect("parses");
        assert_eq!(field(&default.spec), full);
    }
}

/// Bare `--faults` is every plane and `--faults=PLANE,...` the named subset,
/// from the flag or the spec file, with the flag on top. An unknown plane is a
/// usage error that names the valid ones, and so is a subset naming a plane
/// the campaign could never draw.
#[test]
fn faults_selects_every_plane_bare_or_the_named_subset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let faults = |values: &[&str]| parse(args(values)).expect("parses").spec.faults;

    assert_eq!(faults(&["art"]), FaultPlanes::NONE);
    assert_eq!(faults(&["art", "--faults"]), FaultPlanes::ALL);
    let net_sleep = FaultPlanes::from_names(["net", "sleep"]).unwrap();
    assert_eq!(faults(&["art", "--faults=sleep,net"]), net_sleep);

    fs::write(&path, br#"{"faults": ["sleep", "net"]}"#).expect("write");
    assert_eq!(faults(&["art", "--spec", &spec_flag]), net_sleep);
    assert_eq!(
        faults(&["art", "--spec", &spec_flag, "--faults=fs"]),
        FaultPlanes::from_names(["fs"]).unwrap()
    );
    assert_eq!(
        faults(&["art", "--faults", "--spec", &spec_flag]),
        FaultPlanes::ALL
    );

    for refused in [
        args(&["art", "--faults=net,disk"]),
        args(&["art", "--faults="]),
        args(&["art", "--faults=net,"]),
    ] {
        let error = parse(refused.clone())
            .expect_err("an unknown plane is refused")
            .to_string();
        for plane in FAULT_PLANE_NAMES {
            assert!(error.contains(plane), "{refused:?}: {error}");
        }
    }
    fs::write(&path, br#"{"faults": ["disk"]}"#).expect("write");
    let error = parse(args(&["art", "--spec", &spec_flag]))
        .expect_err("an unknown spec plane is refused")
        .to_string();
    for plane in FAULT_PLANE_NAMES {
        assert!(error.contains(plane), "{error}");
    }

    assert!(parse(args(&["art", "--faults=net,dns"])).is_err());
    assert!(parse(args(&["art", "--faults=dns", "--dns-entry", "db=10.0.0.5"])).is_ok());
    assert!(parse(args(&["art", "--faults"])).is_ok());
    assert!(parse(args(&["--extend", "1", "--faults=net"])).is_err());
}

/// A spec's knob exclusion applies once the flags are merged, and is refused
/// when the merged campaign does not draw the excluded knob's plane at all.
#[test]
fn an_exclusion_needs_its_plane_selected_after_the_merge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    fs::write(
        &path,
        br#"{"faults": ["sleep"], "exclude_knobs": ["--net-reset-permille"]}"#,
    )
    .expect("write");
    assert!(parse(args(&["art", "--spec", &spec_flag])).is_err());
    let merged = parse(args(&["art", "--spec", &spec_flag, "--faults=net"]))
        .expect("the flag selects the excluded knob's plane")
        .spec;
    assert_eq!(
        merged.exclude_knobs.into_iter().collect::<Vec<_>>(),
        [patina_dst_runtime::FaultKnob::NetResetPermille]
    );
}

#[test]
fn campaign_locates_the_artifact_around_options() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    // Options may lead the artifact, in any form/order, matching the leading
    // spelling exactly.
    let base = parse(args(&["art", "--gens", "5", "--seed-start", "2"])).unwrap();
    for spelling in [
        &["--gens", "5", "--seed-start", "2", "art"][..],
        &["--gens=5", "art", "--seed-start=2"][..],
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
    let module = dir.path().join("app");
    std::fs::write(&module, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    let m = module.to_str().unwrap();
    let message = error(&["--frob", m]);
    assert!(message.contains("--frob"), "{message}");
    assert!(message.contains(m), "{message}");
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
