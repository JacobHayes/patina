//! Tests for campaign invocation parsing and continuation controls.

use super::super::spec::json_classify_rules;
use super::super::{CampaignSpec, FAULT_SCALE_FULL, FaultPlanes, RunClass, VARY_NAMES, Vary};
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
        br#"{"gens": 7, "swarm": true, "vary": ["buggify"], "liveness_watchdog": 11}"#,
    )
    .expect("write spec");
    let spec = path.display().to_string();
    let argv = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

    // Spec alone.
    let only_spec = parse(argv(&["art", "--spec", &spec])).unwrap().spec;
    assert_eq!(only_spec.generations, 7);
    assert!(only_spec.swarm, "an absent --swarm must not undo the spec");
    assert!(only_spec.vary.buggify);
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
        assert!(
            spec.vary.buggify,
            "the spec's own settings survive for {args:?}"
        );
    }
}

/// The usage-error message of a campaign parse that must fail.
fn refusal(values: &[&str]) -> String {
    match parse(values.iter().map(OsString::from).collect::<Vec<_>>()) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a usage error for {values:?}"),
    }
}

#[test]
fn declared_rules_are_grammar_validated_and_loud() {
    let cross_run = RunClass::ALL
        .iter()
        .find(|class| super::super::classify::is_cross_run(**class))
        .unwrap();
    for bad in [
        serde_json::json!({"patterns": {"NOT_A_CLASS": ["x"]}}),
        serde_json::json!({"exit_codes": {"violation": ["3"]}}),
        // A rule names a finding in the guest, never an outcome of patina's.
        serde_json::json!({"exit_codes": {"internal": [77]}}),
        serde_json::json!({"patterns": {"timeout": ["slow"]}}),
        // No rule over one run's output can say that run would not reproduce.
        serde_json::json!({"patterns": {cross_run.as_str(): ["token"]}}),
    ] {
        let error = json_classify_rules(&bad).expect_err("malformed classify rules are refused");
        assert!(error.to_string().contains("classify"), "{bad}: {error}");
    }
}

/// The bound and the precedence of the scale dial, on the JSON and the flag
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
    let dials: [(&str, &str, &str, Field, u64); 1] = [(
        "net",
        "fault_scale_permille",
        "--fault-scale-permille",
        |spec| spec.fault_scale_permille,
        FAULT_SCALE_FULL,
    )];
    for (switch, key, flag, field, full) in dials {
        fs::write(&path, format!(r#"{{"vary": ["{switch}"], "{key}": 1001}}"#)).expect("write");
        let error = parse(args(&["art", "--spec", &spec_flag]))
            .expect_err("a scale above full intensity must be refused")
            .to_string();
        assert!(error.contains(key), "the refusal must name {key}: {error}");

        fs::write(&path, format!(r#"{{"vary": ["{switch}"], "{key}": 250}}"#)).expect("write");
        let from_spec = parse(args(&["art", "--spec", &spec_flag])).expect("spec parses");
        assert_eq!(field(&from_spec.spec), 250);
        let overridden =
            parse(args(&["art", "--spec", &spec_flag, flag, "10"])).expect("flag parses");
        assert_eq!(field(&overridden.spec), 10);
        let default = parse(args(&["art", "--vary", switch])).expect("parses");
        assert_eq!(field(&default.spec), full);
    }
}

/// `--vary` names what each generation draws, from the flag or the spec file,
/// the flag replacing the spec's list. `faults` is every plane, however the
/// list spells it. An unknown dimension is a usage error that names the valid
/// ones, and so is a plane the campaign could never draw.
#[test]
fn vary_names_what_each_generation_draws() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("spec.json");
    let spec_flag = path.display().to_string();
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let vary = |values: &[&str]| parse(args(values)).expect("parses").spec.vary;

    assert_eq!(vary(&["art"]), Vary::default());
    let every = vary(&["art", "--vary", "faults"]);
    assert_eq!(every.faults, FaultPlanes::ALL);
    assert!(!every.buggify && !every.sched_pct && !every.yield_stride);
    assert_eq!(vary(&["art", "--vary", "net,faults,fs"]), every);
    let net_sleep = vary(&["art", "--vary", "net,sleep"]);
    assert_eq!(net_sleep, vary(&["art", "--vary=sleep,net"]));
    assert!(net_sleep.faults != FaultPlanes::ALL);
    let explored = vary(&["art", "--vary", "buggify,sched-pct,yield-stride"]);
    assert!(explored.buggify && explored.sched_pct && explored.yield_stride);
    assert_eq!(explored.faults, Vary::default().faults);

    fs::write(&path, br#"{"vary": ["sleep", "net"]}"#).expect("write");
    assert_eq!(vary(&["art", "--spec", &spec_flag]), net_sleep);
    assert_eq!(
        vary(&["art", "--spec", &spec_flag, "--vary", "buggify"]),
        vary(&["art", "--vary", "buggify"]),
    );

    let error = refusal(&["art", "--vary", "net,disk"]);
    for name in VARY_NAMES {
        assert!(error.contains(name), "{error}");
    }
    assert!(refusal(&["art", "--vary", "net,dns"]).contains("--dns-entry"));
    assert!(
        parse(args(&[
            "art",
            "--vary",
            "dns",
            "--dns-entry",
            "db=10.0.0.5"
        ]))
        .is_ok()
    );
    // The run flags `--vary` replaced are not campaign flags.
    for gone in ["--buggify", "--faults", "--yield-stride"] {
        assert!(refusal(&["art", gone]).contains(gone));
    }
    assert!(refusal(&["--vary", "net"]).contains("--vary"));
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
        br#"{"vary": ["sleep"], "exclude_knobs": ["--net-reset-permille"]}"#,
    )
    .expect("write");
    assert!(refusal(&["art", "--spec", &spec_flag]).contains("--net-reset-permille"));
    let merged = parse(args(&["art", "--spec", &spec_flag, "--vary", "net"]))
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
    // naming the flag.
    let error = |values: &[&str]| match parse(args(values)) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a usage error for {values:?}"),
    };
    assert!(error(&["--frob"]).contains("--frob"));
    // An unknown flag ahead of the artifact is refused by name.
    let dir = tempfile::tempdir().unwrap();
    let module = dir.path().join("app");
    std::fs::write(&module, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    assert!(error(&["--frob", module.to_str().unwrap()]).contains("--frob"));
}

#[test]
fn allow_unmet_sometimes_parses_flag_and_spec_shapes() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let bare = parse(args(&["art", "--allow-unmet-sometimes"])).unwrap();
    assert!(bare.spec.allow_unmet_sometimes);
    assert!(refusal(&["art", "--allow-unmet-sometimes=10"]).contains("--allow-unmet-sometimes"));

    let mut spec = CampaignSpec::default();
    spec.apply_json(&serde_json::json!({"allow_unmet_sometimes": true}))
        .unwrap();
    assert!(spec.allow_unmet_sometimes);
    for malformed in [serde_json::json!(7), serde_json::json!("yes")] {
        let error = CampaignSpec::default()
            .apply_json(&serde_json::json!({"allow_unmet_sometimes": malformed}))
            .expect_err("a malformed allow_unmet_sometimes is refused");
        assert!(error.to_string().contains("allow_unmet_sometimes"));
    }
}

#[test]
fn a_command_without_an_artifact_continues_and_takes_no_setting() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let to_seven = parse(args(&["--gens", "7", "--out-dir", "d"])).unwrap();
    assert_eq!(to_seven.artifact, None);
    assert_eq!(to_seven.mode, CampaignMode::Continue { gens: Some(7) });
    assert_eq!(to_seven.out_dir, PathBuf::from("d"));
    let as_recorded = parse(args(&["--timeout-secs", "120", "--progress-every", "2"])).unwrap();
    assert_eq!(as_recorded.mode, CampaignMode::Continue { gens: None });
    assert_eq!(as_recorded.timeout_secs_override, Some(120));
    assert_eq!(as_recorded.progress_every, 2);
    // A typed timeout is this invocation's, whichever mode it runs in.
    let fresh = parse(args(&["art", "--timeout-secs", "9"])).unwrap();
    assert_eq!(fresh.mode, CampaignMode::Fresh);
    assert_eq!(fresh.timeout_secs_override, Some(9));
    assert_eq!(fresh.spec.timeout_secs, 9);

    assert!(refusal(&["--", "guest-arg"]).contains("guest arguments"));
    for flag in ["--spec", "--swarm", "--vary", "--seed-start"] {
        let values: Vec<&str> = match flag {
            "--swarm" => vec![flag],
            "--vary" => vec![flag, "net"],
            _ => vec![flag, "1"],
        };
        let message = refusal(&values);
        assert!(message.contains(flag), "{message}");
    }
}

#[test]
fn the_native_invocation_flags_parse_into_the_spec() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let inv = parse(args(&[
        "art",
        "--allow",
        "dlsym",
        "--allow",
        "semaphore_wait",
        "--allow",
        "all",
    ]))
    .unwrap();
    assert_eq!(inv.spec.allow_symbols, ["dlsym", "semaphore_wait", "all"]);
    // They describe the campaign's shape, so a continuation cannot change them.
    for flag in ["--allow=dlsym", "--allow=all"] {
        let error = refusal(&[flag]);
        assert!(
            error.contains(flag.split('=').next().unwrap()),
            "{flag} must be refused on a continuation, got {error}"
        );
    }
}
