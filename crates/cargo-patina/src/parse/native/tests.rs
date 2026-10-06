//! Argument parsing regression tests.

use super::*;
use crate::native_build::DEFAULT_NATIVE_EDITION;
use crate::tests::{native_build_invocation, native_run, strings};
use crate::{
    ArtifactRef, DEFAULT_NATIVE_FINGERPRINT, KnobValues, NativeBuildTarget, NativeRunMode,
};
use patina_dst_runtime::{ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, FaultKnob};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn native_run_parses_fault_knobs() {
    let parsed = native_run(&[
        "native-run",
        "bin",
        "--fs-crash-at",
        "close:1",
        "--fs-torn-granularity",
        "byte",
        "--sleep-jitter-nanos",
        "500..1500",
        "--net-jitter-nanos",
        "0..1000",
        "--net-drop-permille",
        "250",
    ]);
    assert_eq!(parsed.knobs.get(FaultKnob::FsCrashAt), ["close:1"]);
    assert_eq!(parsed.knobs.get(FaultKnob::FsTornGranularity), ["byte"]);
    assert_eq!(parsed.knobs.get(FaultKnob::SleepJitterNanos), ["500..1500"]);
    assert_eq!(parsed.knobs.get(FaultKnob::NetJitterNanos), ["0..1000"]);
    assert_eq!(parsed.knobs.get(FaultKnob::NetDropPermille), ["250"]);
}

#[test]
fn native_run_defaults_leave_fault_knobs_off() {
    let parsed = native_run(&["native-run", "bin"]);
    assert_eq!(parsed.knobs, KnobValues::default());
}

#[test]
fn native_run_buggify_value_form_enables_and_carries_permille() {
    // Point pin for the `--buggify=N` native parser/plumbing path; class-level
    // pairing: runtime/trace `+buggify` metadata-coherence fail-closed guard.
    let parsed = native_run(&[
        "native-run",
        "bin",
        "--buggify=372",
        "--buggify-activation-permille=330",
        "--buggify-cutoff-nanos=12345",
        "--buggify-after-setup",
    ]);
    let buggify = parsed.buggify.expect("--buggify must enable SDK buggify");
    assert_eq!(buggify.fire_permille.as_deref(), Some("372"));
    assert_eq!(buggify.activation_permille.as_deref(), Some("330"));
    assert_eq!(buggify.cutoff_nanos.as_deref(), Some("12345"));
    assert!(buggify.after_setup);
    let env = buggify_env_pairs(&buggify);
    assert!(
        env.iter()
            .any(|(name, value)| *name == ENV_BUGGIFY && value == "372")
    );
    assert!(
        env.iter()
            .any(|(name, value)| *name == ENV_BUGGIFY_ACTIVATION && value == "330")
    );
}

#[test]
fn parses_build_wasi_target_and_native_audit() {
    // `build --target wasi <package>` resolves a manifest-scoped package
    // build; a `.rs` source, `--yield-points`, and an unknown target rejected.
    match parse_build(strings(&["pkg", "--target", "wasi", "--release"])).unwrap() {
        ParseResult::WasiBuild(invocation) => {
            assert_eq!(invocation.manifest, PathBuf::from("pkg/Cargo.toml"));
            assert!(invocation.release);
            assert_eq!(invocation.package, None);
            assert_eq!(invocation.bin, None);
            assert_eq!(invocation.output, None);
        }
        _ => panic!("expected a WASI build"),
    }
    assert!(parse_build(strings(&["probe.rs", "--target", "wasi"])).is_err());
    assert!(parse_build(strings(&["pkg", "--target", "wasi", "--yield-points"])).is_err());
    assert!(parse_build(strings(&["pkg", "--target", "riscv"])).is_err());

    // Native audit parsing (routing to it by artifact magic is covered by e2e).
    let audit = parse_native_audit(strings(&[
        "probe",
        "--allow",
        "write",
        "--allow",
        "clock_gettime",
    ]))
    .unwrap();
    assert_eq!(audit.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
    assert!(audit.allow.contains("write"));
    assert!(audit.allow.contains("clock_gettime"));
}

#[test]
fn parses_native_build_with_output_edition_and_forwarded_rustc_args() {
    let invocation = native_build_invocation(&[
        "native-build",
        "probe.rs",
        "--output",
        "probe",
        "--edition",
        "2021",
        "--release",
        "--",
        "-C",
        "opt-level=2",
    ]);
    assert_eq!(invocation.output.as_deref(), Some(Path::new("probe")));
    assert!(invocation.release);
    match invocation.target {
        NativeBuildTarget::Source {
            source,
            edition,
            rustc_args,
        } => {
            assert_eq!(source, PathBuf::from("probe.rs"));
            assert_eq!(edition, "2021");
            assert_eq!(rustc_args, strings(&["-C", "opt-level=2"]));
        }
        NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
    }
    // The default edition applies and --output is required.
    let invocation =
        native_build_invocation(&["native-build", "probe.rs", "--output", "probe", "--"]);
    assert!(!invocation.release);
    match invocation.target {
        NativeBuildTarget::Source {
            edition,
            rustc_args,
            ..
        } => {
            assert_eq!(edition, DEFAULT_NATIVE_EDITION);
            assert!(rustc_args.is_empty());
        }
        NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
    }
    assert!(parse_native_build(strings(&["probe.rs"])).is_err());
    assert!(parse_native_build(strings(&["--output", "probe"])).is_err());
    // Package-only options are rejected for a single source.
    assert!(parse_native_build(strings(&["probe.rs", "--output", "probe", "--bin", "x"])).is_err());
}

#[test]
fn parses_native_build_for_cargo_packages() {
    // A directory and an explicit Cargo.toml both resolve to a manifest path.
    let invocation = native_build_invocation(&[
        "native-build",
        "pkg",
        "--package",
        "demo",
        "--bin",
        "app",
        "--output",
        "out",
        "--release",
    ]);
    assert_eq!(invocation.output.as_deref(), Some(Path::new("out")));
    assert!(invocation.release);
    match invocation.target {
        NativeBuildTarget::Package {
            manifest,
            package,
            bin,
        } => {
            assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
            assert_eq!(package.as_deref(), Some("demo"));
            assert_eq!(bin.as_deref(), Some("app"));
        }
        NativeBuildTarget::Source { .. } => panic!("expected a package target"),
    }

    // --output is optional for packages; a Cargo.toml path is used as-is.
    let invocation = native_build_invocation(&["native-build", "pkg/Cargo.toml"]);
    assert!(invocation.output.is_none());
    match invocation.target {
        NativeBuildTarget::Package {
            manifest,
            package,
            bin,
        } => {
            assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
            assert_eq!(package, None);
            assert_eq!(bin, None);
        }
        NativeBuildTarget::Source { .. } => panic!("expected a package target"),
    }

    // Single-source options are rejected for a package.
    assert!(parse_native_build(strings(&["pkg", "--edition", "2021"])).is_err());
    assert!(parse_native_build(strings(&["pkg", "--", "-C", "opt-level=2"])).is_err());
}

#[test]
fn parses_native_run_modes_and_rejects_conflicts() {
    let seeded = native_run(&[
        "native-run",
        "probe",
        "--seed",
        "9",
        "--env",
        "RUST_LOG=debug",
        "--",
        "one",
    ]);
    assert_eq!(seeded.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
    assert!(matches!(seeded.mode, NativeRunMode::Seeded { seed: 9 }));
    assert_eq!(seeded.program_args, strings(&["one"]));
    assert_eq!(seeded.environment["RUST_LOG"], "debug");
    assert!(parse_native_run(strings(&["probe", "--env", ""])).is_err());

    let covered = native_run(&[
        "native-run",
        "probe",
        "--seed",
        "9",
        "--coverage-out",
        "run.covmap",
    ]);
    assert_eq!(covered.coverage_out, Some(PathBuf::from("run.covmap")));

    let recorded = native_run(&[
        "native-run",
        "probe",
        "--record",
        "run.patina",
        "--seed",
        "5",
        "--fingerprint",
        "native-v1",
    ]);
    match recorded.mode {
        NativeRunMode::Record {
            seed,
            path,
            fingerprint,
        } => {
            assert_eq!(seed, 5);
            assert_eq!(path, PathBuf::from("run.patina"));
            assert_eq!(fingerprint, "native-v1");
        }
        _ => panic!("expected record mode"),
    }
    // `run <BINARY>` has no `--replay` flag: replay is the sole domain of the
    // `replay` subcommand, so the native runner rejects it as an unknown option.
    assert!(parse_native_run(strings(&["probe", "--replay", "run.patina"])).is_err());
    assert!(parse_native_run(Vec::new()).is_err());

    // `replay <bin> <trace>` parses into replay mode, restoring seed/faults/
    // buggify/argv from the trace and defaulting the fingerprint. `replay` is
    // source-first, so the binary is classified by magic: use a real file
    // carrying native (ELF) magic as the prebuilt artifact.
    let directory = tempfile::tempdir().unwrap();
    let probe = directory.path().join("probe");
    fs::write(&probe, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    let probe = probe.to_str().unwrap();
    match parse(strings(&["replay", probe, "run.patina"])).unwrap() {
        ParseResult::NativeRun(invocation) => {
            assert_eq!(
                invocation.binary,
                ArtifactRef::Prebuilt(PathBuf::from(probe))
            );
            match invocation.mode {
                NativeRunMode::Replay { path, fingerprint } => {
                    assert_eq!(path, PathBuf::from("run.patina"));
                    assert_eq!(fingerprint, DEFAULT_NATIVE_FINGERPRINT);
                }
                _ => panic!("expected replay mode"),
            }
        }
        _ => panic!("expected native-run invocation from replay"),
    }
    // `replay` accepts host/build inputs the trace cannot carry ...
    assert!(
        parse(strings(&[
            "replay",
            probe,
            "run.patina",
            "--fingerprint",
            "fp"
        ]))
        .is_ok()
    );
    assert!(
        parse(strings(&[
            "replay",
            probe,
            "run.patina",
            "--mount",
            "corpus"
        ]))
        .is_ok()
    );
    match parse(strings(&[
        "replay",
        probe,
        "run.patina",
        "--coverage-out",
        "replay.covmap",
    ]))
    .unwrap()
    {
        ParseResult::NativeRun(invocation) => {
            assert_eq!(
                invocation.coverage_out,
                Some(PathBuf::from("replay.covmap"))
            );
        }
        _ => panic!("expected native replay invocation"),
    }
    // ... but rejects semantic knobs (the trace is authoritative) and a
    // missing trace path.
    assert!(
        parse(strings(&[
            "replay",
            probe,
            "run.patina",
            "--net-latency-nanos",
            "5"
        ]))
        .is_err()
    );
    assert!(parse(strings(&["replay", probe, "run.patina", "--seed", "1"])).is_err());
    assert!(
        parse(strings(&[
            "replay",
            probe,
            "run.patina",
            "--env",
            "RUST_LOG=trace"
        ]))
        .is_err()
    );
    assert!(parse(strings(&["replay", probe])).is_err());
}
