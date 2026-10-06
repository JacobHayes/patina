//! Argument parsing regression tests.

use super::*;
use crate::tests::{invocation, parse_error, strings};
use crate::{
    ArtifactRef, ExploreTarget, Mode, NativeBuildTarget, NativeRunInvocation, NativeRunMode,
    manifest_path,
};
use patina_dst_runtime::FaultKnob;
use std::ffi::OsStr;
use std::path::PathBuf;

#[test]
fn strips_cargo_plugin_name_and_forwards_unknown_arguments() {
    let parsed = invocation(&[
        "patina",
        "run",
        "--seed",
        "42",
        "--budget",
        "100",
        "--param",
        "zone=a",
        "--release",
        "--example=demo",
    ]);
    assert_eq!(parsed.cargo_command, "run");
    assert_eq!(parsed.mode, Mode::Seeded { seed: 42 });
    assert_eq!(parsed.step_budget, Some(100));
    assert_eq!(parsed.params.get("zone").map(String::as_str), Some("a"));
    assert_eq!(parsed.cargo_args, strings(&["--release", "--example=demo"]));
}

#[test]
fn does_not_consume_program_arguments_after_separator() {
    let parsed = invocation(&["run", "--seed=1", "--", "--seed", "application"]);
    assert_eq!(parsed.mode, Mode::Seeded { seed: 1 });
    assert_eq!(parsed.cargo_args, strings(&["--", "--seed", "application"]));
}

#[test]
fn parses_record_and_replay_and_rejects_conflicts() {
    assert_eq!(
        invocation(&["test", "--record", "run.patina"]).mode,
        Mode::Record {
            seed: 0,
            path: "run.patina".into()
        }
    );
    // Replaying a Cargo-family recording is the `replay` verb's job. The `.`
    // package positional routes to the Cargo family (the crate directory the
    // test runs in) and the trace positional replaces the old `--replay` PATH.
    let replayed = invocation(&["replay", ".", "run.patina"]);
    assert_eq!(
        replayed.mode,
        Mode::Replay {
            path: "run.patina".into(),
            timeline: "main".into(),
        }
    );
    // A recording is produced by `run`, so replay reproduces the `run`
    // program under the runtime; its package directory is threaded through.
    assert_eq!(replayed.cargo_command, "run");
    assert!(replayed.working_dir.is_some());
    assert_eq!(
        invocation(&[
            "replay",
            ".",
            "run.patina",
            "--branch",
            "--from",
            "4",
            "--branch-seed",
            "99",
            "--branch-id",
            "branch-99",
            "--parent",
            "main",
        ])
        .mode,
        Mode::Branch {
            path: "run.patina".into(),
            parent: "main".into(),
            from_sequence: 4,
            branch_seed: 99,
            branch_id: "branch-99".into(),
        }
    );
    // `--timeline` selects a timeline to replay and cannot combine with the
    // branch controls; branch controls without `--branch` are also rejected.
    assert!(
        parse(strings(&[
            "replay",
            ".",
            "run.patina",
            "--branch",
            "--from",
            "1",
            "--branch-seed",
            "2",
            "--branch-id",
            "b",
            "--timeline",
            "x",
        ]))
        .is_err()
    );
    assert!(parse(strings(&["replay", ".", "run.patina", "--from", "1"])).is_err());
    // `run`/`test` no longer parse the replay/branch flags: an unknown flag is
    // forwarded to Cargo, leaving the Patina mode plainly seeded.
    assert_eq!(
        invocation(&["test", "--seed", "1"]).mode,
        Mode::Seeded { seed: 1 }
    );
}

#[test]
fn cargo_family_parses_fault_knobs_and_explore_run_wasi() {
    // The Cargo family accepts the seed-driven fault knobs on run/test.
    let parsed = invocation(&[
        "run",
        "--fs-crash-at",
        "close:2",
        "--net-drop-permille",
        "300",
        "--",
        "app-arg",
    ]);
    assert_eq!(parsed.knobs.get(FaultKnob::FsCrashAt), ["close:2"]);
    assert_eq!(parsed.knobs.get(FaultKnob::NetDropPermille), ["300"]);
    // The `--` tail is forwarded to Cargo, unaffected by fault parsing.
    assert_eq!(parsed.cargo_args, strings(&["--", "app-arg"]));

    // `explore run <MODULE.wasm>` sweeps the WASI family (build once, run the
    // same artifact across seeds). The module is recognized by magic bytes at
    // execution; here a real `.wasm` file exercises the routing.
    let directory = tempfile::tempdir().unwrap();
    let module = directory.path().join("m.wasm");
    std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
    match parse(strings(&[
        "explore",
        "run",
        module.to_str().unwrap(),
        "--seeds",
        "4",
        "--seed-start",
        "2",
    ]))
    .unwrap()
    {
        ParseResult::Explore(exploration) => {
            assert_eq!(exploration.start_seed, 2);
            assert_eq!(exploration.seed_count, 4);
            assert!(matches!(exploration.target, ExploreTarget::Wasi(_)));
        }
        _ => panic!("expected a WASI exploration"),
    }
}

#[test]
fn parses_manifest_path_for_fingerprinting() {
    assert_eq!(
        manifest_path(&strings(&["--manifest-path", "nested/Cargo.toml"]))
            .unwrap()
            .unwrap(),
        OsStr::new("nested/Cargo.toml")
    );
}

pub(super) fn is_help(values: &[&str]) -> bool {
    matches!(parse(strings(values)), Ok(ParseResult::Help(_)))
}

#[test]
fn help_is_intercepted_for_every_verb_and_position() {
    // `-h`/`--help` in the first flag position of every verb and subcommand
    // routes to Help — never consumed as a positional, never an error.
    for verb in [
        "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize", "coverage",
        "sites", "syscalls", "trace",
    ] {
        assert!(is_help(&[verb, "--help"]), "{verb} --help");
        assert!(is_help(&[verb, "-h"]), "{verb} -h");
    }
    // Explore/trace subcommands.
    assert!(is_help(&["explore", "run", "--help"]));
    assert!(is_help(&["explore", "test", "--help"]));
    assert!(is_help(&["trace", "info", "--help"]));
    assert!(is_help(&["trace", "events", "--help"]));
    // After a positional (the old bug: `--help` swallowed as an artifact/trace
    // path or an unsupported option).
    assert!(is_help(&["run", "./bin", "--help"]));
    assert!(is_help(&["campaign", "artifact", "--help"]));
    assert!(is_help(&["replay", "a.wasm", "trace", "--help"]));
    assert!(is_help(&["audit", "artifact", "--help"]));
    assert!(is_help(&["build", "src.rs", "--help"]));
    assert!(is_help(&["minimize", "trace.patina", "--help"]));
    assert!(is_help(&["explore", "run", "artifact", "--help"]));
    assert!(is_help(&["trace", "events", "trace.patina", "--help"]));
    // Top-level.
    assert!(is_help(&["--help"]));
    assert!(is_help(&["-h"]));
    assert!(is_help(&["patina", "--help"]));
}

#[test]
fn help_after_double_dash_belongs_to_the_guest() {
    // A `--help` after the `--` separator is the guest's/oracle's, never
    // intercepted as Patina help.
    assert!(!is_help(&["run", "mod.wasm", "--", "--help"]));
    assert!(!is_help(&["campaign", "artifact", "--", "--help"]));
    assert!(!is_help(&["test", "--", "--help"]));
}

#[test]
fn inline_arg_passes_a_literal_help_token() {
    // `--arg=--help` delivers a literal `--help` to the WASI guest argv; the
    // inline form is the only way, since a bare `--help` before `--` is
    // intercepted as Patina help (see `help_is_intercepted_for_every_verb`).
    let inv = parse_wasi_run(strings(&["m.wasm", "--arg=--help", "--arg", "tail"])).unwrap();
    assert_eq!(
        inv.arguments,
        vec!["--help".to_string(), "tail".to_string()]
    );
}

#[test]
fn nonexistent_pathlike_positional_fails_closed() {
    // A token that clearly names a file path but does not exist is a hard
    // error, not a silent cargo-family fallthrough.
    assert!(classify_arg(OsStr::new("nonexistent.wasm")).is_err());
    assert!(classify_arg(OsStr::new("missing.rs")).is_err());
    assert!(classify_arg(OsStr::new("sub/dir/thing")).is_err());
    assert!(classify_arg(OsStr::new("no/such/Cargo.toml")).is_err());
    // A bare name (no extension, no separator) stays a cargo argument.
    assert!(matches!(
        classify_arg(OsStr::new("mycrate")).unwrap(),
        ArgKind::Other
    ));
    // Routed through the verbs.
    assert!(parse(strings(&["run", "nope.wasm"])).is_err());
    assert!(parse(strings(&["audit", "nope.wasm"])).is_err());
    assert!(parse(strings(&["replay", "nope.wasm", "trace"])).is_err());
}

#[test]
fn version_intercepted_across_verbs_before_separator() {
    for verb in [
        "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize", "coverage",
        "sites", "syscalls", "trace",
    ] {
        assert!(
            matches!(
                parse(strings(&[verb, "--version"])),
                Ok(ParseResult::Version)
            ),
            "{verb} --version"
        );
        assert!(
            matches!(parse(strings(&[verb, "-V"])), Ok(ParseResult::Version)),
            "{verb} -V"
        );
    }
    assert!(matches!(
        parse(strings(&["--version"])),
        Ok(ParseResult::Version)
    ));
    // After `--` it belongs to the guest and is not intercepted.
    assert!(!matches!(
        parse(strings(&["run", "mycrate", "--", "--version"])),
        Ok(ParseResult::Version)
    ));
}

// ---- Options may precede the artifact (cargo-run/cargo-build ergonomics) ----

/// A real WASI module on disk (recognized by its `\0asm` magic at routing).
pub(super) fn wasm_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
    path
}

/// A real native binary on disk (recognized by its ELF magic at routing).
pub(super) fn native_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    path
}

pub(super) fn native_seed(mode: &NativeRunMode) -> Option<u64> {
    match mode {
        NativeRunMode::Seeded { seed } | NativeRunMode::Record { seed, .. } => Some(*seed),
        NativeRunMode::Replay { .. } => None,
    }
}

#[test]
fn run_locates_a_wasi_artifact_around_options() {
    let dir = tempfile::tempdir().unwrap();
    let module = wasm_fixture(&dir, "m.wasm");
    let m = module.to_str().unwrap();
    let wasi = |values: &[&str]| match parse(strings(values)).unwrap() {
        ParseResult::WasiRun(inv) => inv,
        _ => panic!("expected a WASI run"),
    };
    // Baseline: the artifact leads.
    let base = wasi(&["run", m, "--seed", "5", "--fuel", "128"]);
    // Every ordering with the same registered flags parses identically.
    assert_eq!(base, wasi(&["run", "--seed", "5", "--fuel", "128", m])); // both after
    assert_eq!(base, wasi(&["run", "--seed=5", "--fuel=128", m])); // equals form
    assert_eq!(base, wasi(&["run", "--seed", "5", m, "--fuel", "128"])); // interleaved
    // After a valueless registered switch the module + mode + fuel are unchanged
    // (only the buggify field differs).
    let switched = wasi(&[
        "run",
        "--buggify-after-setup",
        "--fuel",
        "128",
        "--seed",
        "5",
        m,
    ]);
    assert_eq!(switched.module, base.module);
    assert_eq!(switched.mode, base.mode);
    assert_eq!(switched.fuel, base.fuel);
}

#[test]
fn run_locates_a_native_artifact_around_options() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    let native = |values: &[&str]| match parse(strings(values)).unwrap() {
        ParseResult::NativeRun(inv) => inv,
        _ => panic!("expected a native run"),
    };
    // `--fingerprint` labels a recording, so it rides with `--record` (a seeded
    // run refuses it; see
    // `fingerprint_on_a_seeded_native_run_is_refused_not_ignored`).
    let base = native(&[
        "run",
        b,
        "--seed",
        "5",
        "--record",
        "t.patina",
        "--fingerprint",
        "fp",
    ]);
    for spelling in [
        &[
            "run",
            "--seed",
            "5",
            "--record",
            "t.patina",
            "--fingerprint",
            "fp",
            b,
        ][..],
        &[
            "run",
            "--seed=5",
            "--record=t.patina",
            "--fingerprint=fp",
            b,
        ][..],
        &[
            "run",
            "--fingerprint",
            "fp",
            b,
            "--seed",
            "5",
            "--record",
            "t.patina",
        ][..],
    ] {
        let got = native(spelling);
        assert_eq!(got.binary, base.binary);
        assert_eq!(native_seed(&got.mode), native_seed(&base.mode));
    }
    // Interleaved artifact between semantic flags, record mode.
    match native(&["run", "--seed", "5", b, "--record", "t.patina"]).mode {
        NativeRunMode::Record { seed, path, .. } => {
            assert_eq!(seed, 5);
            assert_eq!(path, PathBuf::from("t.patina"));
        }
        _ => panic!("expected record mode"),
    }
}

/// `--fingerprint` is only ever read back off a recorded trace: the seeded
/// native path sets no `PATINA_FINGERPRINT` at all, so a label supplied there
/// could never be compared against anything. It is refused instead of quietly
/// discarded, so "I pinned this run to a build" cannot be believed of a run
/// that pinned nothing.
#[test]
fn fingerprint_on_a_seeded_native_run_is_refused_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    let Err(error) = parse(strings(&["run", b, "--seed", "5", "--fingerprint", "fp"])) else {
        panic!("a seeded run must refuse a fingerprint it cannot record");
    };
    let text = format!("{error}");
    assert!(text.contains("--record"), "{text}");

    // With a recording the same label is accepted and carried into the trace.
    match parse(strings(&[
        "run",
        b,
        "--seed",
        "5",
        "--record",
        "t.patina",
        "--fingerprint",
        "fp",
    ]))
    .unwrap()
    {
        ParseResult::NativeRun(inv) => match inv.mode {
            NativeRunMode::Record { fingerprint, .. } => assert_eq!(fingerprint, "fp"),
            _ => panic!("expected record mode"),
        },
        _ => panic!("expected a native run"),
    }

    // A seeded run without the flag is untouched.
    assert!(matches!(
        parse(strings(&["run", b, "--seed", "5"])).unwrap(),
        ParseResult::NativeRun(NativeRunInvocation {
            mode: NativeRunMode::Seeded { seed: 5 },
            ..
        })
    ));
}

#[test]
fn audit_locates_a_native_artifact_around_options() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    let audit = |values: &[&str]| match parse(strings(values)).unwrap() {
        ParseResult::NativeAudit(inv) => inv,
        _ => panic!("expected a native audit"),
    };
    let base = audit(&["audit", b, "--allow", "foo"]);
    for spelling in [
        &["audit", "--allow", "foo", b][..], // `audit --allow foo ./bin`
        &["audit", "--allow=foo", b][..],
    ] {
        let got = audit(spelling);
        assert_eq!(got.binary, base.binary);
        assert_eq!(got.allow, base.allow);
        assert_eq!(got.raw, base.raw);
    }
}

#[test]
fn replay_locates_two_positionals_around_options_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    // A flag leads the two positionals; their order (binary then trace) holds.
    match parse(strings(&["replay", "--fingerprint", "f", b, "run.patina"])).unwrap() {
        ParseResult::NativeRun(inv) => {
            assert_eq!(inv.binary, ArtifactRef::Prebuilt(PathBuf::from(b)));
            match inv.mode {
                NativeRunMode::Replay { path, fingerprint } => {
                    assert_eq!(path, PathBuf::from("run.patina"));
                    assert_eq!(fingerprint, "f");
                }
                _ => panic!("expected replay mode"),
            }
        }
        _ => panic!("expected a native run from replay"),
    }
    // Interleaved keeps binary-then-trace order.
    match parse(strings(&["replay", b, "--fingerprint", "f", "run.patina"])).unwrap() {
        ParseResult::NativeRun(inv) => {
            assert_eq!(inv.binary, ArtifactRef::Prebuilt(PathBuf::from(b)));
            assert!(matches!(inv.mode, NativeRunMode::Replay { .. }));
        }
        _ => panic!("expected a native run"),
    }
}

#[test]
fn conservative_stop_keeps_unknown_flag_runs_in_the_cargo_family() {
    // `--bin` is registered (source-first selection), so its value `server` is
    // skipped by the scan: no artifact, Cargo family.
    assert!(matches!(
        parse(strings(&["run", "--bin", "server"])).unwrap(),
        ParseResult::Run(_)
    ));
    assert!(matches!(
        parse(strings(&["run", "--seed", "5", "--bin", "server"])).unwrap(),
        ParseResult::Run(_)
    ));
    // An UNKNOWN flag stops the scan; `thing.wasm` after it is path-like but does
    // NOT exist, so it is presumed the unknown flag's value (never an artifact)
    // and the run stays the Cargo family.
    assert!(matches!(
        parse(strings(&[
            "run",
            "--seed",
            "5",
            "--some-unknown",
            "thing.wasm"
        ]))
        .unwrap(),
        ParseResult::Run(_)
    ));
    // A forwarded cargo flag with a (nonexistent) manifest value, no artifact
    // token present: the whole list forwards to Cargo.
    assert!(matches!(
        parse(strings(&["run", "--manifest-path", "./x/Cargo.toml"])).unwrap(),
        ParseResult::Run(_)
    ));
    // `--release` is not a `run` flag; with no artifact it is a forwarded cargo
    // flag (like `cargo run --release`), and the run stays the Cargo family.
    match parse(strings(&["run", "--release", "--seed", "5"])).unwrap() {
        ParseResult::Run(inv) => {
            assert_eq!(inv.mode, Mode::Seeded { seed: 5 });
            assert!(inv.cargo_args.iter().any(|a| a == "--release"));
        }
        _ => panic!("expected a Cargo-family run"),
    }
}

#[test]
fn run_fails_closed_on_a_nonexistent_artifact_after_leading_options() {
    // The motivating fix: `--seed 5` is registered and skipped, so the scan
    // reaches `nonexistent.wasm` — a path-like token that does not exist — and
    // fails closed rather than falling through to a confusing `cargo run`.
    let err = parse_error(&["run", "--seed", "5", "nonexistent.wasm"]);
    assert!(err.contains("no such file"), "{err}");
}

#[test]
fn run_rejects_a_real_artifact_stranded_behind_an_unknown_flag() {
    let dir = tempfile::tempdir().unwrap();
    let module = wasm_fixture(&dir, "app.wasm");
    let m = module.to_str().unwrap();
    // `--frob` is unknown and `app.wasm` is a real compiled artifact (never a
    // flag value): a loud routing error naming both, never a silent Cargo
    // fallthrough.
    let message = parse_error(&["run", "--frob", m]);
    assert!(message.contains("--frob"), "{message}");
    assert!(message.contains(m), "{message}");
}

#[test]
fn artifact_scan_never_crosses_the_double_dash_separator() {
    // Everything after `--` is the guest/cargo tail; an artifact-looking token
    // there is never scanned as the artifact, so no fail-closed "no such file".
    match parse(strings(&["run", "--seed", "5", "--", "nonexistent.wasm"])).unwrap() {
        ParseResult::Run(inv) => {
            assert_eq!(inv.cargo_args, strings(&["--", "nonexistent.wasm"]));
        }
        _ => panic!("expected a Cargo-family run"),
    }
}

/// The message of a `build` parse that must fail (parse_build's `Ok` variant
/// is not `Debug`, so `unwrap_err` cannot be used directly).
pub(super) fn build_error(values: &[&str]) -> String {
    match parse_build(strings(values)) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a build usage error for {values:?}"),
    }
}

#[test]
fn build_locates_the_path_after_options_and_names_bad_flags() {
    // `build --release <pkg>`: the path follows the flag, like `cargo build`.
    match parse_build(strings(&["--release", "pkg"])).unwrap() {
        ParseResult::NativeBuild(inv) => {
            assert!(inv.release);
            assert!(matches!(inv.target, NativeBuildTarget::Package { .. }));
        }
        _ => panic!("expected a native build"),
    }
    // A stray value on the valueless `--release` is a usage error naming the
    // flag, never a bogus `--release=x/Cargo.toml` manifest path.
    let err = build_error(&["--release=x"]);
    assert!(err.contains("--release"), "{err}");
    assert!(err.contains("'x'"), "{err}");
    // An unknown flag is a usage error naming it (not a manifest-path failure).
    assert!(build_error(&["--nonsense"]).contains("--nonsense"));
}
