//! Argument parsing regression tests.

use super::*;
use crate::tests::strings;
use crate::{ArtifactRef, NativeBuildTarget, NativeRunMode};
use std::ffi::OsStr;
use std::path::PathBuf;

fn is_help(values: &[&str]) -> bool {
    matches!(parse(strings(values)), Ok(ParseResult::Help(_)))
}

#[test]
fn help_and_version_are_intercepted_for_every_verb_and_position() {
    // `-h`/`--help` in the first flag position of every verb and subcommand
    // routes to Help — never consumed as a positional, never an error.
    let is_version = |values: &[&str]| matches!(parse(strings(values)), Ok(ParseResult::Version));
    for verb in [
        "run", "test", "build", "audit", "replay", "campaign", "minimize", "coverage", "syscalls",
        "trace",
    ] {
        assert!(is_help(&[verb, "--help"]), "{verb} --help");
        assert!(is_version(&[verb, "-V"]), "{verb} -V");
    }
    // After a positional (the old bug: `--help` swallowed as an artifact/trace
    // path or an unsupported option).
    assert!(is_help(&["run", "./bin", "--help"]));
    assert!(is_help(&["replay", "./bin", "trace", "--help"]));
    assert!(is_help(&["trace", "events", "trace.patina", "--help"]));
    // Top-level.
    assert!(is_help(&["--help"]));
    assert!(is_version(&["--version"]));
    // After `--` both belong to the guest or oracle and are never intercepted.
    assert!(!is_help(&["run", "./bin", "--", "--help"]));
    assert!(!is_version(&["run", "mycrate", "--", "--version"]));
}

#[test]
fn nonexistent_pathlike_positional_fails_closed() {
    // A positional that does not exist is a hard error.
    for missing in ["missing.rs", "no/such/Cargo.toml"] {
        assert!(classify_arg(OsStr::new(missing)).is_err(), "{missing}");
    }
    // Routed through the verbs.
    assert!(parse(strings(&["run", "./nope"])).is_err());
    // Registered options ahead of it are skipped, so the scan still reaches it.
    assert!(parse(strings(&["run", "--seed", "5", "./nonexistent"])).is_err());
}

// ---- Options may precede the artifact (cargo-run/cargo-build ergonomics) ----

/// A real native binary on disk (recognized by its ELF magic at routing).
fn native_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    path
}

fn native_seed(mode: &NativeRunMode) -> Option<u64> {
    match mode {
        NativeRunMode::Seeded { seed } | NativeRunMode::Record { seed, .. } => Some(*seed),
        NativeRunMode::Replay { .. } => None,
    }
}

/// A recording carries no operator label, so nothing a `run` is given can
/// make its trace need a flag to replay.
#[test]
fn a_recording_takes_no_fingerprint_label() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    assert!(
        parse(strings(&[
            "run",
            b,
            "--record",
            "t.patina",
            "--fingerprint",
            "fp"
        ]))
        .is_err()
    );
    assert!(parse(strings(&["replay", b, "t.patina", "--fingerprint", "fp"])).is_err());
}

#[test]
fn run_and_replay_locate_native_positionals_around_options() {
    let dir = tempfile::tempdir().unwrap();
    let binary = native_fixture(&dir, "app");
    let b = binary.to_str().unwrap();
    let native = |values: &[&str]| match parse(strings(values)).unwrap() {
        ParseResult::NativeRun(inv) => inv,
        _ => panic!("expected a native run"),
    };
    let base = native(&["run", b, "--seed", "5", "--record", "t.patina"]);
    for spelling in [
        &["run", "--seed", "5", "--record", "t.patina", b][..],
        &["run", "--record", "t.patina", b, "--seed", "5"][..],
    ] {
        let got = native(spelling);
        assert_eq!(got.binary, base.binary);
        assert_eq!(native_seed(&got.mode), native_seed(&base.mode));
    }
    // Replay's two positionals keep their binary-then-trace order around options.
    {
        let dir = tempfile::tempdir().unwrap();
        let binary = native_fixture(&dir, "app");
        let b = binary.to_str().unwrap();
        // A flag leads the two positionals; their order (binary then trace) holds.
        match parse(strings(&["replay", "--mount", "corpus", b, "run.patina"])).unwrap() {
            ParseResult::NativeRun(inv) => {
                assert_eq!(inv.binary, ArtifactRef::Prebuilt(PathBuf::from(b)));
                assert_eq!(inv.mount, Some(PathBuf::from("corpus")));
                match inv.mode {
                    NativeRunMode::Replay { path } => {
                        assert_eq!(path, PathBuf::from("run.patina"));
                    }
                    _ => panic!("expected replay mode"),
                }
            }
            _ => panic!("expected a native run from replay"),
        }
    }
}

#[test]
fn run_without_an_artifact_and_test_without_a_package_are_usage_errors() {
    // `run` has no implicit artifact, so a missing one (or one hidden behind
    // an unknown flag) is refused rather than run as something else. `test`
    // takes the working directory's package by default, but two positionals
    // must be a package and a filter, and a `--` tail is libtest's own.
    let dir = tempfile::tempdir().unwrap();
    let module = native_fixture(&dir, "app");
    let m = module.to_str().unwrap();
    let d = dir.path().to_str().unwrap();
    for argv in [
        &["run"][..],
        &["run", "--frob", m],
        &["test", m, "name"],
        &["test", d, "name"],
        &["test", "--frob"],
        &["test", ".", "a", "b"],
        &["test", ".", "--", "--exact"],
        &["test", "--exact"],
        &["test", "--workspace", "-p", "a"],
    ] {
        crate::tests::parse_error(argv);
    }
}

/// The message of a `build` parse that must fail (the parsed invocation is not
/// `Debug`, so `unwrap_err` cannot be used directly).
fn build_error(values: &[&str]) -> String {
    match parse_native_build(strings(values)) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a build usage error for {values:?}"),
    }
}

#[test]
fn build_locates_the_path_after_options_and_names_bad_flags() {
    // `build --release <pkg>`: the path follows the flag, like `cargo build`.
    let inv = parse_native_build(strings(&["--release", "pkg"])).unwrap();
    assert!(inv.release);
    assert!(matches!(inv.target, NativeBuildTarget::Package { .. }));
    // A stray value on the valueless `--release` is a usage error naming the
    // flag, never a bogus `--release=x/Cargo.toml` manifest path.
    let err = build_error(&["--release=x"]);
    assert!(err.contains("--release"), "{err}");
    assert!(err.contains("'x'"), "{err}");
    // An unknown flag is a usage error naming it (not a manifest-path failure).
    assert!(build_error(&["--nonsense"]).contains("--nonsense"));
}
