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

#[test]
fn run_and_replay_locate_native_positionals_around_options() {
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
    // Replay's two positionals keep their binary-then-trace order around options.
    {
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
    }
}

/// `--fingerprint` is only ever read back off a recorded trace: the seeded
/// native path sets no `PATINA_RT_FINGERPRINT` at all, so a label supplied there
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
    assert!(format!("{error}").contains("--record"));

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
}

#[test]
fn run_and_test_without_an_artifact_are_usage_errors() {
    // There is no implicit current package: every form names its artifact or
    // package, so a missing one (or one hidden behind an unknown flag) is
    // refused rather than run as something else.
    let dir = tempfile::tempdir().unwrap();
    let module = native_fixture(&dir, "app");
    let m = module.to_str().unwrap();
    for argv in [
        &["run"][..],
        &["run", "--frob", m],
        &["test", "--seed", "1"],
        &["test", m],
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
