//! Argument parsing regression tests.

use super::*;
use crate::native_build::DEFAULT_NATIVE_EDITION;
use crate::tests::{
    invocation, native_build_invocation, native_run, parse_error, strings, wasi_invocation,
};
use crate::{
    ArtifactRef, BuildSpecKind, DEFAULT_NATIVE_FINGERPRINT, ExploreTarget, KnobValues, Mode,
    NativeBuildTarget, NativeRunInvocation, NativeRunMode, manifest_path, minimize, trace_cmd,
    trace_view,
};
use patina_dst_runtime::{ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, FaultKnob};
use patina_dst_wasi_host::{DEFAULT_WASM_FUEL, MountPolicy};
use std::ffi::OsStr;
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
fn parses_bounded_seed_exploration() {
    match parse(strings(&[
        "explore",
        "test",
        "--seeds=3",
        "--seed-start",
        "5",
        "--release",
    ]))
    .unwrap()
    {
        ParseResult::Explore(exploration) => {
            assert_eq!(exploration.start_seed, 5);
            assert_eq!(exploration.seed_count, 3);
            match exploration.target {
                ExploreTarget::Cargo(invocation) => {
                    assert_eq!(invocation.cargo_command, "test");
                    assert_eq!(invocation.cargo_args, strings(&["--release"]));
                }
                _ => panic!("expected a Cargo explore target"),
            }
        }
        _ => panic!("expected exploration"),
    }
    assert!(parse(strings(&["explore", "test", "--seeds", "0"])).is_err());
    assert!(parse(strings(&["explore", "test", "--record", "run.patina"])).is_err());
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

fn trace_invocation(values: &[&str]) -> minimize::TraceMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Trace(invocation)) => invocation,
        _ => panic!("expected trace minimization"),
    }
}

fn scenario_invocation(values: &[&str]) -> minimize::ScenarioMinimize {
    match parse(strings(values)).unwrap() {
        ParseResult::Minimize(minimize::MinimizeInvocation::Scenario(invocation)) => invocation,
        _ => panic!("expected scenario minimization"),
    }
}

#[test]
fn parses_trace_minimization_with_an_external_oracle() {
    let invocation = trace_invocation(&[
        "minimize",
        "failure.patina",
        "--output",
        "small.patina",
        "--timeline",
        "failure",
        "--",
        "./oracle",
        "--exact",
    ]);
    assert_eq!(invocation.trace, PathBuf::from("failure.patina"));
    assert_eq!(invocation.output, PathBuf::from("small.patina"));
    assert_eq!(invocation.timeline.as_deref(), Some("failure"));
    assert!(!invocation.prune);
    assert_eq!(invocation.oracle, strings(&["./oracle", "--exact"]));
    assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
}

#[test]
fn parses_branch_pruning_and_rejects_timeline_combo() {
    let invocation = trace_invocation(&[
        "minimize",
        "failure.patina",
        "--output",
        "small.patina",
        "--prune-branches",
        "--",
        "./oracle",
    ]);
    assert!(invocation.prune);
    assert_eq!(invocation.timeline, None);
    // --prune-branches and --timeline are mutually exclusive.
    assert!(
        parse(strings(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--prune-branches",
            "--timeline",
            "leaf",
            "--",
            "./oracle",
        ]))
        .is_err()
    );
}

#[test]
fn parses_scenario_minimization_with_seed_and_params() {
    let invocation = scenario_invocation(&[
        "minimize",
        "--scenario",
        "--seed",
        "12",
        "--param",
        "zone=a",
        "--seed-budget",
        "16",
        "--",
        "./oracle",
        "--flag",
    ]);
    assert_eq!(invocation.seed, 12);
    assert_eq!(invocation.seed_budget, 16);
    assert_eq!(invocation.params.get("zone").map(String::as_str), Some("a"));
    assert_eq!(invocation.oracle, strings(&["./oracle", "--flag"]));
    // --scenario requires a seed and an oracle after `--`.
    assert!(parse(strings(&["minimize", "--scenario", "--", "./oracle"])).is_err());
    assert!(parse(strings(&["minimize", "--scenario", "--seed", "1"])).is_err());
    // trace-only options are rejected in scenario mode.
    assert!(
        parse(strings(&[
            "minimize",
            "--scenario",
            "--seed",
            "1",
            "--timeline",
            "leaf",
            "--",
            "./oracle",
        ]))
        .is_err()
    );
}

#[test]
fn detects_artifact_family_from_magic() {
    // WebAssembly preamble.
    assert_eq!(
        detect_artifact_family(b"\0asm\x01\0\0\0"),
        Some(ArtifactFamily::Wasm)
    );
    // ELF.
    assert_eq!(
        detect_artifact_family(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
        Some(ArtifactFamily::Native)
    );
    // Mach-O thin (both byte orders) and universal ("fat").
    for magic in [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ] {
        assert_eq!(
            detect_artifact_family(&magic),
            Some(ArtifactFamily::Native),
            "Mach-O magic {magic:02x?} should classify as native"
        );
    }
    // Unrecognized: a Cargo.toml, a too-short buffer, an empty buffer.
    assert_eq!(detect_artifact_family(b"[package]\nname = \"x\"\n"), None);
    assert_eq!(detect_artifact_family(b"\0as"), None);
    assert_eq!(detect_artifact_family(b""), None);
}

#[test]
fn extracts_target_selector() {
    let (target, rest) =
        extract_target(strings(&["src.rs", "--target", "wasi", "--release"])).unwrap();
    assert_eq!(target.as_deref(), Some("wasi"));
    assert_eq!(rest, strings(&["src.rs", "--release"]));

    let (target, rest) = extract_target(strings(&["pkg", "--target=native"])).unwrap();
    assert_eq!(target.as_deref(), Some("native"));
    assert_eq!(rest, strings(&["pkg"]));

    // A `--target` past `--` is a rustc/cargo flag, left in place.
    let (target, rest) = extract_target(strings(&["src.rs", "--", "--target", "x86"])).unwrap();
    assert_eq!(target, None);
    assert_eq!(rest, strings(&["src.rs", "--", "--target", "x86"]));

    assert_eq!(target_family("native").unwrap(), ArtifactFamily::Native);
    assert_eq!(target_family("wasi").unwrap(), ArtifactFamily::Wasm);
    assert!(target_family("riscv").is_err());
}

#[test]
fn classifies_and_resolves_positional_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();

    // A native (ELF) magic file is a built artifact.
    let elf = root.join("bin");
    fs::write(&elf, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
    assert!(matches!(
        classify_arg(elf.as_os_str()).unwrap(),
        ArgKind::Artifact(ArtifactFamily::Native)
    ));
    // A WebAssembly magic file is a built artifact.
    let wasm = root.join("mod.wasm");
    fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
    assert!(matches!(
        classify_arg(wasm.as_os_str()).unwrap(),
        ArgKind::Artifact(ArtifactFamily::Wasm)
    ));
    // A `.rs` source, a package directory, and a Cargo.toml are sources.
    let source = root.join("main.rs");
    fs::write(&source, "fn main() {}").unwrap();
    assert!(matches!(
        classify_arg(source.as_os_str()).unwrap(),
        ArgKind::SourceFile(_)
    ));
    let pkg = root.join("pkg");
    fs::create_dir(&pkg).unwrap();
    fs::write(pkg.join("Cargo.toml"), "[package]").unwrap();
    match classify_arg(pkg.as_os_str()).unwrap() {
        ArgKind::SourcePackage(manifest) => assert_eq!(manifest, pkg.join("Cargo.toml")),
        _ => panic!("expected a source package"),
    }
    assert!(matches!(
        classify_arg(pkg.join("Cargo.toml").as_os_str()).unwrap(),
        ArgKind::SourcePackage(_)
    ));
    // A leading flag and a plain non-source file are neither.
    assert!(matches!(
        classify_arg(OsStr::new("--seed")).unwrap(),
        ArgKind::Other
    ));
    let plain = root.join("notes.txt");
    fs::write(&plain, "hello").unwrap();
    assert!(matches!(
        classify_arg(plain.as_os_str()).unwrap(),
        ArgKind::Other
    ));

    // Resolution: a lone `.rs` builds native; `--target wasi` on a `.rs`
    // errors (native-only); a prebuilt artifact with a mismatched --target
    // errors.
    let (family, artifact) = resolve_positional(source.as_os_str(), None)
        .unwrap()
        .unwrap();
    assert_eq!(family, ArtifactFamily::Native);
    assert!(matches!(artifact, ArtifactRef::Build(_)));
    assert!(resolve_positional(source.as_os_str(), Some("wasi")).is_err());
    assert!(resolve_positional(wasm.as_os_str(), Some("native")).is_err());

    // A package directory resolves to a native build-on-the-fly with no
    // `--target` — the SAME path `audit` uses, so an existing directory is
    // never reinterpreted as guest argv. (Keeping a runtime-linked package on
    // the cargo family is a `run`/`replay` routing decision made upstream via
    // `package_integrates_patina`, not by this pure resolver.) `--target wasi`
    // selects the WASI package build.
    let (family, artifact) = resolve_positional(pkg.as_os_str(), None).unwrap().unwrap();
    assert_eq!(family, ArtifactFamily::Native);
    assert!(matches!(artifact, ArtifactRef::Build(_)));
    let (family, _) = resolve_positional(pkg.as_os_str(), Some("wasi"))
        .unwrap()
        .unwrap();
    assert_eq!(family, ArtifactFamily::Wasm);
    // A leading flag resolves to nothing (the caller's no-artifact path).
    assert!(
        resolve_positional(OsStr::new("--seed"), None)
            .unwrap()
            .is_none()
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
fn source_first_package_selection_threads_into_the_build_spec() {
    // `--package`/`--bin` are extracted from the head (before any `--`) and the
    // rest is passed through; a `--package` in the guest section is untouched.
    let selection = take_package_bin(strings(&[
        "--package",
        "member",
        "--seed",
        "1",
        "--bin",
        "app",
        "--",
        "--package",
        "guest",
    ]))
    .unwrap();
    assert_eq!(selection.package.as_deref(), Some("member"));
    assert_eq!(selection.bin.as_deref(), Some("app"));
    assert_eq!(
        selection.rest,
        strings(&["--seed", "1", "--", "--package", "guest"])
    );

    // Applied to a native package build spec, they select the member/binary.
    let mut artifact = ArtifactRef::Build(Box::new(native_package_spec(
        PathBuf::from("ws"),
        PathBuf::from("ws/Cargo.toml"),
    )));
    apply_package_selection(&mut artifact, Some("member".into()), Some("app".into())).unwrap();
    match &artifact {
        ArtifactRef::Build(spec) => match &spec.kind {
            BuildSpecKind::Native(inv) => match &inv.target {
                NativeBuildTarget::Package { package, bin, .. } => {
                    assert_eq!(package.as_deref(), Some("member"));
                    assert_eq!(bin.as_deref(), Some("app"));
                }
                _ => panic!("expected a package target"),
            },
            _ => panic!("expected a native build"),
        },
        _ => panic!("expected a build spec"),
    }

    // A prebuilt artifact or a single `.rs` source has nothing to select, so a
    // stray selection fails closed rather than being silently ignored; an empty
    // selection is a no-op on any artifact.
    let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
    assert!(apply_package_selection(&mut prebuilt, Some("x".into()), None).is_err());
    assert!(apply_package_selection(&mut prebuilt, None, None).is_ok());
    let mut source = ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs"))));
    assert!(apply_package_selection(&mut source, None, Some("x".into())).is_err());
}

#[test]
fn source_first_release_threads_into_the_build_spec() {
    // `--release` is extracted from the head (before any `--`); the rest passes
    // through, and a `--release` in the guest section stays untouched.
    let (release, rest) =
        take_release(strings(&["--release", "--seed", "1", "--", "--release"])).unwrap();
    assert!(release);
    assert_eq!(rest, strings(&["--seed", "1", "--", "--release"]));

    // Absent, it defaults off; an inline value is rejected (valueless switch).
    let (release, rest) = take_release(strings(&["--seed", "1"])).unwrap();
    assert!(!release);
    assert_eq!(rest, strings(&["--seed", "1"]));
    assert!(take_release(strings(&["--release=yes"])).is_err());

    // Applied to a native source/package build, it flips the release profile;
    // a WASI package build spec flips too.
    for mut artifact in [
        ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs")))),
        ArtifactRef::Build(Box::new(native_package_spec(
            PathBuf::from("ws"),
            PathBuf::from("ws/Cargo.toml"),
        ))),
        ArtifactRef::Build(Box::new(wasi_package_spec(
            PathBuf::from("ws"),
            PathBuf::from("ws/Cargo.toml"),
        ))),
    ] {
        apply_release(&mut artifact, true).unwrap();
        let released = match &artifact {
            ArtifactRef::Build(spec) => match &spec.kind {
                BuildSpecKind::Native(inv) => inv.release,
                BuildSpecKind::Wasi(inv) => inv.release,
            },
            _ => panic!("expected a build spec"),
        };
        assert!(
            released,
            "release profile did not thread into the build spec"
        );
    }

    // An already-built artifact carries no build profile, so `--release` on a
    // prebuilt positional fails closed rather than being silently ignored; a
    // false (absent) release is a no-op on any artifact.
    let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
    assert!(apply_release(&mut prebuilt, true).is_err());
    assert!(apply_release(&mut prebuilt, false).is_ok());
}

#[test]
fn parses_wasi_run_record_and_branch_modes() {
    let invocation = parse_wasi_run(strings(&[
        "module.wasm",
        "--seed",
        "7",
        "--record",
        "run.patina",
        "--arg",
        "one",
        "--env",
        "MODE=test",
        "--socket",
        "4=node-a->node-b",
        "--socket",
        "5=node-b->node-a",
        "--preopen",
        "/data:ro",
        "--max-memory-pages",
        "128",
        "--max-descriptors",
        "32",
        "--max-preopens",
        "4",
        "--max-path-bytes",
        "512",
        "--max-io-bytes",
        "4096",
        "--max-iovecs",
        "16",
    ]))
    .unwrap();
    assert_eq!(
        invocation.module,
        ArtifactRef::Prebuilt(PathBuf::from("module.wasm"))
    );
    assert_eq!(invocation.fuel, DEFAULT_WASM_FUEL);
    assert_eq!(invocation.arguments, ["one"]);
    assert_eq!(invocation.environment["MODE"], "test");
    assert_eq!(invocation.sockets.len(), 2);
    assert_eq!(invocation.sockets[0].fd, 4);
    assert_eq!(invocation.preopens.len(), 1);
    assert_eq!(invocation.preopens[0].guest_path, "/data");
    assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadOnly);
    assert_eq!(invocation.resource_limits.max_memory_pages, Some(128));
    assert_eq!(invocation.resource_limits.max_descriptors, Some(32));
    assert_eq!(invocation.resource_limits.max_preopens, Some(4));
    assert_eq!(invocation.resource_limits.max_path_bytes, Some(512));
    assert_eq!(invocation.resource_limits.max_io_bytes, Some(4096));
    assert_eq!(invocation.resource_limits.max_iovecs, Some(16));
    assert_eq!(
        invocation.mode,
        Mode::Record {
            seed: 7,
            path: "run.patina".into()
        }
    );

    // Replaying and branching a WASI trace is the `replay` verb's job now:
    // the trace is a positional and the flags are semantic-free.
    let module = ArtifactRef::Prebuilt(PathBuf::from("module.wasm"));
    let branched = parse_wasi_replay(
        module.clone(),
        "run.patina".into(),
        strings(&[
            "--branch",
            "--from",
            "3",
            "--branch-seed",
            "8",
            "--branch-id",
            "wasi-branch",
        ]),
    )
    .unwrap();
    assert_eq!(
        branched.mode,
        Mode::Branch {
            path: "run.patina".into(),
            parent: "main".into(),
            from_sequence: 3,
            branch_seed: 8,
            branch_id: "wasi-branch".into(),
        }
    );

    // Strict replay of a named timeline, and the recorded host inputs
    // (`--socket`) still re-supplied as genuine host state.
    let replayed = parse_wasi_replay(
        module,
        "run.patina".into(),
        strings(&["--timeline", "wasi-branch", "--socket", "4=node-a->node-b"]),
    )
    .unwrap();
    assert_eq!(
        replayed.mode,
        Mode::Replay {
            path: "run.patina".into(),
            timeline: "wasi-branch".into(),
        }
    );
    assert_eq!(replayed.sockets.len(), 1);
    // A semantic flag on WASI replay is refused: the trace is authoritative.
    assert!(
        parse_wasi_replay(
            ArtifactRef::Prebuilt(PathBuf::from("module.wasm")),
            "run.patina".into(),
            strings(&["--fs-crash-at", "close:1"]),
        )
        .is_err()
    );
}

#[test]
fn parses_wasi_preopen_policy_forms_and_limits() {
    let invocation = wasi_invocation(&[
        "wasi-run",
        "module.wasm",
        "--fuel",
        "99",
        "--preopen",
        "/default",
        "--preopen",
        "/readonly:ro",
        "--preopen",
        "/readwrite:rw",
        "--max-memory-pages",
        "2",
        "--max-descriptors",
        "3",
        "--max-preopens",
        "4",
        "--max-path-bytes",
        "5",
        "--max-io-bytes",
        "6",
        "--max-iovecs",
        "7",
    ]);
    assert_eq!(invocation.fuel, 99);
    assert_eq!(invocation.resource_limits.fuel, Some(99));
    assert_eq!(invocation.preopens.len(), 3);
    assert_eq!(invocation.preopens[0].guest_path, "/default");
    assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadWrite);
    assert_eq!(invocation.preopens[1].guest_path, "/readonly");
    assert_eq!(invocation.preopens[1].policy, MountPolicy::ReadOnly);
    assert_eq!(invocation.preopens[2].guest_path, "/readwrite");
    assert_eq!(invocation.preopens[2].policy, MountPolicy::ReadWrite);
    assert_eq!(invocation.resource_limits.max_memory_pages, Some(2));
    assert_eq!(invocation.resource_limits.max_descriptors, Some(3));
    assert_eq!(invocation.resource_limits.max_preopens, Some(4));
    assert_eq!(invocation.resource_limits.max_path_bytes, Some(5));
    assert_eq!(invocation.resource_limits.max_io_bytes, Some(6));
    assert_eq!(invocation.resource_limits.max_iovecs, Some(7));
}

#[test]
fn rejects_missing_and_duplicate_wasi_option_values() {
    // Value-GRAMMAR rejection is covered generically by
    // `registry_value_grammars_match_the_parsers`; what stays here are the
    // non-grammar shapes: a required-value flag with no value at all, and a
    // repeated non-repeatable flag.
    assert!(parse_wasi_run(strings(&["module.wasm", "--preopen"])).is_err());
    assert!(
        parse_wasi_run(strings(&[
            "module.wasm",
            "--max-iovecs",
            "1",
            "--max-iovecs",
            "2",
        ]))
        .is_err()
    );
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

#[test]
fn parses_manifest_path_for_fingerprinting() {
    assert_eq!(
        manifest_path(&strings(&["--manifest-path", "nested/Cargo.toml"]))
            .unwrap()
            .unwrap(),
        OsStr::new("nested/Cargo.toml")
    );
}

fn is_help(values: &[&str]) -> bool {
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
fn parses_trace_subcommands_and_events_filters() {
    match parse(strings(&[
        "trace",
        "info",
        "--timeline",
        "b1",
        "run.patina",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Info(info)) => {
            assert_eq!(info.path, PathBuf::from("run.patina"));
            assert_eq!(info.timeline, "b1");
        }
        _ => panic!("expected trace info"),
    }

    match parse(strings(&[
        "trace",
        "events",
        "--kind",
        "fs_write,network",
        "--task",
        "main",
        "--task=2",
        "--seq",
        "2..5",
        "--first",
        "3",
        "run.patina",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Events(events)) => {
            assert_eq!(events.path, PathBuf::from("run.patina"));
            assert_eq!(events.timeline, "main");
            assert!(events.filters.op_kinds.contains("fs_write"));
            assert!(
                events
                    .filters
                    .categories
                    .contains(&trace_view::Category::Net)
            );
            assert!(events.filters.tasks.contains(&trace_view::LaneKey::Main));
            assert!(events.filters.tasks.contains(&trace_view::LaneKey::Task(2)));
            assert_eq!(events.filters.seq, Some((2, 5)));
            assert_eq!(events.filters.first, Some(3));
        }
        _ => panic!("expected trace events"),
    }

    assert!(
        parse_error(&["trace", "events", "--kind", "nope", "run.patina"])
            .contains("unknown --kind token")
    );
    assert!(
        parse_error(&[
            "trace",
            "events",
            "--first",
            "1",
            "--last",
            "1",
            "run.patina",
        ])
        .contains("mutually exclusive")
    );
    match parse(strings(&["trace", "stats", "run.patina", "--timeline=b2"])).unwrap() {
        ParseResult::Trace(trace_cmd::TraceInvocation::Stats(stats)) => {
            assert_eq!(stats.path, PathBuf::from("run.patina"));
            assert_eq!(stats.timeline, "b2");
        }
        _ => panic!("expected trace stats"),
    }

    match parse(strings(&[
        "trace",
        "diff",
        "a.patina",
        "--context",
        "0",
        "b.patina",
        "--timeline",
        "main",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Diff(diff)) => {
            assert_eq!(diff.a, PathBuf::from("a.patina"));
            assert_eq!(diff.b, PathBuf::from("b.patina"));
            assert_eq!(diff.context, 0);
            assert_eq!(diff.timeline, "main");
        }
        _ => panic!("expected trace diff"),
    }

    assert!(
        parse_error(&["trace", "info", "--kind", "fs_write", "run.patina"])
            .contains("does not accept --kind")
    );
    assert!(
        parse_error(&["trace", "stats", "--first", "1", "run.patina"])
            .contains("does not accept --first")
    );
    assert!(parse_error(&["trace", "diff", "a.patina"]).contains("second trace"));
}

// ---- Phase 2: renames, uniform value syntax, fail-closed positionals ----

#[test]
fn explore_seed_start_replaces_start() {
    // The new spelling sets the range start.
    match parse(strings(&["explore", "test", "--seed-start=5"])).unwrap() {
        ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 5),
        _ => panic!("expected exploration"),
    }
    // The old `--start` is no longer an explore flag; it forwards to the
    // wrapped command, so the range start falls back to the default (0).
    match parse(strings(&["explore", "test", "--start", "5"])).unwrap() {
        ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 0),
        _ => panic!("expected exploration"),
    }
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
fn wasm_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
    path
}

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
fn build_error(values: &[&str]) -> String {
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

#[test]
fn minimize_locates_the_trace_after_options() {
    // `minimize --output out.patina trace.patina -- oracle`: the trace follows
    // the option, like the other verbs (previously the option was mistaken for
    // the trace path).
    match parse(strings(&[
        "minimize",
        "--output",
        "out.patina",
        "trace.patina",
        "--",
        "oracle",
    ]))
    .unwrap()
    {
        ParseResult::Minimize(minimize::MinimizeInvocation::Trace(trace)) => {
            assert_eq!(trace.trace, PathBuf::from("trace.patina"));
            assert_eq!(trace.output, PathBuf::from("out.patina"));
            assert_eq!(trace.oracle, strings(&["oracle"]));
        }
        _ => panic!("expected a trace minimization"),
    }
}
