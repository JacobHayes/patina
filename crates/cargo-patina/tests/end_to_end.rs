use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Mutex;

use tempfile::tempdir;

/// Serializes cargo-patina invocations that compile through cargo/rustc. Under
/// default parallel test threads, concurrent builds race on the shared workspace
/// `target/` (cold `patina-dst-native-shim` staticlib builds, cached artifacts) and
/// the global cargo package-cache lock, which surfaces as "Blocking waiting for
/// file lock" stalls or signal-killed cargo processes — a flake where every test
/// passes in isolation and serially. Holding this lock for the duration of a
/// compiling invocation means no two test threads build at once, while
/// executing an already-built artifact (see [`command_compiles`]) stays parallel.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

/// Whether a cargo-patina invocation will compile through cargo/rustc, and so
/// must hold [`BUILD_LOCK`]. `build`/`test`/`explore` always compile.
/// `run`/`replay`/`audit` compile unless handed an already-built artifact file
/// (recognized by wasm/native magic bytes, exactly as the CLI infers the family)
/// — those only execute or inspect it and stay parallel. `minimize` runs an
/// external oracle whose builds reuse the fixture already compiled by the (locked)
/// record step, so it needs no lock here; everything else (`help`, `--version`,
/// usage errors) never compiles.
fn command_compiles(arguments: &[&str]) -> bool {
    match arguments.first().copied() {
        Some("build") | Some("test") | Some("explore") => true,
        Some("run") | Some("replay") | Some("audit") => {
            !arguments[1..].iter().any(|arg| arg_is_built_artifact(arg))
        }
        _ => false,
    }
}

/// Whether `arg` names an existing file whose leading magic bytes mark it as an
/// already-built artifact (a WebAssembly module or a native Mach-O/ELF image),
/// mirroring the CLI's own `detect_artifact_family`. A run/replay/audit handed
/// such a file executes or inspects it without compiling.
fn arg_is_built_artifact(arg: &str) -> bool {
    let Ok(mut file) = fs::File::open(arg) else {
        return false;
    };
    let mut prefix = [0u8; 4];
    let Ok(read) = file.read(&mut prefix) else {
        return false;
    };
    let prefix = &prefix[..read];
    prefix.starts_with(b"\0asm")
        || prefix.starts_with(&[0x7f, b'E', b'L', b'F'])
        || matches!(
            prefix,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        )
}

#[test]
fn wasi_run_preopen_policy_controls_write_access() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("preopen-write.wasm");
    fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open
                        (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
                        (result i32)))
                (import "wasi_snapshot_preview1" "fd_close"
                    (func $fd_close (param i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit"
                    (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "out")
                (func (export "_start")
                    (local $errno i32)
                    (local.set $errno
                        (call $path_open
                            (i32.const 3)   ;; preopened directory fd
                            (i32.const 0)   ;; lookup flags
                            (i32.const 0)   ;; path pointer
                            (i32.const 3)   ;; path length
                            (i32.const 1)   ;; oflags: create
                            (i64.const 66)  ;; rights: fd_read | fd_write
                            (i64.const 0)   ;; inheriting rights
                            (i32.const 0)   ;; fdflags
                            (i32.const 16))) ;; result fd pointer
                    (if (i32.ne (local.get $errno) (i32.const 0))
                        (then (call $proc_exit (local.get $errno))))
                    (drop (call $fd_close (i32.load (i32.const 16))))))"#,
        )
        .unwrap(),
    )
    .unwrap();

    let rw = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module.to_str().unwrap(), "--preopen", "/rw:rw"],
    );
    assert!(
        rw.status.success(),
        "rw preopen failed with {}\nstdout:\n{}\nstderr:\n{}",
        rw.status,
        String::from_utf8_lossy(&rw.stdout),
        String::from_utf8_lossy(&rw.stderr)
    );

    let ro = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module.to_str().unwrap(), "--preopen", "/ro:ro"],
    );
    assert_eq!(ro.status.code(), Some(69));
}

// A WASI record→`replay` round-trip: the `replay` verb restores the recorded
// guest argv (the `--arg` values) and fault configuration from the trace, so a
// replay is flag-free and byte-identical. A re-supplied `--arg` must match the
// recording or the replay is refused up front, naming both.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn wasi_replay_restores_guest_argv_and_faults_flag_free() {
    let directory = tempdir().unwrap();
    let cwd = directory.path();
    // `_start` reads the argument count and exits with it, so the process exit
    // code is a pure function of the guest argv — a compact, observable proxy for
    // "the argv reached the guest".
    let module = directory.path().join("argc.wasm");
    fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "args_sizes_get"
                    (func $args_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (drop (call $args_sizes_get (i32.const 0) (i32.const 8)))
                    (call $proc_exit (i32.load (i32.const 0)))))"#,
        )
        .unwrap(),
    )
    .unwrap();

    let trace = directory.path().join("argc.patina");
    // Record with two guest arguments and a fault knob that this guest never
    // triggers (no filesystem ops): both are captured into the trace metadata.
    let recorded = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        cwd,
        &[
            "run",
            module.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fs-crash-at",
            "close:1",
            "--arg",
            "alpha",
            "--arg",
            "beta",
        ],
    );
    let recorded_code = recorded.status.code();
    assert!(
        matches!(recorded_code, Some(code) if code > 0),
        "expected a positive argc exit code, got {recorded_code:?}\nstderr:\n{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    // Flag-free replay: neither `--arg` nor `--fs-crash-at` is re-passed, yet the
    // run reproduces byte-identically because the trace is authoritative.
    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        cwd,
        &["replay", module.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        replayed.status.code(),
        recorded_code,
        "flag-free WASI replay diverged\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stderr)
    );

    // A re-supplied `--arg` matching the recording is accepted.
    let matching = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        cwd,
        &[
            "replay",
            module.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--arg",
            "alpha",
            "--arg",
            "beta",
        ],
    );
    assert_eq!(matching.status.code(), recorded_code);

    // A conflicting `--arg` is refused up front, naming the conflict.
    let conflict = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        cwd,
        &[
            "replay",
            module.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--arg",
            "gamma",
        ],
    );
    assert!(!conflict.status.success());
    let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
    assert!(
        conflict_stderr.contains("conflict") && conflict_stderr.contains("authoritative"),
        "missing argv-conflict diagnostic:\n{conflict_stderr}"
    );
}

#[test]
fn separate_processes_repeat_record_and_replay() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("fixture");
    create_fixture(&fixture);

    let first = invoke(&fixture, &["run", "--seed", "123"]);
    let repeated = invoke(&fixture, &["run", "--seed", "123"]);
    let different = invoke(&fixture, &["run", "--seed", "124"]);
    let first_result = result_line(&first);
    assert_eq!(result_line(&repeated), first_result);
    assert!(first_result.contains("cfg=true"));
    assert_ne!(result_line(&different), first_result);
    let parameterized = invoke(&fixture, &["run", "--seed", "123", "--param", "zone=a"]);
    assert!(result_line(&parameterized).contains("zone=Some(\"a\")"));

    let budgeted = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["run", "--seed", "123", "--budget", "1"],
    );
    assert!(!budgeted.status.success());
    assert!(String::from_utf8_lossy(&budgeted.stderr).contains("StepBudgetExceeded"));

    let trace = directory.path().join("run.patina");
    let recorded = invoke(
        &fixture,
        &["run", "--seed", "123", "--record", trace.to_str().unwrap()],
    );
    assert!(trace.is_file());
    // Replaying a recording is the `replay` verb's job now. `.` is the package
    // positional (the fixture is the invocation's working directory), and the
    // trace positional replaces the old `--replay` PATH; the run's semantics are
    // restored from the trace, so replay is flag-free.
    let replayed = invoke(&fixture, &["replay", ".", trace.to_str().unwrap()]);
    assert_eq!(result_line(&recorded), result_line(&replayed));
    assert_eq!(result_line(&replayed), first_result);

    let branched = invoke(
        &fixture,
        &[
            "replay",
            ".",
            trace.to_str().unwrap(),
            "--branch",
            "--from",
            "1",
            "--branch-seed",
            "999",
            "--branch-id",
            "branch-999",
        ],
    );
    assert_ne!(result_line(&branched), first_result);
    let replayed_branch = invoke(
        &fixture,
        &[
            "replay",
            ".",
            trace.to_str().unwrap(),
            "--timeline",
            "branch-999",
        ],
    );
    assert_eq!(result_line(&replayed_branch), result_line(&branched));

    invoke(&fixture, &["test", "--seed", "123"]);

    writeln!(
        OpenOptions::new()
            .append(true)
            .open(fixture.join("src/main.rs"))
            .unwrap(),
        "// changed after recording"
    )
    .unwrap();
    let incompatible = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["replay", ".", trace.to_str().unwrap()],
    );
    assert!(!incompatible.status.success());
    let stderr = String::from_utf8_lossy(&incompatible.stderr);
    assert!(
        stderr.contains("FingerprintMismatch") || stderr.contains("fingerprint mismatch"),
        "missing fingerprint diagnostic in stderr:\n{stderr}"
    );
}

// Whole Cargo-package `native-build`: a package with a path dependency and a
// build script builds under Patina control, passes the strict audit, and
// records/replays byte-identically, while multi-bin ambiguity and an
// off-allowlist binary fail closed. `native-build` builds the `patina-dst-native-shim`
// staticlib from the surrounding Patina workspace, so it runs with the workspace
// as its working directory while the fixture is addressed by absolute path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_build_package_audits_records_and_fails_closed() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("pkg");
    create_package_fixture(directory.path());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    // The clean binary builds through the package's own `cargo build`, with the
    // shim link args isolated to the final binary by the explicit host --target
    // (the build script's file I/O proves it did not leak onto host artifacts).
    let clean = package.join("clean-bin");
    let built = invoke_in(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--bin",
            "patina-native-pkg-fixture",
            "--output",
            clean.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&built.stdout).contains("PATINA_NATIVE_BUILD"),
        "missing build marker:\n{}",
        String::from_utf8_lossy(&built.stdout)
    );
    assert!(clean.is_file());

    // The produced binary passes the same strict audit as a single-source
    // binary, with the shim control-plane symbol allowed per audited binary.
    // Under the host-alias doctrine the trace-fd, baton, and thread-creation
    // vehicles are all resolved at runtime through the `dlsym` primitive, so
    // their names never reach the guest import table — the control plane is the
    // single `dlsym` residue on both platforms (Linux reaches the resolver
    // through `-Wl,--wrap=dlsym`).
    let control_plane: &[&str] = &["dlsym"];
    let mut audit_args = vec!["audit", clean.to_str().unwrap()];
    for symbol in control_plane {
        audit_args.push("--allow");
        audit_args.push(symbol);
    }
    invoke_in(workspace, &audit_args);

    // The package binary runs under native-run with cross-process seed stability,
    // seed variation, and byte-identical record/replay through the supervisor.
    let seeded = package_result(&invoke_in(
        workspace,
        &["run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let repeated = package_result(&invoke_in(
        workspace,
        &["run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let other = package_result(&invoke_in(
        workspace,
        &["run", clean.to_str().unwrap(), "--seed", "6"],
    ));
    assert_eq!(seeded, repeated);
    assert_ne!(seeded, other);
    assert!(
        seeded.contains("built=1"),
        "build-script env missing: {seeded}"
    );
    assert!(
        seeded.contains("stored=hello from greeter"),
        "path dependency output missing: {seeded}"
    );

    let trace = directory.path().join("pkg.patina");
    let recorded = package_result(&invoke_in(
        workspace,
        &[
            "run",
            clean.to_str().unwrap(),
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "native-pkg-v1",
        ],
    ));
    let replayed = package_result(&invoke_in(
        workspace,
        &[
            "replay",
            clean.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "native-pkg-v1",
        ],
    ));
    assert_eq!(recorded, seeded);
    assert_eq!(replayed, seeded);

    // Multiple binary targets with no --bin selection fails with a clear message
    // rather than guessing.
    let ambiguous = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["build", package.to_str().unwrap()],
    );
    assert!(!ambiguous.status.success());
    let ambiguous_stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        ambiguous_stderr.contains("multiple binary targets") && ambiguous_stderr.contains("--bin"),
        "missing ambiguity diagnostic:\n{ambiguous_stderr}"
    );

    // A binary whose build product imports an off-allowlist symbol builds, but
    // fails the audit with the existing category diagnostic.
    let leaky = package.join("leaky-bin");
    invoke_in(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--bin",
            "leaky",
            "--output",
            leaky.to_str().unwrap(),
        ],
    );
    let denied = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", leaky.to_str().unwrap()],
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("process"),
        "missing process-category diagnostic:\n{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

// `run` and `audit` infer the target family from the artifact's leading magic
// bytes, and a capability used on the wrong family is refused up front, naming
// the flag and the target.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_and_audit_infer_target_and_reject_cross_target_flags() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();

    // A hand-written WASI module (magic `\0asm`): `audit` lists its imports and
    // `run` executes it, both inferred from the magic bytes with no `--target`.
    let module = directory.path().join("noop.wasm");
    fs::write(
        &module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    invoke_in(workspace, &["audit", module.to_str().unwrap()]);
    invoke_in(workspace, &["run", module.to_str().unwrap(), "--seed", "1"]);

    // `--allow` is native-only, so auditing a WASI module with it is refused.
    let allow_on_wasm = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "audit",
            module.to_str().unwrap(),
            "--allow",
            "clock_gettime",
        ],
    );
    assert!(!allow_on_wasm.status.success());
    let allow_stderr = String::from_utf8_lossy(&allow_on_wasm.stderr);
    assert!(
        allow_stderr.contains("--allow") && allow_stderr.contains("WASI"),
        "missing --allow-on-wasm diagnostic:\n{allow_stderr}"
    );

    // The filesystem/network fault knobs are now honored on a WASI `run` (they
    // route through the same seeded runtime drivers), so a knob the no-op guest
    // never triggers simply runs clean rather than being refused.
    invoke_in(
        workspace,
        &["run", module.to_str().unwrap(), "--fs-crash-at", "close:1"],
    );

    // `--sleep-jitter-nanos` is now honored on a WASI `run`: the wasip1 host
    // applies the seeded jitter at its single sleep entry (`Preview1Host::
    // sleep_until`, also covering `poll_oneoff` timeouts), so a knob the no-op
    // guest never triggers simply runs clean rather than being refused.
    invoke_in(
        workspace,
        &[
            "run",
            module.to_str().unwrap(),
            "--sleep-jitter-nanos",
            "1..2",
        ],
    );

    // A native binary (Mach-O/ELF magic): `build` (default `--target native`),
    // `audit`, and `run` all infer the native path.
    let source = directory.path().join("noop.rs");
    fs::write(&source, "fn main() { println!(\"NATIVE_OK\"); }").unwrap();
    let bin = directory.path().join("noop-native");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    // The pre-run gate auto-allows the shim control-plane vehicle; a standalone
    // audit names it explicitly. The whole control plane is the single `dlsym`
    // host-alias primitive on both platforms.
    let control_plane: &[&str] = &["dlsym"];
    let mut audit_args = vec!["audit", bin.to_str().unwrap()];
    for symbol in control_plane {
        audit_args.push("--allow");
        audit_args.push(symbol);
    }
    invoke_in(workspace, &audit_args);
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(String::from_utf8_lossy(&ran.stdout).contains("NATIVE_OK"));

    // `build --target wasi` is package-only and thread-free: a `.rs` source and
    // `--yield-points` are both refused before any toolchain work.
    let wasi_single = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["build", source.to_str().unwrap(), "--target", "wasi"],
    );
    assert!(!wasi_single.status.success());
    assert!(String::from_utf8_lossy(&wasi_single.stderr).contains("native-only"));

    let wasi_yield = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["build", "somepkg", "--target", "wasi", "--yield-points"],
    );
    assert!(!wasi_yield.status.success());
    let yield_stderr = String::from_utf8_lossy(&wasi_yield.stderr);
    assert!(
        yield_stderr.contains("--yield-points") && yield_stderr.contains("wasip1"),
        "missing yield-points-on-wasi diagnostic:\n{yield_stderr}"
    );
}

// `build --target wasi` compiles a Cargo package for `wasm32-wasip1`, and the
// resulting module composes with `audit` and `run` inferred from its magic
// bytes. Requires the wasm32-wasip1 target (installed in CI and by the
// validate/smoke scripts' preflight).
#[cfg(any(target_os = "linux", target_os = "macos"))]
// End-to-end coverage for `cargo patina campaign` + the liveness watchdog: build
// the buggify-driven planted-bug guest (`testbeds/liveness-campaign`), sweep it,
// and prove the campaign catches the planted liveness violation, deduplicates the
// signature across the generations that fire it, records a working reproduce
// command, and produces byte-identical outcomes/signatures on a deterministic
// re-run. Native (single-threaded guest), so it does not touch the known
// main-thread TLS-teardown race.
#[test]
fn campaign_catches_planted_liveness_bug_dedups_and_reproduces() {
    let workspace = native_workspace();
    let fixture = workspace.join("testbeds/liveness-campaign");
    let directory = tempdir().unwrap();
    let guest = directory.path().join("liveness-guest");

    // Build the planted-bug guest once; the campaign sweeps this same binary.
    let built = invoke_in(
        workspace,
        &[
            "build",
            fixture.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
            "--release",
        ],
    );
    assert!(
        built.status.success(),
        "building the liveness-campaign guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let out = directory.path().join("camp");
    let campaign_args = |out: &Path| {
        vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            "12".to_string(),
            "--buggify".to_string(),
            "--liveness-watchdog".to_string(),
            "600000000000".to_string(),
            "--out".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let owned1 = campaign_args(&out);
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &owned1.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    // A campaign with failures exits nonzero.
    assert_eq!(
        ran.status.code(),
        Some(1),
        "campaign should report failures (exit 1)\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    // A genuine mix: the planted bug fires on some generations and not others.
    let liveness_gens = stdout.matches("class=LIVENESS").count();
    let ok_gens = stdout.matches("class=OK").count();
    assert!(
        liveness_gens >= 1 && ok_gens >= 1,
        "expected a mix of LIVENESS and OK generations, got liveness={liveness_gens} ok={ok_gens}\n{stdout}"
    );

    // The signature store deduplicates the planted liveness bug into ONE signature
    // whose count equals the number of generations that fired it, and flags it as
    // first seen exactly once (NOVEL appears once).
    assert_eq!(
        stdout.matches("NOVEL").count(),
        1,
        "the single planted bug must produce exactly one NOVEL signature\n{stdout}"
    );
    let store: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("signatures.json")).unwrap()).unwrap();
    let signatures = store["signatures"].as_array().unwrap();
    assert_eq!(
        signatures.len(),
        1,
        "expected exactly one deduplicated signature: {store:#}"
    );
    let signature = &signatures[0];
    assert_eq!(signature["class"], "LIVENESS");
    assert_eq!(
        signature["count"].as_u64().unwrap() as usize,
        liveness_gens,
        "signature count must equal the number of LIVENESS generations"
    );

    // The recorded reproduce command deterministically re-triggers the violation.
    let reproduce = signature["reproduce"].as_str().unwrap();
    let repro_args: Vec<&str> = reproduce
        .strip_prefix("cargo patina ")
        .unwrap()
        .split(' ')
        .collect();
    let reproduced = invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &repro_args);
    assert!(
        !reproduced.status.success()
            && String::from_utf8_lossy(&reproduced.stderr).contains("PATINA_VIOLATION liveness "),
        "reproduce command did not re-trigger the liveness violation: {reproduce}\nstderr:\n{}",
        String::from_utf8_lossy(&reproduced.stderr)
    );

    // Determinism: a re-run with the same spec yields byte-identical per-generation
    // outcomes and an identical signature store.
    let out2 = directory.path().join("camp2");
    let owned2 = campaign_args(&out2);
    let ran2 = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &owned2.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let gen_lines = |text: &str| {
        text.lines()
            .filter(|l| l.starts_with("PATINA_CAMPAIGN_GEN"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        gen_lines(&stdout),
        gen_lines(&String::from_utf8_lossy(&ran2.stdout)),
        "a deterministic re-run must produce identical per-generation outcomes"
    );
    assert_eq!(
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        fs::read_to_string(out2.join("signatures.json")).unwrap(),
        "a deterministic re-run must produce an identical signature store"
    );
}

// The campaign classifier `--selftest` proves every outcome class is reachable
// and the signature store dedups/novelty logic bites — the campaign peer of
// fuzz-sweep's `--selftest`.
#[test]
fn campaign_selftest_passes() {
    let ran = invoke_in(native_workspace(), &["campaign", "--selftest"]);
    assert!(
        ran.status.success(),
        "campaign --selftest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("CAMPAIGN SELFTEST PASSED"),
        "missing pass marker:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );
}

#[test]
fn build_target_wasi_compiles_and_composes_with_audit_and_run() {
    if !wasm32_wasip1_installed() {
        eprintln!(
            "skipping build_target_wasi_compiles_and_composes_with_audit_and_run: \
wasm32-wasip1 target not installed"
        );
        return;
    }
    let directory = tempdir().unwrap();
    let package = directory.path().join("wasi-hello");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"wasi-hello\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"wasi-hello\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        "fn main() { println!(\"WASI_HELLO\"); }\n",
    )
    .unwrap();

    let workspace = native_workspace();
    let built = invoke_in(
        workspace,
        &["build", package.to_str().unwrap(), "--target", "wasi"],
    );
    assert!(
        built.status.success(),
        "build --target wasi failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    let module = package
        .join("target/wasm32-wasip1/debug")
        .join("wasi-hello.wasm");
    assert!(
        module.is_file(),
        "missing wasm artifact at {}",
        module.display()
    );

    // `audit` infers the WASI path from the `\0asm` magic and lists imports.
    invoke_in(workspace, &["audit", module.to_str().unwrap()]);
    // `run` infers the WASI runner and executes `_start` deterministically.
    let ran = invoke_in(workspace, &["run", module.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("WASI_HELLO"),
        "unexpected wasi run output:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

fn wasm32_wasip1_installed() -> bool {
    Command::new("rustc")
        .args(["--print", "target-libdir", "--target", "wasm32-wasip1"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// A hand-written wasip1 module that imports the cooperative-SUT `patina_sdk`
// surface, marks the setup boundary, registers a `reachable!`/`sometimes!`/
// `buggify!` triple, and exits with the buggify firing decision (0/1). With
// `--buggify=1000 --buggify-activation-permille 1000` the site is always active
// and always fires, so the exit code is a deterministic, observable proxy for
// "buggify reached the wasip1 guest and fired".
const WASI_BUGGIFY_MODULE: &str = r#"(module
    (import "patina_sdk" "buggify"
        (func $buggify (param i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "sometimes"
        (func $sometimes (param i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "reachable"
        (func $reachable (param i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "lifecycle_setup_complete" (func $setup (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "commit-fault")
    (data (i32.const 16) "wat:site-a")
    (data (i32.const 32) "even-draw")
    (data (i32.const 48) "wat:site-b")
    (data (i32.const 64) "startup")
    (data (i32.const 80) "wat:site-c")
    (func (export "_start")
        (drop (call $reachable (i32.const 64) (i32.const 7) (i32.const 80) (i32.const 10)))
        (drop (call $setup))
        (drop (call $sometimes (i32.const 1)
            (i32.const 32) (i32.const 9) (i32.const 48) (i32.const 10)))
        (call $proc_exit
            (call $buggify (i32.const 0) (i32.const 12) (i32.const 16) (i32.const 10) (i32.const -1)))))"#;

// The single `PATINA_SDK_REPORT` line from a run's stderr (emitted by the runtime
// at `Context::finish`, which the in-process wasip1 host drives).
fn sdk_report_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("PATINA_SDK_REPORT "))
        .unwrap_or_default()
        .to_string()
}

// Buggify reaches a wasip1 guest through the `patina_sdk` import module: an active
// site fires, the exit code reflects the decision, and the runtime emits a
// parseable `PATINA_SDK_REPORT` to stderr — the same report the campaign layer
// consumes for native runs.
#[test]
fn wasi_buggify_fires_and_reports_on_wasip1() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("buggify.wasm");
    fs::write(&module, wat::parse_str(WASI_BUGGIFY_MODULE).unwrap()).unwrap();

    let fired = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &[
            "run",
            module.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify=1000",
            "--buggify-activation-permille",
            "1000",
        ],
    );
    assert_eq!(
        fired.status.code(),
        Some(1),
        "buggify site should fire (exit 1) under permille=1000\nstderr:\n{}",
        String::from_utf8_lossy(&fired.stderr)
    );
    let report = sdk_report_line(&fired);
    assert!(
        report.contains("enabled=1")
            && report.contains("sites_registered=3")
            && report.contains("total_firings=1"),
        "unexpected PATINA_SDK_REPORT on wasip1:\n{report}"
    );
}

// An `always!` invariant violation on wasip1 emits the `PATINA_ALWAYS_VIOLATION`
// marker to stderr and terminates the run with a nonzero exit — the WASI mirror
// of the native shim's abort.
#[test]
fn wasi_always_violation_traps_with_marker() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("always.wasm");
    fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "patina_sdk" "always"
                    (func $always (param i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "must-hold")
                (data (i32.const 16) "wat:inv")
                (func (export "_start")
                    (drop (call $always (i32.const 0)
                        (i32.const 0) (i32.const 9) (i32.const 16) (i32.const 7)))))"#,
        )
        .unwrap(),
    )
    .unwrap();

    let violated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !violated.status.success(),
        "an always! violation must fail the run"
    );
    assert!(
        String::from_utf8_lossy(&violated.stderr)
            .contains("PATINA_ALWAYS_VIOLATION label=must-hold"),
        "missing ALWAYS_VIOLATION marker:\nstderr:\n{}",
        String::from_utf8_lossy(&violated.stderr)
    );
}

// Reusing a label at a different call site is a fatal error on wasip1 exactly as
// on native: the second registration aborts with `PATINA_BUGGIFY_DUPLICATE_LABEL`.
#[test]
fn wasi_buggify_duplicate_label_aborts() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("dup.wasm");
    fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "patina_sdk" "buggify"
                    (func $buggify (param i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "dup")
                (data (i32.const 16) "wat:one")
                (data (i32.const 32) "wat:two")
                (func (export "_start")
                    (drop (call $buggify (i32.const 0) (i32.const 3)
                        (i32.const 16) (i32.const 7) (i32.const -1)))
                    (drop (call $buggify (i32.const 0) (i32.const 3)
                        (i32.const 32) (i32.const 7) (i32.const -1)))))"#,
        )
        .unwrap(),
    )
    .unwrap();

    let aborted = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module.to_str().unwrap(), "--seed", "1", "--buggify"],
    );
    assert!(!aborted.status.success(), "a duplicate label must fail");
    assert!(
        String::from_utf8_lossy(&aborted.stderr)
            .contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=dup"),
        "missing DUPLICATE_LABEL marker:\nstderr:\n{}",
        String::from_utf8_lossy(&aborted.stderr)
    );
}

// `--buggify-after-setup` declares that the guest calls `setup_complete()`. A
// wasip1 guest that registers a site but never does is a harness bug: the run
// finalizes (reproducible) then fails loudly with
// `PATINA_BUGGIFY_SETUP_NEVER_CALLED`, mirroring the native shim's shutdown gate.
#[test]
fn wasi_buggify_after_setup_gate_fails_when_never_called() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("gated.wasm");
    fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "patina_sdk" "buggify"
                    (func $buggify (param i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "gated")
                (data (i32.const 16) "wat:g")
                (func (export "_start")
                    (drop (call $buggify (i32.const 0) (i32.const 5)
                        (i32.const 16) (i32.const 5) (i32.const -1)))))"#,
        )
        .unwrap(),
    )
    .unwrap();

    let gated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &[
            "run",
            module.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify",
            "--buggify-after-setup",
        ],
    );
    assert!(
        !gated.status.success(),
        "a never-reached setup gate must fail the run"
    );
    assert!(
        String::from_utf8_lossy(&gated.stderr).contains("PATINA_BUGGIFY_SETUP_NEVER_CALLED"),
        "missing SETUP_NEVER_CALLED marker:\nstderr:\n{}",
        String::from_utf8_lossy(&gated.stderr)
    );
}

// A buggify wasip1 run records its configuration into the trace metadata; a
// flag-free `replay` restores it and reproduces the run byte-for-byte (exit code
// and the full `PATINA_SDK_REPORT`). Re-passing `--buggify` on replay is refused —
// the trace is authoritative.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn wasi_buggify_record_replay_is_byte_identical() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("buggify.wasm");
    fs::write(&module, wat::parse_str(WASI_BUGGIFY_MODULE).unwrap()).unwrap();
    let trace = directory.path().join("buggify.patina");

    let recorded = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &[
            "run",
            module.to_str().unwrap(),
            "--seed",
            "9",
            "--buggify=500",
            "--buggify-activation-permille",
            "800",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    assert!(
        recorded.status.code().is_some(),
        "record run did not exit cleanly:\nstderr:\n{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let recorded_report = sdk_report_line(&recorded);
    assert!(
        recorded_report.contains("enabled=1"),
        "record run emitted no buggify report:\n{recorded_report}"
    );

    // Flag-free replay reproduces exit code and the full SDK report.
    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["replay", module.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        replayed.status.code(),
        recorded.status.code(),
        "buggify replay diverged on exit code\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    assert_eq!(
        sdk_report_line(&replayed),
        recorded_report,
        "buggify replay diverged on the SDK report"
    );

    // Re-passing a buggify knob on replay is rejected: the trace is authoritative.
    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &[
            "replay",
            module.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--buggify",
        ],
    );
    assert!(
        !refused.status.success()
            && String::from_utf8_lossy(&refused.stderr).contains("the trace is authoritative"),
        "replay should refuse a re-supplied --buggify:\nstderr:\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

// A distinct seed produces a distinct buggify firing profile on wasip1, so the
// report is genuinely seed-driven rather than fixed.
#[test]
fn wasi_buggify_varies_across_seeds() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("buggify.wasm");
    fs::write(&module, wat::parse_str(WASI_BUGGIFY_MODULE).unwrap()).unwrap();

    let run_seed = |seed: &str| {
        // A moderate firing probability so the single site's decision depends on
        // the seed rather than always firing.
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &[
                "run",
                module.to_str().unwrap(),
                "--seed",
                seed,
                "--buggify=500",
                "--buggify-activation-permille",
                "1000",
            ],
        )
    };
    // Sweep several seeds; the firing decision (exit 0/1) must not be constant.
    let codes: Vec<Option<i32>> = ["1", "2", "3", "4", "5", "6", "7", "8"]
        .iter()
        .map(|seed| run_seed(seed).status.code())
        .collect();
    assert!(
        codes.contains(&Some(1)) && codes.contains(&Some(0)),
        "buggify firing did not vary across seeds: {codes:?}"
    );
}

// Create a Cargo package whose `main` is instrumented with the SDK buggify
// macros and path-depends on the workspace `patina` crate (default features =
// the dependency-light SDK). Compiled plain it is inert with zero `patina_sdk`
// imports; compiled through `cargo patina build --target wasi` its macros lower
// to `patina_sdk` imports the deterministic host backs.
fn create_wasi_buggify_package(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"wasi-buggify-guest\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"wasi-buggify-guest\"\npath = \"src/main.rs\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"fn main() {
    let violate = std::env::args().nth(1).as_deref() == Some("violate");
    patina_dst::reachable!("guest-startup");
    patina_dst::lifecycle::setup_complete();
    let iterations = patina_dst::buggify_knob!("iters", 6, 4, 12);
    let mut digest: u64 = 0;
    for _ in 0..iterations {
        if patina_dst::buggify!("inject") { digest = digest.wrapping_add(1); }
        let r = patina_dst::rng();
        patina_dst::sometimes!(r % 2 == 0, "even-draw");
        digest = digest.wrapping_add(r % 13);
    }
    patina_dst::always!(!violate, "guest-invariant");
    println!("WASI_GUEST_DIGEST digest={digest:016x}");
}
"#,
    )
    .unwrap();
}

// The load-bearing no-leakage + full-stack proof: a plain
// `cargo build --target wasm32-wasip1` of a buggify-instrumented guest grows NO
// `patina_sdk` imports (the macros are inert without `cfg(patina)`), while
// `cargo patina build --target wasi` lowers them to `patina_sdk` imports the
// deterministic host backs — the guest runs, fires, and emits a parseable
// PATINA_SDK_REPORT, record/replay reproduces its digest, and `--arg violate`
// trips the ALWAYS_VIOLATION oracle on wasip1.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn wasi_buggify_full_stack_build_run_and_no_import_leakage() {
    if !wasm32_wasip1_installed() {
        eprintln!(
            "skipping wasi_buggify_full_stack_build_run_and_no_import_leakage: \
wasm32-wasip1 target not installed"
        );
        return;
    }
    let directory = tempdir().unwrap();
    let package = directory.path().join("guest");
    create_wasi_buggify_package(&package);
    let wasm = package
        .join("target/wasm32-wasip1/debug")
        .join("wasi-buggify-guest.wasm");

    // Plain build (no `cfg(patina)`): serialized behind BUILD_LOCK because it
    // compiles, and its output must import no `patina_sdk`.
    {
        let _guard = BUILD_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let built = Command::new("cargo")
            .current_dir(&package)
            .args(["build", "--target", "wasm32-wasip1"])
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "plain wasm build failed:\nstderr:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let bytes = fs::read(&wasm).unwrap();
        assert!(
            !contains_bytes(&bytes, b"patina_sdk"),
            "a plain wasm build must not import the patina_sdk module"
        );
    }

    // Patina build: the same source, now with the SDK lowered to patina_sdk.
    let workspace = native_workspace();
    invoke_in(
        workspace,
        &["build", package.to_str().unwrap(), "--target", "wasi"],
    );
    let patina_bytes = fs::read(&wasm).unwrap();
    assert!(
        contains_bytes(&patina_bytes, b"patina_sdk"),
        "a patina wasi build must import the patina_sdk module"
    );

    // Run with buggify: the guest fires, prints its digest, and the host emits a
    // parseable SDK report to stderr.
    let trace = package.join("guest.patina");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            wasm.to_str().unwrap(),
            "--seed",
            "5",
            "--buggify=1000",
            "--buggify-activation-permille",
            "1000",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    assert!(
        ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("WASI_GUEST_DIGEST"),
        "buggify guest run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        sdk_report_line(&ran).contains("enabled=1"),
        "missing PATINA_SDK_REPORT from wasi guest:\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );

    // Flag-free replay reproduces the guest's digest byte-for-byte.
    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["replay", wasm.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        stdout_line_with(&replayed, "WASI_GUEST_DIGEST"),
        stdout_line_with(&ran, "WASI_GUEST_DIGEST"),
        "wasi buggify replay diverged on the guest digest"
    );

    // `--arg violate` makes the always! invariant false: the host emits the
    // ALWAYS_VIOLATION marker and fails the run on wasip1.
    let violated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            wasm.to_str().unwrap(),
            "--seed",
            "5",
            "--buggify",
            "--arg",
            "violate",
        ],
    );
    assert!(
        !violated.status.success()
            && String::from_utf8_lossy(&violated.stderr)
                .contains("PATINA_ALWAYS_VIOLATION label=guest-invariant"),
        "always! violation not detected on wasip1:\nstderr:\n{}",
        String::from_utf8_lossy(&violated.stderr)
    );
}

// Whether `haystack` contains the byte subsequence `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// The first stdout line containing `needle` (the build-on-the-fly identity note
// and the guest's own output share stdout).
fn stdout_line_with(output: &Output, needle: &str) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains(needle))
        .unwrap_or_default()
        .to_string()
}

// The audit's import lines, excluding the build-on-the-fly identity note.
fn audit_imports(output: &Output) -> Vec<String> {
    let mut imports: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.starts_with("PATINA_"))
        .map(str::to_string)
        .collect();
    imports.sort();
    imports
}

// `run <SOURCE.rs>` builds native on the fly (no prior `build`) and runs the
// product; its output matches an explicit `build` + `run` of the same source,
// and the one-line identity note is printed so an implicit build is never silent.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_builds_native_source_on_the_fly_and_matches_explicit_build() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("greet.rs");
    fs::write(
        &source,
        "fn main() { let a: Vec<String> = std::env::args().skip(1).collect(); \
         println!(\"GREET seed_args={:?}\", a); }",
    )
    .unwrap();

    // Explicit: build to an artifact, then run the artifact.
    let bin = directory.path().join("greet");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let explicit = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--",
            "hi",
            "there",
        ],
    );
    let explicit_line = stdout_line_with(&explicit, "GREET");
    assert!(
        explicit_line.contains("[\"hi\", \"there\"]"),
        "{explicit_line}"
    );

    // Implicit: run the source directly — build-on-the-fly then run.
    let implicit = invoke_in(
        workspace,
        &[
            "run",
            source.to_str().unwrap(),
            "--seed",
            "1",
            "--",
            "hi",
            "there",
        ],
    );
    assert_eq!(stdout_line_with(&implicit, "GREET"), explicit_line);
    let note = stdout_line_with(&implicit, "PATINA_BUILD_ON_RUN");
    assert!(
        note.contains("target=native") && note.contains("sha256="),
        "missing build-on-the-fly identity note:\n{}",
        String::from_utf8_lossy(&implicit.stdout)
    );
}

// `audit` and `replay` are source-first too: auditing a source equals auditing
// the explicitly-built artifact; replaying an unchanged source reproduces the
// recording byte-identically; replaying after a behavior-changing edit fails
// closed (fingerprint or operation mismatch — either is a loud refusal).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn audit_and_replay_are_source_first() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("sf.rs");
    // The guest reads the virtual clock (a recorded boundary decision) so a
    // behavior-changing edit alters the op-stream and replay can fail closed —
    // stdout content alone is captured output, not a replay-checked decision.
    fs::write(
        &source,
        "use std::time::Instant; \
         fn main() { let s = Instant::now(); let _ = s.elapsed(); \
         println!(\"SF_MARKER v1\"); }",
    )
    .unwrap();

    let bin = directory.path().join("sf");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let control_plane: &[&str] = &["dlsym"];
    let mut artifact_args = vec!["audit", bin.to_str().unwrap()];
    let mut source_args = vec!["audit", source.to_str().unwrap()];
    for symbol in control_plane {
        artifact_args.push("--allow");
        artifact_args.push(symbol);
        source_args.push("--allow");
        source_args.push(symbol);
    }
    let artifact_audit = invoke_in(workspace, &artifact_args);
    let source_audit = invoke_in(workspace, &source_args);
    assert_eq!(audit_imports(&artifact_audit), audit_imports(&source_audit));

    // Record from the built artifact, then source-first replay of the UNCHANGED
    // source reproduces the recording byte-identically (rebuilt binary matches).
    let trace = directory.path().join("sf.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "sf-v1",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            source.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "sf-v1",
        ],
    );
    assert_eq!(
        stdout_line_with(&recorded, "SF_MARKER"),
        stdout_line_with(&replayed, "SF_MARKER")
    );

    // A behavior-changing edit that reads the clock more times than the recording
    // — the rebuilt binary's op-stream diverges, so source-first replay must fail
    // closed (operation mismatch / trace exhaustion).
    fs::write(
        &source,
        "use std::time::Instant; \
         fn main() { let s = Instant::now(); let mut acc = 0u128; \
         for _ in 0..8 { acc = acc.wrapping_add(s.elapsed().as_nanos()); } \
         println!(\"SF_MARKER v2 CHANGED acc={acc}\"); }",
    )
    .unwrap();
    let broken = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            source.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "sf-v1",
        ],
    );
    assert!(
        !broken.status.success(),
        "source-first replay of a behavior-changed source must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&broken.stdout),
        String::from_utf8_lossy(&broken.stderr)
    );
}

// Auditing a *prebuilt* native binary that was NOT produced by `cargo patina
// build` fails closed: its imports are unsatisfied libc calls (the surface the
// shim interposes once linked), not the post-interposition residual, so a raw
// listing is the opposite of the truth. The refusal names the source-first form.
// `--raw` overrides the gate and runs the full audit (instruction scan and
// escape categories stay meaningful) under a loud stderr banner. A
// Patina-built binary is unaffected: it defines the shim control-plane marker,
// so it audits normally with no banner. (Source-first equivalence and the WASI
// path are covered by `audit_and_replay_are_source_first` / the WASI audit tests.)
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn audit_prebuilt_non_shim_binary_fails_closed_unless_raw() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();

    // A stock binary built by plain `rustc` — no `cargo patina build`, so the
    // shim staticlib is not linked and `patina_init_from_env` is undefined.
    let source = directory.path().join("stock.rs");
    fs::write(&source, "fn main() { println!(\"STOCK\"); }").unwrap();
    let stock = directory.path().join("stock");
    let compiled = Command::new("rustc")
        .arg(&source)
        .arg("-o")
        .arg(&stock)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "rustc failed to build the stock fixture:\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    // (a) A bare audit of the stock binary is refused, not silently listed.
    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", stock.to_str().unwrap()],
    );
    assert!(
        !refused.status.success(),
        "audit of a non-shim-linked binary must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let refusal = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refusal.contains("not built with `cargo patina build`")
            && refusal.contains("cargo patina audit ./Cargo.toml")
            && refusal.contains("--raw"),
        "refusal must explain the shim-link gap and point to source-first + --raw:\n{refusal}"
    );

    // (b) `--raw` runs the full audit anyway under the loud banner. The stock
    // binary's unsatisfied libc surface is denied, so the audit still fails
    // closed — but now with the real categorized findings, which is what makes
    // `--raw` useful for planted-escape fixtures (instruction scan included).
    let raw = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", stock.to_str().unwrap(), "--raw"],
    );
    assert!(
        !raw.status.success(),
        "--raw audit of a stock binary must still fail closed on its denied imports\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&raw.stdout),
        String::from_utf8_lossy(&raw.stderr)
    );
    let raw_stderr = String::from_utf8_lossy(&raw.stderr);
    assert!(
        raw_stderr.contains("PATINA_RAW_AUDIT"),
        "--raw audit must lead with the raw-audit banner:\n{raw_stderr}"
    );
    assert!(
        raw_stderr.contains("unsupported native imports"),
        "--raw audit must render the real categorized findings:\n{raw_stderr}"
    );

    // (c) A Patina-built binary is unaffected: it defines the shim marker, so a
    // bare audit (control-plane vehicle allowed) succeeds with no banner.
    let shim_source = directory.path().join("shim.rs");
    fs::write(&shim_source, "fn main() { println!(\"SHIM\"); }").unwrap();
    let shim_bin = directory.path().join("shim");
    invoke_in(
        workspace,
        &[
            "build",
            shim_source.to_str().unwrap(),
            "--output",
            shim_bin.to_str().unwrap(),
        ],
    );
    let shim_audit = invoke_in(
        workspace,
        &["audit", shim_bin.to_str().unwrap(), "--allow", "dlsym"],
    );
    assert!(
        !String::from_utf8_lossy(&shim_audit.stdout).contains("PATINA_RAW_AUDIT"),
        "a Patina-built binary must audit without the raw banner:\n{}",
        String::from_utf8_lossy(&shim_audit.stdout)
    );
}

// `run <pkg> --target wasi` builds the package for wasip1 on the fly and runs the
// produced module, inferred by the shared resolution step.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_source_package_target_wasi_on_the_fly() {
    if !wasm32_wasip1_installed() {
        eprintln!(
            "skipping run_source_package_target_wasi_on_the_fly: wasm32-wasip1 not installed"
        );
        return;
    }
    let directory = tempdir().unwrap();
    let package = directory.path().join("wasi-run-pkg");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"wasi-run-pkg\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"wasi-run-pkg\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        "fn main() { println!(\"WASI_ON_THE_FLY\"); }\n",
    )
    .unwrap();

    let workspace = native_workspace();
    let ran = invoke_in(
        workspace,
        &[
            "run",
            package.to_str().unwrap(),
            "--target",
            "wasi",
            "--seed",
            "1",
        ],
    );
    assert!(
        ran.status.success(),
        "run --target wasi on the fly failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(String::from_utf8_lossy(&ran.stdout).contains("WASI_ON_THE_FLY"));
    let note = stdout_line_with(&ran, "PATINA_BUILD_ON_RUN");
    assert!(
        note.contains("target=wasi"),
        "missing wasi identity note:\n{note}"
    );
}

fn invoke(fixture: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), fixture, arguments)
}

fn native_workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

// Two threads communicating over `std::sync::mpsc` with `recv_timeout`: on macOS
// this drives std's Darwin thread `Parker` (`park`/`park_timeout` on a
// libdispatch semaphore), on Linux the futex Parker. The interposed dispatch
// semaphore routes the wait through the deterministic scheduler and virtual
// clock, so both the delivery/timeout interleaving and the timeout count are a
// function of the seed alone — byte-identical across repeated runs and exactly
// reproduced by record/replay — never of host wall-clock timing.
const RECV_TIMEOUT_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let (tx, rx) = mpsc::channel::<u64>();
    let producer = thread::spawn(move || {
        for i in 0..5 {
            thread::sleep(Duration::from_millis(10));
            tx.send(i).unwrap();
        }
    });
    let mut delivered = Vec::new();
    let mut timeouts = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_millis(7)) {
            Ok(v) => delivered.push(v),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timeouts += 1;
                if delivered.len() == 5 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    println!("delivered={:?} timeouts={}", delivered, timeouts);
}
"#;

// Part A: `recv_timeout` across two threads is byte-identical across >=3 runs at
// multiple seeds and exactly reproduced by record/replay. Before the fix the
// Parker blocked a real host thread on a libdispatch semaphore and read host
// time for its timeout, escaping the scheduler entirely.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_recv_timeout_is_deterministic_across_seeds_and_replay() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("recv_timeout.rs");
    fs::write(&source, RECV_TIMEOUT_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("recv-timeout");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    for seed in ["1", "5", "9"] {
        let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            baseline.contains("delivered="),
            "unexpected recv_timeout output at seed {seed}: {baseline}"
        );
        for _ in 0..2 {
            let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "recv_timeout output is not byte-identical across runs at seed {seed}"
            );
        }
    }

    let trace = directory.path().join("recv.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "9",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "recv-timeout",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "recv-timeout",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "record and strict replay diverged"
    );
}

// A guest that reads a file the supervisor mounted into the deterministic
// filesystem. Used to exercise `--mount` composing with `--record`/`replay`,
// which hands the child TWO inherited descriptors at once.
const MOUNT_READER_SOURCE: &str = r#"
use std::fs;

fn main() {
    let contents = fs::read_to_string("/data.txt").expect("read mounted file");
    print!("{contents}");
}
"#;

// Regression: `--mount` + `--record`/`replay` hands the child two inherited
// descriptors — the trace channel and the filesystem image. The image temp file
// can be allocated on the same low fd the old fixed-fd installer wanted for the
// trace, so installing fixed targets in the wrong order used to clobber the
// still-unread image source and crash the guest by signal (a guest carrying only
// the single trace fd never tripped it). The supervisor now passes the
// already-open fd numbers through `PATINA_TRACE_FD` / `PATINA_FS_IMAGE_FD` and
// clears close-on-exec only for those descriptors. Asserts a clean record AND
// replay that see the mounted content.
// A hand-declared libc binding with the wrong arity is an ABI break the compiler
// cannot see: Darwin arm64 passes anonymous varargs on the STACK, so calling the
// variadic `fcntl` through a non-variadic declaration leaves the argument in a
// register the callee never reads, and `F_SETFD` writes whatever the stack slot
// holds. Whether that misbehaves depends on stack contents (argv/env size), so
// no runtime test reproduces it reliably — the guard has to be static. Every
// extern declaration of a known-variadic libc function must declare the `...`
// tail (the crate deliberately hand-declares instead of depending on `libc`).
#[test]
fn extern_declarations_of_variadic_libc_functions_declare_the_variadic_tail() {
    const VARIADIC_LIBC: &[&str] = &["fcntl", "ioctl", "open", "openat", "syscall"];
    let source = include_str!("../src/lib.rs");
    for name in VARIADIC_LIBC {
        for (index, line) in source.lines().enumerate() {
            let Some(rest) = line.trim_start().strip_prefix("fn ") else {
                continue;
            };
            let Some(rest) = rest.strip_prefix(name) else {
                continue;
            };
            if !rest.starts_with('(') {
                continue; // longer identifier sharing the prefix
            }
            assert!(
                rest.contains("..."),
                "src/lib.rs:{}: extern declaration of variadic libc `{name}` lacks the `...` \
                 tail; non-variadic arity is an ABI break on Darwin arm64, where varargs are \
                 read from the stack",
                index + 1
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_mount_composes_with_record_and_replay_two_inherited_descriptors() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("read_mount.rs");
    fs::write(&source, MOUNT_READER_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("read-mount");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let mount = directory.path().join("corpus");
    fs::create_dir(&mount).unwrap();
    fs::write(mount.join("data.txt"), "MOUNTED-CONTENT\n").unwrap();

    let trace = directory.path().join("mount.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--mount",
            mount.to_str().unwrap(),
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "MOUNTED-CONTENT\n",
        "record mode with --mount did not see the mounted file"
    );

    // `replay` re-supplies the host corpus with --mount (a host input the trace
    // cannot carry; only its hash is in the fingerprint). The seed and everything
    // else come from the trace, so the run reproduces byte-identically.
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--mount",
            mount.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&replayed.stdout),
        "MOUNTED-CONTENT\n",
        "strict replay with --mount diverged from the recorded run"
    );

    // A DIFFERENT corpus at replay hashes to a different image, so the hash
    // folded into the fingerprint no longer matches and replay must fail closed —
    // and say WHY (the specific fingerprint mismatch), not abort mutely with the
    // generic "no runtime installed" line.
    let other_mount = directory.path().join("corpus-other");
    fs::create_dir(&other_mount).unwrap();
    fs::write(other_mount.join("data.txt"), "DIFFERENT-CONTENT\n").unwrap();
    let cross = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--mount",
            other_mount.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    let cross_stderr = String::from_utf8_lossy(&cross.stderr);
    assert!(
        !cross.status.success(),
        "replay against a different --mount corpus must fail closed:\nstderr:\n{cross_stderr}"
    );
    assert!(
        cross_stderr.contains("failed to initialize")
            && cross_stderr.contains("fingerprint mismatch"),
        "cross-corpus replay must name the fingerprint mismatch, not abort mutely:\nstderr:\n{cross_stderr}"
    );
    // The named mismatch carries the corpus image hash (`+fsimg:<hash>`): it is
    // the recorded corpus's hash that no longer matches the substituted one, so
    // the fail-closed reason points squarely at the corpus, not a generic error.
    assert!(
        cross_stderr.contains("+fsimg:"),
        "the fingerprint mismatch must name the corpus image hash (+fsimg:):\nstderr:\n{cross_stderr}"
    );
}

// A guest that opens the SAME file twice and takes an advisory `flock` on each
// descriptor. The interposed `flock` keys on the deterministic-fs inode, so the
// second `LOCK_EX | LOCK_NB` must report EWOULDBLOCK (-1) — the contention a
// single-opener database's open surfaces as an "already open" error — rather than
// both succeeding as a naive always-0 stub would. Closing the first descriptor
// releases the lock, so a
// third opener then acquires it, proving release-on-close.
const FLOCK_CONTENTION_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

fn try_lock(file: &File) -> i32 {
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) }
}

fn main() {
    let first = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/lock.db")
        .unwrap();
    let first_lock = try_lock(&first);
    let second = File::open("/lock.db").unwrap();
    let second_lock = try_lock(&second);
    drop(first);
    let third = File::open("/lock.db").unwrap();
    let third_lock = try_lock(&third);
    println!("FLOCK first={first_lock} second={second_lock} third={third_lock}");
}
"#;

// The per-inode advisory-lock table: a second open of the same path contends the
// first's `LOCK_EX`, and closing the first releases it. A single-opener path
// still acquires cleanly; this is the can-fail half.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_flock_contends_on_a_second_open_and_releases_on_close() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("flock.rs");
    fs::write(&source, FLOCK_CONTENTION_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("flock");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let run = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("FLOCK first=0 second=-1 third=0"),
        "per-inode flock must contend the second open and release on close:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stderr),
    );
}

// A guest that touches the deterministic filesystem, so its first effect
// boundary routes through `ensure_runtime` (a guest that only writes stdout is
// captured without a runtime check and would never observe a failed init). The
// fault-config conflict is resolved at runtime init, before this body runs, so
// under a conflicting replay the filesystem write never executes — the boundary
// aborts with the runtime's diagnostic first.
const FS_TOUCH_SOURCE: &str = r#"
use std::fs;

fn main() {
    fs::write("/probe", b"x").unwrap();
    println!("TOUCH_ok");
}
"#;

// The trace is authoritative for the fault configuration, so `replay` exposes no
// fault knobs at all: a flag-free `replay` reproduces the recorded fault run, and
// supplying a fault knob is refused UP FRONT (a CLI usage error naming the flag),
// never silently applied. The underlying runtime reconcile-conflict fail-closed
// path is covered directly by patina-dst-runtime's
// `reconcile_replay_faults_enforces_the_authoritative_trace_contract`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_rejects_fault_knobs_and_reproduces_flag_free() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("fs_touch.rs");
    fs::write(&source, FS_TOUCH_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("fs-touch");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("faults.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "trivial-faults",
            "--net-latency-nanos",
            "1000",
        ],
    );

    // Flag-free replay reproduces the recorded fault run — the fault config comes
    // from the trace, not the command line.
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "trivial-faults",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&recorded.stdout),
        "flag-free replay must reproduce the recorded fault run"
    );

    // Supplying a fault knob to `replay` is refused up front (the trace is
    // authoritative), naming the flag — never silently applied.
    let rejected = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "trivial-faults",
            "--net-latency-nanos",
            "2000",
        ],
    );
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "replay must reject a fault knob:\nstderr:\n{rejected_stderr}"
    );
    assert!(
        rejected_stderr.contains("--net-latency-nanos")
            && rejected_stderr.contains("does not accept"),
        "the rejection must name the offending flag:\nstderr:\n{rejected_stderr}"
    );
}

// Two threads contending on a std::sync::RwLock. On the toolchain in use std's
// queue-based RwLock takes its contended `write()` path through
// lock_contended → thread::park → dispatch_semaphore_wait — i.e. the interposed
// Darwin Parker. Each thread holds the write lock across a scheduling point, so
// the other writers PARK on it; the acquisition order is therefore chosen by
// DetScheduler. The total is schedule-invariant (correctly locked, no lost
// updates), the order is byte-identical per seed, and the winning thread order
// varies across seeds — this is the load-bearing piece for reaching a
// lock-contention race (e.g. rung 1's lost-update) deterministically.
const RWLOCK_CONTENTION_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn main() {
    let log = Arc::new(RwLock::new(Vec::<u32>::new()));
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let log = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                let mut g = log.write().unwrap();
                g.push(id);
                thread::sleep(Duration::from_nanos(1));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_log = log.read().unwrap();
    let sum: u32 = final_log.iter().sum();
    println!("RWLOCK_RESULT len={} sum={} order={:?}", final_log.len(), sum, &*final_log);
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_rwlock_contention_is_seed_deterministic_and_varies_across_seeds() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("rwlock.rs");
    fs::write(&source, RWLOCK_CONTENTION_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("rwlock");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let mut outputs = std::collections::BTreeSet::new();
    for seed in ["1", "2", "3", "4", "5", "6"] {
        let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        // Schedule-invariant total (correctly locked, no lost updates).
        assert!(
            baseline.contains("RWLOCK_RESULT len=12 sum=12"),
            "unexpected rwlock output at seed {seed}: {baseline}"
        );
        for _ in 0..2 {
            let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "rwlock contention order is not byte-identical across runs at seed {seed}"
            );
        }
        outputs.insert(baseline);
    }
    // The acquisition order is scheduler-controlled, so it must actually vary
    // across seeds — a fixed order would mean the schedule isn't seed-driven.
    assert!(
        outputs.len() >= 2,
        "rwlock acquisition order did not vary across seeds: {outputs:?}"
    );

    let trace = directory.path().join("rwlock.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "rwlock-contention",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "rwlock-contention",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "rwlock record and strict replay diverged"
    );
}

// Two threads incrementing a shared counter through the atomics-only
// `std::sync::RwLock` fast path — the classic lost-update shape. Reads no
// argv/env, so it audits clean without `--allow-unsupported-symbols`.
const YIELD_POINTS_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;

fn main() {
    let cell = Arc::new(RwLock::new(0u64));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for _ in 0..50 {
                    let current = *cell.read().unwrap();
                    *cell.write().unwrap() = current + 1;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    println!("YP_RESULT total={}", *cell.read().unwrap());
}
"#;

// A `--yield-points` binary schedules under a denser policy than a plain build,
// so their traces are different guests. `native-run` folds the yield-point
// marker into the compatibility fingerprint, so a trace recorded from an
// instrumented binary must fail closed when replayed against a plain one (and
// the reverse), never produce a silently different run. The instrumented binary
// replays its own trace exactly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_trace_fails_closed_against_plain_binary() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("yp.rs");
    fs::write(&source, YIELD_POINTS_SOURCE).unwrap();
    let workspace = native_workspace();
    let plain = directory.path().join("plain");
    let instrumented = directory.path().join("instrumented");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            plain.to_str().unwrap(),
        ],
    );
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            instrumented.to_str().unwrap(),
            "--yield-points",
        ],
    );

    let yp_trace = directory.path().join("yp.patina");
    invoke_in(
        workspace,
        &[
            "run",
            instrumented.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            yp_trace.to_str().unwrap(),
        ],
    );

    // The instrumented binary replays its own trace exactly.
    let self_replay = invoke_in(
        workspace,
        &[
            "replay",
            instrumented.to_str().unwrap(),
            yp_trace.to_str().unwrap(),
        ],
    );
    assert!(
        self_replay.status.success(),
        "an instrumented binary must replay its own yield-points trace"
    );

    // The plain binary must refuse the yield-points trace: the fingerprint suffix
    // makes the policies incompatible, so replay fails closed rather than running
    // a silently different schedule.
    let rejected = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            plain.to_str().unwrap(),
            yp_trace.to_str().unwrap(),
        ],
    );
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "a yield-points trace must not replay against a plain binary; got success\nstdout:\n{}\nstderr:\n{rejected_stderr}",
        String::from_utf8_lossy(&rejected.stdout),
    );
    // Fail-closed, but say WHY: the shim surfaces the runtime's fingerprint
    // mismatch instead of the generic "no runtime installed" abort.
    assert!(
        rejected_stderr.contains("failed to initialize")
            && rejected_stderr.contains("fingerprint mismatch"),
        "cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_stderr}"
    );

    // And the reverse: a plain trace must not replay against the instrumented
    // binary.
    let plain_trace = directory.path().join("plain.patina");
    invoke_in(
        workspace,
        &[
            "run",
            plain.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            plain_trace.to_str().unwrap(),
        ],
    );
    let rejected_reverse = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            instrumented.to_str().unwrap(),
            plain_trace.to_str().unwrap(),
        ],
    );
    let rejected_reverse_stderr = String::from_utf8_lossy(&rejected_reverse.stderr);
    assert!(
        !rejected_reverse.status.success(),
        "a plain trace must not replay against a yield-points binary:\nstderr:\n{rejected_reverse_stderr}"
    );
    assert!(
        rejected_reverse_stderr.contains("failed to initialize")
            && rejected_reverse_stderr.contains("fingerprint mismatch"),
        "reverse cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_reverse_stderr}"
    );
}

// A worker that uses `mpsc::recv_timeout` initializes a thread-local `Thread`
// handle whose destructor runs at pthread exit. Under `--yield-points` that
// destructor is instrumented std code monomorphized into the guest crate, so it
// runs the yield hook AFTER `thread_finish` completed the task — the regression
// that aborted with "scheduler task 2 does not exist" on a multi-thread guest. The
// program itself is trivial and must run to completion, deterministically.
const YIELD_TEARDOWN_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let handle = thread::spawn(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let _ = rx.recv_timeout(Duration::from_millis(5));
    });
    handle.join().unwrap();
    println!("TEARDOWN_ok");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_survive_thread_local_teardown() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("teardown.rs");
    fs::write(&source, YIELD_TEARDOWN_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("teardown");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
            "--yield-points",
        ],
    );

    // Before the fix this aborted at thread exit; it must now run to completion.
    let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
    assert!(
        baseline.contains("TEARDOWN_ok"),
        "yield-points teardown run did not complete: {baseline}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Deterministic across repeats and exactly replayable.
    for _ in 0..2 {
        let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert_eq!(
            baseline,
            String::from_utf8_lossy(&again.stdout),
            "yield-points teardown output is not byte-identical across runs"
        );
    }
    let trace = directory.path().join("teardown.patina");
    invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    let replayed = invoke_in(
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains("TEARDOWN_ok"),
        "replay of the yield-points teardown trace did not complete"
    );
}

// A `--yield-points` guest whose MAIN thread owns a thread-local with an
// instrumented `Drop`, plus a worker thread that recreates the joined-task /
// still-exiting-host-thread teardown window. Under `--yield-points` the main
// thread's thread-local destructor runs instrumented code AFTER `main` returns —
// inside the C runtime's `exit()`, which (on glibc) drives `__call_tls_dtors`
// BEFORE the atexit-registered `patina_shutdown`. Before the `exit`-interposer
// teardown flag, those late yields were recorded as trailing, host-teardown-
// ordering-dependent `TaskYield`s on the ROOT task (which, unlike a worker, has
// no `thread_finish` completion sentinel), so a record run and a replay run could
// disagree on a final yield and abort the replay with "trace ended before
// operation N; actual operation was TaskYield { task: TaskId(1) }" + a signal
// death. The root task must now record exactly ZERO teardown yields, so
// record/replay is byte-identical across repeats. On macOS the natural `main`
// return keeps libSystem's own `exit` (two-level namespace) and teardown is
// already deterministic, so this passes there too; the fix bites on Linux, where
// ELF interposition routes the crt `exit` through the shim.
const MAIN_TLS_TEARDOWN_SOURCE: &str = r#"
use std::cell::Cell;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct Noisy(Cell<u64>);
impl Drop for Noisy {
    fn drop(&mut self) {
        // Instrumented teardown work: enough edges that the --yield-points hook
        // fires while the main thread destroys its thread-local, at process exit.
        let mut acc = self.0.get();
        for i in 0..128u64 {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
        self.0.set(acc);
        // Keep the loop and the drop observable so neither is elided.
        if acc == 0 {
            std::process::abort();
        }
    }
}

thread_local! {
    static MAIN_LOCAL: Noisy = Noisy(Cell::new(1));
}

fn main() {
    // Initialize the main thread's thread-local so its Drop runs at exit.
    MAIN_LOCAL.with(|noisy| noisy.0.set(42));
    // A worker recreates the joined-task / still-exiting-host-thread window.
    let worker = thread::spawn(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let _ = rx.recv_timeout(Duration::from_millis(5));
    });
    worker.join().unwrap();
    println!("MAIN_TLS_ok");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_main_thread_tls_teardown_is_deterministic() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("main_tls.rs");
    fs::write(&source, MAIN_TLS_TEARDOWN_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("main-tls");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
            "--yield-points",
        ],
    );

    let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
    assert!(
        baseline.contains("MAIN_TLS_ok"),
        "main-thread TLS teardown run did not complete: {baseline}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Record once, then replay several times: with the root task recording ZERO
    // teardown yields, replay never exhausts the trace on a trailing teardown
    // yield. Before the fix this replay aborted (fail-closed) on Linux.
    let trace = directory.path().join("main_tls.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    for _ in 0..4 {
        let replayed = invoke_in(
            workspace,
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "main-thread TLS teardown replay diverged from the recording"
        );
    }

    // Re-record and replay repeatedly: a nondeterministic trailing teardown yield
    // would surface as a fresh recording whose own replay fails closed.
    for _ in 0..4 {
        let again = invoke_in(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replay = invoke_in(
            workspace,
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            String::from_utf8_lossy(&again.stdout),
            String::from_utf8_lossy(&replay.stdout),
            "re-recorded main-thread TLS teardown replay diverged"
        );
    }
}

// One uninterposed symbol per escape class in a single guest. Taking each as a
// pointer forces the undefined import, so the pre-run gate must refuse the whole
// binary before it runs. This is the gate-level per-class proof: if any class's
// end-to-end detection path rots (a symbol dropped from the deny lists, or the
// gate stops enumerating it), the corresponding label vanishes and the test
// fails. Two classes have no plantable member here and are covered elsewhere:
// `environment` (getenv/setenv/... are all interposed, so no shim-linked binary
// can import an uninterposed one) and `unmanaged-thread` (pthread_create is
// interposed; the C `escape_probe` in validate-native-shim.sh imports it and
// native-audit rejects it as `unmanaged-thread`).
//
// The `process` representative is `kill`, deliberately NOT a spawn-family symbol
// (`fork`/`posix_spawn*`/`waitpid`/...): those are now shim-*defined* deny-traps
// (they abort deterministically if reached), so they no longer appear as imports
// and could not exercise the gate. `kill` stays uninterposed — the process class
// is a deterministic-runtime non-goal — so it remains an undefined import the
// gate must flag as `process`.
#[cfg(target_os = "macos")]
const ESCAPE_CLASSES_SOURCE: &str = r#"
unsafe extern "C" {
    fn link(a: *const u8, b: *const u8) -> i32;
    fn gethostbyname(name: *const u8) -> *mut u8;
    fn select(n: i32, r: *mut u8, w: *mut u8, e: *mut u8, t: *mut u8) -> i32;
    fn os_unfair_lock_lock(lock: *mut u8);
    fn time(t: *mut i64) -> i64;
    fn arc4random() -> u32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn dlopen(path: *const u8, mode: i32) -> *mut u8;
    fn shm_open(name: *const u8, oflag: i32) -> i32;
    fn setitimer(which: i32, nv: *const u8, ov: *mut u8) -> i32;
    fn syscall(number: i64) -> i64;
}
fn main() {
    let ptrs: &[*const ()] = &[
        link as *const (), gethostbyname as *const (), select as *const (),
        os_unfair_lock_lock as *const (), time as *const (), arc4random as *const (),
        kill as *const (), dlopen as *const (), shm_open as *const (),
        setitimer as *const (), syscall as *const (),
    ];
    let mut acc = 0usize;
    for p in ptrs { acc ^= *p as usize; }
    std::process::exit((acc & 1) as i32);
}
"#;

// Gate-level per-class detection: native-run refuses a guest reaching one
// uninterposed symbol of each class, naming every class. Demonstrably able to
// fail — it depends on the run being refused with each label present.
#[cfg(target_os = "macos")]
#[test]
fn native_run_prerun_gate_refuses_every_escape_class() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("escape_classes.rs");
    fs::write(&source, ESCAPE_CLASSES_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("escape-classes");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !refused.status.success(),
        "the gate must refuse a guest reaching uninterposed escape-class symbols"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    for class in [
        "(filesystem)",
        "(network)",
        "(wait-multiplex)",
        "(unmanaged-sync)",
        "(time)",
        "(entropy)",
        "(process)",
        "(dynamic-loading)",
        "(shared-memory-ipc)",
        "(signals-timers)",
        "(direct-syscall)",
    ] {
        assert!(
            stderr.contains(class),
            "the gate denial must name the {class} class:\n{stderr}"
        );
    }
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("escape"),
        "the guest must not run"
    );
}

// A planted escape: a program that reaches an uninterposed blocking primitive
// (`os_unfair_lock`, in the `unmanaged-sync` class) directly. Uncontended the
// lock returns without a syscall, so the guest runs, but the calls are host
// operations the deterministic runtime does not model — exactly the escape
// class the pre-run gate exists to catch.
#[cfg(target_os = "macos")]
const PLANTED_ESCAPE_SOURCE: &str = r#"
#[repr(C)]
struct OsUnfairLock(u32);
unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut OsUnfairLock);
    fn os_unfair_lock_unlock(lock: *mut OsUnfairLock);
}
fn main() {
    let mut lock = OsUnfairLock(0);
    unsafe {
        os_unfair_lock_lock(&mut lock);
        os_unfair_lock_unlock(&mut lock);
    }
    println!("planted escape ran");
}
"#;

// Part B: the pre-run default-deny gate refuses to run a binary reaching an
// uninterposed blocking symbol (naming and categorizing it), the escape hatch
// downgrades it to a loud warning and runs, and a partial allow list still fails
// closed on the remaining symbol. This gate is demonstrably able to fail: the
// first assertion depends on the run being rejected.
#[cfg(target_os = "macos")]
#[test]
fn native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted_escape.rs");
    fs::write(&source, PLANTED_ESCAPE_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("planted-escape");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let exe = env!("CARGO_BIN_EXE_cargo-patina");

    // (1) Default-deny: refuses to run, names and categorizes the symbols, and
    // the guest never executes.
    let denied = invoke_unchecked(
        exe,
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !denied.status.success(),
        "the pre-run gate must refuse the planted escape"
    );
    let denied_err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_err.contains("os_unfair_lock_lock") && denied_err.contains("unmanaged-sync"),
        "denial must name and categorize the symbol:\n{denied_err}"
    );
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("planted escape ran"),
        "the guest must not run when the gate denies it"
    );

    // (2) Escape hatch: downgrades to a prominent warning and runs.
    let allowed = invoke_unchecked(
        exe,
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--allow-unsupported-symbols",
            "all",
        ],
    );
    assert!(
        allowed.status.success(),
        "the escape hatch must let the guest run:\n{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("planted escape ran"),
        "the guest must run under the escape hatch"
    );
    assert!(
        String::from_utf8_lossy(&allowed.stderr).contains("WARNING"),
        "the escape hatch must warn prominently"
    );

    // (3) A partial allow list still fails closed on the un-allowed symbol.
    let partial = invoke_unchecked(
        exe,
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--allow-unsupported-symbols",
            "os_unfair_lock_lock",
        ],
    );
    assert!(
        !partial.status.success(),
        "a partial allow list must still fail closed"
    );
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("os_unfair_lock_unlock"),
        "the remaining un-allowed symbol must be named"
    );
}

// A guest that actually CALLS a process-spawn symbol under Patina. Once the shim
// deny-trap stubs (task #15 shim portion) land, `fork` is shim-*defined* — so the
// pre-run audit passes (it is no longer an import), the guest runs, and the call
// aborts deterministically with the deny-trap diagnostic. This is the can-fail
// proof for the deny-trap disposition: distinct from the pre-run gate (which
// refuses a guest that merely *imports* an uninterposed spawn symbol), this
// asserts the *runtime* guard fires for a guest that reaches one.
#[cfg(target_os = "macos")]
const PLANTED_SPAWN_SOURCE: &str = r#"
unsafe extern "C" {
    fn fork() -> i32;
}
fn main() {
    println!("before spawn");
    unsafe {
        fork();
    }
    println!("after spawn");
}
"#;

// `fork` is now shim-defined (a deny-trap in `c/patina_posix.c`), so the pre-run
// gate passes this binary (fork is no longer an import) and the runtime deny-trap
// is what fires when the guest reaches fork — the distinct guarantee this proves.
#[cfg(target_os = "macos")]
#[test]
fn native_run_deny_trap_aborts_a_guest_that_actually_spawns() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted_spawn.rs");
    fs::write(&source, PLANTED_SPAWN_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("planted-spawn");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    // The audit passes (fork is shim-defined, not an import), the guest starts,
    // and the fork() call aborts deterministically.
    assert!(
        !ran.status.success(),
        "a guest that reaches fork must abort under the deny-trap"
    );
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        stderr.contains("process spawn reached under patina: fork"),
        "the deny-trap must name the reached spawn symbol:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("before spawn"),
        "the guest must run up to the spawn attempt"
    );
    assert!(
        !stdout.contains("after spawn"),
        "the guest must not continue past the deny-trap"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invoke_in(directory: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), directory, arguments)
}

// Schedule reduction end to end: record a three-task run whose failure depends
// on the interleaving (task b runs before task a completes), then minimize it
// with a replay oracle. The oracle accepts a candidate only when the replayed
// program itself exits with the failure's exact code and marker, so a candidate
// whose rewritten schedule merely breaks replay is rejected rather than
// mistaken for the failure. The minimized trace must still replay to the same
// failure with no more context switches than the original.
#[cfg(unix)]
#[test]
fn minimize_canonicalizes_a_recorded_schedule_via_replay_oracle() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("fixture");
    create_schedule_fixture(&fixture);

    let trace = directory.path().join("sched.patina");
    let mut original = None;
    for seed in 0..32u64 {
        let seed_string = seed.to_string();
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &[
                "run",
                "--seed",
                &seed_string,
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        if recorded.status.code() == Some(3) {
            original = Some(schedule_line(&recorded));
            break;
        }
    }
    let original = original.expect("no seed in 0..32 interleaved b before a completed");
    assert!(original.contains("interleaved=true"));
    let original_switches = switch_count(&original);

    let oracle = directory.path().join("oracle.sh");
    fs::write(
        &oracle,
        format!(
            "#!/bin/sh\nout=$(\"{}\" replay \"{}\" \"$PATINA_MINIMIZE_TRACE\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 3 ] && printf '%s' \"$out\" | grep -q 'interleaved=true'; then\n  exit 1\nfi\nexit 0\n",
            env!("CARGO_BIN_EXE_cargo-patina"),
            fixture.to_str().unwrap(),
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let minimized_path = directory.path().join("sched-min.patina");
    let minimized = invoke(
        &fixture,
        &[
            "minimize",
            trace.to_str().unwrap(),
            "--output",
            minimized_path.to_str().unwrap(),
            "--",
            oracle.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&minimized.stdout).contains("PATINA_MINIMIZE_COMPLETE"),
        "missing completion line:\n{}",
        String::from_utf8_lossy(&minimized.stdout)
    );

    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["replay", ".", minimized_path.to_str().unwrap()],
    );
    assert_eq!(
        replayed.status.code(),
        Some(3),
        "minimized trace no longer reproduces the failure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&replayed.stderr)
    );
    let reduced = schedule_line(&replayed);
    assert!(reduced.contains("interleaved=true"));
    assert!(
        switch_count(&reduced) <= original_switches,
        "schedule reduction increased context switches: {original} -> {reduced}"
    );
}

#[cfg(unix)]
fn schedule_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PATINA_SCHED_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing PATINA_SCHED_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

#[cfg(unix)]
fn switch_count(line: &str) -> u64 {
    line.split("switches=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("missing switches= in {line}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn package_result(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("NATIVE_PKG_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing NATIVE_PKG_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

fn invoke_with(executable: &str, fixture: &Path, arguments: &[&str]) -> Output {
    let output = invoke_unchecked(executable, fixture, arguments);
    assert!(
        output.status.success(),
        "command failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn invoke_unchecked(executable: &str, fixture: &Path, arguments: &[&str]) -> Output {
    // Serialize compiling invocations behind BUILD_LOCK so parallel test threads
    // never build concurrently; executing an already-built artifact stays
    // parallel. The guard is held for the whole process lifetime because the
    // build happens inside it. `unwrap_or_else(into_inner)` tolerates a lock
    // poisoned by an unrelated test's panic — we only need mutual exclusion of
    // builds, not the (unit) protected state.
    let _build_guard = command_compiles(arguments).then(|| {
        BUILD_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    });
    Command::new(executable)
        .current_dir(fixture)
        .args(arguments)
        .output()
        .unwrap()
}

fn result_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PATINA_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing PATINA_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

// Build a self-contained fixture: an ordinary-`std` package with a path
// dependency (`greeter`), a build script (whose output the binary reads back,
// and whose host-side file I/O proves the shim link args do not leak onto build
// scripts), a clean binary that audits and replays, and a second binary that
// imports an off-allowlist process symbol.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_package_fixture(root: &Path) {
    let greeter = root.join("greeter");
    fs::create_dir_all(greeter.join("src")).unwrap();
    fs::write(
        greeter.join("Cargo.toml"),
        "[package]\nname = \"greeter\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        greeter.join("src/lib.rs"),
        "pub fn greeting() -> String {\n    format!(\"hello from {}\", \"greeter\")\n}\n",
    )
    .unwrap();

    let package = root.join("pkg");
    fs::create_dir_all(package.join("src/bin")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"patina-native-pkg-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ngreeter = { path = \"../greeter\" }\n",
    )
    .unwrap();
    fs::write(
        package.join("build.rs"),
        r#"fn main() {
    // Runs on the host. If the shim link args leaked onto this build script, its
    // file I/O would route into an uninitialized Patina runtime and abort; the
    // explicit host --target keeps them off host artifacts.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::fs::read(std::path::Path::new(&manifest).join("Cargo.toml")).unwrap();
    println!("cargo:rustc-env=PKG_BUILT=1");
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        r#"use std::hash::{BuildHasher, Hasher};

fn main() {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(greeter::greeting().as_bytes());
    let hash = hasher.finish();
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", greeter::greeting().as_bytes()).unwrap();
    let stored = std::fs::read_to_string("/state/value").unwrap();
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_PKG_RESULT built={} hash={hash:016x} stored={stored}",
        env!("PKG_BUILT")
    );
}
"#,
    )
    .unwrap();
    fs::write(
        package.join("src/bin/leaky.rs"),
        r#"// Imports an uninterposed process-class libc symbol (`kill`) that the native
// audit denies as "process". The spawn family (fork/posix_spawn*/waitpid/...) is
// now shim-defined (deny-traps), so a `Command::spawn` would leave no process
// *import* to flag; this reaches for a still-uninterposed member of the class
// instead. Taking its address forces the undefined import. Building succeeds; the
// audit must reject the product with the "process" category.
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
fn main() {
    let reached = kill as *const ();
    std::process::exit((reached as usize & 1) as i32);
}
"#,
    )
    .unwrap();
}

// A fixture that drives the explicit scheduler API: three tasks of four rounds
// each, selected by recorded `SchedulerNext` decisions. The schedule-dependent
// failure — task b selected before task a has completed — exits the process
// with code 3 so a replay oracle can demand the exact failure rather than any
// nonzero exit.
#[cfg(unix)]
fn create_schedule_fixture(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let runtime_path = workspace.join("crates/patina-runtime");
    let runtime_path = runtime_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-sched-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-runtime = {{ path = \"{runtime_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use std::collections::BTreeMap;

use patina_dst_runtime::RuntimeError;

fn scenario() -> Result<(String, bool), RuntimeError> {
    patina_dst_runtime::run(|context| {
        let a = context.task_spawn("a")?;
        let b = context.task_spawn("b")?;
        let c = context.task_spawn("c")?;
        let mut remaining = BTreeMap::from([(a, 4_u32), (b, 4), (c, 4)]);
        let mut order = Vec::new();
        let mut interleaved = false;
        while let Some(task) = context.scheduler_next()? {
            order.push(task.0);
            if task == b && remaining.contains_key(&a) {
                interleaved = true;
            }
            let rounds = remaining.get_mut(&task).expect("selected task is live");
            *rounds -= 1;
            if *rounds == 0 {
                remaining.remove(&task);
                context.task_complete(task)?;
            } else {
                context.task_yield(task)?;
            }
        }
        let switches = order.windows(2).filter(|pair| pair[0] != pair[1]).count();
        let line = format!(
            "PATINA_SCHED_RESULT seed={} order={order:?} switches={switches} interleaved={interleaved}",
            context.root_seed()
        );
        Ok((line, interleaved))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (line, interleaved) = scenario()?;
    println!("{line}");
    if interleaved {
        std::process::exit(3);
    }
    Ok(())
}
"#,
    )
    .unwrap();
}

fn create_fixture(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let runtime_path = workspace.join("crates/patina-runtime");
    let runtime_path = runtime_path.to_string_lossy().replace('\\', "\\\\");
    let abi_path = workspace.join("crates/patina-abi");
    let abi_path = abi_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-e2e-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-runtime = {{ path = \"{runtime_path}\" }}\npatina-dst-abi = {{ path = \"{abi_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use patina_dst_abi::ClockKind;
use patina_dst_runtime::RuntimeError;

fn scenario() -> Result<String, RuntimeError> {
    patina_dst_runtime::run(|context| {
        let prefix = context.entropy_bytes(8)?;
        let suffix = context.entropy_bytes(8)?;
        context.write_file("/state/value", &suffix)?;
        context.sleep_for(10)?;
        let stored = context.read_file("/state/value")?;
        let time = context.now(ClockKind::Monotonic)?;
        Ok(format!("PATINA_RESULT seed={} prefix={prefix:?} suffix={stored:?} time={time} zone={:?} cfg={}", context.root_seed(), context.param("zone"), cfg!(all(patina, dst))))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", scenario()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_scenario_runs_under_cargo_patina_test() {
        assert!(super::scenario().unwrap().starts_with("PATINA_RESULT"));
    }
}
"#,
    )
    .unwrap();
}

// ---- Cooperative-SUT (buggify) SDK, end to end -------------------------------
//
// A whole package depending on the `patina` crate's default-feature SDK, built
// and run through native-build/native-run. Verifies that buggify fires
// deterministically, emits `PATINA_SDK_REPORT`, records and replays
// byte-identically without re-supplying `--buggify`, and that a duplicate label
// aborts with the fatal marker.

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_sdk_fixture(root: &Path, main: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"buggify-sdk-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), main).unwrap();
}

// A guest whose buggify sites all activate and always fire under
// `--buggify=1000 --buggify-activation-permille 1000`, so the outcome is
// deterministic without hunting for a firing seed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_SDK_MAIN: &str = r#"
fn main() {
    patina_dst::lifecycle::setup_complete();
    let mut fired = 0u32;
    let knob = patina_dst::buggify_knob!("batch", 10_i64, 1, 100);
    for i in 0..8 {
        patina_dst::reachable!("loop-body");
        if patina_dst::buggify!("early-return") {
            fired += 1;
        }
        patina_dst::sometimes!(i == 3, "index-is-three");
    }
    patina_dst::always!(fired <= 8, "fired-in-bounds");
    println!("RESULT knob={knob} fired={fired} rng={}", patina_dst::rng());
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_sdk_reports_records_and_replays() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_sdk_fixture(&pkg, BUGGIFY_SDK_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-sdk");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Seeded run with every site active and always firing.
    let flags = ["--buggify=1000", "--buggify-activation-permille", "1000"];
    let seeded = invoke_in(
        workspace,
        &[
            &["run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
        ]
        .concat(),
    );
    let stdout = String::from_utf8_lossy(&seeded.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&seeded.stderr).into_owned();
    assert!(
        stdout.contains("fired=8"),
        "all sites should fire: {stdout}"
    );
    assert!(
        stderr.contains("PATINA_SDK_REPORT enabled=1"),
        "expected SDK report: {stderr}"
    );
    assert!(
        stderr.contains("total_firings=") && !stderr.contains("total_firings=0"),
        "expected nonzero firings: {stderr}"
    );

    // Record, then replay WITHOUT re-supplying --buggify: byte-identical stdout.
    let trace = directory.path().join("buggify.patina");
    let recorded = invoke_in(
        workspace,
        &[
            &["run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
            &["--record", trace.to_str().unwrap()][..],
        ]
        .concat(),
    );
    let replayed = invoke_in(
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "record/replay stdout diverged"
    );
}

// A guest that reuses the same label at two different call sites: a fatal
// duplicate, aborting with the marker.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_DUP_MAIN: &str = r#"
fn main() {
    let _ = patina_dst::buggify!("same-label");
    let _ = patina_dst::buggify!("same-label");
    println!("unreachable");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_duplicate_label_aborts_with_marker() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("dup");
    write_sdk_fixture(&pkg, BUGGIFY_DUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-dup");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(!output.status.success(), "duplicate label must abort");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=same-label"),
        "expected duplicate-label marker: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("unreachable"),
        "guest ran past the duplicate label"
    );
}

// A guest that never calls setup_complete; under --buggify-after-setup this is a
// declared-but-never-called harness bug that must fail loudly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_NO_SETUP_MAIN: &str = r#"
fn main() {
    for _ in 0..5 {
        let _ = patina_dst::buggify!("gated");
    }
    println!("guest-finished");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_after_setup_never_called_fails_loudly() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("nosetup");
    write_sdk_fixture(&pkg, BUGGIFY_NO_SETUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-nosetup");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // With the gate declared but never reached: fatal marker + nonzero exit,
    // even though buggify itself injected no fault.
    let gated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify",
            "--buggify-after-setup",
        ],
    );
    assert!(
        !gated.status.success(),
        "declared-but-never-called must fail"
    );
    assert!(
        String::from_utf8_lossy(&gated.stderr).contains("PATINA_BUGGIFY_SETUP_NEVER_CALLED"),
        "expected never-called marker: {}",
        String::from_utf8_lossy(&gated.stderr)
    );

    // Same guest WITHOUT the gate declaration runs clean.
    let plain = invoke_in(
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1", "--buggify"],
    );
    assert!(
        String::from_utf8_lossy(&plain.stdout).contains("guest-finished"),
        "ungated run should finish cleanly"
    );
}

// ---- proptest compatibility (patina-dst-proptest), end to end --------------------
//
// A whole package depending on the `patina-dst-proptest` compat crate, built and run
// through native-build/native-run. The guest runs a proptest property whose cases
// are generated from a `patina-dst-proptest` runner (proptest's ChaCha RNG seeded from
// `patina_dst::rng()`), and prints a fold-digest of every generated case. Under Patina
// that digest is a pure function of the run seed, so the same seed reproduces it,
// a different seed changes it, and record/replay reproduces it byte-identically —
// the determinism model that lets adopters drop proptest's regression files.

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_proptest_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    let proptest_path = native_workspace().join("crates/patina-proptest");
    let proptest_path = proptest_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-dst-proptest-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\npatina-dst-proptest = {{ path = \"{proptest_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), PROPTEST_DIGEST_MAIN).unwrap();
}

// A passing property: with no failure proptest never shrinks, so the closure runs
// exactly `cases` times over freshly generated inputs. Folding those inputs (and
// the case count) produces a digest determined solely by the runner's seed, which
// `patina-dst-proptest` draws from `patina_dst::rng()`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PROPTEST_DIGEST_MAIN: &str = r#"
use std::cell::Cell;

use patina_dst_proptest::prelude::*;

fn case_digest() -> u64 {
    let mut runner = patina_dst_proptest::runner();
    let digest = Cell::new(0xcbf2_9ce4_8422_2325_u64);
    let cases = Cell::new(0u64);
    runner
        .run(&(any::<u64>(), 0i64..1_000_000i64), |(a, b)| {
            let mixed = a ^ (b as u64).rotate_left(21);
            digest.set(
                (digest.get() ^ mixed)
                    .wrapping_mul(0x0000_0100_0000_01b3)
                    .rotate_left(13),
            );
            cases.set(cases.get() + 1);
            Ok(())
        })
        .expect("the property holds for every generated case");
    digest.get() ^ cases.get().rotate_left(7)
}

fn main() {
    println!("PROPTEST_DIGEST digest={:016x}", case_digest());
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn proptest_digest(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PROPTEST_DIGEST"))
        .unwrap_or_else(|| {
            panic!(
                "missing PROPTEST_DIGEST in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_proptest_case_generation_is_seed_deterministic_and_replays() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_proptest_fixture(&pkg);
    let workspace = native_workspace();
    let bin = directory.path().join("proptest-digest");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--bin",
            "patina-dst-proptest-fixture",
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Same seed -> byte-identical case digest across two separate native-run
    // invocations; a different seed -> a different digest.
    let seeded = proptest_digest(&invoke_in(
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "5"],
    ));
    let repeated = proptest_digest(&invoke_in(
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "5"],
    ));
    let other = proptest_digest(&invoke_in(
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "6"],
    ));
    assert_eq!(
        seeded, repeated,
        "same seed must generate a byte-identical case digest"
    );
    assert_ne!(
        seeded, other,
        "a different seed must generate a different case digest"
    );

    // Record at seed 5, then strict replay: byte-identical digest.
    let trace = directory.path().join("proptest.patina");
    let recorded = proptest_digest(&invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "proptest-digest-v1",
        ],
    ));
    let replayed = proptest_digest(&invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "proptest-digest-v1",
        ],
    ));
    assert_eq!(recorded, seeded, "recording must not change the digest");
    assert_eq!(
        replayed, seeded,
        "strict replay must reproduce the recorded case digest byte-identically"
    );
}

// ---- Two-axis shrinking: stateful command-sequence + schedule ----------------
//
// The compose story for the model-based (stateful) layer. A package depending on
// `patina-dst-proptest`'s state module drives a key/value store with a planted
// off-by-one delete bug (`Remove(1)` also evicts key 0 in the SUT) against a
// `BTreeMap` model. Two independent shrinking axes are exercised end to end:
//
//   * Axis 1 (input): `--find` runs the stateful runner, which searches for a
//     failing command sequence and shrinks it. The bug pins both keys and the
//     surviving value shrinks to 0, so it converges to one canonical minimal
//     sequence — `[Insert(0, 0), Remove(1)]` — deterministically from the seed.
//   * Axis 2 (schedule): `--replay-commands` re-runs exactly that minimal
//     sequence (with a little deterministic thread interleaving so the trace
//     carries real scheduler decisions), the run is recorded, and the existing
//     `cargo patina minimize` path canonicalizes its schedule. The minimized
//     artifact must still replay to the same failure marker.
//
// The failure is a deterministic state bug, so under strict replay the schedule
// pass is failure-preserving without deleting decisions (the same soundness the
// schedule-reduction e2e relies on); what this proves is that the two shrinkers
// compose — a shrunk command sequence feeds a recorded run whose minimized trace
// still reproduces.

#[cfg(any(target_os = "linux", target_os = "macos"))]
const TWO_AXIS_MAIN: &str = r#"
use std::collections::BTreeMap;

use patina_dst_proptest::prelude::*;
use patina_dst_proptest::state::{check, execute, StateMachine};

#[derive(Clone, Debug)]
enum Cmd {
    Insert(u8, u8),
    Remove(u8),
    Get(u8),
}

// Planted off-by-one delete bug: Remove(1) also evicts key 0 in the SUT while
// the model removes only key 1. The minimal counterexample is Insert(0, _) then
// Remove(1); the keys are pinned by the bug and the value shrinks to 0, so it is
// canonical across seeds: [Insert(0, 0), Remove(1)].
struct BuggyKv;

impl StateMachine for BuggyKv {
    type Command = Cmd;
    type Model = BTreeMap<u8, u8>;
    type System = BTreeMap<u8, u8>;

    fn init_model() -> Self::Model { BTreeMap::new() }
    fn init_system() -> Self::System { BTreeMap::new() }

    fn command_strategy() -> BoxedStrategy<Self::Command> {
        prop_oneof![
            (0u8..4, 0u8..4).prop_map(|(k, v)| Cmd::Insert(k, v)),
            (0u8..4).prop_map(Cmd::Remove),
            (0u8..4).prop_map(Cmd::Get),
        ]
        .boxed()
    }

    fn next(model: &mut Self::Model, command: &Self::Command) {
        match command {
            Cmd::Insert(k, v) => { model.insert(*k, *v); }
            Cmd::Remove(k) => { model.remove(k); }
            Cmd::Get(_) => {}
        }
    }

    fn apply(system: &mut Self::System, model: &Self::Model, command: &Self::Command) -> Result<(), String> {
        match command {
            Cmd::Insert(k, v) => { system.insert(*k, *v); }
            Cmd::Remove(k) => {
                system.remove(k);
                if *k == 1 { system.remove(&0); }
            }
            Cmd::Get(k) => {
                if system.get(k) != model.get(k) {
                    return Err(format!("get({k}) diverged"));
                }
            }
        }
        if system == model { Ok(()) } else {
            Err(format!("state diverged: sut={system:?} model={model:?}"))
        }
    }
}

fn token(c: &Cmd) -> String {
    match c {
        Cmd::Insert(k, v) => format!("I{k}.{v}"),
        Cmd::Remove(k) => format!("R{k}"),
        Cmd::Get(k) => format!("G{k}"),
    }
}

fn parse(spec: &str) -> Vec<Cmd> {
    spec.split(',').filter(|t| !t.is_empty()).map(|t| {
        match t.as_bytes()[0] {
            b'I' => {
                let (k, v) = t[1..].split_once('.').expect("Insert token needs key.value");
                Cmd::Insert(k.parse().unwrap(), v.parse().unwrap())
            }
            b'R' => Cmd::Remove(t[1..].parse().unwrap()),
            b'G' => Cmd::Get(t[1..].parse().unwrap()),
            other => panic!("bad token byte {other}"),
        }
    }).collect()
}

// A little deterministic thread interleaving so the recorded trace of the
// minimal-sequence run carries real scheduler decisions for the schedule
// minimization pass to engage on. It does not touch the KV state, so the planted
// failure stays a pure function of the command sequence.
fn schedule_noise() {
    use std::sync::{Arc, Mutex};
    let counter = Arc::new(Mutex::new(0u64));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let mut guard = counter.lock().unwrap();
                    *guard += 1;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

fn report_failure(spec: &str, commands: &[Cmd], message: &str) -> ! {
    println!("TWOAXIS_SHRUNK spec={spec} commands={commands:?}");
    println!("TWOAXIS_FAIL {message}");
    std::process::exit(7);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--find") => {
            let mut config = patina_dst_proptest::config();
            config.cases = 64;
            let mut runner = patina_dst_proptest::runner_with_config(config);
            match check::<BuggyKv>(&mut runner, 0..=16) {
                Ok(()) => println!("TWOAXIS_HELD"),
                Err(f) => {
                    let spec = f.commands.iter().map(token).collect::<Vec<_>>().join(",");
                    report_failure(&spec, &f.commands, &f.message);
                }
            }
        }
        Some("--replay-commands") => {
            let spec = args.get(1).map(String::as_str).unwrap_or("");
            schedule_noise();
            match execute::<BuggyKv>(&parse(spec)) {
                Ok(_) => println!("TWOAXIS_NO_REPRO spec={spec}"),
                Err(f) => report_failure(spec, &f.commands, &f.message),
            }
        }
        other => {
            eprintln!("usage: --find | --replay-commands <spec>; got {other:?}");
            std::process::exit(2);
        }
    }
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_two_axis_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    let proptest_path = native_workspace().join("crates/patina-proptest");
    let proptest_path = proptest_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"two-axis-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\npatina-dst-proptest = {{ path = \"{proptest_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), TWO_AXIS_MAIN).unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn two_axis_shrunk_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("TWOAXIS_SHRUNK"))
        .unwrap_or_else(|| {
            panic!(
                "missing TWOAXIS_SHRUNK in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_two_axis_stateful_shrink_then_schedule_minimize() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_two_axis_fixture(&pkg);
    let workspace = native_workspace();
    let bin = directory.path().join("two-axis");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let exe = env!("CARGO_BIN_EXE_cargo-patina");

    // --- Axis 1: the stateful shrinker finds and minimizes the failing command
    // sequence. The planted bug reproduces at essentially every seed; sweep for
    // the first that exits with the failure code.
    let mut found = None;
    for seed in 0..8u64 {
        let out = invoke_unchecked(
            exe,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                &seed.to_string(),
                "--",
                "--find",
            ],
        );
        if out.status.code() == Some(7) {
            found = Some((seed, two_axis_shrunk_line(&out)));
            break;
        }
    }
    let (seed, shrunk) = found.expect("no seed in 0..8 reproduced the planted state bug");
    let seed_string = seed.to_string();
    assert_eq!(
        shrunk, "TWOAXIS_SHRUNK spec=I0.0,R1 commands=[Insert(0, 0), Remove(1)]",
        "the stateful shrinker must converge to the canonical minimal sequence"
    );

    // Stable across a repeated run at the same seed.
    let repeat = invoke_unchecked(
        exe,
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            &seed_string,
            "--",
            "--find",
        ],
    );
    assert_eq!(
        two_axis_shrunk_line(&repeat),
        shrunk,
        "the shrunk command sequence must be stable across repeats"
    );

    let spec = "I0.0,R1";

    // --- Axis 2: record the shrunk failing run, minimize its schedule, and
    // replay the minimized artifact — it must still fail with the same marker.
    let trace = directory.path().join("fail.patina");
    let recorded = invoke_unchecked(
        exe,
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            &seed_string,
            "--record",
            trace.to_str().unwrap(),
            "--",
            "--replay-commands",
            spec,
        ],
    );
    assert_eq!(
        recorded.status.code(),
        Some(7),
        "recording the minimal-sequence run must reproduce the failure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert!(String::from_utf8_lossy(&recorded.stdout).contains("TWOAXIS_FAIL"));

    // The oracle replays each candidate trace and treats a nonzero exit carrying
    // the marker as failure-preserved (exit 1), anything else as not (exit 0).
    let oracle = directory.path().join("oracle.sh");
    fs::write(
        &oracle,
        format!(
            "#!/bin/sh\nout=$(\"{}\" replay \"{}\" \"$PATINA_MINIMIZE_TRACE\" -- --replay-commands \"{}\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -ne 0 ] && printf '%s' \"$out\" | grep -q 'TWOAXIS_FAIL'; then\n  exit 1\nfi\nexit 0\n",
            exe,
            bin.display(),
            spec
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let minimized_path = directory.path().join("fail-min.patina");
    let minimized = invoke_in(
        workspace,
        &[
            "minimize",
            trace.to_str().unwrap(),
            "--output",
            minimized_path.to_str().unwrap(),
            "--",
            oracle.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&minimized.stdout).contains("PATINA_MINIMIZE_COMPLETE"),
        "missing minimize completion line:\n{}",
        String::from_utf8_lossy(&minimized.stdout)
    );

    // The minimized trace must still replay to the same failure marker.
    let replayed = invoke_unchecked(
        exe,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            minimized_path.to_str().unwrap(),
            "--",
            "--replay-commands",
            spec,
        ],
    );
    assert_eq!(
        replayed.status.code(),
        Some(7),
        "minimized trace no longer reproduces the failure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&replayed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains("TWOAXIS_FAIL"),
        "minimized replay must carry the same failure marker"
    );
}

// A guest whose deterministic boundary op-stream DEPENDS on its arguments: it
// opens and reads back a file whose name is `argv[1]` (default "default"), so a
// replay that runs it with the wrong arguments diverges with a trace operation
// mismatch mid-run — exactly the confusing incident that recording guest argv
// fixes. It also echoes `argv[0]` so the supervisor-normalized value is pinned.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ARGV_ECHO_SOURCE: &str = r#"
fn main() {
    let argv: Vec<String> = std::env::args().collect();
    println!("ARGV0={}", argv.first().map(String::as_str).unwrap_or(""));
    let guest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    println!("ARGS={guest:?}");
    // The open path is argv-derived, so the recorded FsOpen operation carries the
    // argument. Replaying with a different argv opens a different path and the
    // strict replay fails closed with an operation mismatch instead of silently
    // running the wrong scenario.
    let name = guest.first().copied().unwrap_or("default");
    let path = format!("/{name}");
    std::fs::write(&path, name.as_bytes()).unwrap();
    let readback = std::fs::read_to_string(&path).unwrap();
    println!("READBACK={readback}");
}
"#;

// Guest argv is recorded into the trace metadata and restored on replay: a bare
// `cargo patina replay <bin> <trace>` reproduces a run recorded with non-default
// `-- ARGS` byte-identically (the incident class), a mismatched `--` section is
// refused up front naming both argv lists, an old trace without the field still
// replays with explicit arguments, and `argv[0]` is normalized to a fixed,
// machine-independent value.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_restores_guest_argv_and_normalizes_argv0() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("argv_echo.rs");
    fs::write(&source, ARGV_ECHO_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("argv-echo");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let exe = env!("CARGO_BIN_EXE_cargo-patina");

    // argv[0] is the supervisor-synthesized fixed name, never the host binary
    // path, so a guest reading std::env::args().next() gets a portable value.
    let seeded = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "0"]);
    let seeded_out = String::from_utf8_lossy(&seeded.stdout);
    assert!(
        seeded_out.contains("ARGV0=patina-guest"),
        "argv[0] must be normalized to a fixed name, got:\n{seeded_out}"
    );
    assert!(
        !seeded_out.contains(bin.to_str().unwrap()),
        "the host binary path must not leak into the guest argv[0]:\n{seeded_out}"
    );

    // Record with NON-DEFAULT guest arguments (the real incident used a
    // non-default --tick-millis), then a BARE replay — no `--` section —
    // reproduces the run byte-identically because the arguments are restored
    // from the trace. Before argv capture this bare replay ran the guest with
    // default args and diverged with an operation mismatch.
    let trace = directory.path().join("argv.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--record",
            trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    let recorded_out = String::from_utf8_lossy(&recorded.stdout).into_owned();
    assert!(
        recorded_out.contains("ARGS=[\"alpha\", \"--tick-millis\", \"50\"]"),
        "record run did not see the passed guest arguments:\n{recorded_out}"
    );
    assert!(recorded_out.contains("READBACK=alpha"), "{recorded_out}");

    let bare_replay = invoke_with(
        exe,
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8_lossy(&bare_replay.stdout),
        recorded_out,
        "bare `replay` must restore the recorded guest arguments and reproduce the run"
    );

    // A mismatched `--` section is refused UP FRONT, naming both the recorded and
    // the passed argument lists — never a confusing mid-run divergence.
    let mismatch = invoke_unchecked(
        exe,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--",
            "beta",
            "--tick-millis",
            "99",
        ],
    );
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        !mismatch.status.success(),
        "a mismatched replay `--` section must fail:\nstderr:\n{mismatch_stderr}"
    );
    assert!(
        mismatch_stderr.contains("alpha")
            && mismatch_stderr.contains("beta")
            && mismatch_stderr.contains("mismatch"),
        "the mismatch error must name BOTH argv lists:\nstderr:\n{mismatch_stderr}"
    );

    // A matching `--` section is accepted (compat for scripts that still pass it).
    let matching = invoke_with(
        exe,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&matching.stdout),
        recorded_out,
        "a byte-identical `--` section must be accepted"
    );

    // Old-trace compatibility: synthesize a trace WITHOUT the guest_argv field
    // (a pre-argv recording) by stripping it, then replay with explicit
    // arguments exactly as before — no new error, arguments taken from the
    // command line.
    let old_trace = directory.path().join("old.patina");
    strip_guest_argv(&trace, &old_trace);
    let old_replay = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            old_trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&old_replay.stdout),
        recorded_out,
        "an old trace without recorded argv must replay with explicit arguments as before"
    );
}

// Rewrite `source` into `dest` with the additive `metadata.guest_argv` field
// removed, synthesizing a trace as a pre-argv-capture recorder would have
// written it. Traces are compact, greppable JSON, so this is a faithful stand-in
// for an old on-disk bundle.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn strip_guest_argv(source: &Path, dest: &Path) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
    let removed = value["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("guest_argv");
    assert!(
        removed.is_some(),
        "the recorded trace was expected to carry guest_argv before stripping"
    );
    fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
}

// A guest that establishes a durable 16-byte baseline, then issues one UNSYNCED
// positional overwrite. `--fs-crash-at write:2` fires right after that pwrite,
// so it is the final write eligible for a sub-block (byte-granularity) tear. The
// guest reopens cold and prints the recovered image. Under whole-block tearing
// the overwrite reverts wholesale (all 'A'); under byte tearing it survives
// partially (an 'B' prefix, an 'A' suffix) -- an image a block model can never
// produce.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TORN_GRANULARITY_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;

fn main() {
    let path = "/f";
    {
        let f = OpenOptions::new().create(true).write(true).open(path).unwrap();
        f.write_all_at(&[b'A'; 16], 0).unwrap();
        f.sync_all().unwrap();
    }
    {
        let f = OpenOptions::new().write(true).open(path).unwrap();
        let _ = f.write_all_at(&[b'B'; 16], 0);
    }
    let mut buf = Vec::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_end(&mut buf);
    }
    println!("recovered={buf:?}");
}
"#;

// `--fs-torn-granularity byte` must actually reach the guest's crash filesystem.
// This FAILED before the structural fix: the shim pre-installed a default-policy
// (whole-block) CrashFs via `with_filesystem`, so `RuntimeBuilder::build` never
// consumed `config.faults.torn_granularity` and every crash ran as block. With
// the runtime now the single choke point that builds the CrashFs from the fault
// config, block and byte produce different guest-visible recovered images.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_fs_torn_granularity_byte_reaches_the_guest() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("torn.rs");
    fs::write(&source, TORN_GRANULARITY_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("torn");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let run = |gran: &str| {
        let output = invoke_in(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--fs-crash-at",
                "write:2",
                "--fs-torn-granularity",
                gran,
            ],
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let block = run("block");
    let byte = run("byte");
    // Block granularity reverts the unsynced overwrite wholesale to the durable
    // baseline; byte granularity keeps a live prefix, so the images differ.
    assert!(
        block
            .contains("recovered=[65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65]"),
        "block granularity should revert wholesale to the durable baseline: {block}"
    );
    assert_ne!(
        block, byte,
        "--fs-torn-granularity byte did not reach the guest (byte tearing == block)"
    );
    assert!(
        byte.contains("66") && byte.contains("65"),
        "byte granularity should leave a partial live/durable mix: {byte}"
    );
}

// The seeded crash-decision stream must be LIVE per `--seed` (the shim used to
// pin the CrashFs to seed 0, so every seed produced the same crash image), and
// still deterministic: identical seed reproduces the identical torn image.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_fs_crash_image_is_seed_live_and_deterministic() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("torn.rs");
    fs::write(&source, TORN_GRANULARITY_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("torn");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let run = |seed: &str| {
        let output = invoke_in(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                seed,
                "--fs-crash-at",
                "write:2",
                "--fs-torn-granularity",
                "byte",
            ],
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let images: Vec<String> = ["1", "2", "3"].iter().map(|seed| run(seed)).collect();
    // Seed liveness: the seeded tear point varies, so not every seed yields the
    // same recovered image.
    assert!(
        images.iter().any(|image| *image != images[0]),
        "crash image did not vary across seeds (seed stream is pinned): {images:?}"
    );
    // Determinism: each seed reproduces its image byte-identically on re-run.
    for seed in ["1", "2", "3"] {
        assert_eq!(
            run(seed),
            run(seed),
            "crash image is not deterministic for seed {seed}"
        );
    }
}

// ---------------------------------------------------------------------------
// Wave 14: observability — HTML timeline (`--render`/`--report`) and the
// machine-readable `--format json` result envelope. These prove the render path
// is a pure read-only consumer (rendering a trace does not change its hash) and
// that the envelope has a stable, parseable shape for each verb.
// ---------------------------------------------------------------------------

// A small threaded guest that touches the scheduler and the filesystem, so its
// trace has multiple task lanes and fs ops to render.
const RENDER_GUEST_SOURCE: &str = r#"
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0u64));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let c = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                *c.lock().unwrap() += 1;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = *counter.lock().unwrap();
    std::fs::write("/out.txt", format!("{total}")).unwrap();
    println!("PATINA_RESULT total={total}");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_render_produces_standalone_timeline_and_preserves_replay_hash() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("render_guest.rs");
    fs::write(&source, RENDER_GUEST_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("render-guest");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("run.patina");
    invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "7",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    let recorded_bytes = fs::read(&trace).unwrap();

    // Replaying WITH --render must not perturb the trace file (render only reads
    // it and writes a separate HTML file).
    let html = directory.path().join("timeline.html");
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--render",
            html.to_str().unwrap(),
        ],
    );
    assert!(replayed.status.success());
    assert_eq!(
        recorded_bytes,
        fs::read(&trace).unwrap(),
        "rendering a trace changed its bytes — the render path is not read-only"
    );

    let page = fs::read_to_string(&html).unwrap();
    // Well-formed, self-contained HTML.
    assert!(page.starts_with("<!doctype html>"), "missing doctype");
    assert!(page.trim_end().ends_with("</html>"), "unterminated html");
    assert!(
        !page.contains("http://") && !page.contains("https://"),
        "external reference leaked"
    );
    assert!(!page.contains("<script"), "unexpected script tag");
    // The three spawned workers plus the main lane are rendered.
    assert!(page.contains("task 1") && page.contains("task 2") && page.contains("task 3"));
    // Event count on the page reflects the recorded timeline.
    let events = trace_event_count(&trace);
    assert!(
        page.contains(&format!("{events} events")),
        "event count not shown ({events})"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_run_json_envelope_has_stable_shape() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("json_guest.rs");
    fs::write(&source, RENDER_GUEST_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("json-guest");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("run.patina");
    let output = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "7",
            "--record",
            trace.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("--format json stdout was not a single JSON object: {error}\n{stdout}")
    });
    assert_eq!(value["schema"], "patina.result/v1");
    assert_eq!(value["verb"], "run");
    assert_eq!(value["family"], "native");
    assert_eq!(value["result"], "ok");
    assert_eq!(value["exit_code"], 0);
    assert_eq!(value["seed"], 7);
    assert_eq!(value["trace"]["format_version"], 4);
    assert!(value["trace"]["event_count"].as_u64().unwrap() > 0);
    // The guest's PATINA_RESULT line is captured and surfaced as a marker.
    assert!(
        value["markers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m.as_str().unwrap().starts_with("PATINA_RESULT")),
        "PATINA_RESULT marker missing from envelope: {value}"
    );
    // Metadata is rendered generically (seed + policy present).
    assert_eq!(value["trace"]["metadata"]["root_seed"], 7);
}

// A guest that fails loudly with a violation marker, to exercise the per-failure
// report and the `violation` classification.
const PLANTED_FAILURE_SOURCE: &str = r#"
fn main() {
    eprintln!("WORKQ_VIOLATION planted two-leaders term=4");
    std::process::exit(3);
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_planted_failure_emits_report_and_json_violation() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted.rs");
    fs::write(&source, PLANTED_FAILURE_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("planted");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("run.patina");
    let report = directory.path().join("report.html");
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "planted failure must propagate exit 3"
    );
    let page = fs::read_to_string(&report).unwrap();
    assert!(page.starts_with("<!doctype html>"));
    assert!(
        page.contains("Run failed"),
        "failure summary section missing"
    );
    assert!(
        page.contains("WORKQ_VIOLATION planted"),
        "violation line missing from report"
    );

    // The same run under --format json classifies as a violation and echoes the
    // result line.
    let trace2 = directory.path().join("run2.patina");
    let json = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace2.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(json.status.code(), Some(3));
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim()).unwrap();
    assert_eq!(value["result"], "violation");
    assert_eq!(value["exit_code"], 3);
    assert_eq!(
        value["result_line"],
        "WORKQ_VIOLATION planted two-leaders term=4"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_build_json_envelope_reports_output_and_hash() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("build_json.rs");
    fs::write(&source, "fn main() { println!(\"hi\"); }\n").unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("build-json");
    let output = invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(value["verb"], "build");
    assert_eq!(value["result"], "ok");
    assert_eq!(value["family"], "native");
    assert!(
        value["content_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        value["output_path"]
            .as_str()
            .unwrap()
            .ends_with("build-json")
    );
}

// `--render` on a plain seeded run (no trace on disk) is a clear error, not a
// silent no-op.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn render_without_a_trace_is_rejected() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("no_trace.rs");
    fs::write(&source, "fn main() { println!(\"hi\"); }\n").unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("no-trace");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let html = directory.path().join("out.html");
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--render",
            html.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("recorded or replayed trace"),
        "expected a clear no-trace error, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Count the events in the main timeline of a recorded trace file.
fn trace_event_count(trace: &Path) -> usize {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
    value["timelines"][0]["decisions"].as_array().unwrap().len()
}
