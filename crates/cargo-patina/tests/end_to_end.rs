use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
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

// Options and the artifact may appear in any order (the `cargo run` ergonomic):
// a registered flag before the module runs identically to the module-leading
// spelling; a real artifact stranded behind an UNKNOWN flag is a loud routing
// error; and a nonexistent artifact reached after a registered flag fails closed.
#[test]
fn run_accepts_options_before_the_wasi_artifact() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    fs::write(
        &module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let module = module.to_str().unwrap();

    // Artifact leads.
    let leading = invoke_unchecked(patina, directory.path(), &["run", module, "--seed", "7"]);
    assert!(
        leading.status.success(),
        "module-leading run failed: {}",
        String::from_utf8_lossy(&leading.stderr)
    );
    // A registered flag leads the artifact: identical success.
    let flag_first = invoke_unchecked(patina, directory.path(), &["run", "--seed", "7", module]);
    assert!(
        flag_first.status.success(),
        "flag-leading run failed: {}",
        String::from_utf8_lossy(&flag_first.stderr)
    );

    // A real artifact stranded behind an unknown flag is a loud routing error
    // naming the flag — never a silent Cargo fallthrough.
    let stranded = invoke_unchecked(patina, directory.path(), &["run", "--frob", module]);
    assert!(!stranded.status.success());
    assert!(
        String::from_utf8_lossy(&stranded.stderr).contains("--frob"),
        "stranded-artifact error should name the unknown flag: {}",
        String::from_utf8_lossy(&stranded.stderr)
    );

    // A path-like artifact that does not exist, reached after a registered flag,
    // fails closed rather than falling through to a confusing `cargo run`.
    let missing = invoke_unchecked(
        patina,
        directory.path(),
        &["run", "--seed", "1", "does-not-exist.wasm"],
    );
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("no such file"),
        "nonexistent artifact should fail closed: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
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

const WASI_FS_EIO_READ: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_filestat_get"
    (func $path_filestat_get (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT eio\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 25))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $errno i32)
    (local.set $errno
      (call $path_filestat_get
        (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 100)))
    (if (i32.ne (local.get $errno) (i32.const 29)) (then (call $proc_exit (local.get $errno))))
    (call $print)))"#;

const WASI_FS_ENOSPC_WRITE: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_create_directory"
    (func $path_create_directory (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "dir")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT enospc\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 28))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $errno i32)
    (local.set $errno (call $path_create_directory (i32.const 3) (i32.const 0) (i32.const 3)))
    (if (i32.ne (local.get $errno) (i32.const 51)) (then (call $proc_exit (local.get $errno))))
    (call $print)))"#;

const WASI_FS_SHORT_WRITE: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 16) "abcdef")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT short_write\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 33))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $fd i32) (local $errno i32) (local $n i32)
    (local.set $errno
      (call $path_open
        (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4)
        (i32.const 1) (i64.const 66) (i64.const 0) (i32.const 0) (i32.const 100)))
    (if (i32.ne (local.get $errno) (i32.const 0)) (then (call $proc_exit (local.get $errno))))
    (local.set $fd (i32.load (i32.const 100)))
    (i32.store (i32.const 64) (i32.const 16))
    (i32.store (i32.const 68) (i32.const 6))
    (local.set $errno (call $fd_write (local.get $fd) (i32.const 64) (i32.const 1) (i32.const 80)))
    (if (i32.ne (local.get $errno) (i32.const 0)) (then (call $proc_exit (local.get $errno))))
    (local.set $n (i32.load (i32.const 80)))
    (if (i32.eqz (local.get $n)) (then (call $proc_exit (i32.const 70))))
    (if (i32.ge_u (local.get $n) (i32.const 6)) (then (call $proc_exit (i32.const 71))))
    (call $print)))"#;

#[test]
fn wasi_fs_fault_errors_and_short_io_are_observable() {
    let directory = tempdir().unwrap();
    let eio = directory.path().join("eio.wasm");
    let enospc = directory.path().join("enospc.wasm");
    let short = directory.path().join("short.wasm");
    fs::write(&eio, wat::parse_str(WASI_FS_EIO_READ).unwrap()).unwrap();
    fs::write(&enospc, wat::parse_str(WASI_FS_ENOSPC_WRITE).unwrap()).unwrap();
    fs::write(&short, wat::parse_str(WASI_FS_SHORT_WRITE).unwrap()).unwrap();

    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    for (module, seed, flag, value, marker) in [
        (
            &eio,
            "1",
            "--fs-error-permille",
            "1000",
            "WASI_FS_FAULT_RESULT eio",
        ),
        (
            &enospc,
            "2",
            "--fs-error-permille",
            "1000",
            "WASI_FS_FAULT_RESULT enospc",
        ),
        (
            &short,
            "5",
            "--fs-short-permille",
            "1000",
            "WASI_FS_FAULT_RESULT short_write",
        ),
    ] {
        let output = invoke_unchecked(
            patina,
            directory.path(),
            &[
                "run",
                module.to_str().unwrap(),
                "--seed",
                seed,
                "--preopen",
                "/fs:rw",
                flag,
                value,
            ],
        );
        assert!(
            output.status.success(),
            "WASI fs fault module failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "missing marker {marker}:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
            "WASI fs fault run should be non-vacuous:\n{stderr}"
        );
    }
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

// Building the same package twice unchanged must hit Cargo's fingerprint cache
// the second time: the shim POSIX object (and the yield-point hook object under
// `--yield-points`) is staged at a stable content-addressed path in the shim's
// own target dir, not a fresh tempdir, so the `-Clink-arg=<object>` rustflag
// Cargo hashes into every crate fingerprint is byte-identical across runs. Cargo
// prints `Compiling` on stderr (which `build_native_package` inherits) only for
// crates it actually recompiles, so a cache hit leaves the second build's stderr
// free of any `Compiling` line.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn second_native_package_build_reuses_cargo_cache() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("pkg");
    create_package_fixture(directory.path());
    let workspace = native_workspace();
    let package = package.to_str().unwrap();
    let plain: &[&str] = &[
        "build",
        package,
        "--bin",
        "patina-native-pkg-fixture",
        "--release",
    ];
    let yielded: &[&str] = &[
        "build",
        package,
        "--bin",
        "patina-native-pkg-fixture",
        "--release",
        "--yield-points",
    ];

    // Cold build compiles the graph; the warm build must recompile nothing.
    invoke_in(workspace, plain);
    let warm = invoke_in(workspace, plain);
    let warm_stderr = String::from_utf8_lossy(&warm.stderr);
    assert!(
        !warm_stderr.contains("Compiling "),
        "second unchanged build recompiled the guest graph (cache miss):\n{warm_stderr}"
    );

    // The same must hold for `--yield-points`, whose second object is also
    // content-addressed rather than tempdir-staged.
    invoke_in(workspace, yielded);
    let warm_yield = invoke_in(workspace, yielded);
    let warm_yield_stderr = String::from_utf8_lossy(&warm_yield.stderr);
    assert!(
        !warm_yield_stderr.contains("Compiling "),
        "second unchanged --yield-points build recompiled the guest graph (cache miss):\n{warm_yield_stderr}"
    );
}

// Regression for the SlateDB dogfooding feedback: a dependency that declares
// `crate-type = ["rlib", "cdylib"]` (crc-fast 1.10.0 in the field report) makes
// Cargo build BOTH crate types even though the guest links only the rlib, and
// the cdylib runs a real link. The shim's link arguments must never reach it: on
// x86_64 Linux that link is refused outright (`relocation R_X86_64_PC32 cannot
// be used against symbol 'environ'`, from `patina_environ_base`), and on every
// platform the whole deterministic shim is force-included into a shared object
// nobody loads. Scoping the link arguments to `cargo rustc`'s trailing arguments
// confines them to the guest's own final link.
//
// The load-bearing assertion is the shim-symbol one, which goes red on macOS and
// Linux alike. The personality check is a realism guard — it keeps the
// dependency a stand-in for crc-fast rather than a trivial arithmetic crate —
// and is deliberately NOT claimed as the duplicate-symbol discriminator: a
// dependency like this still links clean under `-fPIC`, so that rung of the
// original report remains unreproduced synthetically (see
// `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`). Exercised under
// `--yield-points`, whose extra object travels the same path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_build_package_keeps_shim_link_args_off_a_dependency_cdylib() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("cdylib-pkg");
    create_cdylib_dependency_package_fixture(directory.path());
    let workspace = native_workspace();

    let output = package.join("cdylib-dep-bin");
    let built = invoke_in(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--yield-points",
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&built.stdout).contains("PATINA_NATIVE_BUILD"),
        "missing build marker:\n{}",
        String::from_utf8_lossy(&built.stdout)
    );
    assert!(output.is_file());

    let cdylib = find_dependency_cdylib(&package.join("Cargo.toml"));
    let cdylib_bytes = fs::read(&cdylib).unwrap();
    assert!(
        contains_symbol(&cdylib_bytes, b"rust_eh_personality"),
        "{} does not reference the unwind personality, so it could not have hit \
         the duplicate-symbol failure this fixture pins; the dependency needs \
         real landing pads",
        cdylib.display()
    );
    for symbol in SHIM_LINK_MARKER_SYMBOLS {
        assert!(
            !contains_symbol(&cdylib_bytes, symbol),
            "shim symbol {} leaked into the dependency cdylib {}: the shim link \
             arguments are reaching more than the guest's final link",
            String::from_utf8_lossy(symbol),
            cdylib.display()
        );
    }

    // The same markers must still be in the guest binary: scoping the link args
    // must not have weakened interposition on the artifact that matters.
    let guest_bytes = fs::read(&output).unwrap();
    for symbol in SHIM_LINK_MARKER_SYMBOLS {
        assert!(
            contains_symbol(&guest_bytes, symbol),
            "shim symbol {} missing from the guest binary {}",
            String::from_utf8_lossy(symbol),
            output.display()
        );
    }

    let result = String::from_utf8_lossy(
        &invoke_in(workspace, &["run", output.to_str().unwrap(), "--seed", "1"]).stdout,
    )
    .into_owned();
    assert!(
        result.contains("NATIVE_CDYLIB_DEP_RESULT"),
        "missing result marker: {result}"
    );
}

/// Symbols that exist only because the shim's C object and staticlib were on a
/// link line: the POSIX layer's constructor-retained `environ` accessor and the
/// `--yield-points` hook.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SHIM_LINK_MARKER_SYMBOLS: &[&[u8]] = &[b"patina_environ_base", b"patina_yield_point"];

/// Whether `image`'s symbol table names `symbol`. Symbol names are stored as
/// plain NUL-terminated strings in both Mach-O and ELF string tables, so a byte
/// search reads both without shelling out to `nm`/`objdump`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn contains_symbol(image: &[u8], symbol: &[u8]) -> bool {
    image.windows(symbol.len()).any(|window| window == symbol)
}

/// Locate the `cdylib-dep` shared library Cargo built alongside the guest.
/// Cargo may place intermediates outside `target/` (the `build-dir` setting), so
/// ask `cargo metadata` for both directories and search each.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_dependency_cdylib(manifest: &Path) -> std::path::PathBuf {
    let metadata = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .unwrap();
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata = String::from_utf8_lossy(&metadata.stdout).into_owned();
    let roots: Vec<String> = ["target_directory", "build_directory"]
        .iter()
        .filter_map(|key| {
            let needle = format!("\"{key}\":\"");
            let start = metadata.find(&needle)? + needle.len();
            let rest = &metadata[start..];
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect();
    assert!(
        !roots.is_empty(),
        "cargo metadata reported no build directories"
    );
    let mut found = Vec::new();
    for root in &roots {
        collect_files(Path::new(root), &mut found);
    }
    let mut cdylibs: Vec<std::path::PathBuf> = found
        .into_iter()
        .filter(|path| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("libcdylib_dep") && (name.ends_with(".so") || name.ends_with(".dylib"))
        })
        .collect();
    cdylibs.sort();
    assert!(
        !cdylibs.is_empty(),
        "no cdylib-dep shared library under {roots:?}; the dependency's cdylib \
         crate type was not built, so this fixture would pass vacuously"
    );
    cdylibs.remove(0)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collect_files(directory: &Path, into: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, into);
        } else {
            into.push(path);
        }
    }
}

// Source-first `audit` and `run` honor `--package`/`--bin` against a WORKSPACE
// manifest — the exact form the help advertises (`audit <Cargo.toml> --package X
// --bin Y`) and the one the bug report showed rejected. A virtual workspace (no
// root package) forces the selection: without `--package` the build cannot pick a
// member. `audit` builds the selected member with the shim linked and audits the
// true residual; `run` builds the same selection and executes it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn audit_and_run_select_workspace_member_with_package_and_bin() {
    let directory = tempdir().unwrap();
    let ws = directory.path().join("ws");
    fs::create_dir_all(ws.join("crates/app/src")).unwrap();
    fs::write(
        ws.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/app\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    fs::write(
        ws.join("crates/app/Cargo.toml"),
        "[package]\nname = \"patina-ws-app\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[[bin]]\nname = \"patina-ws-app\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    fs::write(
        ws.join("crates/app/src/main.rs"),
        "fn main() { println!(\"WORKSPACE_MEMBER_OK\"); }\n",
    )
    .unwrap();
    let manifest = ws.join("Cargo.toml");
    let build_workspace = native_workspace();

    // The bug's exact command: audit a workspace Cargo.toml with --package/--bin.
    // Previously rejected ("unsupported option \"--package\" for `audit`"); now it
    // builds the selected member's shim-linked binary and audits it (exit 0).
    invoke_in(
        build_workspace,
        &[
            "audit",
            manifest.to_str().unwrap(),
            "--package",
            "patina-ws-app",
            "--bin",
            "patina-ws-app",
        ],
    );

    // `run` honors the identical selection (source-first uniformity) and executes
    // the chosen member. `--target native` pins the native build-on-the-fly path
    // this fix wires the selection into. (A bare `Cargo.toml` with no `--target`
    // also builds native on the fly now, unless the package integrates the Patina
    // runtime — then it stays the cargo family; see the package-dir routing
    // tests above.)
    let ran = invoke_in(
        build_workspace,
        &[
            "run",
            manifest.to_str().unwrap(),
            "--target",
            "native",
            "--package",
            "patina-ws-app",
            "--bin",
            "patina-ws-app",
            "--seed",
            "1",
        ],
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("WORKSPACE_MEMBER_OK"),
        "missing member output:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );

    // `--package`/`--bin` do not apply to an already-built artifact: fail closed
    // with a precise message rather than silently ignoring the selection.
    let prebuilt = ws.join("prebuilt-bin");
    invoke_in(
        build_workspace,
        &[
            "build",
            manifest.to_str().unwrap(),
            "--package",
            "patina-ws-app",
            "--output",
            prebuilt.to_str().unwrap(),
        ],
    );
    let rejected = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        build_workspace,
        &["audit", prebuilt.to_str().unwrap(), "--package", "whatever"],
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("already-built artifact"),
        "missing prebuilt-selection diagnostic:\n{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

// Write a minimal plain Cargo package (no Patina dependency) with a single
// binary that prints `body`. Such a package integrates no runtime, so `run`/
// `replay` must build it shim-linked and run it under the native pre-run gate —
// never fall through to a toothless cargo-family `cargo run`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_plain_package(root: &Path, name: &str, main: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), main).unwrap();
}

// DEFECT 1 (parity/misroute): a `run <package-dir>` positional must resolve as a
// SOURCE — built on the fly and run — exactly like `audit <package-dir>`, never
// be silently reinterpreted as guest argv of some other package. The regression
// ran the CWD's package with the directory passed through as an argument. Here
// the run is issued FROM A DIFFERENT package's directory (a decoy that would have
// been run instead): the built guest's own marker must appear and the decoy's
// must not. This also proves the shim-staticlib build is pinned to the Patina
// source workspace (not the caller's CWD): building the positional package from a
// foreign CWD previously failed to locate `patina-dst-native-shim`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_package_dir_positional_resolves_as_source_not_cwd_package() {
    let directory = tempdir().unwrap();
    let target_pkg = directory.path().join("target-pkg");
    write_plain_package(
        &target_pkg,
        "patina-run-target-pkg",
        "fn main() { println!(\"TARGET_PKG_MARKER\"); }\n",
    );
    let decoy = directory.path().join("decoy");
    write_plain_package(
        &decoy,
        "patina-decoy-pkg",
        "fn main() { println!(\"DECOY_MARKER\"); }\n",
    );

    // Run the target package by path, from inside the decoy package's directory.
    let ran = invoke_in(
        &decoy,
        &["run", target_pkg.to_str().unwrap(), "--seed", "1"],
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("TARGET_PKG_MARKER"),
        "run <dir> did not build/run the positional package:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        !stdout.contains("DECOY_MARKER"),
        "run <dir> ran the CWD's package instead of the positional source:\n{stdout}"
    );
    assert!(
        stdout.contains("PATINA_BUILD_ON_RUN"),
        "missing build-on-run identity note:\n{stdout}"
    );

    // Shim-pinning corollary: `build .` from INSIDE the package directory now
    // succeeds (the shim staticlib is built from the Patina workspace, not the
    // caller's). The regression failed here with "building the
    // patina-dst-native-shim staticlib failed".
    let built = directory.path().join("built-in-place");
    let build = invoke_in(
        &target_pkg,
        &["build", ".", "--output", built.to_str().unwrap()],
    );
    assert!(
        String::from_utf8_lossy(&build.stdout).contains("PATINA_NATIVE_BUILD"),
        "`build .` from the package CWD failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(built.is_file());
}

// DEFECT 2 (silent drop): a package-mode `run <dir> --record` must actually
// produce a trace, and that trace must replay byte-identically. The regression
// silently ignored `--record` in cwd/package mode (exit 0, no file). Because a
// plain package now takes the native build-on-run path, recording is done by the
// supervisor exactly as for a prebuilt binary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_package_dir_records_and_replays_byte_identically() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("rec-pkg");
    write_plain_package(
        &pkg,
        "patina-rec-pkg",
        "fn main() { let a: Vec<String> = std::env::args().skip(1).collect(); \
         println!(\"REC_PKG args={a:?}\"); }\n",
    );
    let trace = directory.path().join("rec.patina");
    let recorded = invoke_in(
        &pkg,
        &[
            "run",
            pkg.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    assert!(
        trace.is_file(),
        "package-mode --record produced no trace (silent no-op):\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&recorded.stderr)
    );
    let replayed = invoke_in(
        &pkg,
        &["replay", pkg.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        stdout_line_with(&recorded, "REC_PKG"),
        stdout_line_with(&replayed, "REC_PKG"),
        "package-mode replay diverged from the recording",
    );
}

// DEFECT 3 (fail-open): `replay <dir> <trace>` with a missing/unreadable trace
// must hard-error BEFORE any guest execution, in every mode. The regression did a
// plain run and exited 0. Assert nonzero exit, a named trace error, and that the
// guest never ran (its marker is absent).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn replay_missing_trace_hard_errors_without_running_the_guest() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("replay-pkg");
    write_plain_package(
        &pkg,
        "patina-replay-pkg",
        "fn main() { println!(\"REPLAY_PKG_RAN\"); }\n",
    );
    let missing = directory.path().join("does-not-exist.patina");
    let out = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &["replay", pkg.to_str().unwrap(), missing.to_str().unwrap()],
    );
    assert!(
        !out.status.success(),
        "replay with a missing trace exited successfully (fail-open):\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("trace") && (stderr.contains("read") || stderr.contains("open")),
        "missing named trace-read error:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("REPLAY_PKG_RAN"),
        "replay ran the guest despite the unreadable trace:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// DEFECT 4 (SEVERE, gate bypass): package-mode `run <dir>` must apply the SAME
// pre-run default-deny symbol gate the prebuilt-binary path applies. The
// regression ran a denied-import guest to completion from package/cwd mode. A
// plain package that imports an uninterposed process-class symbol (`killpg`) is
// refused on BOTH paths, and the parity assertion checks both stderrs name the
// SAME symbol (one gate, not two independent checks).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_package_dir_and_prebuilt_gate_deny_the_same_symbol() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("gate-pkg");
    write_plain_package(
        &pkg,
        "patina-gate-pkg",
        // Imports `killpg` (process class, denied) behind an opaque branch so it
        // is never actually called but stays in the import table. `kill` itself is
        // now shim-defined (a deterministic-model interposer that drops off the
        // import table), so `killpg` is the still-uninterposed process-class member
        // the gate must flag.
        "unsafe extern \"C\" { fn killpg(pgrp: i32, sig: i32) -> i32; }\n\
         fn main() {\n\
         let g = std::hint::black_box(0i32);\n\
         if g != 0 { unsafe { killpg(g, 0); } }\n\
         println!(\"GATE_PKG_RAN\");\n\
         }\n",
    );

    // Prebuilt path: build the artifact, then run it.
    let bin = directory.path().join("gate-bin");
    invoke_in(
        &pkg,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let prebuilt = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    // Package/cwd path: run the directory directly.
    let dir_run = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &["run", pkg.to_str().unwrap(), "--seed", "1"],
    );

    for (label, out) in [("prebuilt", &prebuilt), ("package-dir", &dir_run)] {
        assert!(
            !out.status.success(),
            "{label} run of a denied-import guest was not refused:\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("GATE_PKG_RAN"),
            "{label} run executed the gated guest:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    // Parity: both stderrs name the SAME denied symbol/category line.
    let denied_line = |out: &Output| -> String {
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .find(|line| line.contains("(process)"))
            .unwrap_or_else(|| {
                panic!(
                    "no denied-symbol line in stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                )
            })
            .trim()
            .to_owned()
    };
    assert_eq!(
        denied_line(&prebuilt),
        denied_line(&dir_run),
        "the two paths named different denied symbols (gate not shared)",
    );
    assert!(denied_line(&prebuilt).contains("killpg"));
}

// DEFECT 4 corollary (cwd/no-positional): `cargo patina run --seed N` from inside
// a plain package's directory — the exact form the coordinator saw bypass the
// gate — must NOT silently run the guest. The cargo-family path links no runtime
// for a package that does not integrate Patina, so it refuses loudly and points
// at the native path rather than degrading to a plain `cargo run`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cwd_run_of_a_non_patina_package_is_refused_loudly() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("cwd-pkg");
    write_plain_package(
        &pkg,
        "patina-cwd-pkg",
        "fn main() { println!(\"CWD_PKG_RAN\"); }\n",
    );
    let out = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &["run", "--seed", "1"],
    );
    assert!(
        !out.status.success(),
        "cwd-mode run of a non-Patina package was not refused:\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("CWD_PKG_RAN"),
        "cwd-mode run executed the guest without a gate:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not depend on the Patina runtime")
            && stderr.contains("cargo patina run <DIR"),
        "missing loud refusal pointing at the native path:\n{stderr}"
    );
}

// `audit` reports exactly the static surface `run` enforces. The shim's `dlsym`
// control-plane vehicle — auto-allowed by the pre-run `run` gate — was reported by
// standalone `audit` as `_dlsym (dynamic-loading)` denied, the reported
// audit/run disparity. Both now audit against the shared effective-allow set, so a
// plain guest that imports `dlsym` is accepted by BOTH with no `--allow`, and
// `audit` no longer lists a dynamic-loading denial.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn audit_and_run_agree_on_the_shim_control_plane_symbol() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("parity.rs");
    fs::write(&source, "fn main() { println!(\"PARITY_OK\"); }").unwrap();
    let bin = directory.path().join("parity-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // audit with NO --allow now passes and reports no dynamic-loading (dlsym)
    // denial — before the parity fix this failed closed on the control-plane
    // vehicle that `run` silently permits.
    let audited = invoke_in(workspace, &["audit", bin.to_str().unwrap()]);
    let audit_out = String::from_utf8_lossy(&audited.stdout);
    assert!(
        !audit_out.contains("dynamic-loading"),
        "audit still reports the shim control-plane dlsym as denied:\n{audit_out}"
    );

    // run with NO --allow succeeds: the same symbol `run` enforces is the same one
    // `audit` accepted.
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("PARITY_OK"),
        "run did not execute the guest:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );
}

// A custom `#[global_allocator]` is SUPPORTED — it audits clean and runs
// deterministically, with no flags. This is the support regression for the
// tikv-jemallocator blocker: the shim's synchronization interposers register each
// lock in host-libc-backed tables (never the guest allocator), and an allocator's
// own `os_unfair_lock` runs natively during the bootstrap window / reentrantly
// under a held spinlock, so the allocator's init cannot re-enter the shim and
// deadlock. The fixture's allocator takes an interposed `os_unfair_lock` from
// INSIDE the global-allocator path (mimicking jemalloc's `malloc_mutex`), which is
// the exact reentrancy that used to deadlock: pre-fix, the shim's lock-table
// registration allocated through this very allocator; the RED proof is the real
// tikv-jemallocator MRE hanging/aborting when the fix is reverted (see the shim
// crate). macOS-specific (`os_unfair_lock`).
#[cfg(target_os = "macos")]
#[test]
fn native_run_supports_a_custom_global_allocator() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("custom-alloc.rs");
    fs::write(
        &source,
        r#"use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};

// `os_unfair_lock` is a bare `u32` (OS_UNFAIR_LOCK_INIT == 0), interposed by the
// shim. This allocator guards its one-time setup with it — reached from inside the
// global-allocator path, exactly like jemalloc's `malloc_mutex` during init.
unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut u32);
    fn os_unfair_lock_unlock(lock: *mut u32);
}

struct LockingAlloc { lock: UnsafeCell<u32>, ready: AtomicU32 }
unsafe impl Sync for LockingAlloc {}

unsafe impl GlobalAlloc for LockingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.ready.load(Ordering::Acquire) == 0 {
            unsafe { os_unfair_lock_lock(self.lock.get()) };
            self.ready.store(1, Ordering::Release);
            unsafe { os_unfair_lock_unlock(self.lock.get()) };
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { unsafe { System.dealloc(ptr, layout) } }
}

#[global_allocator]
static GLOBAL: LockingAlloc = LockingAlloc { lock: UnsafeCell::new(0), ready: AtomicU32::new(0) };

fn main() { let v: Vec<u8> = vec![1, 2, 3]; println!("CUSTOM_ALLOC_OK len={}", v.len()); }
"#,
    )
    .unwrap();
    let bin = directory.path().join("custom-alloc-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Audits clean with NO flags: a custom global allocator is no longer refused.
    let audited = invoke_in(workspace, &["audit", bin.to_str().unwrap()]);
    assert!(
        !String::from_utf8_lossy(&audited.stderr).contains("custom-global-allocator"),
        "custom global allocator is still refused by audit:\n{}",
        String::from_utf8_lossy(&audited.stderr)
    );

    // Runs with NO flags and prints — the allocator's interposed `os_unfair_lock`
    // never re-enters the shim.
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("CUSTOM_ALLOC_OK len=3"),
        "custom-allocator guest did not run:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );

    // Deterministic: two same-seed runs are byte-identical.
    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(
        ran.stdout, again.stdout,
        "custom-allocator run is not seed-stable"
    );
}

// `localtime_r` (the `time`/`chrono` crates' local-offset path) is interposed as
// a PURE UTC conversion: fixed timezone, tm_gmtoff=0, tm_zone="UTC". A guest that
// breaks down a fixed time_t sees the exact civil fields with no dependence on
// the host timezone, and two same-seed runs are byte-identical. Before the change
// `localtime_r` was an uninterposed `time`-class import and the run was refused
// before `main`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_localtime_r_is_pure_utc_and_deterministic() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("localtime.rs");
    fs::write(
        &source,
        r#"use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_long};

#[repr(C)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

unsafe extern "C" {
    fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
}

fn main() {
    // 2001-09-09 01:46:40 UTC — a Sunday, day-of-year 251.
    let t: i64 = 1_000_000_000;
    let mut tm: Tm = unsafe { std::mem::zeroed() };
    let returned = unsafe { localtime_r(&t, &mut tm) };
    assert!(!returned.is_null(), "localtime_r returned null");
    let zone = unsafe { CStr::from_ptr(tm.tm_zone) }.to_str().unwrap();
    println!(
        "LT y={} mon={} mday={} h={} m={} s={} wday={} yday={} isdst={} gmtoff={} zone={}",
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday,
        tm.tm_yday, tm.tm_isdst, tm.tm_gmtoff, zone
    );
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("localtime-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let out = String::from_utf8_lossy(&ran.stdout);
    assert!(
        out.contains(
            "LT y=101 mon=8 mday=9 h=1 m=46 s=40 wday=0 yday=251 isdst=0 gmtoff=0 zone=UTC"
        ),
        "localtime_r did not produce the exact UTC fields:\nstdout:\n{out}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );

    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(
        ran.stdout, again.stdout,
        "localtime_r run is not seed-stable"
    );
}

// Build a single-file native source, run it twice at the same seed, assert the
// two runs are byte-identical, and hand back the stdout. Used by the
// dormant-surface conversion tests below (native-trust-root, host-inventory,
// local-timezone, kill/if_nametoindex): each source calls the converted C
// symbols directly (the extern-"C" fixture form the localtime_r test uses) and
// prints its result. Before the conversion each of those calls hit a shim
// deny-trap that aborts before printing, so `invoke_in`'s success assertion
// fails; after it, the printed result is deterministic.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native_source_prints_deterministically(source_name: &str, source: &str) -> String {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let src = directory.path().join(source_name);
    fs::write(&src, source).unwrap();
    let bin = directory.path().join("dormant-bin");
    invoke_in(
        workspace,
        &[
            "build",
            src.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(
        ran.stdout, again.stdout,
        "same-seed runs of {source_name} are not byte-identical"
    );
    String::from_utf8_lossy(&ran.stdout).into_owned()
}

// Native-trust-root surface (rustls-native-certs' `load_native_certs()`): the
// shim returns `errSecNoTrustSettings` from `SecTrustSettingsCopyCertificates`
// for every domain, so security-framework maps each to an EMPTY certificate
// iterator (built via an empty `CFArrayCreate`/`CFArrayGetCount`/`CFRelease`) and
// the loader yields zero certs and zero errors — a locked-down host. The guest
// mirrors that exact reachable sequence across the User/Admin/System domains.
// Before the conversion `SecTrustSettingsCopyCertificates` was a deny-trap and
// the run aborted with "host-introspection/macos-framework reached under patina".
#[cfg(target_os = "macos")]
#[test]
fn native_trust_root_surface_is_deterministically_empty() {
    let out = native_source_prints_deterministically(
        "certs.rs",
        r#"use std::os::raw::{c_long, c_void};
use std::ptr;

unsafe extern "C" {
    fn SecTrustSettingsCopyCertificates(domain: u32, out: *mut *const c_void) -> i32;
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        num_values: c_long,
        callbacks: *const c_void,
    ) -> *const c_void;
    fn CFArrayGetCount(array: *const c_void) -> c_long;
    fn CFRelease(cf: *const c_void);
}

fn main() {
    let mut total_certs: c_long = 0;
    let mut errors = 0;
    // Domain::User = 1, Admin = 2, System = 3 (security-framework order).
    for domain in [1u32, 2, 3] {
        let mut array_ptr: *const c_void = ptr::null();
        let status = unsafe { SecTrustSettingsCopyCertificates(domain, &mut array_ptr) };
        if status != -25263 {
            errors += 1;
            continue;
        }
        // errSecNoTrustSettings -> empty CFArray (CFArray::from_CFTypes(&[])).
        let array = unsafe { CFArrayCreate(ptr::null(), ptr::null(), 0, ptr::null()) };
        total_certs += unsafe { CFArrayGetCount(array) };
        unsafe { CFRelease(array) };
    }
    println!("certs={total_certs} errors={errors}");
}
"#,
    );
    assert!(
        out.contains("certs=0 errors=0"),
        "native trust-root surface did not resolve to an empty deterministic result:\n{out}"
    );
}

// Host-inventory surface (sysinfo's `System::new_all()`): the shim returns fixed
// deterministic Mach/BSD values — `host_statistics64` KERN_SUCCESS with the 8 GiB
// VM model, `host_processor_info` a single-CPU load block (so `cpus().len() == 1`
// consistent with sysctl HW_NCPU=1), `proc_listallpids` the self-only pid, and a
// NULL `IOServiceMatching` (CPU frequency unknown). The guest exercises that
// reachable set directly. Before the conversion each was a host-introspection
// deny-trap and the run aborted before printing.
#[cfg(target_os = "macos")]
#[test]
fn host_inventory_surface_is_deterministic() {
    let out = native_source_prints_deterministically(
        "hostinfo.rs",
        r#"use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

unsafe extern "C" {
    fn mach_host_self() -> c_uint;
    fn host_statistics64(host: c_uint, flavor: c_int, out: *mut c_void, count: *mut c_uint) -> c_int;
    fn host_processor_info(
        host: c_uint,
        flavor: c_int,
        out_count: *mut c_uint,
        out_info: *mut *mut c_int,
        out_info_count: *mut c_uint,
    ) -> c_int;
    fn vm_deallocate(task: c_uint, addr: usize, size: usize) -> c_int;
    fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn IOServiceMatching(name: *const c_char) -> *const c_void;
}

fn main() {
    let port = unsafe { mach_host_self() };

    const HOST_VM_INFO64: c_int = 4;
    let mut stat = [0u8; 1024];
    let mut count: c_uint = 256;
    let vm = unsafe {
        host_statistics64(port, HOST_VM_INFO64, stat.as_mut_ptr() as *mut c_void, &mut count)
    };

    const PROCESSOR_CPU_LOAD_INFO: c_int = 2;
    let mut ncpu: c_uint = 0;
    let mut info: *mut c_int = ptr::null_mut();
    let mut info_count: c_uint = 0;
    let cpu = unsafe {
        host_processor_info(port, PROCESSOR_CPU_LOAD_INFO, &mut ncpu, &mut info, &mut info_count)
    };
    if cpu == 0 && !info.is_null() {
        // Free the buffer via vm_deallocate (the shim no-ops it); task port is ignored.
        unsafe { vm_deallocate(0, info as usize, (info_count as usize) * 4) };
    }

    let pids = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    let iokit = unsafe { IOServiceMatching(b"AppleARMIODevice\0".as_ptr() as *const c_char) };

    println!(
        "vm={vm} cpu={cpu} ncpu={ncpu} pids={pids} iokit_null={}",
        iokit.is_null()
    );
}
"#,
    );
    assert!(
        out.contains("vm=0 cpu=0 ncpu=1 pids=1 iokit_null=true"),
        "host-inventory surface did not resolve to the fixed deterministic values:\n{out}"
    );
}

// Local-timezone surface (iana-time-zone / chrono `Local`): the runtime models a
// single fixed timezone, UTC (matching the localtime_r interposer), so
// `CFTimeZoneCopySystem`/`GetName`/`CFStringGetCStringPtr` report "UTC"
// deterministically and iana-time-zone's `get_timezone()` returns Ok("UTC"). The
// guest walks tz_darwin.rs's exact call sequence. Before the conversion
// `CFTimeZoneCopySystem` was a deny-trap and the run aborted before printing.
#[cfg(target_os = "macos")]
#[test]
fn local_timezone_surface_reports_utc() {
    let out = native_source_prints_deterministically(
        "timezone.rs",
        r#"use std::ffi::CStr;
use std::os::raw::{c_char, c_uint, c_void};

unsafe extern "C" {
    fn CFTimeZoneResetSystem();
    fn CFTimeZoneCopySystem() -> *const c_void;
    fn CFTimeZoneGetName(tz: *const c_void) -> *const c_void;
    fn CFStringGetCStringPtr(string: *const c_void, encoding: c_uint) -> *const c_char;
    fn CFRelease(cf: *const c_void);
}

fn main() {
    unsafe { CFTimeZoneResetSystem() };
    let tz = unsafe { CFTimeZoneCopySystem() };
    assert!(!tz.is_null(), "CFTimeZoneCopySystem returned null");
    let name = unsafe { CFTimeZoneGetName(tz) };
    assert!(!name.is_null(), "CFTimeZoneGetName returned null");
    const K_CF_STRING_ENCODING_UTF8: c_uint = 0x0800_0100;
    let ptr = unsafe { CFStringGetCStringPtr(name, K_CF_STRING_ENCODING_UTF8) };
    assert!(!ptr.is_null(), "CFStringGetCStringPtr returned null");
    let zone = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { CFRelease(tz) };
    println!("tz={zone}");
}
"#,
    );
    assert!(
        out.contains("tz=UTC"),
        "local-timezone surface did not resolve to the modeled UTC zone:\n{out}"
    );
}

// Cross-platform members: `kill` in the single-process world is an existence
// probe (self/pid 1 alive; any other pid ESRCH) and `if_nametoindex` reports no
// such interface (0 + ENXIO). Before the conversion both were deny-traps that
// aborted the run.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn kill_and_if_nametoindex_are_deterministic_errors() {
    let out = native_source_prints_deterministically(
        "killiface.rs",
        r#"use std::io::Error;
use std::os::raw::{c_char, c_int, c_uint};

unsafe extern "C" {
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn if_nametoindex(name: *const c_char) -> c_uint;
}

fn main() {
    let self_alive = unsafe { kill(1, 0) };
    let other = unsafe { kill(4242, 0) };
    let other_errno = Error::last_os_error().raw_os_error().unwrap_or(0);
    let idx = unsafe { if_nametoindex(b"patina-nope0\0".as_ptr() as *const c_char) };
    let idx_errno = Error::last_os_error().raw_os_error().unwrap_or(0);
    // ESRCH = 3, ENXIO = 6 on both Linux and macOS.
    println!(
        "self_alive={self_alive} other={other} other_esrch={} idx={idx} idx_enxio={}",
        other_errno == 3,
        idx_errno == 6
    );
}
"#,
    );
    assert!(
        out.contains("self_alive=0 other=-1 other_esrch=true idx=0 idx_enxio=true"),
        "kill/if_nametoindex did not resolve to the deterministic error shape:\n{out}"
    );
}

// `sleep` (mimalloc's yield fallback) is interposed onto the virtual clock: it
// returns 0 promptly under virtual time and the run completes rather than
// blocking a real host thread. Before the change `sleep` was an uninterposed
// `time`-class import and the run was refused before `main`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_sleep_uses_virtual_clock_and_returns_promptly() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("sleep.rs");
    fs::write(
        &source,
        r#"unsafe extern "C" {
    fn sleep(seconds: u32) -> u32;
}

fn main() {
    // A one-hour sleep completes instantly under the virtual clock, returning 0
    // (no seconds remaining). sleep(0) is mimalloc's actual yield-fallback call.
    let remaining = unsafe { sleep(3600) };
    let zero = unsafe { sleep(0) };
    println!("SLEEP remaining={remaining} zero={zero} done");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("sleep-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("SLEEP remaining=0 zero=0 done"),
        "sleep did not return promptly under virtual time:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

// `getrusage(RUSAGE_SELF)` reports MODEL-DERIVED CPU time, not a fixed zero: the
// interposer fills ru_utime from the deterministic virtual clock
// (patina_cpu_time_nanos). A guest that does virtual-clock work between two reads
// sees the second reading STRICTLY GREATER, and two same-seed runs are
// byte-identical. Before the model wiring both reads were 0 (static memset) and
// the strict-increase assertion failed — the RED that pinned this behavior. ru_sec
// is the first field of `struct timeval` / `struct rusage` (a `time_t`, 8 bytes,
// on both platforms), so reading offset 0 as an i64 is layout-portable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_getrusage_reports_deterministic_model_cpu_time() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("rusage.rs");
    fs::write(
        &source,
        r#"use std::os::raw::c_int;

unsafe extern "C" {
    fn getrusage(who: c_int, usage: *mut u8) -> c_int;
    fn sleep(seconds: u32) -> u32;
}

const RUSAGE_SELF: c_int = 0;

// Read ru_utime.tv_sec — the first 8 bytes of `struct rusage` on both platforms.
fn utime_secs() -> i64 {
    let mut buf = [0u8; 256];
    let rc = unsafe { getrusage(RUSAGE_SELF, buf.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage failed");
    i64::from_ne_bytes(buf[0..8].try_into().unwrap())
}

fn main() {
    let before = utime_secs();
    // Advance the virtual clock deterministically (whole seconds so tv_sec moves).
    let _ = unsafe { sleep(5) };
    let after = utime_secs();
    println!("RU before={before} after={after}");
    assert!(
        after > before,
        "getrusage CPU time did not strictly advance: {before} -> {after}"
    );
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("rusage-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let out = String::from_utf8_lossy(&ran.stdout);
    assert!(
        out.contains("RU before=0 after=5"),
        "getrusage did not report the modeled virtual-clock CPU time:\nstdout:\n{out}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );

    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(ran.stdout, again.stdout, "getrusage run is not seed-stable");
}

// task_info(MACH_TASK_BASIC_INFO) reports MODEL-DERIVED user_time from the same
// deterministic clock model as getrusage (patina_cpu_time_nanos), not a fixed
// zero. Same shape as the getrusage RED: a guest that does virtual-clock work
// between two reads sees user_time strictly increase, byte-identically across
// same-seed runs. macOS only (task_info is Mach). user_time.seconds sits at byte
// offset 24 of `struct mach_task_basic_info` (after three 8-byte vm sizes) and is
// an `integer_t` (i32); the flavor is 20 with a 12-word count.
#[cfg(target_os = "macos")]
#[test]
fn native_task_info_reports_deterministic_model_cpu_time() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("taskinfo.rs");
    fs::write(
        &source,
        r#"use std::os::raw::c_int;

unsafe extern "C" {
    fn task_info(target: u32, flavor: u32, info: *mut u8, count: *mut u32) -> c_int;
    fn sleep(seconds: u32) -> u32;
}

const MACH_TASK_BASIC_INFO: u32 = 20;
const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
const KERN_SUCCESS: c_int = 0;

// user_time.seconds is at offset 24 (three 8-byte vm sizes precede it).
fn user_time_secs() -> i32 {
    let mut buf = [0u8; 256];
    let mut count = MACH_TASK_BASIC_INFO_COUNT;
    let rc = unsafe { task_info(0, MACH_TASK_BASIC_INFO, buf.as_mut_ptr(), &mut count) };
    assert_eq!(rc, KERN_SUCCESS, "task_info failed");
    i32::from_ne_bytes(buf[24..28].try_into().unwrap())
}

fn main() {
    let before = user_time_secs();
    let _ = unsafe { sleep(5) };
    let after = user_time_secs();
    println!("TI before={before} after={after}");
    assert!(
        after > before,
        "task_info user_time did not strictly advance: {before} -> {after}"
    );
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("taskinfo-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let out = String::from_utf8_lossy(&ran.stdout);
    assert!(
        out.contains("TI before=0 after=5"),
        "task_info did not report the modeled virtual-clock CPU time:\nstdout:\n{out}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );

    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(ran.stdout, again.stdout, "task_info run is not seed-stable");
}

// libc `FILE*` stdio (`fputs`/`fprintf`/`fwrite` to the `stdout`/`stderr`
// sentinels — mimalloc + aws-lc error output) routes to the deterministic
// captured stdio: stdout writes land on the run's captured stdout, stderr writes
// on captured stderr, byte-identically across runs. Before the change these were
// uninterposed `unknown-import` symbols (`fputs`/`fprintf`/`fwrite` and the
// `__stdoutp`/`__stderrp`/`stdout`/`stderr` data symbols) and the run was refused.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_libc_file_stdio_routes_to_captured_streams() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("stdio.rs");
    fs::write(
        &source,
        r#"use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

unsafe extern "C" {
    fn fputs(string: *const c_char, stream: *mut c_void) -> c_int;
    fn fprintf(stream: *mut c_void, format: *const c_char, ...) -> c_int;
    fn fwrite(pointer: *const c_void, size: usize, count: usize, stream: *mut c_void) -> usize;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static __stdoutp: *mut c_void;
    static __stderrp: *mut c_void;
}
#[cfg(target_os = "linux")]
unsafe extern "C" {
    static stdout: *mut c_void;
    static stderr: *mut c_void;
}

#[cfg(target_os = "macos")]
fn streams() -> (*mut c_void, *mut c_void) {
    unsafe { (__stdoutp, __stderrp) }
}
#[cfg(target_os = "linux")]
fn streams() -> (*mut c_void, *mut c_void) {
    unsafe { (stdout, stderr) }
}

fn main() {
    let (out, err) = streams();
    let line = CString::new("FPUTS_OUT line\n").unwrap();
    unsafe { fputs(line.as_ptr(), out) };
    let fmt = CString::new("FPRINTF n=%d\n").unwrap();
    unsafe { fprintf(out, fmt.as_ptr(), 42) };
    let e = CString::new("FWRITE_ERR line\n").unwrap();
    unsafe { fwrite(e.as_ptr() as *const c_void, 1, e.as_bytes().len(), err) };
    println!("STDIO_DONE");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("stdio-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let out = String::from_utf8_lossy(&ran.stdout);
    let err = String::from_utf8_lossy(&ran.stderr);
    assert!(
        out.contains("FPUTS_OUT line")
            && out.contains("FPRINTF n=42")
            && out.contains("STDIO_DONE"),
        "stdout-sentinel writes did not reach captured stdout:\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        err.contains("FWRITE_ERR line"),
        "stderr-sentinel write did not reach captured stderr:\nstdout:\n{out}\nstderr:\n{err}"
    );
    let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(
        ran.stdout, again.stdout,
        "stdio run is not seed-stable (stdout)"
    );
    assert_eq!(
        ran.stderr, again.stderr,
        "stdio run is not seed-stable (stderr)"
    );
}

// `pthread_once` (aws-lc's lazy init) runs the init routine exactly once through
// the shim-side registry keyed on the control-block address, guarded by the
// deterministic scheduler's mutex/condvar. Two calls on the same control block
// run the init exactly once. Before the change `pthread_once` was an uninterposed
// `unknown-import` and the run was refused before `main`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_pthread_once_runs_init_exactly_once() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("once.rs");
    fs::write(
        &source,
        r#"use std::os::raw::c_int;
use std::sync::atomic::{AtomicU32, Ordering};

// 16 bytes with 8-byte alignment covers both pthread_once_t layouts (glibc's
// bare int and Darwin's signature-word struct). The shim keys on the address and
// ignores the contents, so zeroed storage is valid under the interposed once.
#[repr(C, align(8))]
struct Once([u8; 16]);

unsafe extern "C" {
    fn pthread_once(once_control: *mut Once, init_routine: extern "C" fn()) -> c_int;
}

static COUNT: AtomicU32 = AtomicU32::new(0);
extern "C" fn init() {
    COUNT.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    static mut ONCE: Once = Once([0u8; 16]);
    let control = &raw mut ONCE;
    let a = unsafe { pthread_once(control, init) };
    let b = unsafe { pthread_once(control, init) };
    println!("ONCE a={a} b={b} count={}", COUNT.load(Ordering::SeqCst));
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("once-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("ONCE a=0 b=0 count=1"),
        "pthread_once did not run the init exactly once:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

// macOS `sysctlbyname`/`sysctl` (mimalloc, sysinfo, aws-lc) serve a small set of
// known keys as fixed world-model constants and fail unmodeled keys with a
// deterministic ENOENT. Before the change `sysctlbyname` was an uninterposed
// `host-introspection` import and the run was refused before `main`.
#[cfg(target_os = "macos")]
#[test]
fn native_sysctlbyname_serves_fixed_values_and_fails_unknown() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("sysctl.rs");
    fs::write(
        &source,
        r#"use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
}

fn query_i64(key: &str) -> (c_int, i64) {
    let name = CString::new(key).unwrap();
    let mut value: i64 = -1;
    let mut len = std::mem::size_of::<i64>();
    let r = unsafe {
        sysctlbyname(
            name.as_ptr(),
            &mut value as *mut i64 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (r, value)
}

fn query_i32(key: &str) -> (c_int, i32) {
    let name = CString::new(key).unwrap();
    let mut value: i32 = -1;
    let mut len = std::mem::size_of::<i32>();
    let r = unsafe {
        sysctlbyname(
            name.as_ptr(),
            &mut value as *mut i32 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (r, value)
}

fn main() {
    let (mem_r, mem) = query_i64("hw.memsize");
    let (ncpu_r, ncpu) = query_i32("hw.ncpu");
    let unknown = CString::new("hw.this.key.does.not.exist").unwrap();
    let mut junk: i64 = 0;
    let mut junk_len = std::mem::size_of::<i64>();
    let unknown_r = unsafe {
        sysctlbyname(
            unknown.as_ptr(),
            &mut junk as *mut i64 as *mut c_void,
            &mut junk_len,
            std::ptr::null_mut(),
            0,
        )
    };
    println!("MEMSIZE r={mem_r} val={mem} NCPU r={ncpu_r} val={ncpu} UNKNOWN r={unknown_r}");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("sysctl-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        String::from_utf8_lossy(&ran.stdout)
            .contains("MEMSIZE r=0 val=8589934592 NCPU r=0 val=1 UNKNOWN r=-1"),
        "sysctlbyname did not serve fixed values / fail unknown key deterministically:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
}

// A guest importing a macOS Security-framework symbol that the shim does NOT
// deny-trap is classified `macos-framework` and refused with a determinism note
// that names the host-trust-store problem and the explicit allow path. `audit`
// reports the same class. The representative is `SecTrustEvaluateWithError`,
// deliberately NOT one of the enumerated dormant rustls-native-certs symbols
// (`SecTrustSettingsCopy*`, `SecCertificateCopyData`, the `CF*` helpers): those
// are now shim-defined (honest returns or documented traps) and drop off the
// import table, so a still-refused (non-enumerated) framework symbol is what
// exercises the pre-run refusal path.
// macOS-only: the Security framework and its symbols do not exist on Linux (there
// the import is a bare unknown, still denied).
#[cfg(target_os = "macos")]
#[test]
fn native_gate_classifies_and_refuses_a_security_framework_symbol() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("sec.rs");
    fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTrustEvaluateWithError(trust: *const c_void, error: *mut *const c_void) -> bool;
}
fn main() {
    let mut error: *const c_void = std::ptr::null();
    let ok = unsafe { SecTrustEvaluateWithError(std::ptr::null(), &mut error) };
    println!("SEC ok={ok}");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("sec-bin");
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
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("macos-framework"),
        "missing macos-framework class:\n{stderr}"
    );
    assert!(
        stderr.contains("keychain") || stderr.contains("trust store"),
        "missing host-trust-store determinism note:\n{stderr}"
    );
    assert!(
        stderr.contains("--allow-unsupported-symbols"),
        "missing explicit allow path:\n{stderr}"
    );

    let audited = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", bin.to_str().unwrap()],
    );
    assert!(!audited.status.success());
    assert!(
        String::from_utf8_lossy(&audited.stderr).contains("macos-framework"),
        "audit did not report the macos-framework class:\n{}",
        String::from_utf8_lossy(&audited.stderr)
    );
}

// A guest that LINKS the enumerated dormant native-trust-root / host-inventory
// surface (`SecTrustSettingsCopyCertificates` + `CFRelease` + `IOServiceMatching`)
// but never reaches it — the references sit behind a runtime-false branch so they
// are real imports the linker must resolve — RUNS to completion. Those symbols are
// now shim-defined (honest deterministic returns): a strong def binds each
// reference at link (dropping it off the import table), so the pre-run gate passes
// whether the path is dormant (here) or live (the conversion tests above). This is
// the Issue-1/Issue-2 fix: an unrelated scenario no longer needs
// `--allow-unsupported-symbols` just because the binary links optional TLS-trust /
// host-inventory code. macOS-only (the symbols are Darwin framework/Mach names).
#[cfg(target_os = "macos")]
#[test]
fn native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("dormant.rs");
    fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "Security", kind = "framework")]
#[link(name = "CoreFoundation", kind = "framework")]
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn SecTrustSettingsCopyCertificates(domain: i32, out: *mut *const c_void) -> i32;
    fn CFRelease(cf: *const c_void);
    fn IOServiceMatching(name: *const u8) -> *mut c_void;
}
fn main() {
    // A runtime-false branch keeps the three symbols as real imports (the linker
    // must resolve them) without ever calling them.
    if std::hint::black_box(false) {
        let mut out: *const c_void = std::ptr::null();
        unsafe { SecTrustSettingsCopyCertificates(0, &mut out) };
        unsafe { CFRelease(out) };
        let _ = unsafe { IOServiceMatching(b"x\0".as_ptr()) };
    }
    println!("DORMANT_PATH_OK");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("dormant-bin");
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
    assert!(
        ran.status.success(),
        "a guest with only a DORMANT framework path must run:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("DORMANT_PATH_OK"),
        "the dormant-path guest must reach its marker:\nstdout:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );
}

// Task #52 ("fails later" must be visible up front): a guest that references a
// deny-trap-armed symbol behind a runtime-false branch passes both the import
// audit and the pre-run gate (the shim strong-def drops the symbol off the import
// table), so nothing today warns that a call would abort. `audit` AND `run` now
// print a non-blocking stderr note naming EXACTLY the referenced armed symbol and
// its class, so the "fails later" contract is visible before the guest launches —
// while the dormant guest still runs to completion (the note never blocks).
// The note's precision relies on the final link dead-stripping an *unreferenced*
// trap so a defined match means the guest genuinely references it. Only ld64 can do
// that (atom granularity), so this test is macOS-only: on ELF every libc-shadowing
// definition is auto-exported to `.dynsym` (that export is what lets the shim
// interpose glibc-internal calls at all) and a dynamic-exported symbol is a
// permanent GC root, so the ELF note truthfully reports the full armed union
// instead (see `native_deny_trap_armed`).
#[cfg(target_os = "macos")]
#[test]
fn native_audit_and_run_note_a_referenced_deny_trap_symbol() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("armed.rs");
    fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceGetMatchingServices(master: u32, matching: *const c_void, existing: *mut u32) -> i32;
}
fn main() {
    // A runtime-false branch keeps IOServiceGetMatchingServices a real reference
    // the linker resolves (so the trap symbol is defined) without ever calling it.
    if std::hint::black_box(false) {
        let mut it: u32 = 0;
        let _ = unsafe { IOServiceGetMatchingServices(0, std::ptr::null(), &mut it) };
    }
    println!("ARMED_DORMANT_OK");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("armed-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // audit: succeeds (exit 0), and the note names exactly the referenced symbol.
    let audited = invoke_in(workspace, &["audit", bin.to_str().unwrap()]);
    let audit_stderr = String::from_utf8_lossy(&audited.stderr);
    assert!(
        audit_stderr.contains("deny-trap armed")
            && audit_stderr.contains("IOServiceGetMatchingServices (host-introspection)"),
        "audit must note the referenced deny-trap symbol up front:\n{audit_stderr}"
    );

    // run: the same note, and the dormant guest still runs to completion.
    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let run_stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        run_stderr.contains("IOServiceGetMatchingServices (host-introspection)"),
        "run must note the referenced deny-trap symbol up front:\n{run_stderr}"
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("ARMED_DORMANT_OK"),
        "the note is non-blocking: the dormant-path guest must still run to completion:\nstdout:\n{}",
        String::from_utf8_lossy(&ran.stdout)
    );
}

// The negative: a guest that references NO deny-trap symbol emits NO note at audit
// or at run — the note must not be noise on an ordinary binary. macOS-gated for
// the same dead-strip reason as the positive case above.
#[cfg(target_os = "macos")]
#[test]
fn native_audit_and_run_emit_no_deny_trap_note_when_none_referenced() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("plain.rs");
    fs::write(
        &source,
        r#"fn main() { println!("PLAIN_OK"); }
"#,
    )
    .unwrap();
    let bin = directory.path().join("plain-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let audited = invoke_in(workspace, &["audit", bin.to_str().unwrap()]);
    assert!(
        !String::from_utf8_lossy(&audited.stderr).contains("deny-trap armed"),
        "audit must emit no deny-trap note for a guest that references none:\n{}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let ran = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert!(
        !String::from_utf8_lossy(&ran.stderr).contains("deny-trap armed"),
        "run must emit no deny-trap note for a guest that references none:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("PLAIN_OK"),
        "the plain guest must run to completion"
    );
}

// `run --release` must reprofile the GUEST for a single `.rs` source, not just the
// shim staticlib: a `debug_assert!` is a live failure oracle under the default
// (debug) build and compiled out under `--release`, exactly as it is for a package
// guest. The debug leg here is also the pre-fix release behavior — before the
// release profile was threaded into the single-source `rustc` invocation, a
// `run --release <source.rs>` produced a byte-for-byte debug guest, so its assert
// fired identically. That makes the release-clean assertion below non-vacuous: it
// can only pass because the fix strips the assert.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_single_source_release_strips_debug_asserts() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("assert-guest.rs");
    fs::write(
        &source,
        r#"fn main() {
    debug_assert!(false, "SINGLE_SOURCE_DEBUG_ASSERT");
    println!("SINGLE_SOURCE_RELEASE_CLEAN");
}
"#,
    )
    .unwrap();

    // Default (debug) build-on-run: the debug_assert fires, aborting the guest.
    let debug = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", source.to_str().unwrap(), "--seed", "0"],
    );
    assert!(
        !debug.status.success(),
        "default single-source run must fire the debug_assert:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&debug.stdout),
        String::from_utf8_lossy(&debug.stderr)
    );
    assert!(
        String::from_utf8_lossy(&debug.stderr).contains("SINGLE_SOURCE_DEBUG_ASSERT"),
        "the debug run must name the fired assert:\n{}",
        String::from_utf8_lossy(&debug.stderr)
    );

    // `--release` build-on-run: the debug_assert is compiled out, so the guest
    // reaches its clean exit — proof the guest itself (not only the shim) was built
    // release.
    let release = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", "--release", source.to_str().unwrap(), "--seed", "0"],
    );
    assert!(
        release.status.success(),
        "single-source run --release must compile out the debug_assert:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&release.stdout),
        String::from_utf8_lossy(&release.stderr)
    );
    assert!(
        String::from_utf8_lossy(&release.stdout).contains("SINGLE_SOURCE_RELEASE_CLEAN"),
        "the release guest must run to its clean exit:\n{}",
        String::from_utf8_lossy(&release.stdout)
    );
}

// Detection guard (RED-proven): no future link change (gc flags, sectioning,
// visibility, staging) may silently drop a load-bearing interposer. On ELF the
// printf family, the stdout/stderr sentinels, and the deterministic-IO interposers
// are reached through glibc-internal paths a defined/undefined scan cannot see, so
// a plain guest references none of them directly — yet ALL must survive the link.
// If one ever went missing, a determinism hole (host stdio leak / sentinel abort)
// would reopen silently; this turns that into a loud test failure.
#[cfg(target_os = "linux")]
#[test]
fn native_live_interposers_survive_the_link() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("plain.rs");
    fs::write(&source, "fn main() { println!(\"PLAIN_OK\"); }\n").unwrap();
    let bin = directory.path().join("plain-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bytes = fs::read(&bin).unwrap();
    let missing = patina_dst_target::native_missing_live_interposers(
        &bytes,
        patina_dst_target::NATIVE_LINUX_LIVE_INTERPOSERS,
    )
    .unwrap();
    assert!(
        missing.is_empty(),
        "the link dropped load-bearing interposer(s) from the emitted ELF: {missing:?}"
    );
}

// The live-interposer guard's detection logic, proven both directions on a real
// binary (macOS-gated because it only needs to build one; the Linux gc-safety
// invariant is `native_live_interposers_survive_the_link`). A guest that calls
// `printf` links+defines it, so the guard confirms a present interposer and, with a
// name no binary defines, flags an absent one — the assertion is non-vacuous.
#[cfg(target_os = "macos")]
#[test]
fn native_live_interposer_guard_detects_presence_and_absence() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("printer.rs");
    fs::write(
        &source,
        r#"unsafe extern "C" {
    fn printf(format: *const u8, ...) -> i32;
}
fn main() {
    unsafe { printf(b"HELLO\n\0".as_ptr()); }
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("printer-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bytes = fs::read(&bin).unwrap();
    assert!(
        patina_dst_target::native_missing_live_interposers(&bytes, &["printf"])
            .unwrap()
            .is_empty(),
        "a referenced interposer must be reported present"
    );
    assert_eq!(
        patina_dst_target::native_missing_live_interposers(&bytes, &["patina_absent_marker_xyz"])
            .unwrap(),
        vec!["patina_absent_marker_xyz".to_string()],
        "the guard must flag a name the binary does not define"
    );
}

// The can-fail companion to the dormant test: a guest that ACTUALLY reaches one
// of the still-trapped host-introspection symbols aborts deterministically with
// the deny-trap diagnostic naming the symbol. The honest entry points now return
// real values (IOServiceMatching -> NULL, host_statistics64 -> fixed stats, ...),
// so the symbols that remain deny-traps are the helpers those honest returns make
// unreachable by construction — `IOServiceGetMatchingServices` is one (reached
// only with a non-NULL matching dictionary, which IOServiceMatching never yields).
// It is shim-defined, so the pre-run gate passes (it is no longer an import) and
// the runtime deny-trap is what fires when a guest genuinely calls it — the
// distinct guarantee this proves, mirroring
// `native_run_deny_trap_aborts_a_guest_that_actually_spawns`. Run twice with the
// same seed and assert byte-identical output (determinism).
#[cfg(target_os = "macos")]
#[test]
fn native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("trap.rs");
    fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceGetMatchingServices(master: u32, matching: *const c_void, existing: *mut u32) -> i32;
}
fn main() {
    println!("BEFORE_INTROSPECTION");
    if std::hint::black_box(true) {
        let mut it: u32 = 0;
        let _ = unsafe { IOServiceGetMatchingServices(0, std::ptr::null(), &mut it) };
    }
    println!("AFTER_INTROSPECTION");
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("trap-bin");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let run_once = || {
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        )
    };
    let first = run_once();
    assert!(
        !first.status.success(),
        "a guest that reaches IOServiceGetMatchingServices must abort under the deny-trap"
    );
    let first_stderr = String::from_utf8_lossy(&first.stderr).into_owned();
    let first_stdout = String::from_utf8_lossy(&first.stdout).into_owned();
    assert!(
        first_stderr
            .contains("host-introspection reached under patina: IOServiceGetMatchingServices"),
        "the deny-trap must name the reached host-introspection symbol:\n{first_stderr}"
    );
    assert!(
        first_stdout.contains("BEFORE_INTROSPECTION"),
        "the guest must run up to the introspection call:\n{first_stdout}"
    );
    assert!(
        !first_stdout.contains("AFTER_INTROSPECTION"),
        "the guest must not continue past the deny-trap:\n{first_stdout}"
    );

    // Determinism: a second identical-seed run produces byte-identical output.
    let second = run_once();
    assert_eq!(
        first_stdout,
        String::from_utf8_lossy(&second.stdout),
        "deny-trap stdout is not deterministic across runs"
    );
    assert_eq!(
        first_stderr,
        String::from_utf8_lossy(&second.stderr),
        "deny-trap stderr is not deterministic across runs"
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
fn campaign_gen_lines(text: &str) -> String {
    text.lines()
        .filter(|line| line.starts_with("PATINA_CAMPAIGN_GEN"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn campaign_json_without_invocations(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    value.as_object_mut().unwrap().remove("invocations");
    value
}

fn campaign_state_without_invocations(path: &Path) -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("invocations");
    value
}

fn campaign_json_stdout(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "campaign JSON stdout was not a single object: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn campaign_coverage_file_hashes(out_dir: &Path) -> BTreeMap<String, String> {
    let coverage_dir = out_dir.join("coverage");
    assert!(
        coverage_dir.is_dir(),
        "campaign coverage store is missing at {}",
        coverage_dir.display()
    );
    let mut hashes = BTreeMap::new();
    collect_file_hashes(&coverage_dir, &coverage_dir, &mut hashes);
    assert!(
        hashes.contains_key("meta.json")
            && hashes.contains_key("union.bits")
            && hashes.contains_key("hits.u64le")
            && hashes.contains_key("sites.i64le"),
        "coverage store did not contain every checkpoint file: {hashes:?}"
    );
    hashes
}

fn collect_file_hashes(root: &Path, dir: &Path, hashes: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_file_hashes(root, &path, hashes);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).unwrap();
        let digest = Sha256::digest(&bytes);
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        hashes.insert(rel, hex);
    }
}

fn sometimes_gate_wat(label: &str, satisfied: bool) -> Vec<u8> {
    let bit = if satisfied { 1 } else { 0 };
    let wat = format!(
        r#"(module
    (import "patina_sdk" "sometimes"
        (func $sometimes (param i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "lifecycle_setup_complete" (func $setup (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "{label}")
    (data (i32.const 32) "wat:sometimes")
    (func (export "_start")
        (drop (call $setup))
        (drop (call $sometimes (i32.const {bit})
            (i32.const 0) (i32.const {label_len}) (i32.const 32) (i32.const 13)))))"#,
        label_len = label.len()
    );
    wat::parse_str(&wat).unwrap()
}

#[test]
fn campaign_sometimes_gate_fails_unmet_accepts_met_and_waives_threshold() {
    let directory = tempdir().unwrap();
    let unmet = directory.path().join("never-green.wasm");
    let met = directory.path().join("met.wasm");
    fs::write(&unmet, sometimes_gate_wat("never-green", false)).unwrap();
    fs::write(&met, sometimes_gate_wat("met-green", true)).unwrap();

    let run = |module: &Path, out: &Path, extra: &[&str], inherited_report: Option<&str>| {
        let mut args = vec![
            "campaign".to_string(),
            module.to_str().unwrap().to_string(),
            "--gens".to_string(),
            "5".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ];
        args.extend(extra.iter().map(|arg| arg.to_string()));
        let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
        command.current_dir(native_workspace()).args(&args);
        if let Some(value) = inherited_report {
            command.env("PATINA_SDK_REPORT", value);
        }
        command.output().unwrap()
    };

    let unmet_out = directory.path().join("unmet");
    let unmet_run = run(&unmet, &unmet_out, &[], Some("0"));
    let unmet_stdout = String::from_utf8_lossy(&unmet_run.stdout);
    assert_eq!(
        unmet_run.status.code(),
        Some(1),
        "never-satisfied sometimes! must fail the campaign even when PATINA_SDK_REPORT=0 is inherited\nstdout:\n{unmet_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&unmet_run.stderr)
    );
    assert!(
        unmet_stdout.contains("UNMET sometimes 'never-green'")
            && unmet_stdout
                .contains("PATINA_CAMPAIGN_COVERAGE oracle_sites=1 satisfied=0 unmet=1 gate=fail"),
        "unmet campaign did not surface the coverage gate:\n{unmet_stdout}"
    );
    let unmet_sites: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(unmet_out.join("sites.json")).unwrap()).unwrap();
    assert_eq!(unmet_sites["schema"], "patina.campaign.sites/v1");
    assert_eq!(unmet_sites["generations_observed"], 5);
    assert_eq!(unmet_sites["sites"][0]["label"], "never-green");
    assert_eq!(unmet_sites["sites"][0]["registered_gens"], 5);
    assert_eq!(unmet_sites["sites"][0]["satisfied_gens"], 0);

    let met_out = directory.path().join("met");
    let met_run = run(&met, &met_out, &[], None);
    let met_stdout = String::from_utf8_lossy(&met_run.stdout);
    assert!(
        met_run.status.success(),
        "satisfied sometimes! campaign should stay green\nstdout:\n{met_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&met_run.stderr)
    );
    assert!(
        met_stdout
            .contains("PATINA_CAMPAIGN_COVERAGE oracle_sites=1 satisfied=1 unmet=0 gate=pass"),
        "met campaign did not report a passing coverage gate:\n{met_stdout}"
    );

    let waived_out = directory.path().join("waived");
    let waived_run = run(&unmet, &waived_out, &["--allow-unmet-sometimes=10"], None);
    let waived_stdout = String::from_utf8_lossy(&waived_run.stdout);
    assert!(
        waived_run.status.success()
            && waived_stdout.contains("gate=waived")
            && waived_stdout.contains("UNMET sometimes 'never-green'"),
        "threshold waiver below MIN_GENS should report but not fail:\nstdout:\n{waived_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&waived_run.stderr)
    );

    let enforced_out = directory.path().join("enforced");
    let enforced_run = run(&unmet, &enforced_out, &["--allow-unmet-sometimes=5"], None);
    assert_eq!(
        enforced_run.status.code(),
        Some(1),
        "threshold waiver must enforce at observed generations >= MIN_GENS\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&enforced_run.stdout),
        String::from_utf8_lossy(&enforced_run.stderr)
    );
}

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
            // Restore the full per-generation stream: this test asserts on the
            // per-generation OK/LIVENESS lines and their determinism, which the
            // summary-first default (novel/failing + periodic heartbeat) elides.
            "--progress-every".to_string(),
            "1".to_string(),
            "--buggify".to_string(),
            "--liveness-watchdog".to_string(),
            "600000000000".to_string(),
            "--out-dir".to_string(),
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
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("campaign-state.json")).unwrap())
            .unwrap();
    assert_eq!(state["schema"], "patina.campaign.state/v1");
    assert_eq!(state["generations_done"], 12);
    assert_eq!(state["artifact"]["path"], guest.to_str().unwrap());
    assert!(state["artifact"]["sha256"].as_str().unwrap().len() == 64);
    assert_eq!(state["signatures"], store["signatures"]);
    assert_eq!(state["invocations"].as_array().unwrap().len(), 1);

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
    assert_eq!(
        campaign_gen_lines(&stdout),
        campaign_gen_lines(&String::from_utf8_lossy(&ran2.stdout)),
        "a deterministic re-run must produce identical per-generation outcomes"
    );
    assert_eq!(
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        fs::read_to_string(out2.join("signatures.json")).unwrap(),
        "a deterministic re-run must produce an identical signature store"
    );
    assert_eq!(
        fs::read_to_string(out.join("sites.json")).unwrap(),
        fs::read_to_string(out2.join("sites.json")).unwrap(),
        "a deterministic re-run must produce an identical sites.json store"
    );
    assert_eq!(
        campaign_state_without_invocations(&out.join("campaign-state.json")),
        campaign_state_without_invocations(&out2.join("campaign-state.json")),
        "a deterministic re-run must produce identical persisted state except audit invocations"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// Swarm fault-class deselection stays coherent end to end (SlateDB feedback item
// 9). `--swarm` applies a seed-derived subset of the enabled classes, so some
// generations run WITHOUT buggify even though the operator asked for it. That
// masked state used to keep `+buggify` in the run fingerprint while disarming
// buggify, which the coherence guard then refused — a legitimate generation died
// with "fingerprint declares +buggify but buggify is not enabled".
//
// This proves the three things the fix owes:
//   1. a masked generation RUNS, and its trace declares the effective state
//      (no `+buggify`, no buggify config, swarm names it a dropped candidate);
//   2. a masked generation is DISTINGUISHABLE from "buggify was never requested"
//      — the ambiguity that sent the original bug report after the wrong cause;
//   3. an unmasked swarm generation still carries `+buggify`, and genuine
//      incoherence (declaring `+buggify` with no buggify at all) still refuses.
#[test]
fn swarm_deselection_stays_coherent_with_fingerprint_and_metadata() {
    let workspace = native_workspace();
    let fixture = workspace.join("testbeds/liveness-campaign");
    let directory = tempdir().unwrap();
    let guest = directory.path().join("swarm-guest");
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
        "building the swarm guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    // Find one generation that drops buggify and one that keeps it by reading
    // each run's own PATINA_SWARM_REPORT rather than re-deriving the mask here. A
    // wedged generation (the fixture's planted liveness bug) is skipped: this
    // test is about configuration coherence, not the planted bug.
    let mut dropped: Option<(u64, std::path::PathBuf, String)> = None;
    let mut kept: Option<(u64, std::path::PathBuf, String)> = None;
    for seed in 0..24u64 {
        if dropped.is_some() && kept.is_some() {
            break;
        }
        let trace = directory.path().join(format!("swarm-{seed}.patina"));
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                &seed.to_string(),
                "--swarm",
                "--buggify=372",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let stderr = String::from_utf8_lossy(&ran.stderr).to_string();
        if !ran.status.success() {
            assert!(
                !stderr.contains("fingerprint declares +buggify"),
                "seed {seed}: a swarm-masked generation must not abort on the \
                 buggify coherence guard\nstderr:\n{stderr}"
            );
            continue;
        }
        let swarm_line = stderr
            .lines()
            .find(|line| line.starts_with("PATINA_SWARM_REPORT "))
            .unwrap_or_else(|| panic!("seed {seed}: no swarm report\nstderr:\n{stderr}"))
            .to_string();
        if swarm_line.contains("class=buggify|0") {
            dropped.get_or_insert((seed, trace, stderr));
        } else if swarm_line.contains("class=buggify|1") {
            kept.get_or_insert((seed, trace, stderr));
        }
    }
    let (dropped_seed, dropped_trace, dropped_stderr) =
        dropped.expect("no seed in 0..24 deselected buggify");
    let (_kept_seed, kept_trace, kept_stderr) = kept.expect("no seed in 0..24 selected buggify");

    // (1) The masked run's trace declares the effective configuration.
    let info = invoke_in(
        workspace,
        &["trace", "info", dropped_trace.to_str().unwrap()],
    );
    let info = String::from_utf8_lossy(&info.stdout).to_string();
    assert!(
        info.contains("fingerprint: patina-native+swarm"),
        "a masked run must not declare +buggify:\n{info}"
    );
    assert!(
        !info.contains("\nbuggify:"),
        "a masked run must record no buggify config:\n{info}"
    );
    assert!(
        info.contains("swarm: candidates=buggify selected=(none) deselected=buggify"),
        "the trace must name buggify as a dropped candidate:\n{info}"
    );

    // (2) Distinguishable from "never requested". Both report `enabled=0`; only
    // the masked one reports `swarm_deselected=1`.
    assert!(
        dropped_stderr.contains("PATINA_SDK_REPORT enabled=0 swarm_deselected=1"),
        "a masked run must report swarm_deselected=1\nstderr:\n{dropped_stderr}"
    );
    let never_asked = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            guest.to_str().unwrap(),
            "--seed",
            &dropped_seed.to_string(),
        ],
    );
    let never_asked = String::from_utf8_lossy(&never_asked.stderr).to_string();
    assert!(
        never_asked.contains("PATINA_SDK_REPORT enabled=0 swarm_deselected=0"),
        "a run that never asked for buggify must report swarm_deselected=0\nstderr:\n{never_asked}"
    );

    // Replay of the masked trace reproduces the run: the fingerprint check holds
    // in both directions (the replay recomputes `+swarm` without `+buggify` from
    // the metadata), and the diagnostics are identical to the recording's.
    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            guest.to_str().unwrap(),
            dropped_trace.to_str().unwrap(),
        ],
    );
    assert!(
        replayed.status.success(),
        "replaying a swarm-masked trace failed:\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replayed = String::from_utf8_lossy(&replayed.stderr).to_string();
    let reports = |stderr: &str| -> Vec<String> {
        stderr
            .lines()
            .filter(|line| {
                line.starts_with("PATINA_SWARM_REPORT ") || line.starts_with("PATINA_SDK_REPORT ")
            })
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        reports(&dropped_stderr),
        reports(&replayed),
        "record and replay of a masked run must report the same swarm/SDK state"
    );

    // (3) An unmasked swarm generation is untouched: `+buggify` and the buggify
    // config both stand.
    assert!(
        kept_stderr.contains("PATINA_SDK_REPORT enabled=1 swarm_deselected=0"),
        "an unmasked swarm run must keep buggify armed\nstderr:\n{kept_stderr}"
    );
    let info = invoke_in(workspace, &["trace", "info", kept_trace.to_str().unwrap()]);
    let info = String::from_utf8_lossy(&info.stdout).to_string();
    assert!(
        info.contains("fingerprint: patina-native+buggify+swarm"),
        "an unmasked swarm run must keep +buggify:\n{info}"
    );
    assert!(
        info.contains("swarm: candidates=buggify selected=buggify deselected=(none)"),
        "the trace must name buggify as selected:\n{info}"
    );

    // Genuine incoherence — a fingerprint declaring `+buggify` on a run that
    // never armed buggify — still fails closed, exactly as before.
    let incoherent = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            guest.to_str().unwrap(),
            "--seed",
            "0",
            "--fingerprint",
            "patina-native+buggify",
            "--record",
            directory.path().join("incoherent.patina").to_str().unwrap(),
        ],
    );
    assert!(!incoherent.status.success());
    assert!(
        String::from_utf8_lossy(&incoherent.stderr)
            .contains("fingerprint declares +buggify but buggify is not enabled"),
        "the coherence guard must still refuse genuine incoherence:\nstderr:\n{}",
        String::from_utf8_lossy(&incoherent.stderr)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// A `--buggify --swarm` campaign is the shape that made item 9 look like a broken
// flag: the campaign emits both flags on every generation, so each generation
// whose seed dropped buggify aborted on the coherence guard. Before the fix an
// eight generation sweep of the planted-bug fixture reported FAIL_CLOSED_ABORT on
// six of them; it must now report only the planted liveness bug.
#[test]
fn campaign_with_swarm_and_buggify_has_no_coherence_aborts() {
    let workspace = native_workspace();
    let fixture = workspace.join("testbeds/liveness-campaign");
    let directory = tempdir().unwrap();
    let guest = directory.path().join("swarm-campaign-guest");
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
    assert!(built.status.success());

    let out = directory.path().join("camp");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            "12",
            "--buggify",
            "--swarm",
            "--liveness-watchdog",
            "600000000000",
            "--progress-every",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&ran.stdout).to_string();
    assert!(
        !stdout.contains("FAIL_CLOSED_ABORT"),
        "a swarm+buggify campaign must not abort on configuration incoherence\n{stdout}"
    );
    // The sweep still does its job: it finds the planted liveness bug and has
    // clean generations too, so "no aborts" is not "nothing ran".
    assert!(
        stdout.contains("class=LIVENESS") && stdout.contains("class=OK"),
        "the sweep must still find the planted bug and have clean generations\n{stdout}"
    );

    // Non-vacuous: the sweep really did drop buggify on some of its generations
    // and keep it on others, so the coherence path was exercised both ways. The
    // swarm draw is a function of the run seed alone, so replaying the campaign's
    // own generation seeds reports the same decision each generation made.
    let mut dropped = 0usize;
    let mut kept = 0usize;
    for line in stdout.lines() {
        let Some(seed) = line.strip_prefix("PATINA_CAMPAIGN_GEN ").and_then(|rest| {
            rest.split_whitespace()
                .find_map(|f| f.strip_prefix("seed="))
        }) else {
            continue;
        };
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                seed,
                "--swarm",
                "--buggify=372",
                // `run` takes the optional-value form with `=`; the space form is
                // a usage error, which would silently make this check vacuous.
                "--liveness-watchdog=600000000000",
            ],
        );
        assert!(
            ran.status.code() != Some(2),
            "seed {seed}: usage error re-running a campaign generation:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        let stderr = String::from_utf8_lossy(&ran.stderr);
        if stderr.contains("class=buggify|0") {
            dropped += 1;
        } else if stderr.contains("class=buggify|1") {
            kept += 1;
        }
    }
    assert!(
        dropped > 0 && kept > 0,
        "the sweep must exercise both swarm outcomes, got dropped={dropped} kept={kept}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_timeout_does_not_save_incomplete_trace() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("spin_forever.rs");
    fs::write(
        &source,
        r#"fn main() {
    loop {
        std::hint::spin_loop();
    }
}
"#,
    )
    .unwrap();
    let guest = directory.path().join("spin-forever");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
    );

    let out = directory.path().join("timeout-campaign");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            "1",
            "--timeout-secs",
            "1",
            "--progress-every",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(
        ran.status.code(),
        Some(1),
        "timeout campaign should report the INFRA failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("class=INFRA"),
        "timeout was not classified as INFRA:\n{stdout}"
    );
    assert!(
        stdout.contains("PATINA_CAMPAIGN_GEN generation=0"),
        "missing per-generation timeout line:\n{stdout}"
    );

    let scratch = out.join("traces/generation-0.patina");
    assert!(
        !scratch.exists(),
        "timed-out generation must not leave a zero-byte scratch trace"
    );
    let traces_dir = out.join("traces");
    let leftovers = fs::read_dir(&traces_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        leftovers.is_empty(),
        "timed-out generation left trace scratch files: {leftovers:?}"
    );
    assert!(
        !out.join("failures/generation-0.patina").exists(),
        "campaign must not save an incomplete failure trace"
    );
    let store: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("signatures.json")).unwrap()).unwrap();
    let signature = &store["signatures"].as_array().unwrap()[0];
    assert_eq!(signature["class"], "INFRA");
    assert!(
        signature.get("trace").is_none(),
        "timeout signature should fall back to a rerun command, not an unreplayable trace: {signature:#}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_extend_equals_fresh_campaign() {
    let workspace = native_workspace();
    let fixture = workspace.join("testbeds/liveness-campaign");
    let directory = tempdir().unwrap();
    let guest = directory.path().join("liveness-guest");

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

    let campaign_args = |out: &Path, gens: u64, json: bool| {
        let mut args = vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            gens.to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--buggify".to_string(),
            "--liveness-watchdog".to_string(),
            "600000000000".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ];
        if json {
            args.extend(["--format".to_string(), "json".to_string()]);
        }
        args
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };
    let concat_gen_lines = |outputs: &[&str]| {
        outputs
            .iter()
            .map(|text| campaign_gen_lines(text))
            .filter(|lines| !lines.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let out = directory.path().join("camp");
    let fresh = run(campaign_args(&out, 12, false));
    assert_eq!(
        fresh.status.code(),
        Some(1),
        "fresh campaign should find the planted failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_signatures = fs::read_to_string(out.join("signatures.json")).unwrap();
    let fresh_sites = fs::read_to_string(out.join("sites.json")).unwrap();
    let fresh_state = campaign_state_without_invocations(&out.join("campaign-state.json"));

    fs::remove_dir_all(&out).unwrap();
    let split1 = run(campaign_args(&out, 5, false));
    assert!(
        matches!(split1.status.code(), Some(0) | Some(1)),
        "split segment exited unexpectedly: {}\nstdout:\n{}\nstderr:\n{}",
        split1.status,
        String::from_utf8_lossy(&split1.stdout),
        String::from_utf8_lossy(&split1.stderr)
    );
    let extend_args = vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "7".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ];
    let split2 = run(extend_args);
    assert_eq!(
        split2.status.code(),
        Some(1),
        "extended campaign should preserve cumulative failure exit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split2.stdout),
        String::from_utf8_lossy(&split2.stderr)
    );
    let split1_stdout = String::from_utf8_lossy(&split1.stdout);
    let split2_stdout = String::from_utf8_lossy(&split2.stdout);
    assert!(
        split2_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && split2_stdout.contains("done=5")
            && split2_stdout.contains("target=12"),
        "extension should announce the recorded cursor and cumulative target:\n{split2_stdout}"
    );
    assert!(
        split2_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=12"),
        "extension summary must be cumulative:\n{split2_stdout}"
    );
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        concat_gen_lines(&[&split1_stdout, &split2_stdout]),
        "k-then-extend must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        split1_stdout.matches("NOVEL").count() + split2_stdout.matches("NOVEL").count(),
        1,
        "novelty must survive the split"
    );
    assert_eq!(
        fresh_signatures,
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        "k-then-extend must reproduce the fresh signature store"
    );
    assert_eq!(
        fresh_sites,
        fs::read_to_string(out.join("sites.json")).unwrap(),
        "k-then-extend must reproduce the fresh sites.json store"
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&out.join("campaign-state.json")),
        "k-then-extend must reproduce persisted state except audit invocations"
    );

    let json_out = directory.path().join("camp-json");
    let fresh_json = run(campaign_args(&json_out, 12, true));
    assert_eq!(fresh_json.status.code(), Some(1));
    let fresh_envelope = campaign_json_stdout(&fresh_json);
    fs::remove_dir_all(&json_out).unwrap();
    let split_json1 = run(campaign_args(&json_out, 5, true));
    assert!(matches!(split_json1.status.code(), Some(0) | Some(1)));
    let split_json2 = run(vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "7".to_string(),
        "--out-dir".to_string(),
        json_out.to_str().unwrap().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ]);
    assert_eq!(split_json2.status.code(), Some(1));
    let split_envelope = campaign_json_stdout(&split_json2);
    assert_eq!(
        campaign_json_without_invocations(&fresh_envelope),
        campaign_json_without_invocations(&split_envelope),
        "k-then-extend final JSON envelope must match fresh except audit invocations"
    );
    assert_eq!(split_envelope["invocations"].as_array().unwrap().len(), 2);
    assert!(
        split_envelope["artifacts"]["campaign_state"]
            .as_str()
            .unwrap()
            .ends_with("campaign-state.json")
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_extend_reproduces_aux_store_bytes_for_sites_and_coverage() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("aux_guest.rs");
    let guest = directory.path().join("aux-guest");
    fs::write(
        &source,
        r#"fn main() {
    eprintln!("PATINA_SDK_REPORT enabled=1 site=aux|sometimes|a1|e3|f1|r1|s1|v0|k-|@src/main.rs:1");
    let mut sum = 0u64;
    for i in 0..128u64 {
        sum = sum.wrapping_add(i.rotate_left((i % 17) as u32));
        std::hint::black_box(sum);
    }
    println!("AUX_DONE {sum}");
}
"#,
    )
    .unwrap();
    let built = invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
            "--yield-points",
        ],
    );
    assert!(
        built.status.success(),
        "building aux coverage guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let campaign_args = |out: &Path, gens: u64| {
        vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            gens.to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };
    let concat_gen_lines = |outputs: &[&str]| {
        outputs
            .iter()
            .map(|text| campaign_gen_lines(text))
            .filter(|lines| !lines.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let fresh_out = directory.path().join("fresh");
    let fresh = run(campaign_args(&fresh_out, 6));
    assert!(
        fresh.status.success(),
        "fresh aux campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_sites = fs::read_to_string(fresh_out.join("sites.json")).unwrap();
    let fresh_site_json: serde_json::Value = serde_json::from_str(&fresh_sites).unwrap();
    assert_eq!(fresh_site_json["generations_observed"], 6);
    assert_eq!(fresh_site_json["sites"][0]["registered_gens"], 6);
    let fresh_coverage_hashes = campaign_coverage_file_hashes(&fresh_out);
    let fresh_state = campaign_state_without_invocations(&fresh_out.join("campaign-state.json"));

    let split_out = directory.path().join("split");
    let split1 = run(campaign_args(&split_out, 2));
    assert!(
        split1.status.success(),
        "first split aux segment failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split1.stdout),
        String::from_utf8_lossy(&split1.stderr)
    );
    let split2 = run(vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "4".to_string(),
        "--out-dir".to_string(),
        split_out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ]);
    assert!(
        split2.status.success(),
        "extended aux campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split2.stdout),
        String::from_utf8_lossy(&split2.stderr)
    );
    let split1_stdout = String::from_utf8_lossy(&split1.stdout);
    let split2_stdout = String::from_utf8_lossy(&split2.stdout);
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        concat_gen_lines(&[&split1_stdout, &split2_stdout]),
        "aux k-then-extend must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        fresh_sites,
        fs::read_to_string(split_out.join("sites.json")).unwrap(),
        "aux k-then-extend must reproduce sites.json bytes"
    );
    assert_eq!(
        fresh_coverage_hashes,
        campaign_coverage_file_hashes(&split_out),
        "aux k-then-extend must reproduce coverage store file hashes"
    );
    println!(
        "AUX_STORE_BYTE_EQUALITY sites.json_bytes={} coverage_hashes={fresh_coverage_hashes:?}",
        fresh_sites.len()
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&split_out.join("campaign-state.json")),
        "aux k-then-extend must reproduce persisted state except audit invocations"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_resume_after_interruption_matches_fresh_campaign() {
    let workspace = native_workspace();
    let directory = tempdir().unwrap();
    let source = directory.path().join("burn.rs");
    let guest = directory.path().join("burn-guest");
    fs::write(
        &source,
        r#"
fn main() {
    let mut x = 0u64;
    for i in 0..20_000_000u64 {
        x = x.wrapping_add(i.rotate_left((i % 31) as u32));
        std::hint::black_box(x);
    }
    println!("BURN_DONE {x}");
}
"#,
    )
    .unwrap();
    let built = invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
    );
    assert!(
        built.status.success(),
        "building burn guest failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let campaign_args = |out: &Path| {
        vec![
            "campaign".to_string(),
            guest.to_str().unwrap().to_string(),
            "--gens".to_string(),
            "8".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &refs)
    };

    let out = directory.path().join("camp");
    let fresh = run(campaign_args(&out));
    assert!(
        fresh.status.success(),
        "fresh burn campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_state = campaign_state_without_invocations(&out.join("campaign-state.json"));
    let fresh_signatures = fs::read_to_string(out.join("signatures.json")).unwrap();

    fs::remove_dir_all(&out).unwrap();
    let owned = campaign_args(&out);
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
        .current_dir(workspace)
        .args(&refs)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let state_path = out.join("campaign-state.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    let observed_done = loop {
        if state_path.exists() {
            let state: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
            let done = state["generations_done"].as_u64().unwrap();
            if (2..8).contains(&done) {
                break done;
            }
            assert!(done < 8, "campaign finished before it could be interrupted");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for an interruptible campaign checkpoint"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let concurrent = run(campaign_args(&out));
    assert_eq!(
        concurrent.status.code(),
        Some(2),
        "second writer should fail immediately while the first campaign holds the lock\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&concurrent.stdout),
        String::from_utf8_lossy(&concurrent.stderr)
    );
    assert!(
        String::from_utf8_lossy(&concurrent.stderr)
            .contains("another campaign is writing this out-dir"),
        "concurrent writer refusal should name the lock:\n{}",
        String::from_utf8_lossy(&concurrent.stderr)
    );
    child.kill().unwrap();
    let interrupted = child.wait_with_output().unwrap();
    assert!(
        !interrupted.status.success(),
        "killed campaign unexpectedly exited successfully"
    );
    assert!(
        state_path.exists(),
        "interrupted campaign left no state file"
    );
    assert!(
        out.join("signatures.json").exists(),
        "interrupted campaign left no derived signature store"
    );

    let resumed = run(vec![
        "campaign".to_string(),
        "--resume".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ]);
    assert!(
        resumed.status.success(),
        "resume failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    let interrupted_stdout = String::from_utf8_lossy(&interrupted.stdout);
    let resumed_stdout = String::from_utf8_lossy(&resumed.stdout);
    assert!(
        resumed_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && resumed_stdout.contains(&format!("done={observed_done}"))
            && resumed_stdout.contains("target=8"),
        "resume should announce the persisted cursor:\n{resumed_stdout}"
    );
    let combined = [
        campaign_gen_lines(&interrupted_stdout),
        campaign_gen_lines(&resumed_stdout),
    ]
    .into_iter()
    .filter(|lines| !lines.is_empty())
    .collect::<Vec<_>>()
    .join("\n");
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        combined,
        "interrupted + resumed stream must match a fresh campaign"
    );
    assert_eq!(
        fresh_state,
        campaign_state_without_invocations(&state_path),
        "interrupted + resumed state must match fresh except audit invocations"
    );
    assert_eq!(
        fresh_signatures,
        fs::read_to_string(out.join("signatures.json")).unwrap(),
        "interrupted + resumed signature store must match fresh"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_continuation_refusals_are_loud() {
    let directory = tempdir().unwrap();
    let cwd = directory.path();
    let module = cwd.join("noop.wasm");
    fs::write(
        &module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let run = |args: &[&str]| invoke_unchecked(patina, cwd, args);
    let assert_refuses = |output: Output, needle: &str| {
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected refusal containing {needle:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(needle),
            "refusal did not contain {needle:?}:\n{stderr}"
        );
    };

    let missing = cwd.join("missing-out");
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            missing.to_str().unwrap(),
        ]),
        "no campaign-state.json",
    );

    let pre_steering = cwd.join("pre-steering");
    fs::create_dir_all(&pre_steering).unwrap();
    fs::write(
        pre_steering.join("signatures.json"),
        r#"{"schema":"patina.campaign.signatures/v1","signatures":[]}"#,
    )
    .unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--resume",
            "--out-dir",
            pre_steering.to_str().unwrap(),
        ]),
        "no campaign-state.json",
    );

    let out = cwd.join("camp");
    let fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        out.to_str().unwrap(),
    ]);
    assert!(
        fresh.status.success(),
        "fresh campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    assert_refuses(
        run(&[
            "campaign",
            module.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "already contains campaign-state.json",
    );
    assert_refuses(
        run(&["campaign", "--resume", "--out-dir", out.to_str().unwrap()]),
        "campaign complete at 1/1",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
            "--gens",
            "2",
        ]),
        "out-dir's recorded spec is authoritative",
    );
    assert_refuses(
        run(&[
            "campaign",
            module.to_str().unwrap(),
            "--extend",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "artifact positional cannot be used with --extend/--resume",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--resume",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "choose exactly one continuation mode",
    );
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "0",
            "--out-dir",
            out.to_str().unwrap(),
        ]),
        "--extend must be >= 1",
    );

    let heartbeat_out = cwd.join("heartbeat-camp");
    let heartbeat_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "3",
        "--progress-every",
        "0",
        "--out-dir",
        heartbeat_out.to_str().unwrap(),
    ]);
    assert!(heartbeat_fresh.status.success());
    let heartbeat_extend = run(&[
        "campaign",
        "--extend",
        "2",
        "--out-dir",
        heartbeat_out.to_str().unwrap(),
        "--progress-every",
        "2",
    ]);
    assert!(
        heartbeat_extend.status.success(),
        "heartbeat extension failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&heartbeat_extend.stdout),
        String::from_utf8_lossy(&heartbeat_extend.stderr)
    );
    let heartbeat_stdout = String::from_utf8_lossy(&heartbeat_extend.stdout);
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_RESUME")
            && heartbeat_stdout.contains("done=3")
            && heartbeat_stdout.contains("target=5"),
        "resume line should be cumulative:\n{heartbeat_stdout}"
    );
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_PROGRESS generation=4/5")
            && heartbeat_stdout.contains("failures=0")
            && heartbeat_stdout.contains("OK=4"),
        "extension heartbeat should be cumulative:\n{heartbeat_stdout}"
    );
    assert!(
        heartbeat_stdout.contains("PATINA_CAMPAIGN_COMPLETE generations=5"),
        "extension summary should be cumulative:\n{heartbeat_stdout}"
    );

    let schema_out = cwd.join("schema-camp");
    let schema_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        schema_out.to_str().unwrap(),
    ]);
    assert!(schema_fresh.status.success());
    let schema_path = schema_out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    state["schema"] = "patina.campaign.state/v999".into();
    fs::write(&schema_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            schema_out.to_str().unwrap(),
        ]),
        "different cargo-patina version",
    );

    let corrupt_out = cwd.join("corrupt-camp");
    let corrupt_fresh = run(&[
        "campaign",
        module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        corrupt_out.to_str().unwrap(),
    ]);
    assert!(corrupt_fresh.status.success());
    let corrupt_path = corrupt_out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&corrupt_path).unwrap()).unwrap();
    state["classes"] = serde_json::json!({"MYSTERY": 1});
    fs::write(&corrupt_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            corrupt_out.to_str().unwrap(),
        ]),
        "corrupt",
    );

    let missing_artifact_module = cwd.join("missing-artifact.wasm");
    fs::write(
        &missing_artifact_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let missing_artifact_out = cwd.join("missing-artifact-camp");
    let missing_artifact_fresh = run(&[
        "campaign",
        missing_artifact_module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        missing_artifact_out.to_str().unwrap(),
    ]);
    assert!(missing_artifact_fresh.status.success());
    fs::remove_file(&missing_artifact_module).unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            missing_artifact_out.to_str().unwrap(),
        ]),
        "cannot be read",
    );

    let hash_module = cwd.join("hash.wasm");
    fs::write(
        &hash_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
    let hash_out = cwd.join("hash-camp");
    let hash_fresh = run(&[
        "campaign",
        hash_module.to_str().unwrap(),
        "--gens",
        "1",
        "--out-dir",
        hash_out.to_str().unwrap(),
    ]);
    assert!(hash_fresh.status.success());
    fs::write(
        &hash_module,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start") (nop)))"#)
            .unwrap(),
    )
    .unwrap();
    assert_refuses(
        run(&[
            "campaign",
            "--extend",
            "1",
            "--out-dir",
            hash_out.to_str().unwrap(),
        ]),
        "the artifact changed since this campaign started",
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
            && report.contains("total_firings=1")
            && report.contains("|@wat:site-a"),
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
    if std::env::args().any(|arg| arg == "never") {
        patina_dst::reachable!("never-wasi-branch");
    }
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
    let sdk_report = sdk_report_line(&ran);
    assert!(
        sdk_report.contains("enabled=1") && sdk_report.contains("|@src/main.rs:"),
        "missing Wave 2 PATINA_SDK_REPORT from wasi guest:\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert_sites_join_for_sdk_report(
        &package,
        &String::from_utf8_lossy(&ran.stderr),
        &[
            "guest-startup",
            "never-wasi-branch",
            "iters",
            "inject",
            "even-draw",
            "guest-invariant",
        ],
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_audit_attributes_unsupported_imports_to_dependency_crates() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("provenance-pkg");
    fs::create_dir_all(package.join("src")).unwrap();
    for crate_name in ["leaker_a", "leaker_b"] {
        fs::create_dir_all(package.join(crate_name).join("src")).unwrap();
    }
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"provenance-pkg\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nleaker-a = { path = \"leaker_a\" }\nleaker-b = { path = \"leaker_b\" }\n\n[workspace]\n",
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        "fn main() { let value = leaker_a::addr() ^ leaker_b::addr(); std::process::exit((value & 1) as i32); }\n",
    )
    .unwrap();
    fs::write(
        package.join("leaker_a/Cargo.toml"),
        "[package]\nname = \"leaker-a\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        package.join("leaker_a/src/lib.rs"),
        "unsafe extern \"C\" { fn killpg(pgrp: i32, sig: i32) -> i32; }\n#[inline(never)] pub fn addr() -> usize { killpg as *const () as usize }\n",
    )
    .unwrap();
    fs::write(
        package.join("leaker_b/Cargo.toml"),
        "[package]\nname = \"leaker-b\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        package.join("leaker_b/src/lib.rs"),
        "unsafe extern \"C\" { fn shm_open(name: *const core::ffi::c_char, oflag: i32, mode: u32) -> i32; }\n#[inline(never)] pub fn addr() -> usize { shm_open as *const () as usize }\n",
    )
    .unwrap();

    let workspace = native_workspace();
    let bin = directory.path().join("provenance-bin");
    invoke_in(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let human = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", bin.to_str().unwrap()],
    );
    assert!(!human.status.success());
    let stderr = String::from_utf8_lossy(&human.stderr);
    for needle in [
        "unsupported native imports:",
        "provenance=crate=leaker_a",
        "provenance=crate=leaker_b",
        "object=libleaker_a-",
        "object=libleaker_b-",
        "killpg (process)",
        "shm_open (shared-memory-ipc)",
    ] {
        assert!(
            stderr.contains(needle),
            "missing {needle:?} in provenance-grouped audit stderr:\n{stderr}"
        );
    }

    let json = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["audit", bin.to_str().unwrap(), "--format", "json"],
    );
    assert!(!json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap_or_else(|error| {
        panic!(
            "audit --format json did not emit JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&json.stdout),
            String::from_utf8_lossy(&json.stderr)
        )
    });
    assert_eq!(value["result"], "violation");
    assert_eq!(value["exit_code"], 2);
    assert_json_finding_has_crate(&value, "killpg", "leaker_a");
    assert_json_finding_has_crate(&value, "shm_open", "leaker_b");
}

fn assert_json_finding_has_crate(value: &serde_json::Value, symbol: &str, crate_name: &str) {
    let details = value["finding_details"]
        .as_array()
        .unwrap_or_else(|| panic!("missing finding_details array in {value:#}"));
    let finding = details
        .iter()
        .find(|detail| {
            detail["symbol"]
                .as_str()
                .map(|got| got.trim_start_matches('_') == symbol)
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("missing finding for {symbol} in {value:#}"));
    assert!(
        finding["provenance"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provenance for {symbol}: {finding:#}"))
            .iter()
            .any(|origin| origin["crate"].as_str() == Some(crate_name)
                && origin["object"]
                    .as_str()
                    .map(|object| object.starts_with(&format!("lib{crate_name}-")))
                    .unwrap_or(false)),
        "finding for {symbol} lacks crate/object provenance {crate_name}: {finding:#}"
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

// Exercises the two std filesystem APIs that lower onto `linkat` and
// `fdopendir` -- both unsupported native imports before this shim wave, so a
// guest using either was refused by the pre-run audit up front.
//
// Part (a) hard links (`std::fs::hard_link` -> `linkat(AT_FDCWD, .., 0)`): after
// linking, a write through one path is observed through the other, the
// same-inode/same-content contract of a hard link (a copy would not see the
// mutation). Part (b) recursive removal (`std::fs::remove_dir_all`, which on
// both macOS and Linux std opens each directory with `openat(.., O_DIRECTORY)`,
// reads it via `fdopendir`, and removes children with `unlinkat(dirfd, ..)`):
// a nested tree is built and removed, and its absence is asserted.
const HARD_LINK_AND_REMOVE_TREE_SOURCE: &str = r#"
use std::fs;

fn main() {
    // (a) hard link: mutate through one name, observe through the other.
    fs::write("/original.txt", b"one").unwrap();
    fs::hard_link("/original.txt", "/alias.txt").unwrap();
    fs::write("/original.txt", b"two-longer").unwrap();
    let via_alias = fs::read_to_string("/alias.txt").unwrap();

    // (b) recursive removal of a nested tree via the openat/fdopendir/unlinkat path.
    fs::create_dir_all("/tree/sub/deep").unwrap();
    fs::write("/tree/top.txt", b"x").unwrap();
    fs::write("/tree/sub/mid.txt", b"y").unwrap();
    fs::write("/tree/sub/deep/leaf.txt", b"z").unwrap();
    fs::remove_dir_all("/tree").unwrap();

    println!("via_alias={via_alias}");
    println!("tree_exists={}", fs::metadata("/tree").is_ok());
}
"#;

// `linkat` (hard links) and `fdopendir` (the openat-traversal `remove_dir_all`
// uses) are strong-def'd by the shim: the audit is clean (no unsupported-import
// note, no allowances), the guest runs deterministically, same-seed double runs
// are byte-identical, and a recorded run replays byte-identically. Before this
// wave the audit refused the binary outright ("unsupported native imports:
// _fdopendir _linkat"), which is the RED evidence this test's fix clears.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_record_abort_leaves_trace_absent_and_infra_classified() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("abort_record.rs");
    fs::write(
        &source,
        r#"fn main() {
    eprintln!("guest-about-to-abort");
    std::process::abort();
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("abort-record");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("abort.patina");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "abort-record",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        ran.status.code(),
        Some(134),
        "abort should be surfaced as 128+SIGABRT with a named infra marker\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        !trace.exists(),
        "record abort must leave the requested trace path absent, not zero-byte"
    );
    assert!(
        fs::read_dir(directory.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("abort.patina.tmp")),
        "record abort must clean up its temporary trace"
    );
    let envelope: serde_json::Value = serde_json::from_slice(&ran.stdout).unwrap_or_else(|error| {
        panic!(
            "native run did not emit a JSON envelope: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        )
    });
    assert_eq!(envelope["result"], "infra");
    assert!(
        envelope.get("trace").is_none(),
        "no absent trace fact should be advertised: {envelope:#}"
    );
    let stderr = envelope["stderr"].as_str().unwrap();
    assert!(
        stderr.contains("PATINA_INFRA native_run"),
        "missing infra marker: {stderr}"
    );
    assert!(
        stderr.contains("signal=6"),
        "missing signal detail: {stderr}"
    );
    assert!(
        stderr.contains("trace=incomplete"),
        "missing trace detail: {stderr}"
    );
    assert!(
        stderr.contains("empty trace"),
        "missing empty-trace refusal: {stderr}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_refuses_incomplete_traces_before_guest_exec() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("noop_replay.rs");
    fs::write(&source, "fn main() { println!(\"SHOULD_NOT_RUN\"); }\n").unwrap();
    let bin = directory.path().join("noop-replay");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let cases: [(&str, &[u8], &str); 3] = [
        ("empty", b"", "empty trace"),
        ("truncated", b"{\"format_version\":4,", "truncated JSON"),
        (
            "incomplete-metadata",
            br#"{"format_version":4,"metadata":{"root_seed":1,"decision_policy":"splitmix64-v1"},"timelines":[]}"#,
            "trace metadata is missing required field `fingerprint`",
        ),
    ];
    for (name, bytes, needle) in cases {
        let trace = directory.path().join(format!("{name}.patina"));
        fs::write(&trace, bytes).unwrap();
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "noop-replay",
            ],
        );
        assert_eq!(
            replayed.status.code(),
            Some(2),
            "{name} trace should refuse with the CLI error exit\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&replayed.stderr)
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            stderr.contains("incomplete trace"),
            "{name} stderr:\n{stderr}"
        );
        assert!(stderr.contains(needle), "{name} stderr:\n{stderr}");
        assert!(
            !stderr.contains("terminated by a signal"),
            "{name} replay must refuse before guest exec, not die by signal:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("SHOULD_NOT_RUN"),
            "{name} replay executed the guest before refusing"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_hard_link_and_remove_dir_all_are_supported_and_deterministic() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("hard_link_tree.rs");
    fs::write(&source, HARD_LINK_AND_REMOVE_TREE_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("hard-link-tree");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Audit is clean: `invoke_in` already asserts exit 0, and neither `linkat`
    // nor `fdopendir` may surface as an unsupported/unknown import or force an
    // allowance -- the strong defs drop them off the import table entirely.
    let audited = invoke_in(workspace, &["audit", bin.to_str().unwrap()]);
    let audit_text = format!(
        "{}{}",
        String::from_utf8_lossy(&audited.stdout),
        String::from_utf8_lossy(&audited.stderr)
    );
    for needle in [
        "unsupported native imports",
        "unknown-import",
        "linkat",
        "fdopendir",
    ] {
        assert!(
            !audit_text.contains(needle),
            "audit must be clean but mentioned {needle:?}:\n{audit_text}"
        );
    }

    const EXPECTED: &str = "via_alias=two-longer\ntree_exists=false\n";

    // Runs deterministically: byte-identical across repeated same-seed runs at
    // several seeds. The hard link observes the mutation (same inode) and the
    // tree is gone.
    for seed in ["0", "3", "8"] {
        let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        assert_eq!(
            baseline, EXPECTED,
            "unexpected hard-link/remove-tree output at seed {seed}: {baseline}"
        );
        for _ in 0..2 {
            let again = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "output not byte-identical across runs at seed {seed}"
            );
        }
    }

    // A recorded run replays byte-identically under strict replay.
    let trace = directory.path().join("hard-link.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "8",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "hard-link-tree",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&recorded.stdout), EXPECTED);
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "hard-link-tree",
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

// `std::fs::canonicalize` on macOS reaches `realpath(path, NULL)` (the
// allocating convention) and on Linux `realpath(path, buf)`; both must resolve
// an existing guest path to the same canonical absolute spelling driven purely
// by the deterministic filesystem. The guest canonicalizes the path two ways --
// its exact spelling and a `..`/`.`/`//`-laden spelling of the same directory --
// so the assertion catches both the destination==NULL ENOSYS regression and a
// verbatim (non-canonicalizing) result.
const CANONICALIZE_SOURCE: &str = r#"
use std::fs;

fn main() {
    fs::create_dir_all("/tmp/patina-root/fragments").unwrap();
    let direct = fs::canonicalize("/tmp/patina-root/fragments").unwrap();
    let noisy = fs::canonicalize("/tmp/patina-root/../patina-root/./fragments//").unwrap();
    println!("direct={}", direct.display());
    println!("noisy={}", noisy.display());
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_canonicalize_resolves_an_existing_guest_path_deterministically() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("canonicalize.rs");
    fs::write(&source, CANONICALIZE_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("canonicalize");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let first = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first_stdout.contains("direct=/tmp/patina-root/fragments")
            && first_stdout.contains("noisy=/tmp/patina-root/fragments"),
        "canonicalize must resolve both spellings to the same canonical guest path:\nstdout:\n{first_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stderr),
    );
    let second = invoke_in(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
    assert_eq!(
        first.stdout,
        second.stdout,
        "a same-seed canonicalize run must be byte-identical:\nstderr:\n{}",
        String::from_utf8_lossy(&second.stderr),
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

// A guest/static constructor can run before Patina's startup constructor. If it
// reaches an effectful interposed API, fail closed with the ctor-specific
// diagnostic rather than the misleading not-launched/runtime-missing path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_ctor_preinit_open_reports_static_constructor_diagnostic() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("ctor_open.rs");
    fs::write(
        &source,
        r#"extern "C" fn patina_ctor() {
    let _ = std::fs::File::open("/tmp/patina-ctor-trigger");
}

#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array.00099"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
static PATINA_CTOR: extern "C" fn() = patina_ctor;

fn main() {
    println!("main should not run");
}
"#,
    )
    .unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("ctor-open");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !output.status.success(),
        "ctor pre-init open unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interposed call before deterministic runtime initialization"),
        "missing pre-init condition:\n{stderr}"
    );
    assert!(
        stderr.contains("static constructor/ctor"),
        "missing ctor attribution:\n{stderr}"
    );
    assert!(
        stderr.contains("calling symbol: open"),
        "missing calling symbol:\n{stderr}"
    );
    assert!(
        stderr.contains("#[cfg(not(patina))]") && stderr.contains("#[cfg(not(dst))]"),
        "missing cfg-gate workaround:\n{stderr}"
    );
    assert!(
        !stderr.contains("must run under `cargo patina run`"),
        "ctor diagnostic must be distinct from not-launched message:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("main should not run"),
        "ctor failure should happen before main"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_env_injection_records_replays_and_tempdir_is_seed_stable() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("env_tmp_guest");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        r#"[package]
name = "env-tmp-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
tempfile = "3"
"#,
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        r#"fn main() {
    let value = std::env::var("PATINA_TEST_ENV").unwrap_or_else(|_| "<missing>".to_string());
    let dir = tempfile::Builder::new()
        .prefix("patina-env-")
        .tempdir()
        .expect("tempdir under deterministic /tmp");
    let file = dir.path().join("value.txt");
    std::fs::write(&file, value.as_bytes()).unwrap();
    let read_back = std::fs::read_to_string(&file).unwrap();
    println!(
        "NATIVE_ENV_TMP value={} path={} read={}",
        value,
        dir.path().display(),
        read_back
    );
}
"#,
    )
    .unwrap();

    let workspace = native_workspace();
    let bin = directory.path().join("env-tmp-bin");
    invoke_in(
        workspace,
        &[
            "build",
            package.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bin = bin.to_str().unwrap();

    let empty_a = invoke_in(workspace, &["run", bin, "--seed", "7"]);
    let empty_b = invoke_in(workspace, &["run", bin, "--seed", "7"]);
    assert_eq!(
        empty_a.stdout, empty_b.stdout,
        "tempfile path must be same-seed deterministic with an empty guest env"
    );
    let empty_stdout = String::from_utf8_lossy(&empty_a.stdout);
    assert!(empty_stdout.contains("value=<missing>"), "{empty_stdout}");
    assert!(empty_stdout.contains("path=/tmp/"), "{empty_stdout}");

    let trace = directory.path().join("env-tmp.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "7",
            "--env",
            "PATINA_TEST_ENV=alpha",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    let replayed = invoke_in(workspace, &["replay", bin, trace.to_str().unwrap()]);
    assert_eq!(
        recorded.stdout, replayed.stdout,
        "native replay must restore --env and tempfile effects flag-free"
    );
    let recorded_stdout = String::from_utf8_lossy(&recorded.stdout);
    assert!(recorded_stdout.contains("value=alpha"), "{recorded_stdout}");
    assert!(recorded_stdout.contains("read=alpha"), "{recorded_stdout}");
    assert!(recorded_stdout.contains("path=/tmp/"), "{recorded_stdout}");

    let trace_text = fs::read_to_string(&trace).unwrap();
    assert!(trace_text.contains("\"guest_env\":{"), "{trace_text}");
    assert!(
        trace_text.contains("\"PATINA_TEST_ENV\":\"alpha\""),
        "{trace_text}"
    );

    let conflict = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            bin,
            trace.to_str().unwrap(),
            "--env",
            "PATINA_TEST_ENV=beta",
        ],
    );
    assert!(!conflict.status.success());
    let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
    assert!(
        conflict_stderr.contains("does not accept --env")
            && conflict_stderr.contains("trace is authoritative"),
        "native replay conflict should refuse re-supplied --env:\n{conflict_stderr}"
    );
}

// Guest-driven environment mutation is a deterministic in-process operation, so
// `setenv`/`unsetenv` succeed and every reader agrees: the `getenv` interposer,
// the `environ` array std::env::vars walks, and the seeded `--env` map share one
// source of truth. Mutations are derived from guest control flow rather than the
// host, so nothing is recorded per mutation — only the initial `--env` set lives
// in the trace metadata — and replay reproduces the whole sequence byte for byte.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_guest_env_mutation_is_coherent_and_replays() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("env_mutation.rs");
    fs::write(
        &source,
        r#"fn scan() -> String {
    let mut entries: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    entries.sort();
    entries.join(",")
}

fn main() {
    let seeded = std::env::var("SEEDED").unwrap_or_else(|_| "<missing>".to_string());
    println!("start seeded={seeded} scan=[{}]", scan());

    unsafe { std::env::set_var("ALPHA", "one") };
    println!(
        "set alpha={} scan=[{}]",
        std::env::var("ALPHA").unwrap(),
        scan()
    );

    unsafe { std::env::set_var("ALPHA", "two") };
    println!(
        "overwrite alpha={} scan=[{}]",
        std::env::var("ALPHA").unwrap(),
        scan()
    );

    unsafe { std::env::set_var("SEEDED", "replaced") };
    println!("reseed seeded={} scan=[{}]", std::env::var("SEEDED").unwrap(), scan());

    unsafe { std::env::remove_var("ALPHA") };
    println!(
        "remove alpha_missing={} scan=[{}]",
        std::env::var_os("ALPHA").is_none(),
        scan()
    );

    unsafe { std::env::remove_var("SEEDED") };
    unsafe { std::env::remove_var("NEVER_SET") };
    println!("drain scan=[{}]", scan());
}
"#,
    )
    .unwrap();

    let workspace = native_workspace();
    let bin = directory.path().join("env-mutation");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bin = bin.to_str().unwrap();

    let seeded_run = invoke_in(
        workspace,
        &["run", bin, "--seed", "11", "--env", "SEEDED=from-flag"],
    );
    let stdout = String::from_utf8_lossy(&seeded_run.stdout);
    // The seeded `--env` map is visible to BOTH readers from the first line: the
    // getenv interposer and the environ array std::env::vars walks.
    assert!(
        stdout.contains("start seeded=from-flag scan=[SEEDED=from-flag]"),
        "{stdout}"
    );
    // set_var is visible to getenv and to the rebuilt environ array.
    assert!(
        stdout.contains("set alpha=one scan=[ALPHA=one,SEEDED=from-flag]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("overwrite alpha=two scan=[ALPHA=two,SEEDED=from-flag]"),
        "{stdout}"
    );
    // A guest overwrite of a `--env`-seeded key wins over the seeded value; the
    // trace metadata still records only what `--env` supplied.
    assert!(
        stdout.contains("reseed seeded=replaced scan=[ALPHA=two,SEEDED=replaced]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("remove alpha_missing=true scan=[SEEDED=replaced]"),
        "{stdout}"
    );
    // Removing every key — including one that was never set — leaves an empty
    // environ, exactly as the run started before `--env`.
    assert!(stdout.contains("drain scan=[]"), "{stdout}");

    // Same seed, same bytes: mutation is a pure function of guest control flow.
    let repeat = invoke_in(
        workspace,
        &["run", bin, "--seed", "11", "--env", "SEEDED=from-flag"],
    );
    assert_eq!(
        seeded_run.stdout, repeat.stdout,
        "guest env mutation must be byte-identical across same-seed runs"
    );

    let trace = directory.path().join("env-mutation.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "11",
            "--env",
            "SEEDED=from-flag",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    let replayed = invoke_in(workspace, &["replay", bin, trace.to_str().unwrap()]);
    assert_eq!(
        recorded.stdout, replayed.stdout,
        "replay must reproduce a guest that mutates its environment, flag-free"
    );
    assert_eq!(
        seeded_run.stdout, replayed.stdout,
        "the recorded/replayed run must match the seeded run byte for byte"
    );

    // Only the initial `--env` set is metadata; the guest's later overwrite of
    // SEEDED and its ALPHA writes leave no per-mutation record.
    let trace_text = fs::read_to_string(&trace).unwrap();
    assert!(
        trace_text.contains("\"SEEDED\":\"from-flag\""),
        "{trace_text}"
    );
    assert!(
        !trace_text.contains("replaced") && !trace_text.contains("ALPHA"),
        "guest env mutations must not be recorded as trace events:\n{trace_text}"
    );

    // Re-recording produces a byte-identical trace: no mutation-derived state
    // leaks into the recorded stream.
    let trace_again = directory.path().join("env-mutation-again.patina");
    invoke_in(
        workspace,
        &[
            "run",
            bin,
            "--seed",
            "11",
            "--env",
            "SEEDED=from-flag",
            "--record",
            trace_again.to_str().unwrap(),
        ],
    );
    assert_eq!(
        fs::read(&trace).unwrap(),
        fs::read(&trace_again).unwrap(),
        "repeat records of an env-mutating guest must be byte-identical"
    );
}

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

// A single-process loopback TCP echo: a listener thread reads a fixed 16-byte
// payload and answers with its checksum; main streams the payload as eight
// 2-byte segments and prints a deterministic result line. Exercises the SimNet
#[cfg(any(target_os = "linux", target_os = "macos"))]
const FS_FAULT_SOURCE: &str = r#"
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

fn raw(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(-1)
}

fn expect_errno(label: &str, error: std::io::Error, expected: i32) {
    let errno = raw(error);
    assert_eq!(errno, expected, "{label} errno");
    println!("NATIVE_FS_FAULT_RESULT mode={label} errno={errno}");
}

fn main() {
    let mode = env::args().nth(1).expect("mode");
    match mode.as_str() {
        "eio_read" => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-eio")
                .expect("open");
            file.write_all(b"abcdef").expect("setup write");
            file.seek(SeekFrom::Start(0)).expect("seek");
            let mut buf = [0u8; 6];
            match file.read(&mut buf) {
                Err(error) => expect_errno("eio_read", error, 5),
                Ok(read) => panic!("expected EIO read, got {read}"),
            }
        }
        "enospc_write" => {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-enospc")
                .expect("open");
            match file.write(b"abcdef") {
                Err(error) => expect_errno("enospc_write", error, 28),
                Ok(written) => panic!("expected ENOSPC write, wrote {written}"),
            }
        }
        "short_write" => {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-short-write")
                .expect("open");
            let written = file.write(b"abcdef").expect("short write");
            assert!((1..6).contains(&written), "written={written}");
            println!("NATIVE_FS_FAULT_RESULT mode=short_write written={written}");
        }
        "short_read" => {
            std::fs::write("/fault-short-read", b"abcdef").expect("setup write_all");
            let mut file = OpenOptions::new()
                .read(true)
                .open("/fault-short-read")
                .expect("open read");
            let mut buf = [0u8; 6];
            let read = file.read(&mut buf).expect("short read");
            assert!((1..6).contains(&read), "read={read}");
            println!("NATIVE_FS_FAULT_RESULT mode=short_read read={read}");
        }
        other => panic!("unknown mode {other}"),
    }
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_fs_fault_errors_and_shorts_are_deterministic_replayable_and_reported() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("fs_fault.rs");
    fs::write(&source, FS_FAULT_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("fs-fault");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let bin = bin.to_str().unwrap().to_owned();

    let trace1 = directory.path().join("eio1.patina");
    let trace2 = directory.path().join("eio2.patina");
    let eio_args = |trace: &Path| {
        vec![
            "run".to_string(),
            bin.clone(),
            "--seed".to_string(),
            "70".to_string(),
            "--record".to_string(),
            trace.to_str().unwrap().to_string(),
            "--fs-error-permille".to_string(),
            "100".to_string(),
            "--".to_string(),
            "eio_read".to_string(),
        ]
    };
    let run_vec = |args: Vec<String>| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        invoke_in(workspace, &refs)
    };
    let eio1 = run_vec(eio_args(&trace1));
    let eio2 = run_vec(eio_args(&trace2));
    let eio_line = stdout_line_with(&eio1, "NATIVE_FS_FAULT_RESULT");
    assert_eq!(eio_line, stdout_line_with(&eio2, "NATIVE_FS_FAULT_RESULT"));
    assert_eq!(fs::read(&trace1).unwrap(), fs::read(&trace2).unwrap());
    let eio_stderr = String::from_utf8_lossy(&eio1.stderr);
    assert!(
        eio_stderr.contains("PATINA_FS_FAULT_REPORT") && eio_stderr.contains("vacuous=0"),
        "fs fault report must prove the read EIO was non-vacuous:\n{eio_stderr}"
    );

    let replayed = invoke_in(workspace, &["replay", &bin, trace1.to_str().unwrap()]);
    assert_eq!(
        eio_line,
        stdout_line_with(&replayed, "NATIVE_FS_FAULT_RESULT"),
        "flag-free replay must reproduce the fs error"
    );
    let rejected = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "replay",
            &bin,
            trace1.to_str().unwrap(),
            "--fs-short-permille",
            "1",
        ],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("--fs-short-permille"));

    let enospc = invoke_in(
        workspace,
        &[
            "run",
            &bin,
            "--seed",
            "29",
            "--fs-error-permille",
            "100",
            "--",
            "enospc_write",
        ],
    );
    assert!(stdout_line_with(&enospc, "NATIVE_FS_FAULT_RESULT").contains("errno=28"));

    for mode in ["short_write", "short_read"] {
        let output = invoke_in(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "5",
                "--fs-short-permille",
                "1000",
                "--",
                mode,
            ],
        );
        let line = stdout_line_with(&output, "NATIVE_FS_FAULT_RESULT");
        assert!(
            line.contains(mode),
            "missing short-I/O result for {mode}: {line}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
            "short-I/O run should be non-vacuous for {mode}:\n{stderr}"
        );
    }
}

// TCP *stream* path — the surface the `--net-jitter-nanos`/`--net-drop-permille`
// knobs historically ignored.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TCP_ECHO_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:6123").expect("bind");
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut got = vec![0u8; 16];
        sock.read_exact(&mut got).expect("read_exact");
        let sum: u32 = got.iter().map(|&b| b as u32).sum();
        sock.write_all(&sum.to_le_bytes()).expect("reply");
        sum
    });
    let mut client = TcpStream::connect("127.0.0.1:6123").expect("connect");
    for i in 0u8..8 {
        client.write_all(&[i, i.wrapping_add(100)]).expect("write");
    }
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("read reply");
    let sum = server.join().unwrap();
    println!("TCP_ECHO_RESULT sum={} reply={}", sum, u32::from_le_bytes(reply));
}
"#;

// TCP-stream fault injection end to end. The datagram-only reputation of the net
// fault knobs was a real bug (they were inert on the stream path); this locks in
// the fixed contract: on the SimNet TCP path the knobs (a) reproduce a
// same-seed run byte-identically, (b) record + strict-replay byte-identically,
// (c) differ across seeds, (d) differ from the no-fault run at the same seed
// (non-vacuity — the fault is not silently ignored), while NEVER losing data (a
// reliable stream: the checksum is invariant), and (e) the default-on vacuity
// diagnostic reports the faults as APPLIED (`vacuous=0`) and stays silent — no
// "net fault knobs inert" warning — precisely because they now bite.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_tcp_stream_faults_are_deterministic_replayable_and_non_vacuous() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("tcp_echo.rs");
    fs::write(&source, TCP_ECHO_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("tcp-echo");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let bin_str = bin.to_str().unwrap().to_owned();
    let trace_path = |name: &str| directory.path().join(name);
    let run_fault = |seed: &str, trace: &Path| {
        invoke_in(
            workspace,
            &[
                "run",
                &bin_str,
                "--seed",
                seed,
                "--record",
                trace.to_str().unwrap(),
                "--net-jitter-nanos",
                "1000..50000",
                "--net-drop-permille",
                "100",
            ],
        )
    };

    let f1 = trace_path("fault1.patina");
    let f2 = trace_path("fault2.patina");
    let nf = trace_path("nofault.patina");
    let f_seed2 = trace_path("fault_seed2.patina");

    let out1 = run_fault("1", &f1);
    let out2 = run_fault("1", &f2);
    let out_seed2 = run_fault("2", &f_seed2);
    let out_nofault = invoke_in(
        workspace,
        &[
            "run",
            &bin_str,
            "--seed",
            "1",
            "--record",
            nf.to_str().unwrap(),
        ],
    );

    let result1 = stdout_line_with(&out1, "TCP_ECHO_RESULT");
    // (a) same-seed byte-identical: identical result line AND identical trace.
    assert_eq!(
        result1,
        stdout_line_with(&out2, "TCP_ECHO_RESULT"),
        "same-seed fault runs must produce the same result line"
    );
    let f1_bytes = fs::read(&f1).unwrap();
    assert_eq!(
        f1_bytes,
        fs::read(&f2).unwrap(),
        "same-seed fault runs must record byte-identical traces"
    );

    // (b) record + strict replay byte-identical.
    let replayed = invoke_in(workspace, &["replay", &bin_str, f1.to_str().unwrap()]);
    assert_eq!(
        result1,
        stdout_line_with(&replayed, "TCP_ECHO_RESULT"),
        "strict replay of a faulted TCP run must reproduce the result line"
    );
    assert!(
        !String::from_utf8_lossy(&replayed.stderr).contains("net fault knobs inert"),
        "replay of a genuinely-faulted run must not raise the vacuity warning"
    );

    // (c) different seed differs.
    assert_ne!(
        f1_bytes,
        fs::read(&f_seed2).unwrap(),
        "a different seed must draw a different fault schedule"
    );
    let _ = &out_seed2;

    // (d) non-vacuity: the faulted trace differs from the no-fault trace at the
    // same seed — the knobs are NOT silently ignored on the stream path.
    assert_ne!(
        f1_bytes,
        fs::read(&nf).unwrap(),
        "the fault knobs must perturb the TCP trace (non-vacuity)"
    );

    // Reliability: a stream never loses data, so the checksum is invariant
    // across the fault and no-fault runs.
    assert_eq!(
        result1,
        stdout_line_with(&out_nofault, "TCP_ECHO_RESULT"),
        "TCP faults must reorder/delay but never lose data — result invariant"
    );

    // (e) the default-on diagnostic reports the faults as applied and stays
    // silent (no false-positive vacuity warning).
    let stderr1 = String::from_utf8_lossy(&out1.stderr);
    assert!(
        stderr1.contains("PATINA_NET_FAULT_REPORT") && stderr1.contains("vacuous=0"),
        "the net fault report must show the faults were applied:\nstderr:\n{stderr1}"
    );
    assert!(
        !stderr1.contains("net fault knobs inert"),
        "the vacuity warning must NOT fire when faults actually applied:\nstderr:\n{stderr1}"
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

// Wave-A coverage detector/determinism gate. `--coverage-out` is legal only on
// the yield-point build (D1 plain-binary refusal); a yield-point run writes the
// `patina.covmap/v1` artifact, emits the numeric report, and the full map is
// byte-identical for same-seed repeats and record→replay at two seeds.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_coverage_out_writes_covmap_and_is_byte_identical() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("yp_cov.rs");
    fs::write(&source, YIELD_POINTS_SOURCE).unwrap();
    let workspace = native_workspace();
    let plain = directory.path().join("plain-cov");
    let instrumented = directory.path().join("instrumented-cov");
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

    let refused_map = directory.path().join("plain.covmap");
    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            plain.to_str().unwrap(),
            "--seed",
            "1",
            "--coverage-out",
            refused_map.to_str().unwrap(),
        ],
    );
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success()
            && refused_stderr.contains("--coverage-out requires")
            && refused_stderr.contains("cargo patina build --yield-points"),
        "D1 plain-binary coverage request should fail closed with the yield-points hint:\n{refused_stderr}"
    );

    for seed in [3u64, 7] {
        let seed = seed.to_string();
        let first_map = directory.path().join(format!("seed-{seed}-a.covmap"));
        let first = invoke_in(
            workspace,
            &[
                "run",
                instrumented.to_str().unwrap(),
                "--seed",
                &seed,
                "--coverage-out",
                first_map.to_str().unwrap(),
            ],
        );
        assert_covmap_has_magic_and_report(&first_map, &first);

        let second_map = directory.path().join(format!("seed-{seed}-b.covmap"));
        let second = invoke_in(
            workspace,
            &[
                "run",
                instrumented.to_str().unwrap(),
                "--seed",
                &seed,
                "--coverage-out",
                second_map.to_str().unwrap(),
            ],
        );
        assert_covmap_has_magic_and_report(&second_map, &second);
        assert_eq!(
            fs::read(&first_map).unwrap(),
            fs::read(&second_map).unwrap(),
            "same-seed coverage maps must be byte-identical for seed {seed}"
        );

        let trace = directory.path().join(format!("seed-{seed}.patina"));
        let record_map = directory.path().join(format!("seed-{seed}-record.covmap"));
        let recorded = invoke_in(
            workspace,
            &[
                "run",
                instrumented.to_str().unwrap(),
                "--seed",
                &seed,
                "--record",
                trace.to_str().unwrap(),
                "--coverage-out",
                record_map.to_str().unwrap(),
            ],
        );
        assert_covmap_has_magic_and_report(&record_map, &recorded);

        let replay_map = directory.path().join(format!("seed-{seed}-replay.covmap"));
        let replayed = invoke_in(
            workspace,
            &[
                "replay",
                instrumented.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--coverage-out",
                replay_map.to_str().unwrap(),
            ],
        );
        assert_covmap_has_magic_and_report(&replay_map, &replayed);
        assert_eq!(
            fs::read(&record_map).unwrap(),
            fs::read(&replay_map).unwrap(),
            "record→replay coverage maps must be byte-identical for seed {seed}"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_covmap_has_magic_and_report(path: &Path, output: &Output) {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("missing covmap {path:?}: {error}"));
    assert!(
        bytes.starts_with(b"patina.covmap/v1"),
        "coverage map {path:?} missing magic"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PATINA_COVERAGE_REPORT edges_total=")
            && stderr.contains("PATINA_COVERAGE map=")
            && stderr.contains("covered_permille="),
        "coverage run should emit report + pointer lines; stderr:\n{stderr}"
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
// record/replay is byte-identical across repeats. On macOS (where the natural
// `main` return keeps libSystem's own `exit` and the root task's teardown
// yields stay recorded) the same guest exposed a second race: the joiner's
// `Arc<thread::Inner>` drop against the worker's still-exiting host thread,
// worth ±2 root-task yields under host load. `patina_thread_join` reaps the
// worker's host thread on every platform, so that drop ordering is fixed and
// the count is load-independent.
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

// Detection for the yield-accounting failure class: a `--yield-points` replay
// whose guard-driven TaskYield stream stops matching the recording must fail
// with the classified diagnostic — per-task record-vs-replay yield accounting
// plus the instrumented guest site of the unmatched yield — never the bare
// "trace ended before operation N" cursor error. Doctoring a recording by
// dropping its final TaskYield(+scheduler_next) pair synthesizes the exact
// on-disk shape the Darwin join-teardown race produced (a recording one root
// yield short of what replay executes), so this proves the detector on the
// class without needing the host-timing race to fire.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_divergence_reports_accounting_and_site() {
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
    let trace = directory.path().join("full.patina");
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
    let short = directory.path().join("short.patina");
    drop_trailing_task_yield(&trace, &short);

    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["replay", bin.to_str().unwrap(), short.to_str().unwrap()],
    );
    assert!(
        !replayed.status.success(),
        "replaying a yield-short recording must fail closed"
    );
    let stderr = String::from_utf8_lossy(&replayed.stderr);
    assert!(
        stderr.contains("yield-point replay divergence on task"),
        "divergence must be classified with yield accounting, not a bare trace error:\n{stderr}"
    );
    assert!(
        stderr.contains("TaskYield operations for it"),
        "the diagnostic must report the recording's per-task yield count:\n{stderr}"
    );
    assert!(
        stderr.contains("divergent yield point: guest pc"),
        "the diagnostic must name the instrumented site of the unmatched yield:\n{stderr}"
    );
}

// Rewrite `source` into `dest` with the final TaskYield decision (and the
// scheduler_next recorded after it) removed, synthesizing a recording whose
// root-task yield count is one short of what a faithful replay executes.
// Traces are compact, greppable JSON, so editing the decision list directly is
// a faithful stand-in for a genuinely divergent recording.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn drop_trailing_task_yield(source: &Path, dest: &Path) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
    let timeline = &mut value["timelines"][0];
    assert_eq!(timeline["id"], "main", "expected the main timeline first");
    let decisions = timeline["decisions"].as_array_mut().unwrap();
    let next = decisions.pop().unwrap();
    assert_eq!(
        next["operation"]["kind"], "scheduler_next",
        "expected the recording to end with a scheduler_next decision"
    );
    let yielded = decisions.pop().unwrap();
    assert_eq!(
        yielded["operation"]["kind"], "task_yield",
        "expected a trailing task_yield decision before the final scheduler_next"
    );
    fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
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
// The `process` representative is `killpg`, deliberately NOT a spawn-family
// symbol (`fork`/`posix_spawn*`/`waitpid`/...) nor `kill`: the spawn family is now
// shim-*defined* deny-traps (they abort deterministically if reached) and `kill`
// is a shim-defined deterministic-model interposer (existence-probe / ESRCH), so
// none of them appears as an import and could exercise the gate. `killpg` stays
// uninterposed — the process class is a deterministic-runtime non-goal — so it
// remains an undefined import the gate must flag as `process`.
//
// The `unmanaged-sync` representative is the Mach `semaphore_wait`, NOT
// `os_unfair_lock_*`: os_unfair_lock is now shim-interposed (routed through
// DetScheduler), so it is a defined symbol and no longer appears as an import.
// `semaphore_wait` stays uninterposed (the shim's baton reaches the real Mach
// semaphore through the host-alias `dlsym`, never a public strong def), so it
// remains an undefined import the gate must flag as `unmanaged-sync`.
#[cfg(target_os = "macos")]
const ESCAPE_CLASSES_SOURCE: &str = r#"
unsafe extern "C" {
    // pwritev: an uninterposed positional vectored write -- the filesystem-class
    // representative. (`link` used to serve here, but hard links are now routed
    // through the deterministic filesystem, so it is no longer an escape.)
    fn pwritev(fd: i32, iov: *const u8, iovcnt: i32, offset: i64) -> isize;
    fn gethostbyname(name: *const u8) -> *mut u8;
    fn select(n: i32, r: *mut u8, w: *mut u8, e: *mut u8, t: *mut u8) -> i32;
    fn semaphore_wait(s: u32) -> i32;
    fn time(t: *mut i64) -> i64;
    fn arc4random() -> u32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
    fn dlopen(path: *const u8, mode: i32) -> *mut u8;
    fn shm_open(name: *const u8, oflag: i32) -> i32;
    fn setitimer(which: i32, nv: *const u8, ov: *mut u8) -> i32;
    fn syscall(number: i64) -> i64;
}
fn main() {
    let ptrs: &[*const ()] = &[
        pwritev as *const (), gethostbyname as *const (), select as *const (),
        semaphore_wait as *const (), time as *const (), arc4random as *const (),
        killpg as *const (), dlopen as *const (), shm_open as *const (),
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

// A planted escape: a program that references two uninterposed blocking
// primitives (the Mach `semaphore_wait`/`semaphore_signal`, in the
// `unmanaged-sync` class) directly. Taking their addresses forces the undefined
// imports without a host call, and they are operations the deterministic runtime
// does not model — exactly the escape class the pre-run gate exists to catch.
// (os_unfair_lock is now interposed and accepted, so the still-uninterposed Mach
// semaphore is the blocking representative for the gate-mechanics test.)
#[cfg(target_os = "macos")]
const PLANTED_ESCAPE_SOURCE: &str = r#"
unsafe extern "C" {
    fn semaphore_wait(s: u32) -> i32;
    fn semaphore_signal(s: u32) -> i32;
}
fn main() {
    let ptrs: &[*const ()] = &[semaphore_wait as *const (), semaphore_signal as *const ()];
    let mut acc = 0usize;
    for p in ptrs {
        acc ^= *p as usize;
    }
    std::hint::black_box(acc);
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
        denied_err.contains("semaphore_wait") && denied_err.contains("unmanaged-sync"),
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
            "semaphore_wait",
        ],
    );
    assert!(
        !partial.status.success(),
        "a partial allow list must still fail closed"
    );
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("semaphore_signal"),
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

#[test]
fn config_precedence_and_no_config_are_provenanced() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    write_noop_wasm(&module);
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[defaults.run]\nseed = 3\n",
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let module = module.to_str().unwrap();

    let from_config = json_output(&invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", module, "--format", "json"],
        &[],
    ));
    assert_eq!(from_config["seed"], 3, "{from_config:#}");
    assert_eq!(from_config["config"]["applied"][0]["source"], "config");

    let from_env = json_output(&invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", module, "--format", "json"],
        &[("PATINA_SEED", "4")],
    ));
    assert_eq!(from_env["seed"], 4, "{from_env:#}");
    assert_eq!(from_env["config"]["applied"][0]["source"], "env");

    let from_flag = json_output(&invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", module, "--seed", "5", "--format", "json"],
        &[("PATINA_SEED", "4")],
    ));
    assert_eq!(from_flag["seed"], 5, "{from_flag:#}");
    assert!(
        from_flag["config"].get("applied").is_none(),
        "explicit flag should leave lower-priority defaults unapplied: {from_flag:#}"
    );

    let no_config = json_output(&invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", "--no-config", module, "--format", "json"],
        &[],
    ));
    assert_eq!(no_config["seed"], 0, "{no_config:#}");
    assert!(no_config.get("config").is_none(), "{no_config:#}");
}

#[test]
fn config_effective_values_do_not_change_trace_bytes() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    write_noop_wasm(&module);
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[defaults.run]\nseed = 9\n",
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let module = module.to_str().unwrap();
    let config_trace = directory.path().join("config.patina");
    let explicit_trace = directory.path().join("explicit.patina");

    let config_record = invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", module, "--record", config_trace.to_str().unwrap()],
        &[],
    );
    assert!(
        config_record.status.success(),
        "config record failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&config_record.stdout),
        String::from_utf8_lossy(&config_record.stderr)
    );
    let explicit_record = invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &[
            "run",
            "--no-config",
            module,
            "--seed",
            "9",
            "--record",
            explicit_trace.to_str().unwrap(),
        ],
        &[],
    );
    assert!(
        explicit_record.status.success(),
        "explicit record failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&explicit_record.stdout),
        String::from_utf8_lossy(&explicit_record.stderr)
    );
    assert_eq!(
        fs::read(config_trace).unwrap(),
        fs::read(explicit_trace).unwrap(),
        "config provenance must not enter traces when effective values match"
    );
}

#[test]
fn bad_config_is_loud_and_no_config_ignores_it() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    write_noop_wasm(&module);
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[defaults.run]\nseed = \"abc\"\n",
    )
    .unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let module = module.to_str().unwrap();

    let bad = invoke_unchecked_clean_env(patina, directory.path(), &["run", module], &[]);
    assert!(!bad.status.success());
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("seed"), "{stderr}");
    assert!(stderr.contains("config.toml:2:1"), "{stderr}");

    let help = invoke_unchecked_clean_env(patina, directory.path(), &["run", "--help"], &[]);
    assert!(
        help.status.success(),
        "help must not be blocked by a bad project config:\nstderr:\n{}",
        String::from_utf8_lossy(&help.stderr)
    );

    let ignored = json_output(&invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["run", "--no-config", module, "--format", "json"],
        &[],
    ));
    assert_eq!(ignored["seed"], 0, "{ignored:#}");
}

#[test]
fn replay_config_defaults_are_refused() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    write_noop_wasm(&module);
    let trace = directory.path().join("run.patina");
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let recorded = invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &[
            "run",
            "--no-config",
            module.to_str().unwrap(),
            "--record",
            trace.to_str().unwrap(),
        ],
        &[],
    );
    assert!(recorded.status.success());
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[defaults.replay]\ntimeline = \"other\"\n",
    )
    .unwrap();

    let replayed = invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &["replay", module.to_str().unwrap(), trace.to_str().unwrap()],
        &[],
    );
    assert!(!replayed.status.success());
    let stderr = String::from_utf8_lossy(&replayed.stderr);
    assert!(stderr.contains("trace-authoritative"), "{stderr}");
    assert!(stderr.contains("config.toml:2:1"), "{stderr}");
}

#[test]
fn campaign_children_scrub_run_config_and_env_defaults() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    write_noop_wasm(&module);
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[defaults.campaign]\ngenerations = 1\n\n[defaults.run]\nharness = true\n",
    )
    .unwrap();
    let out_dir = directory.path().join("campaign-out");
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let output = invoke_unchecked_clean_env(
        patina,
        directory.path(),
        &[
            "campaign",
            module.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--format",
            "json",
        ],
        &[("PATINA_HARNESS", "1")],
    );
    assert!(
        output.status.success(),
        "campaign child should ignore run defaults from config/env:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_output(&output);
    assert_eq!(json["generations"], 1, "{json:#}");
    assert_eq!(json["config"]["applied"][0]["key"], "generations");
}

#[test]
fn sites_config_groups_apply_to_rollups() {
    let directory = tempdir().unwrap();
    fs::create_dir_all(directory.path().join("src")).unwrap();
    fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname = \"site-groups\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("src/lib.rs"),
        "macro_rules! always { ($cond:expr, $label:literal) => {}; }\npub fn check() { always!(true, \"ledger-check\"); assert!(true); }\n",
    )
    .unwrap();
    fs::create_dir_all(directory.path().join(".patina")).unwrap();
    fs::write(
        directory.path().join(".patina/config.toml"),
        "[groups.durability]\npaths = [\"src/**\"]\nlabels = [\"ledger-*\"]\n",
    )
    .unwrap();
    let output = invoke_unchecked_clean_env(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["sites", "--no-cache", "--all", "--format", "json"],
        &[],
    );
    assert!(
        output.status.success(),
        "sites failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_output(&output);
    assert!(
        json["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["name"] == "durability" && group["sites"].as_u64().unwrap() >= 1),
        "{json:#}"
    );
    assert!(
        json["sites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|site| site["groups"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g == "durability")),
        "{json:#}"
    );
}

fn write_noop_wasm(path: &Path) {
    fs::write(
        path,
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
            .unwrap(),
    )
    .unwrap();
}

fn json_output(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn invoke_unchecked_clean_env(
    executable: &str,
    fixture: &Path,
    arguments: &[&str],
    envs: &[(&str, &str)],
) -> Output {
    let _build_guard = command_compiles(arguments).then(|| {
        BUILD_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    });
    let mut command = Command::new(executable);
    command.current_dir(fixture).args(arguments);
    for name in [
        "PATINA_SEED",
        "PATINA_RECORD",
        "PATINA_BUDGET",
        "PATINA_PARAM",
        "PATINA_BUGGIFY",
        "PATINA_BUGGIFY_AFTER_SETUP",
        "PATINA_BUGGIFY_ACTIVATION_PERMILLE",
        "PATINA_BUGGIFY_CUTOFF_NANOS",
        "PATINA_HARNESS",
        "PATINA_FUEL",
        "PATINA_ARG",
        "PATINA_ENV",
        "PATINA_PREOPEN",
        "PATINA_KIND",
        "PATINA_RUNTIME",
        "PATINA_ALL",
        "PATINA_EXERCISED",
        "PATINA_GENERATIONS",
    ] {
        command.env_remove(name);
    }
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().unwrap()
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
        r#"// Imports an uninterposed process-class libc symbol (`killpg`) that the native
// audit denies as "process". The spawn family (fork/posix_spawn*/waitpid/...) is
// shim-defined deny-traps and `kill` a deterministic-model interposer, so a
// `Command::spawn` — or a `kill` — would
// leave no process *import* to flag; this reaches for a still-uninterposed member
// of the class instead. Taking its address forces the undefined import. Building
// succeeds; the audit must reject the product with the "process" category.
unsafe extern "C" {
    fn killpg(pgrp: i32, sig: i32) -> i32;
}
fn main() {
    let reached = killpg as *const ();
    std::process::exit((reached as usize & 1) as i32);
}
"#,
    )
    .unwrap();
}

/// A package depending on a local path crate whose `[lib]` declares
/// `crate-type = ["rlib", "cdylib"]` — the shape that made crc-fast 1.10.0 fail
/// the native shim link on Linux (see
/// `native_build_package_keeps_shim_link_args_off_a_dependency_cdylib`). No
/// external dependency is needed to reproduce the shape: Cargo builds every
/// declared crate type for a path dependency regardless of which one the
/// depender actually links against, so the dependency's own `cdylib` link always
/// runs alongside the guest build.
///
/// The dependency's exported functions allocate, format, and catch a panic so
/// the cdylib has genuine cleanup landing pads and a live `rust_eh_personality`
/// reference — keeping it a realistic stand-in for crc-fast instead of a trivial
/// arithmetic crate. That is a realism guard, not the trigger for the
/// duplicate-symbol rung of the original report: measured on x86_64 Linux, a
/// dependency shaped exactly like this still links clean once the shim objects
/// are `-fPIC`.
fn create_cdylib_dependency_package_fixture(root: &Path) {
    let dependency = root.join("cdylib-dep");
    fs::create_dir_all(dependency.join("src")).unwrap();
    fs::write(
        dependency.join("Cargo.toml"),
        "[package]\nname = \"cdylib-dep\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"rlib\", \"cdylib\"]\n",
    )
    .unwrap();
    fs::write(
        dependency.join("src/lib.rs"),
        r#"use std::panic::{self, AssertUnwindSafe};

/// Exported from the cdylib (so it survives dead-stripping) and full of
/// unwinding cleanup: the `String`s need drop glue on the unwind path and
/// `catch_unwind` pulls in the personality routine directly.
#[unsafe(no_mangle)]
pub extern "C" fn cdylib_dep_landing_pads(count: u32) -> u32 {
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut rendered = String::new();
        for index in 0..count {
            rendered.push_str(&format!("{index},"));
            if index == u32::MAX {
                panic!("unreachable, but the compiler cannot prove it");
            }
        }
        rendered.len() as u32
    }));
    caught.unwrap_or(0)
}

pub fn checksum(bytes: &[u8]) -> u32 {
    let seed = cdylib_dep_landing_pads(bytes.len() as u32);
    bytes
        .iter()
        .fold(seed, |acc, byte| acc.wrapping_mul(31).wrapping_add(u32::from(*byte)))
}
"#,
    )
    .unwrap();

    let package = root.join("cdylib-pkg");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"patina-native-cdylib-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ncdylib-dep = { path = \"../cdylib-dep\" }\n",
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        r#"fn main() {
    let checksum = cdylib_dep::checksum(b"patina");
    println!("NATIVE_CDYLIB_DEP_RESULT checksum={checksum}");
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
    assert!(
        sdk_report_line(&seeded).contains("|@src/main.rs:"),
        "SDK report rows must carry Wave 2 file:line identities: {stderr}"
    );
    assert_sites_join_for_sdk_report(
        &pkg,
        &stderr,
        &[
            "batch",
            "loop-body",
            "early-return",
            "index-is-three",
            "fired-in-bounds",
        ],
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
    // Point pin for `--buggify=N` value-form plumbing; class-level pairing:
    // the trace/runtime `+buggify` fingerprint metadata-coherence invariant.
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let buggify = bundle
        .metadata
        .buggify
        .as_ref()
        .expect("value-form --buggify must record an armed SDK config");
    assert_eq!(buggify.fire_permille, 1000);
    assert_eq!(buggify.activation_permille, 1000);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_sites_join_for_sdk_report(package: &Path, stderr: &str, expected_labels: &[&str]) {
    let report_path = package.join("sdk-report.stderr");
    fs::write(&report_path, stderr).unwrap();
    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        package,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            report_path.to_str().unwrap(),
            "--all",
            "--format",
            "json",
        ],
    );
    assert!(
        joined.status.success(),
        "sites --exercised failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&joined.stdout).unwrap_or_else(|error| {
        panic!(
            "sites --exercised did not emit JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&joined.stdout)
        )
    });
    assert_eq!(json["schema"], "patina.sites/v1");
    assert_eq!(json["unmatched_runtime_labels"], 0, "{json:#}");
    assert_eq!(
        json["totals"]["exercised"]["unmatched_runtime_labels"], 0,
        "{json:#}"
    );
    for label in expected_labels {
        let row = json["sites"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["label"].as_str() == Some(label))
            .unwrap_or_else(|| panic!("missing static site for label {label}: {json:#}"));
        assert!(
            row.get("exercised").is_some(),
            "label {label} did not join an exercised row: {json:#}"
        );
    }
}

// A guest whose `reachable!` site is behind an argv branch the campaign never
// takes: invisible to lazy registration, visible through the link-time table.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_NEVER_REACHABLE_MAIN: &str = r#"
fn main() {
    patina_dst::lifecycle::setup_complete();
    if std::env::args().any(|arg| arg == "--take-never-branch") {
        patina_dst::reachable!("never-called-reachable");
    }
    println!("guest-finished");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_static_site_table_surfaces_never_called_reachable_in_campaign() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("never");
    write_sdk_fixture(&pkg, BUGGIFY_NEVER_REACHABLE_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-never-reachable");
    invoke_in(
        workspace,
        &[
            "build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let out_dir = directory.path().join("campaign");
    let campaign = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "campaign",
            bin.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
    );
    let campaign_stdout = String::from_utf8_lossy(&campaign.stdout);
    assert_eq!(
        campaign.status.code(),
        Some(1),
        "never-called reachable! must fail the campaign coverage gate\nstdout:\n{campaign_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&campaign.stderr)
    );
    assert!(
        campaign_stdout.contains("UNMET reachable 'never-called-reachable'")
            && campaign_stdout.contains("registered_gens=0"),
        "campaign did not surface the never-called reachable site:\n{campaign_stdout}"
    );
    let sites_path = out_dir.join("sites.json");
    let sites_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&sites_path).unwrap()).unwrap();
    let row = sites_json["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|site| site["label"].as_str() == Some("never-called-reachable"))
        .unwrap_or_else(|| panic!("missing never-called reachable in sites.json: {sites_json:#}"));
    assert_eq!(row["kind"], "reachable");
    assert_eq!(row["registered_gens"], 0);
    assert_eq!(row["first_registered_gen"], serde_json::Value::Null);

    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &pkg,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            out_dir.to_str().unwrap(),
            "--site",
            "never-called-reachable",
            "--format",
            "json",
        ],
    );
    assert!(
        joined.status.success(),
        "sites --exercised campaign out-dir failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    let joined_json: serde_json::Value = serde_json::from_slice(&joined.stdout).unwrap();
    assert_eq!(
        joined_json["unmatched_runtime_labels"], 0,
        "{joined_json:#}"
    );
    assert_eq!(
        joined_json["totals"]["exercised"]["never_exercised"], 1,
        "{joined_json:#}"
    );
    assert_eq!(
        joined_json["sites"][0]["exercised"]["registered_gens"], 0,
        "{joined_json:#}"
    );
}

// A guest that reuses the same label at two different call sites: a fatal
// duplicate, aborting with the marker. With literal labels the link-time site
// table catches it at install, before the first evaluation.
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
        File::open("/").unwrap().sync_all().unwrap();
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

// A native guest that follows the parent-directory fsync pattern for namespace
// durability: write tmp, fsync file, rename, open parent directory read-only,
// fstat it, fsync it, then recover. Without the parent fsync, a crash after the
// rename can lose the destination; with the parent fsync, a crash after the dir
// fsync preserves it. This is the SlateDB local-object-store pattern that used
// to be impossible because File::open(parent_dir) returned EISDIR under Patina.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const NAMESPACE_DURABILITY_SOURCE: &str = r#"
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

fn main() {
    let with_dir_fsync = env::args().any(|arg| arg == "--dir-fsync");
    let tmp = "/tmp/patina-ns.tmp";
    let final_path = "/tmp/patina-ns.final";
    let _ = fs::remove_file(tmp);
    let _ = fs::remove_file(final_path);

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(tmp)
        .unwrap();
    file.write_all(b"stable").unwrap();
    file.sync_all().unwrap();
    fs::rename(tmp, final_path).unwrap();

    if with_dir_fsync {
        let dir = File::open("/tmp").unwrap();
        println!("dir_is_dir={}", dir.metadata().unwrap().is_dir());
        dir.sync_all().unwrap();
    }
    drop(file);

    let mut contents = String::new();
    match File::open(final_path) {
        Ok(mut file) => {
            file.read_to_string(&mut contents).unwrap();
            println!("NS_RESULT present {contents}");
        }
        Err(error) => println!("NS_RESULT missing {:?}", error.kind()),
    }
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_directory_fsync_guards_namespace_durability_and_replays() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("namespace.rs");
    fs::write(&source, NAMESPACE_DURABILITY_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("namespace");
    invoke_in(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let run_stdout = |args: &[&str]| -> String {
        String::from_utf8_lossy(&invoke_in(workspace, args).stdout).into_owned()
    };
    let bin_str = bin.to_str().unwrap();

    // RED detector: without the parent-directory fsync, a crash after the rename
    // (the file close immediately after rename) loses the destination. Same seed
    // repeats byte-identically.
    let lost_args = ["run", bin_str, "--seed", "5", "--fs-crash-at", "close:1"];
    let lost_a = run_stdout(&lost_args);
    let lost_b = run_stdout(&lost_args);
    assert_eq!(lost_a, lost_b, "same-seed namespace crash outcome changed");
    assert!(
        lost_a.contains("NS_RESULT missing"),
        "missing parent fsync should be able to lose the rename:\n{lost_a}"
    );

    // Guarded green: the same workload with parent-dir fsync survives a crash
    // immediately after the directory fsync.
    let guarded = run_stdout(&[
        "run",
        bin_str,
        "--seed",
        "5",
        "--fs-crash-at",
        "sync:2",
        "--",
        "--dir-fsync",
    ]);
    assert!(
        guarded.contains("dir_is_dir=true"),
        "fstat did not report a directory:\n{guarded}"
    );
    assert!(
        guarded.contains("NS_RESULT present stable"),
        "parent dir fsync should preserve the rename:\n{guarded}"
    );

    // A dir-fsync-bearing trace records and replays byte-identically.
    let trace = directory.path().join("namespace.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "run",
            bin_str,
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "namespace-dir-fsync",
            "--",
            "--dir-fsync",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "replay",
            bin_str,
            trace.to_str().unwrap(),
            "--fingerprint",
            "namespace-dir-fsync",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "directory-fsync trace replay diverged"
    );
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
fn native_run_source_json_artifact_names_source_not_tempdir() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("source_json.rs");
    fs::write(&source, "fn main() { println!(\"SOURCE_JSON_OK\"); }\n").unwrap();
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "run",
            source.to_str().unwrap(),
            "--seed",
            "0",
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "source-first json run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(value["artifact"], source.to_str().unwrap());
    assert!(
        !value["artifact"]
            .as_str()
            .unwrap()
            .contains("patina-run-artifact"),
        "source-first envelope must not name the throwaway build artifact: {value}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn explore_failure_reports_copy_paste_repro_in_line_and_json() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("explore_fail.rs");
    fs::write(
        &source,
        "fn main() { eprintln!(\"BUG_CAUGHT explore planted\"); std::process::exit(3); }\n",
    )
    .unwrap();
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "explore",
            "run",
            source.to_str().unwrap(),
            "--seeds",
            "1",
            "--format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PATINA_EXPLORE_FAILURE seed=0 exit=3 repro="),
        "missing explore repro line:\n{stderr}"
    );
    assert!(
        stderr.contains("cargo patina run") && stderr.contains("--seed 0"),
        "repro line should be copy-pasteable:\n{stderr}"
    );
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(value["verb"], "explore");
    assert_eq!(value["result"], "failure");
    assert!(
        value["message"]
            .as_str()
            .unwrap()
            .contains("repro: cargo patina run"),
        "JSON envelope should carry the repro: {value}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_harness_mode_filters_records_replays_and_refuses_missing_target() {
    let directory = tempdir().unwrap();
    create_native_harness_fixture(directory.path());
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let harness = "dst_harness_fixture";
    let passing_args = [
        "test",
        ".",
        "--harness-target",
        harness,
        "--exact",
        "tests::epoch_is_seeded",
        "--seed",
        "1",
        "--format",
        "json",
    ];
    let first = invoke_unchecked(patina, directory.path(), &passing_args);
    assert!(
        first.status.success(),
        "first filtered harness run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let second = invoke_unchecked(patina, directory.path(), &passing_args);
    assert!(
        second.status.success(),
        "second filtered harness run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout),
        "filtered harness JSON stdout should be byte-identical across repeats"
    );

    let pass_guest = directory.path().join(
        "target/patina/dst/dst_harness_fixture/dst_harness_fixture/tests__epoch_is_seeded/guest",
    );
    assert!(
        pass_guest.exists(),
        "staged pass harness missing: {pass_guest:?}"
    );
    let audit = invoke_unchecked(
        patina,
        directory.path(),
        &["audit", pass_guest.to_str().unwrap()],
    );
    assert!(
        audit.status.success(),
        "libtest harness audit surface should pass:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );

    let failing = invoke_unchecked(
        patina,
        directory.path(),
        &[
            "test",
            ".",
            "--harness-target",
            harness,
            "--exact",
            "tests::buggify_failure_records",
            "--seeds",
            "3",
            "--buggify=1000",
            "--buggify-activation-permille",
            "1000",
        ],
    );
    assert_eq!(failing.status.code(), Some(101));
    let fail_stderr = String::from_utf8_lossy(&failing.stderr);
    assert!(
        fail_stderr.contains(
            "patina dst test failed: dst_harness_fixture::tests::buggify_failure_records"
        ),
        "failure block missing test name:\n{fail_stderr}"
    );
    assert!(
        fail_stderr.contains("seed 0 of 0..3")
            && fail_stderr.contains("cargo patina test")
            && fail_stderr.contains("cargo patina replay"),
        "failure block missing seed/repro commands:\n{fail_stderr}"
    );
    let fail_guest = directory.path().join(
        "target/patina/dst/dst_harness_fixture/dst_harness_fixture/tests__buggify_failure_records/guest",
    );
    let trace = directory.path().join(
        "target/patina/dst/dst_harness_fixture/dst_harness_fixture/tests__buggify_failure_records/seed-0.patina",
    );
    assert!(trace.exists(), "record-on-failure trace missing: {trace:?}");
    let replay = invoke_unchecked(
        patina,
        directory.path(),
        &[
            "replay",
            fail_guest.to_str().unwrap(),
            trace.to_str().unwrap(),
        ],
    );
    assert_eq!(replay.status.code(), Some(101));
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("HARNESS_BUG"),
        "replay should reproduce the recorded failing libtest body:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );

    let missing = invoke_unchecked(
        patina,
        directory.path(),
        &[
            "test",
            ".",
            "--harness-target",
            "missing_harness",
            "--exact",
            "tests::epoch_is_seeded",
            "--seed",
            "0",
        ],
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("no libtest harness target named"),
        "missing harness target should refuse loudly:\n{}",
        String::from_utf8_lossy(&missing.stderr)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_native_harness_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"dst_harness_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dev-dependencies]\npatina-dst = {{ path = \"{}\" }}\n",
            native_workspace().join("crates/patina").display()
        ),
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        r#"
#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn epoch_is_seeded() {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        println!("HARNESS_PASS epoch={epoch}");
        assert_eq!(epoch, 0);
    }

    #[test]
    fn buggify_failure_records() {
        if patina_dst::buggify_with_prob!("native-harness-record", 1.0) {
            eprintln!("HARNESS_BUG record-on-failure");
            panic!("HARNESS_BUG");
        }
    }
}
"#,
    )
    .unwrap();
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

// ---- patina-dst-harness (shim-backed configure-then-run harness) --------------
//
// Validation gates for USAGE-MODES.md usage mode 2 (startup Option B, deferred
// init). A harness binary depends on `patina-dst-harness` and is built and run
// through `cargo patina run --harness`; ordinary `std` effects in the application
// closure are interposed by the native shim, and the harness's `HarnessBuilder`
// overlay flows through the same `RuntimeConfig` fields the CLI env path sets.
// Gate 7 (SDK dependency-lightness) belongs to the facade builder; gate 8
// (explicit-context separateness) is out of scope here — the explicit `Context`
// API lives in `patina-dst-runtime` and is exercised by `create_fixture`'s
// `patina_dst::run` scenarios, which never install the shim's global context.

/// Write a harness fixture crate at `dir` whose `main.rs` is `main_rs`, with a
/// path dependency on the workspace `patina-dst-harness`. Modeled on
/// `create_fixture`, but the dependency is the harness crate, not the SDK.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_harness_fixture(dir: &Path, name: &str, main_rs: &str) {
    fs::create_dir_all(dir.join("src")).unwrap();
    let harness_path = native_workspace().join("crates/patina-harness");
    let harness_path = harness_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-harness = {{ path = \"{harness_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(dir.join("src/main.rs"), main_rs).unwrap();
}

/// Build a harness fixture into `out` through `cargo patina build`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_harness_bin(dir: &Path, out: &Path) {
    invoke_in(
        native_workspace(),
        &[
            "build",
            dir.join("Cargo.toml").to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
        ],
    );
}

/// The single `HARNESS_OUT ...` line the harness fixtures print.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn harness_out_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("HARNESS_OUT"))
        .unwrap_or_else(|| {
            panic!(
                "missing HARNESS_OUT in stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .to_owned()
}

/// Parse `elapsed=N` (virtual monotonic nanoseconds observed through std's clock)
/// from a harness fixture's output line.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn harness_elapsed(output: &Output) -> u128 {
    harness_out_line(output)
        .split("elapsed=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("missing elapsed= in harness output"))
}

// A harness fixture that reads a file back through `std::fs` and times a
// `std::thread::sleep` through std's clock — all interposed by the shim, so the
// output (including the elapsed virtual-time reading) is a pure function of the
// seed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HARNESS_DETERMINISM_SRC: &str = r#"
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run(|| {
        std::fs::create_dir_all("/state")?;
        std::fs::write("/state/v", b"hello")?;
        let read = std::fs::read_to_string("/state/v")?;
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_nanos(10));
        let elapsed = start.elapsed().as_nanos();
        println!("HARNESS_OUT read={read} elapsed={elapsed}");
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}
"#;

// Gate 1: a harness binary executed directly (no Patina control plane) fails
// loudly with NotUnderPatina BEFORE any application code runs — never a silent
// host-effect fallback.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_direct_exec_without_patina_fails_closed() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("det");
    write_harness_fixture(&fixture, "harness-det-direct", HARNESS_DETERMINISM_SRC);
    let bin = directory.path().join("harness-det-direct-bin");
    build_harness_bin(&fixture, &bin);

    // Direct exec with a scrubbed environment: no PATINA_MODE, so the shim's
    // constructor installs nothing and `run` fails closed.
    let output = Command::new(&bin).env_clear().output().unwrap();
    assert!(
        !output.status.success(),
        "harness binary ran to success without Patina"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not running under `cargo patina run`"),
        "missing NotUnderPatina diagnostic:\nstderr:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("HARNESS_OUT"),
        "application code ran before the fail-closed check"
    );
}

// Gate 2: `cargo patina run --harness --target native` succeeds with std::fs and
// the std clock interposed, and is byte-identical across repeated runs at the same
// seed (determinism, including the std clock reads).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_run_is_deterministic_with_std_interposed() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("det");
    write_harness_fixture(&fixture, "harness-det", HARNESS_DETERMINISM_SRC);
    let bin = directory.path().join("harness-det-bin");
    build_harness_bin(&fixture, &bin);

    let first = invoke_in(
        native_workspace(),
        &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
    );
    let baseline = harness_out_line(&first);
    assert!(
        baseline.contains("read=hello"),
        "std::fs was not interposed (unexpected output): {baseline}"
    );
    for _ in 0..2 {
        let again = invoke_in(
            native_workspace(),
            &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
        );
        assert_eq!(
            baseline,
            harness_out_line(&again),
            "harness output (incl. std clock reads) is not byte-identical across runs"
        );
    }
}

// A harness fixture whose configuration is toggled by a guest argument: with
// `--jitter` the harness adds a fixed seeded sleep jitter, observable through the
// same std clock the application reads.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HARNESS_JITTER_TOGGLE_SRC: &str = r#"
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run_with(
        |harness| {
            if std::env::args().any(|arg| arg == "--jitter") {
                Ok(harness.sleep_jitter_nanos(1_000_000, 1_000_000))
            } else {
                Ok(harness)
            }
        },
        || {
            let start = Instant::now();
            std::thread::sleep(std::time::Duration::from_nanos(10));
            println!("HARNESS_OUT elapsed={}", start.elapsed().as_nanos());
            Ok::<(), std::io::Error>(())
        },
    )?;
    Ok(())
}
"#;

// Gate 3: a harness-configured knob observably affects behavior seen through
// ordinary application code. A configured sleep jitter shifts the std-clock
// elapsed reading by exactly the jitter, proving the overlay reached the same
// `RuntimeConfig` field the CLI `--sleep-jitter-nanos` sets.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_configured_knob_affects_std_observed_behavior() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("jitter");
    write_harness_fixture(&fixture, "harness-jitter", HARNESS_JITTER_TOGGLE_SRC);
    let bin = directory.path().join("harness-jitter-bin");
    build_harness_bin(&fixture, &bin);

    let base = invoke_in(
        native_workspace(),
        &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
    );
    let jittered = invoke_in(
        native_workspace(),
        &[
            "run",
            bin.to_str().unwrap(),
            "--harness",
            "--seed",
            "1",
            "--",
            "--jitter",
        ],
    );
    let base_elapsed = harness_elapsed(&base);
    let jittered_elapsed = harness_elapsed(&jittered);
    assert_eq!(
        base_elapsed, 10,
        "baseline sleep should advance virtual time by exactly the requested 10ns"
    );
    assert_eq!(
        jittered_elapsed,
        base_elapsed + 1_000_000,
        "harness-configured sleep jitter did not shift the std-observed elapsed time"
    );
}

// Gate 4: record then flag-free replay of a harness-driven application is
// byte-identical. Replay of a harness binary carries `--harness` (deferred init)
// but no semantic flags — the trace is authoritative.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_record_then_flag_free_replay_is_byte_identical() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("det");
    write_harness_fixture(&fixture, "harness-replay", HARNESS_DETERMINISM_SRC);
    let bin = directory.path().join("harness-replay-bin");
    build_harness_bin(&fixture, &bin);

    let trace = directory.path().join("harness.patina");
    let recorded = invoke_in(
        native_workspace(),
        &[
            "run",
            bin.to_str().unwrap(),
            "--harness",
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "harness-replay",
        ],
    );
    let replayed = invoke_in(
        native_workspace(),
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--harness",
            "--fingerprint",
            "harness-replay",
        ],
    );
    assert_eq!(
        harness_out_line(&recorded),
        harness_out_line(&replayed),
        "record and flag-free harness replay diverged"
    );
}

// A harness fixture that unconditionally sets a fixed sleep jitter, so two builds
// with different jitter values embed conflicting fault configuration.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn harness_fixed_jitter_src(jitter: u64) -> String {
    format!(
        r#"
fn main() -> Result<(), Box<dyn std::error::Error>> {{
    patina_dst_harness::run_with(
        |harness| Ok(harness.sleep_jitter_nanos({jitter}, {jitter})),
        || {{
            std::thread::sleep(std::time::Duration::from_nanos(1));
            println!("HARNESS_OUT ok");
            Ok::<(), std::io::Error>(())
        }},
    )?;
    Ok(())
}}
"#
    )
}

// Gate 5: replaying with a conflicting harness configuration fails closed. The
// harness overlay flows through the same `RuntimeConfig::faults` field the CLI
// sets, so the runtime's `reconcile_replay_faults` (the trace is authoritative)
// catches a divergent harness-configured knob exactly like a CLI flag conflict.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_replay_with_conflicting_config_fails_closed() {
    let directory = tempdir().unwrap();
    let fixture_a = directory.path().join("jit-a");
    let fixture_b = directory.path().join("jit-b");
    write_harness_fixture(
        &fixture_a,
        "harness-jit-a",
        &harness_fixed_jitter_src(1_000_000),
    );
    write_harness_fixture(
        &fixture_b,
        "harness-jit-b",
        &harness_fixed_jitter_src(2_000_000),
    );
    let bin_a = directory.path().join("harness-jit-a-bin");
    let bin_b = directory.path().join("harness-jit-b-bin");
    build_harness_bin(&fixture_a, &bin_a);
    build_harness_bin(&fixture_b, &bin_b);

    let trace = directory.path().join("jit.patina");
    invoke_in(
        native_workspace(),
        &[
            "run",
            bin_a.to_str().unwrap(),
            "--harness",
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "harness-jit",
        ],
    );

    // Binary B embeds a different (conflicting) sleep jitter; both share the same
    // fingerprint (faults are reconciled from trace metadata, not fingerprinted),
    // so the run reaches fault reconciliation and fails closed there.
    let conflict = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "replay",
            bin_b.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--harness",
            "--fingerprint",
            "harness-jit",
        ],
    );
    assert!(
        !conflict.status.success(),
        "replay with a conflicting harness config succeeded"
    );
    let stderr = String::from_utf8_lossy(&conflict.stderr);
    assert!(
        stderr.contains("conflict with the trace's recorded configuration"),
        "missing fault-reconciliation conflict diagnostic:\nstderr:\n{stderr}"
    );

    // The original binary (matching config) replays cleanly.
    let matching = invoke_in(
        native_workspace(),
        &[
            "replay",
            bin_a.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--harness",
            "--fingerprint",
            "harness-jit",
        ],
    );
    assert!(harness_out_line(&matching).contains("ok"));
}

// A harness fixture that performs an interposed std effect BEFORE calling the
// harness — the classic configure-after-boundary mistake.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HARNESS_BOUNDARY_SRC: &str = r#"
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Interposed std effect before the harness installs the runtime.
    std::fs::create_dir_all("/early")?;
    println!("HARNESS_APP_RAN");
    patina_dst_harness::run(|| Ok::<(), std::io::Error>(()))?;
    Ok(())
}
"#;

// Gate 6: an interposed effect before the harness installs the runtime fails
// closed. Under deferred init the effect reaches the boundary with no context
// installed and no auto-init is allowed, so the shim aborts loudly and the
// application code never proceeds.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_effect_before_install_fails_closed() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("boundary");
    write_harness_fixture(&fixture, "harness-boundary", HARNESS_BOUNDARY_SRC);
    let bin = directory.path().join("harness-boundary-bin");
    build_harness_bin(&fixture, &bin);

    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
    );
    assert!(
        !output.status.success(),
        "an effect before the harness install did not fail the run"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("harness has not installed the runtime yet"),
        "missing boundary-before-install diagnostic:\nstderr:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("HARNESS_APP_RAN"),
        "application code ran past the pre-install boundary"
    );
}

// `--harness` is native-only: on a WASI run it is rejected up front (the WASI
// supervisor owns run configuration), never silently ignored.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn harness_flag_rejected_for_wasi_target() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("app.wasm");
    fs::write(
        &module,
        wat::parse_str("(module (func (export \"_start\")))").unwrap(),
    )
    .unwrap();
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &["run", module.to_str().unwrap(), "--harness"],
    );
    assert!(
        !output.status.success(),
        "--harness on a WASI run succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("`run` of a WASI module does not accept --harness"),
        "missing native-only rejection:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// The registry-driven help system: a per-verb `--help` prints that verb's
// focused section and exits 0 (regression for the wall-dump / `--help`-consumed-
// as-a-positional bug where `campaign --help` errored with "failed to read
// artifact --help"), and `--help --format json` emits the machine-readable
// registry covering every verb.
#[test]
fn per_verb_help_and_json_registry() {
    let directory = tempdir().unwrap();

    // `cargo patina campaign --help` exits 0 with the campaign synopsis + --gens.
    let help = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["campaign", "--help"],
    );
    assert!(
        help.status.success(),
        "campaign --help exited {}\nstderr:\n{}",
        help.status,
        String::from_utf8_lossy(&help.stderr)
    );
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        stdout.contains("cargo patina campaign"),
        "campaign --help missing synopsis:\n{stdout}"
    );
    assert!(
        stdout.contains("--gens"),
        "campaign --help missing --gens:\n{stdout}"
    );
    // The old bug's error string must be gone.
    assert!(
        !stdout.contains("failed to read artifact"),
        "campaign --help still consumes --help as a positional"
    );

    // `cargo patina --help --format json` exits 0 and parses as the compact INDEX:
    // schema patina.help/v2, every verb as {summary, forms} but NO flag_groups,
    // the global flags + environment protocol, and a per-verb command pointer.
    let index_out = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["--help", "--format", "json"],
    );
    assert!(
        index_out.status.success(),
        "--help --format json exited {}",
        index_out.status
    );
    let index: serde_json::Value =
        serde_json::from_slice(&index_out.stdout).expect("--help --format json emits valid JSON");
    assert_eq!(index["schema"], "patina.help/v2", "index schema tag");
    assert!(
        index["environment"].is_array(),
        "index carries the environment protocol"
    );
    assert!(
        index["verb_detail"]["command_template"]
            .as_str()
            .is_some_and(|t| t.contains("{verb}")),
        "index carries a substitutable per-verb command template:\n{}",
        String::from_utf8_lossy(&index_out.stdout)
    );
    let verbs = index["verbs"].as_object().expect("verbs object");
    for verb in [
        "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize",
    ] {
        assert!(
            verbs.contains_key(verb),
            "JSON index missing verb {verb}:\n{}",
            String::from_utf8_lossy(&index_out.stdout)
        );
        assert!(
            verbs[verb].get("flag_groups").is_none(),
            "index must not carry flag_groups for {verb}"
        );
    }

    // `cargo patina run --help --format json` emits ONLY run's detail: run's own
    // flags (its unique --harness) but NOT another verb's unique flag (campaign's
    // --gens), and no environment block. Absent-field defaults hold: --release is
    // native to build; run's repeatable --param carries `repeatable: true`.
    let run_out = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", "--help", "--format", "json"],
    );
    assert!(
        run_out.status.success(),
        "run --help --format json exited {}",
        run_out.status
    );
    let run: serde_json::Value =
        serde_json::from_slice(&run_out.stdout).expect("run --help --format json emits valid JSON");
    assert_eq!(run["schema"], "patina.help/v2", "verb-scoped schema tag");
    assert_eq!(run["verb"]["name"], "run", "scoped payload names its verb");
    assert!(
        run.get("verbs").is_none() && run.get("environment").is_none(),
        "scoped payload carries neither the verbs index nor the environment block"
    );
    let run_flags = e2e_flag_names(&run["verb"]["flag_groups"]);
    assert!(
        run_flags.contains("--harness"),
        "run's payload should carry its own --harness flag"
    );
    assert!(
        !run_flags.contains("--gens"),
        "run's payload leaked campaign's unique --gens flag"
    );
    let param = e2e_find_flag(&run["verb"]["flag_groups"], "--param").expect("run has --param");
    assert_eq!(
        param["repeatable"], true,
        "a repeatable flag emits repeatable: true"
    );
    assert!(
        param.get("short").is_none(),
        "a short-less flag omits the `short` key entirely (absent means none)"
    );
}

/// Every flag `name` across an array of `{title, flags}` groups.
fn e2e_flag_names(flag_groups: &serde_json::Value) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for group in flag_groups.as_array().into_iter().flatten() {
        for flag in group["flags"].as_array().into_iter().flatten() {
            if let Some(name) = flag["name"].as_str() {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// The first flag object named `name` across an array of `{title, flags}` groups.
fn e2e_find_flag(flag_groups: &serde_json::Value, name: &str) -> Option<serde_json::Value> {
    for group in flag_groups.as_array().into_iter().flatten() {
        for flag in group["flags"].as_array().into_iter().flatten() {
            if flag["name"].as_str() == Some(name) {
                return Some(flag.clone());
            }
        }
    }
    None
}

// Phase 2: `--arg=--help` is the only way to deliver a literal `--help` to a WASI
// guest, because a bare `--help` before `--` is intercepted as Patina help. This
// pins both halves: the inline form runs the guest; the space form shows help.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn inline_arg_delivers_literal_help_while_space_form_shows_help() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("noop.wasm");
    fs::write(
        &module,
        wat::parse_str("(module (func (export \"_start\")))").unwrap(),
    )
    .unwrap();
    let module = module.to_str().unwrap();

    // Inline: the guest runs and exits 0; Patina help is NOT shown.
    let inline = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module, "--arg=--help"],
    );
    assert!(
        inline.status.success(),
        "inline --arg=--help failed: {}\n{}",
        inline.status,
        String::from_utf8_lossy(&inline.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&inline.stdout).contains("cargo patina run"),
        "inline --arg=--help wrongly triggered Patina help"
    );

    // Space form: the bare `--help` is intercepted and prints run help (exit 0).
    let spaced = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", module, "--arg", "--help"],
    );
    assert!(spaced.status.success(), "run --arg --help should exit 0");
    assert!(
        String::from_utf8_lossy(&spaced.stdout).contains("cargo patina run"),
        "space-form --help should show run help:\n{}",
        String::from_utf8_lossy(&spaced.stdout)
    );
}

// Phase 2: a path-like positional that does not exist fails closed with a clear
// "no such file" (exit 2), instead of falling through to a confusing `cargo run`.
#[test]
fn nonexistent_wasm_positional_fails_closed() {
    let directory = tempdir().unwrap();
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        directory.path(),
        &["run", "definitely-missing.wasm"],
    );
    assert_eq!(output.status.code(), Some(2), "expected a usage-error exit");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no such file"),
        "missing the fail-closed message:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// WASI depth (coverage-depth arc, wave D): fuel + per-import hostcall counts.
// ---------------------------------------------------------------------------

// A wasip1 guest whose hostcall mix is fixed by the module text and whose work
// (and therefore fuel) is driven by one deterministic random byte, so depth
// varies across seeds while staying exactly reproducible for any one seed.
const WASI_DEPTH_MODULE: &str = r#"(module
    (import "wasi_snapshot_preview1" "random_get"
        (func $random (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "clock_time_get"
        (func $clock (param i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write"
        (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 128) "DEPTH_GUEST ok\n")
    (func (export "_start")
        (local $n i32)
        (drop (call $random (i32.const 64) (i32.const 1)))
        (local.set $n (i32.and (i32.load8_u (i32.const 64)) (i32.const 63)))
        (block $done (loop $spin
            (br_if $done (i32.eqz (local.get $n)))
            (local.set $n (i32.sub (local.get $n) (i32.const 1)))
            (br $spin)))
        (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 72)))
        (i32.store (i32.const 0) (i32.const 128))
        (i32.store (i32.const 4) (i32.const 15))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 16)))))"#;

fn depth_report_line(output: &Output) -> String {
    let line = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("PATINA_DEPTH_REPORT "))
        .unwrap_or_default()
        .to_string();
    assert!(
        !line.is_empty(),
        "a WASI run must emit PATINA_DEPTH_REPORT:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    line
}

// Depth is a measurement, so it must obey the same determinism contract as every
// other Patina observation: byte-identical for one seed across repeats AND across
// record -> replay, while a different seed moves it (otherwise the "measurement"
// would be a constant and the campaign's novelty signal inert).
#[test]
fn wasi_depth_is_byte_identical_across_repeats_and_replay_and_varies_by_seed() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("depth.wasm");
    fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
    let module_path = module.to_str().unwrap().to_string();
    let run = |arguments: &[&str]| {
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            arguments,
        )
    };

    let first = run(&["run", &module_path, "--seed", "5"]);
    assert!(first.status.success(), "depth guest run failed");
    let second = run(&["run", &module_path, "--seed", "5"]);
    assert_eq!(
        depth_report_line(&first),
        depth_report_line(&second),
        "repeat runs of one seed must report byte-identical depth"
    );

    let trace = directory.path().join("depth.patina");
    let trace_path = trace.to_str().unwrap().to_string();
    let recorded = run(&["run", &module_path, "--seed", "5", "--record", &trace_path]);
    let replayed = run(&["replay", &module_path, &trace_path]);
    assert_eq!(
        depth_report_line(&recorded),
        depth_report_line(&replayed),
        "replay must reproduce the recorded run's depth exactly"
    );
    assert_eq!(depth_report_line(&first), depth_report_line(&recorded));

    // Seed variation: the guest's loop length comes from deterministic entropy, so
    // some seed must report different fuel. A constant here would mean depth is
    // not actually measuring the guest.
    let baseline = depth_report_line(&first);
    let varied = (6..16)
        .map(|seed| depth_report_line(&run(&["run", &module_path, "--seed", &seed.to_string()])))
        .any(|line| line != baseline);
    assert!(
        varied,
        "depth never changed across ten seeds; the measurement is inert:\n{baseline}"
    );

    // The structured envelope carries the same facts, and an import the guest
    // never calls has no row at all — "no depth data" is never spelled as zero.
    let json = run(&["run", &module_path, "--seed", "5", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let depth = &envelope["depth"];
    assert_eq!(depth["family"], "wasi");
    assert_eq!(depth["hostcalls"]["fd_write"], 1);
    assert_eq!(depth["hostcalls"]["random_get"], 1);
    assert_eq!(depth["hostcalls"]["clock_time_get"], 1);
    assert_eq!(depth["hostcalls_total"], 3);
    assert!(depth["hostcalls"].get("fd_read").is_none());
    assert!(depth["fuel_consumed"].as_u64().unwrap() > 0);
    assert!(
        envelope["markers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|marker| marker.as_str().unwrap().starts_with("PATINA_DEPTH_REPORT ")),
        "the depth marker must surface in the envelope's markers"
    );
}

fn campaign_depth_meta(out_dir: &Path) -> serde_json::Value {
    let path = out_dir.join("depth").join("meta.json");
    assert!(
        path.is_file(),
        "campaign depth store is missing at {}",
        path.display()
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

// The depth store follows the shared aux-store resume contract: k generations
// then `--extend` must reproduce the fresh campaign's persisted bytes exactly.
// The hostcall sums are saturating ADDS, so a missing watermark skip would
// double-count them and this comparison would fail — the WASI mirror of the
// native coverage store's idempotency proof.
#[test]
fn campaign_extend_reproduces_aux_store_bytes_for_wasi_depth() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("depth.wasm");
    fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
    let module_path = module.to_str().unwrap().to_string();
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
    };
    let campaign_args = |out: &Path, gens: u64| {
        vec![
            "campaign".to_string(),
            module_path.clone(),
            "--gens".to_string(),
            gens.to_string(),
            "--plateau-after".to_string(),
            "4".to_string(),
            "--progress-every".to_string(),
            "1".to_string(),
            "--out-dir".to_string(),
            out.to_str().unwrap().to_string(),
        ]
    };

    let fresh_out = directory.path().join("fresh");
    let fresh = run(campaign_args(&fresh_out, 12));
    assert!(
        fresh.status.success(),
        "fresh WASI depth campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );
    let fresh_stdout = String::from_utf8_lossy(&fresh.stdout).into_owned();
    let fresh_meta_bytes = fs::read_to_string(fresh_out.join("depth").join("meta.json")).unwrap();
    let meta = campaign_depth_meta(&fresh_out);

    // Non-vacuity: every generation ran to completion, so every generation must
    // have contributed a measurement. `generations_with_depth=0` would be a store
    // that cannot tell "no data" from "zero depth".
    assert_eq!(meta["generations_applied"], 12);
    assert_eq!(meta["generations_with_depth"], 12);
    assert_eq!(meta["hostcall_kinds"], 3);
    assert_eq!(meta["hostcalls"]["fd_write"], 12);
    assert!(meta["fuel_max"].as_u64().unwrap() > 0);
    assert!(meta["fuel_total"].as_u64().unwrap() >= meta["fuel_max"].as_u64().unwrap());
    assert!(
        !meta["new_depth_log"].as_array().unwrap().is_empty(),
        "the first generation always establishes a fuel high-water mark"
    );

    // The plateau flag is exactly the arc's rule over the persisted log, not an
    // approximation of it.
    let last_new = meta["last_new_depth_gen"].as_u64().unwrap();
    let expected_plateau = 11 - last_new >= 4;
    assert_eq!(
        meta["depth_plateaued"].as_bool().unwrap(),
        expected_plateau,
        "depth_plateaued must be (generations_applied - 1 - last_new_depth_gen) >= plateau_after"
    );
    assert!(
        fresh_stdout.contains(&format!("depth_plateaued={}", u8::from(expected_plateau))),
        "PATINA_CAMPAIGN_COMPLETE must carry the depth plateau verdict:\n{fresh_stdout}"
    );
    assert!(
        !fresh_stdout.contains("PATINA_CAMPAIGN_DEPTH_VACUOUS"),
        "a campaign whose generations all reported depth is not vacuous:\n{fresh_stdout}"
    );

    let split_out = directory.path().join("split");
    let split1 = run(campaign_args(&split_out, 4));
    assert!(split1.status.success(), "first WASI depth segment failed");
    let split2 = run(vec![
        "campaign".to_string(),
        "--extend".to_string(),
        "8".to_string(),
        "--out-dir".to_string(),
        split_out.to_str().unwrap().to_string(),
        "--progress-every".to_string(),
        "1".to_string(),
    ]);
    assert!(
        split2.status.success(),
        "extended WASI depth campaign failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&split2.stdout),
        String::from_utf8_lossy(&split2.stderr)
    );
    let split1_stdout = String::from_utf8_lossy(&split1.stdout);
    let split2_stdout = String::from_utf8_lossy(&split2.stdout);
    assert_eq!(
        campaign_gen_lines(&fresh_stdout),
        [
            campaign_gen_lines(&split1_stdout),
            campaign_gen_lines(&split2_stdout)
        ]
        .join("\n"),
        "4-then-extend must reproduce the fresh per-generation stream"
    );
    assert_eq!(
        fresh_meta_bytes,
        fs::read_to_string(split_out.join("depth").join("meta.json")).unwrap(),
        "4-then-extend must reproduce the depth store bytes"
    );
    println!(
        "WASI_DEPTH_STORE_BYTE_EQUALITY bytes={} fuel_max={} kinds={}",
        fresh_meta_bytes.len(),
        meta["fuel_max"],
        meta["hostcall_kinds"]
    );

    // The envelope reports the same accumulation, under its own `depth` object
    // (never folded into `coverage`, which stays honestly unavailable here).
    let json_out = directory.path().join("json");
    let mut json_args = campaign_args(&json_out, 3);
    json_args.extend(["--format".to_string(), "json".to_string()]);
    let json = run(json_args);
    assert!(
        json.status.success(),
        "JSON WASI depth campaign failed:\nstderr:\n{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let envelope = campaign_json_stdout(&json);
    assert_eq!(envelope["depth"]["state"], "available");
    assert_eq!(envelope["depth"]["generations_with_depth"], 3);
    assert_eq!(envelope["coverage"]["edge"]["state"], "unavailable");
    assert_eq!(envelope["coverage"]["edge"]["reason"], "not-native");
    assert!(envelope["artifacts"]["depth_dir"].is_string());
}

// The checkpoint-tear leg of the aux-store contract, deterministically staged:
// the depth store is written BEFORE `campaign-state.json`, so a crash between the
// two leaves the store one generation ahead of the cursor and resume re-runs that
// generation. Rewinding the cursor by one reproduces exactly that state without
// racing a process. The re-run's fold must be skipped by the watermark: the
// hostcall sums are saturating adds, so folding it twice would inflate them and
// break the byte comparison below (RED-proven by disabling the skip).
#[test]
fn campaign_resume_after_a_depth_checkpoint_tear_does_not_double_fold() {
    let directory = tempdir().unwrap();
    let module = directory.path().join("depth.wasm");
    fs::write(&module, wat::parse_str(WASI_DEPTH_MODULE).unwrap()).unwrap();
    let out = directory.path().join("camp");
    let run = |owned: Vec<String>| {
        let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), directory.path(), &refs)
    };

    let fresh = run(vec![
        "campaign".to_string(),
        module.to_str().unwrap().to_string(),
        "--gens".to_string(),
        "6".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
    ]);
    assert!(
        fresh.status.success(),
        "fresh depth campaign failed:\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    let untorn_meta = fs::read_to_string(out.join("depth").join("meta.json")).unwrap();
    let torn_hostcalls = campaign_depth_meta(&out)["hostcalls"].clone();

    // Stage the tear: the cursor claims five generations, the depth store already
    // reflects six.
    let state_path = out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state["generations_done"] = serde_json::Value::from(5u64);
    // The class histogram is validated against the cursor, so it rewinds too —
    // this is a checkpoint tear, not a corrupt out-dir.
    let classes = state["classes"].as_object_mut().unwrap();
    let ok = classes.get_mut("OK").expect("a clean campaign records OK");
    *ok = serde_json::Value::from(ok.as_u64().unwrap() - 1);
    fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let resumed = run(vec![
        "campaign".to_string(),
        "--resume".to_string(),
        "--out-dir".to_string(),
        out.to_str().unwrap().to_string(),
    ]);
    assert!(
        resumed.status.success(),
        "resume after a depth checkpoint tear failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        untorn_meta,
        fs::read_to_string(out.join("depth").join("meta.json")).unwrap(),
        "re-running the torn generation must contribute nothing to the depth store"
    );
    assert_eq!(
        torn_hostcalls,
        campaign_depth_meta(&out)["hostcalls"],
        "hostcall sums must not be double-counted across a resume"
    );
}
