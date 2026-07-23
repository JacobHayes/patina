use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

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
        &["wasi-run", module.to_str().unwrap(), "--preopen", "/rw:rw"],
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
        &["wasi-run", module.to_str().unwrap(), "--preopen", "/ro:ro"],
    );
    assert_eq!(ro.status.code(), Some(69));
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
    let replayed = invoke(&fixture, &["run", "--replay", trace.to_str().unwrap()]);
    assert_eq!(result_line(&recorded), result_line(&replayed));
    assert_eq!(result_line(&replayed), first_result);

    let branched = invoke(
        &fixture,
        &[
            "run",
            "--branch",
            trace.to_str().unwrap(),
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
            "run",
            "--replay",
            trace.to_str().unwrap(),
            "--timeline",
            "branch-999",
        ],
    );
    assert_eq!(result_line(&replayed_branch), result_line(&branched));

    invoke(&fixture, &["test", "--seed", "123"]);
    let alias = invoke_with(
        env!("CARGO_BIN_EXE_cargo-dst"),
        &fixture,
        &["run", "--seed", "123"],
    );
    assert_eq!(result_line(&alias), first_result);

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
        &["run", "--replay", trace.to_str().unwrap()],
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
// off-allowlist binary fail closed. `native-build` builds the `patina-native-shim`
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
            "native-build",
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
    // binary, with the shim control-plane vehicles allowed per audited binary.
    let control_plane: &[&str] = if cfg!(target_os = "macos") {
        &[
            "_read$NOCANCEL",
            "_write$NOCANCEL",
            "pthread_create_suspended_np",
            "pthread_mach_thread_np",
            "thread_resume",
            "dispatch_semaphore_create",
            "dispatch_semaphore_wait",
            "dispatch_semaphore_signal",
            "dispatch_release",
        ]
    } else {
        &[
            "__read",
            "__write",
            "pthread_create",
            "sem_init",
            "sem_post",
            "sem_wait",
        ]
    };
    let mut audit_args = vec!["native-audit", clean.to_str().unwrap()];
    for symbol in control_plane {
        audit_args.push("--allow");
        audit_args.push(symbol);
    }
    invoke_in(workspace, &audit_args);

    // The package binary runs under native-run with cross-process seed stability,
    // seed variation, and byte-identical record/replay through the supervisor.
    let seeded = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let repeated = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let other = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "6"],
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
            "native-run",
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
            "native-run",
            clean.to_str().unwrap(),
            "--replay",
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
        &["native-build", package.to_str().unwrap()],
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
            "native-build",
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
        &["native-audit", leaky.to_str().unwrap()],
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("process"),
        "missing process-category diagnostic:\n{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

fn invoke(fixture: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), fixture, arguments)
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
            "#!/bin/sh\nout=$(\"{}\" run --replay \"$PATINA_MINIMIZE_TRACE\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 3 ] && printf '%s' \"$out\" | grep -q 'interleaved=true'; then\n  exit 1\nfi\nexit 0\n",
            env!("CARGO_BIN_EXE_cargo-patina")
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
        &["run", "--replay", minimized_path.to_str().unwrap()],
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
        r#"// Imports a process-spawning libc symbol the native audit denies as
// "process". Building succeeds; the audit must reject the product.
fn main() {
    let status = std::process::Command::new("/bin/true").status().unwrap();
    std::process::exit(status.code().unwrap_or(1));
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
    let patina_path = workspace.join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-sched-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use std::collections::BTreeMap;

use patina::RuntimeError;

fn scenario() -> Result<(String, bool), RuntimeError> {
    patina::run(|context| {
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
    let patina_path = workspace.join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-e2e-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use patina::{ClockKind, RuntimeError};

fn scenario() -> Result<String, RuntimeError> {
    patina::run(|context| {
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
