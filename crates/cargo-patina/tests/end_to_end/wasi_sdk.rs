//! WASI cooperative SDK imports, buggify behavior, and replay.

#[cfg(test)]
mod tests {
    use super::super::*;

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

    // An `always!` invariant violation on wasip1 reports a `violation` verdict and
    // terminates the run with a nonzero exit — the WASI mirror of the native shim's
    // abort. The verdict line is the announcement; there is no legacy marker.
    #[test]
    fn wasi_always_violation_traps_with_a_violation_verdict() {
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
        let stderr = String::from_utf8_lossy(&violated.stderr);
        assert!(
            stderr.contains("kind=violation") && stderr.contains("label=must-hold"),
            "missing violation verdict:\nstderr:\n{stderr}"
        );
        assert!(
            !stderr.contains("PATINA_ALWAYS_VIOLATION"),
            "the legacy always-violation marker must no longer print:\nstderr:\n{stderr}"
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
        let wasm =
            fixture_target_directory(&package).join("wasm32-wasip1/debug/wasi-buggify-guest.wasm");

        // Plain build (no `cfg(patina)`): its output must import no `patina_sdk`.
        {
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
        invoke(
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
            ran.status.success()
                && String::from_utf8_lossy(&ran.stdout).contains("WASI_GUEST_DIGEST"),
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

        // `--arg violate` makes the always! invariant false: the host records the
        // `violation` verdict and fails the run on wasip1.
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
        let violated_stderr = String::from_utf8_lossy(&violated.stderr);
        assert!(
            !violated.status.success()
                && violated_stderr.contains("kind=violation")
                && violated_stderr.contains("label=guest-invariant"),
            "always! violation not detected on wasip1:\nstderr:\n{violated_stderr}"
        );
    }

    // Whether `haystack` contains the byte subsequence `needle`.
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
