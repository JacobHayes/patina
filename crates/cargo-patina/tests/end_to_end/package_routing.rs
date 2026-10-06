//! Source/package routing and consistent native run/audit gates.

#[cfg(test)]
mod tests {
    use super::super::*;

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
        invoke(
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
        let ran = invoke(
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
        invoke(
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

    // DEFECT 1 (parity/misroute): a `run <package-dir>` positional must resolve as a
    // SOURCE — built on the fly and run — exactly like `audit <package-dir>`, never
    // be silently reinterpreted as guest argv of some other package. The regression
    // ran the CWD's package with the directory passed through as an argument. Here
    // the run is issued FROM A DIFFERENT package's directory (a decoy that would have
    // been run instead): the built guest's own marker must appear and the decoy's
    // must not. This also proves the shim-staticlib build runs in the unpacked shim
    // source cache (not the caller's CWD): building the positional package from a
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
        let ran = invoke(
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
        let build = invoke(
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
        let recorded = invoke(
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
        let replayed = invoke(
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
    // plain package that imports an uninterposed process-class symbol (`system`) is
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
            // Imports `system` (process class, denied) behind an opaque branch so it
            // is never actually called but stays in the import table. `kill` itself is
            // now shim-defined (a deterministic-model interposer that drops off the
            // import table), so `system` is the still-uninterposed process-class member
            // the gate must flag.
            "unsafe extern \"C\" { fn system(command: *const u8) -> i32; }\n\
         fn main() {\n\
         let g = std::hint::black_box(0i32);\n\
         if g != 0 { unsafe { system(std::ptr::null()); } }\n\
         println!(\"GATE_PKG_RAN\");\n\
         }\n",
        );

        // Prebuilt path: build the artifact, then run it.
        let bin = directory.path().join("gate-bin");
        invoke(
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
        assert!(denied_line(&prebuilt).contains("system"));
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
        invoke(
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
        let audited = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        let audit_out = String::from_utf8_lossy(&audited.stdout);
        assert!(
            !audit_out.contains("dynamic-loading"),
            "audit still reports the shim control-plane dlsym as denied:\n{audit_out}"
        );

        // run with NO --allow succeeds: the same symbol `run` enforces is the same one
        // `audit` accepted.
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("PARITY_OK"),
            "run did not execute the guest:\n{}",
            String::from_utf8_lossy(&ran.stdout)
        );
    }
}
