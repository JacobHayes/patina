//! Source and package routing for the native verbs.

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
        // the chosen member, built native on the fly (a package that integrates the
        // Patina runtime would stay the cargo family instead).
        let ran = invoke(
            build_workspace,
            &[
                "run",
                manifest.to_str().unwrap(),
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
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            build_workspace,
            &[
                "audit",
                env!("CARGO_BIN_EXE_cargo-patina"),
                "--package",
                "whatever",
            ],
        );
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("already-built artifact"),
            "missing prebuilt-selection diagnostic:\n{}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }

    // A package directory is a source in every verb, resolved from the
    // positional and never from the caller's CWD.
    //
    // * `run <dir>` from inside a DIFFERENT package's directory (a decoy) builds
    //   and runs the positional package, not the decoy, with the build-on-run note.
    //   The shim staticlib builds from the unpacked shim source cache, not the
    //   caller's CWD.
    // * `--record` in package mode produces a trace, and `replay <dir>` reproduces it.
    // * `replay <dir>` with a missing trace hard-errors before any guest runs.
    // * `build .` from inside the package directory succeeds.
    // * A bare `run` from inside a package that does not integrate the Patina
    //   runtime is refused loudly, pointing at the native path, instead of
    //   degrading to a plain `cargo run` that bypasses the gate.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn package_dir_positional_is_a_source_for_run_record_replay_and_build() {
        let directory = tempdir().unwrap();
        let pkg = directory.path().join("target-pkg");
        write_plain_package(
            &pkg,
            "patina-run-target-pkg",
            "fn main() { let a: Vec<String> = std::env::args().skip(1).collect(); \
             println!(\"TARGET_PKG_MARKER args={a:?}\"); }\n",
        );
        let decoy = directory.path().join("decoy");
        write_plain_package(
            &decoy,
            "patina-decoy-pkg",
            "fn main() { println!(\"DECOY_MARKER\"); }\n",
        );

        let trace = directory.path().join("rec.patina");
        let recorded = invoke(
            &decoy,
            &[
                "run",
                pkg.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--",
                "alpha",
            ],
        );
        let stdout = String::from_utf8_lossy(&recorded.stdout);
        assert!(
            stdout.contains("TARGET_PKG_MARKER")
                && !stdout.contains("DECOY_MARKER")
                && stdout.contains("PATINA_BUILD_ON_RUN"),
            "run <dir> must build and run the positional package, with its note:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        assert!(trace.is_file(), "package-mode --record produced no trace");
        let replayed = invoke(
            &pkg,
            &["replay", pkg.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            stdout_line_with(&recorded, "TARGET_PKG_MARKER"),
            stdout_line_with(&replayed, "TARGET_PKG_MARKER"),
            "package-mode replay diverged from the recording",
        );

        let missing = directory.path().join("does-not-exist.patina");
        let out = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &pkg,
            &["replay", pkg.to_str().unwrap(), missing.to_str().unwrap()],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success()
                && stderr.contains("trace")
                && (stderr.contains("read") || stderr.contains("open")),
            "replay with a missing trace must name the trace-read error:\n{stderr}"
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("TARGET_PKG_MARKER"));

        let built = directory.path().join("built-in-place");
        let build = invoke(&pkg, &["build", ".", "--output", built.to_str().unwrap()]);
        assert!(
            String::from_utf8_lossy(&build.stdout).contains("PATINA_BUILD output=")
                && built.is_file(),
            "`build .` from the package CWD failed:\nstderr:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );

        let out = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &pkg,
            &["run", "--seed", "1"],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success()
                && !String::from_utf8_lossy(&out.stdout).contains("TARGET_PKG_MARKER"),
            "cwd-mode run of a non-Patina package must not run the guest:\n{stderr}"
        );
        assert!(
            stderr.contains("does not depend on the Patina runtime")
                && stderr.contains("cargo patina run <DIR"),
            "missing loud refusal pointing at the native path:\n{stderr}"
        );
    }

    // `run <package dir>` builds on the fly and must reach the same pre-run gate
    // a prebuilt binary of that package does: one refused package (an
    // uninterposed process-class import kept behind an opaque branch) and one
    // allowed, each judged the same way on both paths.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_package_dir_and_its_prebuilt_binary_get_the_same_gate_verdict() {
        let directory = tempdir().unwrap();
        let verdict = |out: &Output| {
            let envelope: serde_json::Value = serde_json::from_slice(&out.stdout)
                .unwrap_or_else(|error| panic!("{error}: {out:?}"));
            (
                out.status.code(),
                envelope["refusal"]["class"].clone(),
                envelope["guest_exit"].is_null(),
            )
        };
        for (name, main, refused) in [
            (
                "refused",
                "unsafe extern \"C\" { fn system(command: *const u8) -> i32; }\n\
                 fn main() {\n\
                 if std::hint::black_box(0) != 0 { unsafe { system(std::ptr::null()); } }\n\
                 }\n",
                true,
            ),
            ("allowed", "fn main() {}\n", false),
        ] {
            let pkg = directory.path().join(name);
            write_plain_package(&pkg, &format!("patina-gate-{name}"), main);
            let bin = directory.path().join(format!("{name}-bin"));
            invoke(
                &pkg,
                &[
                    "build",
                    pkg.to_str().unwrap(),
                    "--output",
                    bin.to_str().unwrap(),
                ],
            );
            let [prebuilt, package_dir] = [&bin, &pkg].map(|target| {
                verdict(&invoke_unchecked(
                    env!("CARGO_BIN_EXE_cargo-patina"),
                    &pkg,
                    &[
                        "run",
                        "--seed",
                        "1",
                        "--format",
                        "json",
                        target.to_str().unwrap(),
                    ],
                ))
            });
            assert_eq!(prebuilt, package_dir, "{name}");
            assert_eq!(
                prebuilt.2, refused,
                "{name}: did the guest run? {prebuilt:?}"
            );
            if refused {
                assert_eq!(prebuilt.0, Some(2), "{name}");
                assert_eq!(prebuilt.1, "native_prerun_audit", "{name}");
            } else {
                assert_eq!(prebuilt.0, Some(0), "{name}");
            }
        }
    }
}
