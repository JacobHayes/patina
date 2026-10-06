//! Cargo libtest harness selection, seed runs, and refusal provenance.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn explore_failure_reports_copy_paste_repro_in_line_and_json() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("explore_fail.rs");
        fs::write(
            &source,
            "fn main() { eprintln!(\"GUEST_FAILED explore planted\"); std::process::exit(3); }\n",
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

        let pass_guest = fixture_target_directory(directory.path()).join(
            "patina/dst/dst_harness_fixture/lib/dst_harness_fixture/tests__epoch_is_seeded/guest",
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
                "--format",
                "json",
            ],
        );
        assert_eq!(failing.status.code(), Some(101));
        let result: serde_json::Value = serde_json::from_slice(&failing.stdout).unwrap();
        // Positive control for the refusal detector: the receipt must contain real
        // trace facts, and the path it advertises must actually replay the failure.
        assert!(result["trace"].is_object(), "{result}");
        assert!(result["trace"]["event_count"].as_u64().unwrap() > 0);
        let trace = PathBuf::from(result["trace"]["path"].as_str().unwrap());
        let failure_dir = fixture_target_directory(directory.path()).join(
            "patina/dst/dst_harness_fixture/lib/dst_harness_fixture/tests__buggify_failure_records",
        );
        let fail_guest = failure_dir.join("guest");
        assert_eq!(trace, failure_dir.join("seed-0.patina"));
        assert!(trace.is_file());
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

    /// Portable class pairing for the executable-metadata pin. An import refusal
    /// happens before guest launch on every native platform, not just x86-64 Linux.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_harness_import_refusal_has_no_trace() {
        assert_native_harness_prerun_refusal(
            "import_refusal",
            "import_is_linked",
            r#"
unsafe extern "C" { fn system(command: *const u8) -> i32; }
#[test]
fn import_is_linked() {
    // Retain the import without invoking a shell, natively or under Patina.
    assert_ne!(std::hint::black_box(system as *const () as usize), 0);
}
"#,
            "process",
        );
    }

    /// Same-name targets are Cargo's default for a package with lib.rs + main.rs.
    /// Class pairing: the target-kind/package selection matrix in lib.rs.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_harness_selects_same_named_library_binary_and_integration_test() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"same_name\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        // Native and simulated oracles are the same; no sleep or host input.
        let case = r#"
#[test]
fn roundtrip() {
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || tx.send(42).unwrap());
    assert_eq!(rx.recv().unwrap(), 42);
    thread.join().unwrap();
}
"#;
        for (kind, path, entry) in [
            ("lib", "src/lib.rs", ""),
            ("bin", "src/main.rs", "fn main() {}"),
            ("test", "tests/same_name.rs", ""),
        ] {
            // Each harness also has a distinct failing selection canary under
            // Patina. A wrong target or an empty filter must not look like success.
            fs::write(
            root.join(path),
            format!(
                "{entry}\n{case}\n#[test]\n#[allow(unexpected_cfgs)]\nfn selected_{kind}() {{ assert!(!cfg!(patina)); }}\n"
            ),
        )
        .unwrap();
        }
        let native = Command::new("cargo")
            .args(["test", "--quiet"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(native.status.success(), "{native:?}");
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let ambiguous = invoke_unchecked(
            patina,
            root,
            &[
                "test",
                ".",
                "--harness-target",
                "same_name",
                "--exact",
                "roundtrip",
                "--seed",
                "0",
            ],
        );
        assert_eq!(ambiguous.status.code(), Some(2));
        for kind in ["lib", "bin", "test"] {
            let selector = format!("{kind}:same_name");
            let run = invoke_unchecked(
                patina,
                root,
                &[
                    "test",
                    ".",
                    "--harness-target",
                    &selector,
                    "--exact",
                    "roundtrip",
                    "--seed",
                    "0",
                ],
            );
            assert!(run.status.success(), "{selector}: {run:?}");
            let canary = invoke_unchecked(
                patina,
                root,
                &[
                    "test",
                    ".",
                    "--harness-target",
                    &selector,
                    "--exact",
                    &format!("selected_{kind}"),
                    "--seed",
                    "0",
                ],
            );
            assert_eq!(canary.status.code(), Some(101), "{selector}: {canary:?}");
        }
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
        // Default epoch plus the fixed boot origin, in whole seconds.
        assert_eq!(epoch, DEFAULT_START_SECONDS);
    }


    #[test]
    fn buggify_failure_records() {
        if patina_dst::buggify_with_prob!("native-harness-record", 1.0) {
            eprintln!("HARNESS_BUG record-on-failure");
            panic!("HARNESS_BUG");
        }
    }
}
"#
            .replace(
                "DEFAULT_START_SECONDS",
                &((patina_dst_runtime::DEFAULT_REALTIME_EPOCH_NANOS
                    + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS)
                    / 1_000_000_000)
                    .to_string(),
            ),
        )
        .unwrap();
    }
}
