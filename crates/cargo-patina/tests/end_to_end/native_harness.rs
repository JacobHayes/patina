//! Cargo libtest harness selection, seed runs, and refusal provenance.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn native_harness_mode_filters_records_replays_and_refuses_missing_target() {
        let directory = tempdir().unwrap();
        create_native_harness_fixture(directory.path());
        let patina = env!("CARGO_BIN_EXE_patina");
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
        let passed = invoke_unchecked(patina, directory.path(), &passing_args);
        assert!(
            passed.status.success(),
            "filtered harness run failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&passed.stdout),
            String::from_utf8_lossy(&passed.stderr)
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

        // A path the target has no test for runs nothing, so it is refused
        // rather than passed: libtest itself exits 0 for it.
        let unmatched = invoke_unchecked(
            patina,
            directory.path(),
            &[
                "test",
                ".",
                "--harness-target",
                harness,
                "--exact",
                "tests::no_such_test",
                "--seeds",
                "2",
                "--format",
                "json",
            ],
        );
        assert_eq!(unmatched.status.code(), Some(2), "{unmatched:?}");
        let refused: serde_json::Value = serde_json::from_slice(&unmatched.stdout).unwrap();
        assert_ne!(refused["result"], "ok", "{refused}");

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
        // A failing test body is a finding in the guest: exit 1, with the
        // libtest harness's own status reported beside it.
        assert_eq!(failing.status.code(), Some(1));
        let result: serde_json::Value = serde_json::from_slice(&failing.stdout).unwrap();
        assert_eq!(
            (
                &result["result"],
                &result["attribution"],
                &result["guest_exit"]["code"]
            ),
            (&"failure".into(), &"guest".into(), &101.into()),
            "{result}"
        );
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
        assert_eq!(replay.status.code(), Some(1));
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
    /// A bare name is ambiguous, and each `kind:name` selector runs its own
    /// target: every target carries a canary that fails only under Patina, so a
    /// wrong target or an empty filter cannot look like success. Class pairing:
    /// the target-kind/package selection matrix in lib.rs.
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
        for (kind, path, entry) in [
            ("lib", "src/lib.rs", ""),
            ("bin", "src/main.rs", "fn main() {}"),
            ("test", "tests/same_name.rs", ""),
        ] {
            fs::write(
                root.join(path),
                format!(
                    "{entry}\n#[test]\n#[allow(unexpected_cfgs)]\nfn selected_{kind}() {{ assert!(!cfg!(patina)); }}\n"
                ),
            )
            .unwrap();
        }
        let patina = env!("CARGO_BIN_EXE_patina");
        let ambiguous = invoke_unchecked(
            patina,
            root,
            &[
                "test",
                ".",
                "--harness-target",
                "same_name",
                "--exact",
                "selected_lib",
                "--seed",
                "0",
            ],
        );
        assert_eq!(ambiguous.status.code(), Some(2));
        for kind in ["lib", "bin", "test"] {
            let selector = format!("{kind}:same_name");
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
            assert_eq!(canary.status.code(), Some(1), "{selector}: {canary:?}");
        }
    }

    /// `test` ends in the class of the seed's own run, with the attribution
    /// and exit status that follow from it: the vocabulary and the table are
    /// `run`'s.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_reports_the_class_of_the_run_that_decided_it() {
        let directory = tempdir().unwrap();
        create_native_harness_fixture(directory.path());
        for (exact, result, attribution, exit) in [
            ("tests::epoch_is_seeded", "ok", None, 0),
            ("tests::always_is_violated", "violation", Some("guest"), 1),
            ("tests::aborts", "crash", Some("guest"), 1),
            ("tests::no_such_test", "error", Some("request"), 2),
        ] {
            let ran = invoke_unchecked(
                env!("CARGO_BIN_EXE_patina"),
                directory.path(),
                &[
                    "test",
                    ".",
                    "--harness-target",
                    "dst_harness_fixture",
                    "--exact",
                    exact,
                    "--seed",
                    "1",
                    "--format",
                    "json",
                ],
            );
            let envelope: serde_json::Value = serde_json::from_slice(&ran.stdout)
                .unwrap_or_else(|error| panic!("{exact}: {error}: {ran:?}"));
            assert_eq!(
                (
                    envelope["result"].as_str(),
                    envelope["attribution"].as_str(),
                    envelope["exit_code"].as_i64(),
                    ran.status.code(),
                ),
                (Some(result), attribution, Some(i64::from(exit)), Some(exit)),
                "{exact}: {envelope:#}"
            );
        }
    }

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
    fn always_is_violated() {
        patina_dst::always!(std::env::args().count() > 64, "harness-always");
    }

    #[test]
    fn aborts() {
        std::process::abort();
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
