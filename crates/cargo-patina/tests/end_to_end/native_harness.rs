//! `patina test`: a package's own test suite, one simulated run per test.

#[cfg(test)]
mod tests {
    use super::super::*;

    fn json_of(output: &std::process::Output) -> serde_json::Value {
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    /// Each test's result by name.
    fn results(document: &serde_json::Value) -> BTreeMap<String, String> {
        document["tests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|test| test["skipped"].is_null())
            .map(|test| {
                (
                    test["name"].as_str().unwrap().to_string(),
                    test["result"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// The whole suite runs, one verdict per test: each in the class its own
    /// run ends in, `#[should_panic]` honoured, `#[ignore]` skipped unless
    /// asked, and the exit status the most severe test's. Every test the
    /// fixture declares is listed; none is lost or invented.
    #[test]
    fn the_whole_suite_runs_with_one_verdict_per_test() {
        let directory = tempdir().unwrap();
        let source = create_native_harness_fixture(directory.path());
        let declared = source.matches("#[test]").count();
        let patina = env!("CARGO_BIN_EXE_patina");
        let ran = invoke_unchecked(
            patina,
            directory.path(),
            &["test", "--format", "json", "--progress"],
        );
        let document = json_of(&ran);
        assert_eq!(document["schema"], "patina.test/v1");
        assert_eq!(document["listed"], declared, "{document:#}");
        // `--progress`: one `test_finished` event per test run, counting up
        // to the tests the document reports, beside the one document.
        let finished: Vec<serde_json::Value> = progress_events(&ran, "test")
            .into_iter()
            .filter(|event| event["event"] == "test_finished")
            .collect();
        let ran_tests = results(&document);
        let failing = ran_tests.values().filter(|class| *class != "ok").count();
        let done: Vec<u64> = finished
            .iter()
            .map(|event| event["done"].as_u64().unwrap())
            .collect();
        assert_eq!(done, (1..=ran_tests.len() as u64).collect::<Vec<_>>());
        assert!(
            finished
                .windows(2)
                .all(|pair| pair[0]["failures"].as_u64() <= pair[1]["failures"].as_u64())
        );
        let last = finished.last().unwrap();
        assert_eq!(last["total"], ran_tests.len(), "{last:#}");
        assert_eq!(last["failures"], failing, "{last:#}");
        let expected: BTreeMap<String, String> = [
            ("tests::epoch_is_seeded", "ok"),
            ("tests::should_panic_panics", "ok"),
            ("tests::always_is_violated", "violation"),
            ("tests::aborts", "crash"),
            ("tests::panics", "failure"),
            ("tests::should_panic_does_not", "failure"),
            ("tests::spawns_a_process", "unsupported"),
            ("tests::buggify_failure_records", "ok"),
        ]
        .into_iter()
        .map(|(name, class)| (name.to_string(), class.to_string()))
        .collect();
        assert_eq!(results(&document), expected, "{document:#}");
        assert_eq!(document["skipped"], 1, "{document:#}");
        assert_eq!(
            (document["result"].as_str(), ran.status.code()),
            (Some("violation"), Some(1))
        );
        let counted: u64 = document["counts"]
            .as_object()
            .unwrap()
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum();
        assert_eq!(counted as usize, declared - 1);

        // The staged guest is where the document says, and passes the audit.
        let guest = document["targets"][0]["guest"].as_str().unwrap();
        assert!(
            invoke_unchecked(patina, directory.path(), &["audit", guest])
                .status
                .success()
        );

        // `--include-ignored` runs the ignored test too.
        let all = invoke_unchecked(
            patina,
            directory.path(),
            &["test", "ignored", "--include-ignored", "--format", "json"],
        );
        let all = json_of(&all);
        assert_eq!(all["skipped"], 0);
        assert_eq!(results(&all)["tests::ignored_panics"], "failure", "{all:#}");

        // `--skip` is libtest's: a substring leaves out every test whose path
        // contains it, and with `--exact` only the test it names.
        let skipped = |extra: &[&str]| {
            let ran = invoke_unchecked(
                patina,
                directory.path(),
                &[&["test", "--format", "json"][..], extra].concat(),
            );
            results(&json_of(&ran)).into_keys().collect::<Vec<_>>()
        };
        let kept: Vec<String> = expected
            .keys()
            .filter(|name| !name.contains("panic") && !name.contains("abort"))
            .cloned()
            .collect();
        assert_eq!(skipped(&["--skip", "panic", "--skip", "abort"]), kept);
        let kept: Vec<String> = expected
            .keys()
            .filter(|name| *name != "tests::panics")
            .cloned()
            .collect();
        assert_eq!(skipped(&["--skip", "tests::panics", "--exact"]), kept);
    }

    /// A finding is recorded on its seed: the trace it names replays the
    /// failure, and the rerun command it prints runs that one test on that
    /// seed to the same end.
    #[test]
    fn a_finding_replays_and_its_rerun_reproduces_it() {
        let directory = tempdir().unwrap();
        create_native_harness_fixture(directory.path());
        let patina = env!("CARGO_BIN_EXE_patina");
        let ran = invoke_unchecked(
            patina,
            directory.path(),
            &[
                "test",
                "tests::buggify_failure_records",
                "--exact",
                "--seeds",
                "3",
                "--buggify-fire-permille",
                "1000",
                "--buggify-activation-permille",
                "1000",
                "--format",
                "json",
            ],
        );
        assert_eq!(ran.status.code(), Some(1));
        let document = json_of(&ran);
        let test = &document["tests"][0];
        assert_eq!(
            (
                &test["result"],
                &test["attribution"],
                &test["guest_exit"]["code"],
                &test["seed"]
            ),
            (&"failure".into(), &"guest".into(), &101.into(), &0.into()),
            "{document:#}"
        );
        assert!(test["trace"]["event_count"].as_u64().unwrap() > 0);
        let trace = test["trace"]["path"].as_str().unwrap();
        let guest = document["targets"][0]["guest"].as_str().unwrap();
        let replay = invoke_unchecked(patina, directory.path(), &["replay", guest, trace]);
        assert_eq!(replay.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&replay.stderr).contains("HARNESS_BUG"),
            "{replay:?}"
        );
        let rerun = test["rerun"].as_str().unwrap();
        let rerun = rerun.strip_prefix("patina ").expect("a patina command");
        let again = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("exec \"$0\" {rerun} --format json"))
            .arg(patina)
            .current_dir(directory.path())
            .output()
            .unwrap();
        let again = json_of(&again);
        assert_eq!(results(&again), results(&document));
        assert_eq!(again["tests"][0]["seed"], 0);
    }

    /// The exit status: an unsupported test raises it to 2 unless an
    /// `--accept-unsupported` text names its stop, and even then it is
    /// reported unsupported, never ok. A filter that matches nothing is an
    /// error, not a pass of nothing.
    #[test]
    fn unsupported_tests_are_never_passes() {
        let directory = tempdir().unwrap();
        create_native_harness_fixture(directory.path());
        let patina = env!("CARGO_BIN_EXE_patina");
        let spawn = [
            "test",
            "tests::spawns_a_process",
            "--exact",
            "--format",
            "json",
        ];
        let refused = invoke_unchecked(patina, directory.path(), &spawn);
        assert_eq!(refused.status.code(), Some(2));
        let refused = json_of(&refused);
        assert_eq!(refused["tests"][0]["result"], "unsupported", "{refused:#}");
        let detail = refused["tests"][0]["stop"]["detail"].as_str().unwrap();
        // The refusal names what the test spawned, not only the call it
        // reached first: the program and its argument the fixture passed.
        assert!(
            detail.contains("patina-spawn-probe") && detail.contains("--probe-argument"),
            "{refused:#}"
        );
        let accepted = invoke_unchecked(
            patina,
            directory.path(),
            &[&spawn[..], &["--accept-unsupported", detail]].concat(),
        );
        assert_eq!(accepted.status.code(), Some(0));
        let accepted = json_of(&accepted);
        assert_eq!(
            (
                &accepted["tests"][0]["result"],
                &accepted["tests"][0]["accepted"]
            ),
            (&"unsupported".into(), &true.into()),
            "{accepted:#}"
        );
        let other = invoke_unchecked(
            patina,
            directory.path(),
            &[&spawn[..], &["--accept-unsupported", "dlopen"]].concat(),
        );
        assert_eq!(other.status.code(), Some(2));

        let unmatched = invoke_unchecked(
            patina,
            directory.path(),
            &["test", "tests::no_such_test", "--exact", "--format", "json"],
        );
        assert_eq!(unmatched.status.code(), Some(2), "{unmatched:?}");
        assert_eq!(json_of(&unmatched)["result"], "error");
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

    /// Same-named targets are Cargo's default for a package with lib.rs and
    /// main.rs. Each selection flag runs its own target and no other: every
    /// target carries a canary that fails only under Patina, so a wrong
    /// target or an empty run cannot look like success.
    #[test]
    fn selection_flags_run_their_own_targets() {
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
        let everything = json_of(&invoke_unchecked(
            patina,
            root,
            &["test", "--format", "json"],
        ));
        assert_eq!(
            results(&everything).into_keys().collect::<Vec<_>>(),
            ["selected_bin", "selected_lib", "selected_test"]
        );
        for (selection, kind) in [
            (&["--lib"][..], "lib"),
            (&["--bin", "same_name"][..], "bin"),
            (&["--test", "same_name"][..], "test"),
        ] {
            let ran = invoke_unchecked(
                patina,
                root,
                &[&["test", "--format", "json"][..], selection].concat(),
            );
            assert_eq!(ran.status.code(), Some(1), "{selection:?}: {ran:?}");
            let document = json_of(&ran);
            assert_eq!(
                results(&document),
                BTreeMap::from([(format!("selected_{kind}"), "failure".to_string())]),
                "{selection:?}"
            );
        }
        let missing = invoke_unchecked(patina, root, &["test", "--test", "missing"]);
        assert_eq!(missing.status.code(), Some(2));
    }

    /// A package whose own binary calls the SDK, with an integration test:
    /// Cargo builds the binary beside the test, compiled for Patina like
    /// every crate of the build but linked without the shim. The test still
    /// builds, and its own SDK calls reach the runtime: it is simulated and
    /// its fault site fires, where the binary's stand-ins would abort.
    #[test]
    fn an_integration_test_builds_beside_a_binary_that_calls_the_sdk() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        write_sdk_fixture(
            root,
            r#"
fn main() {
    println!("{} {}", patina_dst::is_simulated(), patina_dst::rng());
    patina_dst::lifecycle::setup_complete();
    patina_dst::lifecycle::event!("workload");
    patina_dst::reachable!("started");
    let batch = patina_dst::buggify_knob!("batch", 64_i64, 1, 1024);
    let fired = patina_dst::buggify!("rare") || patina_dst::buggify_delay!("slow");
    patina_dst::sometimes!(fired, "rare-fired");
    patina_dst::always!(batch > 0, "batch-positive");
    patina_dst::verdict(patina_dst::VerdictKind::Pass, "done", "{}");
    println!("{:?}", patina_dst::param("mode"));
}
"#,
        );
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("tests/dst.rs"),
            r#"
#[test]
fn the_sdk_reaches_the_runtime() {
    assert!(patina_dst::is_simulated());
    assert!(patina_dst::buggify_with_prob!("always-fires", 1.0));
}
"#,
        )
        .unwrap();
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            root,
            &[
                "test",
                "--test",
                "dst",
                "--seed",
                "1",
                "--buggify",
                "--buggify-activation-permille",
                "1000",
                "--format",
                "json",
            ],
        );
        let document = json_of(&ran);
        assert_eq!(
            (results(&document), ran.status.code()),
            (
                BTreeMap::from([("the_sdk_reaches_the_runtime".to_string(), "ok".to_string())]),
                Some(0)
            ),
            "{document:#}\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
    }

    /// A package's binaries are admitted: its tests name each by the path
    /// `CARGO_BIN_EXE_*` gives them, which stands for a shim-linked build
    /// staged apart from the one Cargo installed there. A spawn of one runs
    /// that staged artifact as a child process; a spawn of one the pre-run
    /// gate refuses, or of
    /// anything else, is refused. A recording names each program by digest
    /// and verdict: its replay refuses a changed artifact or a changed
    /// verdict, and needs no artifact the run never spawned.
    #[test]
    fn a_packages_binaries_are_admitted_judged_and_replayed_by_digest() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir_all(root.join("src/bin")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"admits\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        // A binary the pre-run gate refuses: it links a libc entry Patina
        // does not model.
        fs::write(
            root.join("src/bin/refused.rs"),
            r#"
unsafe extern "C" {
    fn newlocale(mask: i32, locale: *const u8, base: *mut u8) -> *mut u8;
}

fn main() {
    let _ = unsafe { newlocale(0, c"C".as_ptr().cast(), std::ptr::null_mut()) };
}
"#,
        )
        .unwrap();
        fs::write(
            root.join("tests/spawn.rs"),
            r#"
#[test]
fn spawns_its_own_binary() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_admits")).status();
    assert!(status.unwrap().success());
}

#[test]
fn spawns_a_refused_binary() {
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_refused")).status();
}

#[test]
fn spawns_another_program() {
    let _ = std::process::Command::new("/bin/true").status();
}

#[test]
fn names_its_binary() {
    panic!("{}", env!("CARGO_BIN_EXE_admits"));
}
"#,
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_patina");
        let ran = invoke_unchecked(patina, root, &["test", "--format", "json"]);
        let document = json_of(&ran);
        let test = |name: &str| {
            document["tests"]
                .as_array()
                .unwrap()
                .iter()
                .find(|test| test["name"] == name)
                .unwrap_or_else(|| panic!("no {name}: {document:#}"))
                .clone()
        };
        let stopped = |name: &str| {
            let test = test(name);
            (test["result"].clone(), test["stop"]["reason"].clone())
        };
        assert_eq!(
            stopped("spawns_its_own_binary"),
            ("ok".into(), serde_json::Value::Null),
            "{document:#}"
        );
        for refused in ["spawns_a_refused_binary", "spawns_another_program"] {
            assert_eq!(
                stopped(refused),
                ("unsupported".into(), "deny_trap".into()),
                "{document:#}"
            );
        }

        // The finding's recording names the programs it could spawn: each
        // binary by the path its test was given, standing for the staged
        // artifact, and whether it was admitted.
        let finding = test("names_its_binary");
        assert_eq!(finding["result"], "failure", "{finding:#}");
        let trace = PathBuf::from(finding["trace"]["path"].as_str().unwrap());
        let guest = trace.parent().unwrap().parent().unwrap().join("guest");
        let info = json_of(&invoke_unchecked(
            patina,
            root,
            &["trace", "info", trace.to_str().unwrap(), "--format", "json"],
        ));
        let admitted = info["trace_info"]["native"]["admitted"]
            .as_array()
            .unwrap_or_else(|| panic!("{info:#}"));
        let why = finding["why"].as_str().unwrap();
        let binary = admitted
            .iter()
            .find(|program| why.ends_with(program["program"].as_str().unwrap()))
            .unwrap_or_else(|| panic!("{why} is not admitted: {admitted:#?}"));
        assert!(binary["refused"].is_null(), "{admitted:#?}");
        assert_ne!(binary["artifact"], binary["program"]);
        let refused = admitted
            .iter()
            .find(|program| !program["refused"].is_null())
            .unwrap_or_else(|| panic!("no program is refused: {admitted:#?}"));

        let replay = |extra: &[&str]| {
            let mut args = vec![
                "replay",
                guest.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--format",
                "json",
            ];
            args.extend(extra);
            let replayed = json_of(&invoke_unchecked(patina, root, &args));
            (
                replayed["result"].clone(),
                replayed["stop"]["reason"].clone(),
            )
        };
        assert_eq!(replay(&[]).0, "failure");
        // Another verdict on the refused binary is another program.
        assert_eq!(
            replay(&["--allow", "newlocale"]),
            ("error".into(), "trace_mismatch".into())
        );
        // An artifact the run never spawned need not be there.
        fs::remove_file(binary["artifact"].as_str().unwrap()).unwrap();
        assert_eq!(replay(&[]).0, "failure");
        // One that is there must be the one recorded.
        let artifact = PathBuf::from(refused["artifact"].as_str().unwrap());
        let mut bytes = fs::read(&artifact).unwrap();
        bytes.push(0);
        fs::write(&artifact, bytes).unwrap();
        assert_eq!(replay(&[]), ("error".into(), "trace_mismatch".into()));
    }

    /// A test that reads its fixture by absolute host path fails under
    /// Patina, whose filesystem was never given it: the test keeps its class
    /// and the suite its exit status, and the test carries the path as a
    /// likely artifact, in the document and beside it in the human summary.
    /// The `--mount` the artifact names makes the test pass. A test that fails
    /// on its own carries none.
    #[test]
    fn a_test_reading_a_host_fixture_is_flagged_and_its_mount_passes_it() {
        let directory = tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("fixtures")).unwrap();
        fs::write(root.join("fixtures/data.txt"), "fixture\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"host_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/lib.rs"),
            r#"
#[test]
fn reads_fixture() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/data.txt");
    assert_eq!(std::fs::read_to_string(path).expect("fixture"), "fixture\n");
}

#[test]
fn fails_on_its_own() {
    assert_eq!(1 + 1, 3);
}
"#,
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_patina");
        let test = |extra: &[&str]| {
            let ran = invoke_unchecked(
                patina,
                &root,
                &[&["test", "--format", "json"][..], extra].concat(),
            );
            (ran.status.code(), json_of(&ran))
        };
        let entry = |document: &serde_json::Value, name: &str| {
            document["tests"]
                .as_array()
                .unwrap()
                .iter()
                .find(|test| test["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("no {name}: {document:#}"))
        };

        let (code, document) = test(&[]);
        assert_eq!(
            (code, document["result"].as_str()),
            (Some(1), Some("failure"))
        );
        let flagged = entry(&document, "reads_fixture");
        assert_eq!(flagged["result"], "failure", "{flagged:#}");
        let artifact = &flagged["likely_artifacts"][0];
        assert_eq!(artifact["kind"], "missing_host_path", "{flagged:#}");
        let fixture = root.join("fixtures/data.txt");
        assert_eq!(artifact["path"], fixture.to_str().unwrap());
        let own = entry(&document, "fails_on_its_own");
        assert_eq!(own["result"], "failure", "{own:#}");
        assert!(own["likely_artifacts"].is_null(), "{own:#}");

        // The human summary names the mount beside the failing test.
        let mount = artifact["mount"].as_str().unwrap();
        let human = invoke_unchecked(patina, &root, &["test", "reads_fixture"]);
        assert_eq!(human.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&human.stdout).contains(mount),
            "{}",
            String::from_utf8_lossy(&human.stdout)
        );

        let (code, mounted) = test(&["--mount", mount, "reads_fixture"]);
        assert_eq!(code, Some(0), "{mounted:#}");
        assert_eq!(entry(&mounted, "reads_fixture")["result"], "ok");
    }

    /// Writes the fixture and returns its test source.
    fn create_native_harness_fixture(root: &Path) -> String {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"dst_harness_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dev-dependencies]\npatina-dst = {{ path = \"{}\" }}\n",
            native_workspace().join("crates/patina").display()
        ),
    )
    .unwrap();
        let source = r#"
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
    fn panics() {
        panic!("HARNESS_PANIC");
    }

    #[test]
    #[should_panic(expected = "expected")]
    fn should_panic_panics() {
        panic!("expected");
    }

    #[test]
    #[should_panic]
    fn should_panic_does_not() {}

    #[test]
    #[ignore]
    fn ignored_panics() {
        panic!("HARNESS_IGNORED");
    }

    #[test]
    fn spawns_a_process() {
        // A working directory takes std's chdir spawn action, which on
        // macOS it looks up by name: the run must still reach the refusal.
        let _ = std::process::Command::new("patina-spawn-probe")
            .arg("--probe-argument")
            .current_dir("/")
            .status();
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
        );
        fs::write(root.join("src/lib.rs"), &source).unwrap();
        source
    }
}
