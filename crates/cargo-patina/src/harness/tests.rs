use super::run::{SeedRun, TestCase, listed_tests, push_run_flags, seed_outcome};
use super::select::{TargetKind, select_packages, select_targets};
use super::*;
use crate::help;
use crate::parse::knobs_of;
use crate::tests::knob_sample;
use crate::{cli, parse};
use patina_dst_runtime::FaultKnob;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

fn metadata() -> serde_json::Value {
    let target =
        |name: &str, kind: &str| serde_json::json!({"name": name, "kind": [kind], "test": true});
    serde_json::json!({
        "workspace_members": ["a-id", "b-id"],
        "workspace_default_members": ["a-id"],
        "packages": [
            {
                "id": "a-id",
                "name": "a",
                "manifest_path": "/nowhere/a/Cargo.toml",
                "features": {"default": ["fast"], "fast": [], "slow": []},
                "targets": [
                    target("a", "lib"),
                    target("a", "bin"),
                    target("it-works", "test"),
                    {"name": "needs-slow", "kind": ["test"], "test": true, "required-features": ["slow"]},
                    {"name": "needs-fast", "kind": ["test"], "test": true, "required-features": ["fast"]},
                    {"name": "untested", "kind": ["bin"], "test": false},
                    {"name": "build-script-build", "kind": ["custom-build"]},
                    {"name": "demo", "kind": ["example"]},
                ],
            },
            {
                "id": "b-id",
                "name": "b",
                "manifest_path": "/nowhere/b/Cargo.toml",
                "targets": [target("b", "lib")],
            },
        ],
    })
}

fn chosen(selection: &Selection, features: &CargoFeatures) -> Result<Vec<String>, CliError> {
    let metadata = metadata();
    let packages = select_packages(&metadata, Path::new("/nowhere/Cargo.toml"), selection)?;
    let (targets, skipped) = select_targets(&packages, selection, features)?;
    Ok(targets
        .iter()
        .map(|target| format!("{}:{}:{}", target.package, target.kind.name(), target.name))
        .chain(
            skipped
                .iter()
                .map(|skipped| format!("skipped {}", skipped.target.name)),
        )
        .collect())
}

/// Selection follows `cargo test`: a virtual manifest tests its default
/// members, each package its lib, bins and integration tests whose `test` is
/// on, minus those whose required features are off; `-p`/`--workspace` pick
/// members and the target flags pick targets, by target or crate name.
#[test]
fn selection_follows_cargo_test() {
    let none = CargoFeatures::default();
    assert_eq!(
        chosen(&Selection::default(), &none).unwrap(),
        [
            "a:lib:a",
            "a:bin:a",
            "a:test:it-works",
            "a:test:needs-fast",
            "skipped needs-slow"
        ]
    );
    let workspace = Selection {
        workspace: true,
        lib: true,
        ..Selection::default()
    };
    assert_eq!(chosen(&workspace, &none).unwrap(), ["a:lib:a", "b:lib:b"]);
    let one_test = Selection {
        packages: vec!["a".into()],
        tests: vec!["it_works".into()],
        ..Selection::default()
    };
    assert_eq!(chosen(&one_test, &none).unwrap(), ["a:test:it-works"]);
    let slow = CargoFeatures {
        features: Some("slow".into()),
        no_default_features: true,
        ..CargoFeatures::default()
    };
    let tests = Selection {
        all_tests: true,
        ..Selection::default()
    };
    assert_eq!(
        chosen(&tests, &slow).unwrap(),
        ["a:test:it-works", "a:test:needs-slow", "skipped needs-fast"]
    );
    // An explicit target that cannot build, or does not exist, or a package
    // that is not a member, is refused rather than run as nothing.
    for selection in [
        Selection {
            tests: vec!["needs-slow".into()],
            ..Selection::default()
        },
        Selection {
            tests: vec!["missing".into()],
            ..Selection::default()
        },
        Selection {
            bins: vec!["it-works".into()],
            ..Selection::default()
        },
        Selection {
            packages: vec!["c".into()],
            ..Selection::default()
        },
        Selection {
            skip_targets: vec!["not-a-target".into()],
            ..Selection::default()
        },
    ] {
        assert!(chosen(&selection, &none).is_err(), "{selection:?}");
    }
    // `--skip-target` leaves out every selected target of that name (by
    // target or crate name), reported as skipped, and nothing else.
    let skipping = Selection {
        skip_targets: vec!["it_works".into(), "a".into()],
        ..Selection::default()
    };
    assert_eq!(
        chosen(&skipping, &none).unwrap(),
        [
            "a:test:needs-fast",
            "skipped a",
            "skipped a",
            "skipped it-works",
            "skipped needs-slow"
        ]
    );
    assert_eq!(TargetKind::Lib.name(), "lib");
}

#[test]
fn a_listing_names_its_tests_and_not_its_benchmarks() {
    let stdout = "a::one: test\nb::two: bench\nc::three: test\n\n2 tests, 1 benchmarks\n";
    assert_eq!(listed_tests(stdout), ["a::one", "c::three"]);
}

/// `#[patina_dst::test(...)]` refuses, when the test is compiled, an argument
/// that is not a flag of this verb. Its table of them is this registry's,
/// flag for flag and arity for arity, but for the selection the attribute
/// makes itself and the flags that cannot apply to one test.
#[test]
fn the_test_attribute_takes_exactly_this_verbs_flags() {
    mod attribute {
        include!("../../../patina-macros/src/test_flags.rs");
    }
    use attribute::Arity;
    let registered: BTreeMap<String, Arity> = help::verb("test")
        .expect("the test verb")
        .family_flags(help::Family::Sole)
        .filter(|flag| !attribute::NOT_ACCEPTED.contains(&flag.name))
        .map(|flag| {
            let arity = match flag.value {
                help::Value::None => Arity::Switch,
                help::Value::Required(..) => Arity::Value,
            };
            (flag.name.trim_start_matches("--").replace('-', "_"), arity)
        })
        .collect();
    let table: BTreeMap<String, Arity> = attribute::TEST_FLAGS
        .iter()
        .map(|(name, arity)| (name.to_string(), *arity))
        .collect();
    assert_eq!(table, registered);
    assert_eq!(table.len(), attribute::TEST_FLAGS.len(), "a flag twice");
    for supplied in attribute::NOT_ACCEPTED {
        assert!(
            help::verb("test")
                .expect("the test verb")
                .family_flags(help::Family::Sole)
                .any(|flag| flag.name == *supplied),
            "{supplied} is not a flag of the verb"
        );
    }
}

/// A child of another supervisor build stops the whole invocation, naming
/// the supervisor, instead of being filed as one test's result; a child whose
/// report cannot be read is patina's own failure for that test.
#[test]
fn a_child_of_another_supervisor_build_stops_the_run() {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "echo '{{\"result\":\"failure\"}}'; \
             echo 'patina: {} this patina is another build' >&2; exit 2",
            crate::supervisor_identity::SUPERVISOR_MISMATCH
        ))
        .output()
        .unwrap();
    let stopped = seed_outcome(output.status, &output.stdout, &output.stderr)
        .err()
        .map(|error| error.to_string());
    assert!(
        stopped
            .as_deref()
            .is_some_and(|error| error.contains("supervisor")),
        "{stopped:?}"
    );
    for script in [
        "echo 'not json'; exit 1",
        "echo '{\"result\":\"ok\"}'; exit 1",
        "exit 0",
    ] {
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        let run = seed_outcome(output.status, &output.stdout, &output.stderr).unwrap();
        assert_eq!(run.result, RunClass::Internal, "{script}");
    }
}

/// Every flag the invocation parsed reaches each test's child `run` with its
/// value: one parsed and not re-emitted would be silently inert in every test.
#[test]
fn every_run_flag_reaches_each_tests_run() {
    let mut tokens: Vec<OsString> = Vec::new();
    for knob in FaultKnob::ALL {
        tokens.push(OsString::from(knob.meta().flag));
        tokens.push(OsString::from(knob_sample(*knob)));
    }
    let pairs = [
        ("--realtime-epoch", "2001-09-09T01:46:40Z"),
        ("--hostname", "db-1"),
        ("--cpus", "3"),
        ("--compute-watchdog-ms", "5000"),
        ("--budget", "9"),
        ("--param", "k=v=w"),
        ("--env", "E=1"),
        ("--mount", "corpus"),
        ("--buggify-activation-permille", "500"),
        ("--sched-pct-steps", "40"),
        ("--yield-stride", "7"),
        ("--heal-after", "1000"),
    ];
    for (flag, value) in pairs {
        tokens.push(OsString::from(flag));
        tokens.push(OsString::from(value));
    }
    let switches = [
        "--buggify-fire-permille",
        "250",
        "--buggify-after-setup",
        "--sched-pct",
        "2",
        "--swarm",
        "--liveness-watchdog",
        "1000",
        "--converge-within",
        "2000",
        "--allow-randomized-address-layout",
    ];
    tokens.extend(switches.iter().map(OsString::from));
    let invocation = parse::parse_test_from(
        PathBuf::from("."),
        PathBuf::from("Cargo.toml"),
        None,
        tokens,
    )
    .expect("test parse");
    let mut emitted: Vec<OsString> = Vec::new();
    push_run_flags(&mut emitted, &invocation.run);
    // And the child `run` accepts what was emitted.
    let args = cli::parse("run", help::Family::Sole, emitted.clone()).expect("run parse");
    assert_eq!(knobs_of(&args).unwrap(), invocation.run.knobs);
    let emitted_pairs: Vec<(&OsStr, &OsStr)> = emitted
        .windows(2)
        .map(|pair| (pair[0].as_os_str(), pair[1].as_os_str()))
        .collect();
    for knob in FaultKnob::ALL {
        let pair = (OsStr::new(knob.meta().flag), OsStr::new(knob_sample(*knob)));
        assert!(emitted_pairs.contains(&pair), "dropped {pair:?}");
    }
    for (flag, value) in pairs {
        assert!(
            emitted_pairs.contains(&(OsStr::new(flag), OsStr::new(value))),
            "dropped {flag} {value}: {emitted:?}"
        );
    }
    for switch in switches {
        assert!(
            emitted.iter().any(|token| token == switch),
            "dropped {switch}: {emitted:?}"
        );
    }
}

#[test]
fn why_names_the_panic_or_the_stop() {
    let run = |stderr: &str, stop: Option<&str>| SeedRun {
        result: RunClass::Failure,
        stop: stop.map(|detail| crate::output::Stop::new("panic", detail)),
        guest_exit: None,
        stdout: String::new(),
        stderr: stderr.to_string(),
        message: None,
        trace: None,
        likely_artifacts: Vec::new(),
    };
    let panicked = run(
        "note: linked\nthread 'a::b' (3) panicked at src/lib.rs:5:26:\nassertion failed\n",
        Some("the guest panicked"),
    );
    assert_eq!(
        report::why(&panicked),
        "panicked at src/lib.rs:5:26: assertion failed"
    );
    assert_eq!(report::why(&run("", Some("stopped"))), "stopped");
    assert_eq!(
        report::without_numbers("task=3 steps=1249 at 0x30"),
        "task=N steps=N at NxN"
    );
    let case = TestCase {
        target: 0,
        name: "m::t".into(),
        ignored: true,
    };
    assert!(run::libtest_args(&case).contains(&"--include-ignored".to_string()));
}
