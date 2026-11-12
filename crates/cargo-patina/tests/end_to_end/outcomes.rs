//! The one outcome model: every way a run ends has one class, the class
//! decides the attribution and the exit status, and `run`, `test` and
//! `campaign` report the same one.

use super::*;

/// An SDK guest whose first argument picks how the run ends.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const OUTCOME_MATRIX_MAIN: &str = r#"
use patina_dst::VerdictKind;

unsafe extern "C" {
    fn fork() -> i32;
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("ok") => println!("done"),
        Some("panic") => panic!("an assertion of the guest's own"),
        // A status patina itself uses for something else.
        Some("exit") => std::process::exit(2),
        Some("abort") => std::process::abort(),
        Some("fault") => unsafe { std::ptr::null_mut::<u8>().write_volatile(1) },
        Some("always") => patina_dst::always!(std::env::args().count() > 64, "never-holds"),
        // A reported violation, then a clean return.
        Some("verdict") => patina_dst::verdict(VerdictKind::Violation, "ledger", "unbalanced"),
        // Every thread blocked for good: the receiver waits on a sender that
        // is alive and never sends.
        Some("deadlock") => {
            let (sender, receiver) = std::sync::mpsc::channel::<()>();
            let _ = receiver.recv();
            drop(sender);
        }
        // Something patina does not model.
        Some("fork") => unsafe {
            fork();
        },
        // Boundary operations for a step budget to run out on.
        Some("work") => {
            for index in 0..64u32 {
                std::fs::write(format!("/entry-{index}"), b"payload").unwrap();
            }
        }
        // The same, where the budget can run out in a scheduling operation.
        Some("threads") => {
            let workers: Vec<_> = (0..4)
                .map(|_| std::thread::spawn(|| std::thread::yield_now()))
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        }
        other => panic!("unknown mode {other:?}"),
    }
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn outcome_matrix_guest() -> PathBuf {
    run_facts::shared_sdk_guest("outcome-matrix", OUTCOME_MATRIX_MAIN)
}

/// One way a run ends: the guest's mode, the run flags that go with it, and
/// the class, attribution and exit status it must be reported with.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Ending {
    mode: &'static str,
    flags: &'static [&'static str],
    result: &'static str,
    attribution: Option<&'static str>,
    exit: i32,
    /// Whether a campaign can sweep the mode with nothing but guest arguments.
    campaign: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const ENDINGS: &[Ending] = &[
    Ending {
        mode: "ok",
        flags: &[],
        result: "ok",
        attribution: None,
        exit: 0,
        campaign: true,
    },
    Ending {
        mode: "panic",
        flags: &[],
        result: "failure",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "exit",
        flags: &[],
        result: "failure",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "abort",
        flags: &[],
        result: "crash",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "fault",
        flags: &[],
        result: "crash",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "always",
        flags: &[],
        result: "violation",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "verdict",
        flags: &[],
        result: "violation",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "deadlock",
        flags: &[],
        result: "liveness",
        attribution: Some("guest"),
        exit: 1,
        campaign: true,
    },
    Ending {
        mode: "fork",
        flags: &[],
        result: "unsupported",
        attribution: Some("patina_unsupported"),
        exit: 2,
        campaign: true,
    },
    Ending {
        mode: "work",
        flags: &["--budget", "8"],
        result: "timeout",
        attribution: Some("patina_unsupported"),
        exit: 2,
        campaign: false,
    },
    Ending {
        mode: "threads",
        flags: &["--budget", "3"],
        result: "timeout",
        attribution: Some("patina_unsupported"),
        exit: 2,
        campaign: false,
    },
];

/// What an envelope says the outcome is: its class and attribution, and the
/// exit status it reports.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reported(envelope: &serde_json::Value) -> (String, Option<String>, i64) {
    (
        envelope["result"].as_str().unwrap_or_default().to_owned(),
        envelope["attribution"].as_str().map(str::to_owned),
        envelope["exit_code"].as_i64().unwrap_or(-1),
    )
}

/// `run` reports each ending under its one class, the envelope's attribution
/// and exit status follow from the class, the process exits with that status
/// and never the guest's own, and a run that did not end clean says what
/// stopped it. The human format exits the same way.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_reports_every_ending_under_one_class_and_exit_status() {
    let guest = outcome_matrix_guest();
    let patina = env!("CARGO_BIN_EXE_patina");
    for ending in ENDINGS {
        let mut args = vec!["run", guest.to_str().unwrap(), "--seed", "3"];
        args.extend_from_slice(ending.flags);
        let human = [&args[..], &["--", ending.mode]].concat();
        let json = [&args[..], &["--format", "json", "--", ending.mode]].concat();

        let ran = invoke_unchecked(patina, native_workspace(), &json);
        let envelope: serde_json::Value = serde_json::from_slice(&ran.stdout)
            .unwrap_or_else(|error| panic!("{}: {error}: {ran:?}", ending.mode));
        assert_eq!(
            reported(&envelope),
            (
                ending.result.to_owned(),
                ending.attribution.map(str::to_owned),
                i64::from(ending.exit)
            ),
            "{}: {envelope:#}",
            ending.mode
        );
        assert_eq!(
            ran.status.code(),
            Some(ending.exit),
            "{}: {envelope:#}",
            ending.mode
        );
        assert_eq!(
            envelope["stop"].is_object(),
            ending.exit != 0,
            "{}: a run that did not end clean names what stopped it: {envelope:#}",
            ending.mode
        );
        // A run Patina stopped on a bound of its own says so beside its
        // class, and only such a run does.
        let limited = envelope["likely_artifacts"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|artifact| artifact["kind"] == "patina_limit");
        assert_eq!(
            limited,
            ending.result == "timeout",
            "{}: {envelope:#}",
            ending.mode
        );
        // The guest's own status is reported beside the tool's, wherever a
        // guest ran (a platform's pre-run audit may refuse `fork` outright).
        assert!(
            envelope["guest_exit"].is_object() || envelope["stop"]["reason"] == "prerun_audit",
            "{}: the guest's own status is reported, not passed through: {envelope:#}",
            ending.mode
        );

        let ran = invoke_unchecked(patina, native_workspace(), &human);
        assert_eq!(ran.status.code(), Some(ending.exit), "{}", ending.mode);
    }
}

/// A campaign files each generation under the class its run reported, and
/// ends in that class's attribution and exit status itself.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn campaign_files_each_ending_under_the_runs_own_class() {
    let guest = outcome_matrix_guest();
    let directory = tempdir().unwrap();
    for ending in ENDINGS.iter().filter(|ending| ending.campaign) {
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            native_workspace(),
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "1",
                "--out-dir",
                directory.path().join(ending.mode).to_str().unwrap(),
                "--format",
                "json",
                "--",
                ending.mode,
            ],
        );
        let envelope = campaign_json_stdout(&output);
        assert_eq!(
            envelope["classes"],
            serde_json::json!({ ending.result: 1 }),
            "{}: {envelope:#}",
            ending.mode
        );
        assert_eq!(
            reported(&envelope),
            (
                ending.result.to_owned(),
                ending.attribution.map(str::to_owned),
                i64::from(ending.exit)
            ),
            "{}: {envelope:#}",
            ending.mode
        );
        assert_eq!(
            output.status.code(),
            Some(ending.exit),
            "{}: {envelope:#}",
            ending.mode
        );
    }
}

/// A run that did not end clean names the command that repeats it, and the
/// command ends the same way: the replay of the recording it kept (which a
/// failing replay names too, so the two say the same), else the `run` itself
/// with its seed spelled out. A Rust guest's panic is told from a status the
/// guest chose: its stop is `panic`, the other's `exit_status`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_failed_run_names_the_command_that_repeats_it() {
    let guest = outcome_matrix_guest();
    let guest = guest.to_str().unwrap();
    let directory = tempdir().unwrap();
    let patina = env!("CARGO_BIN_EXE_patina");
    let ended = |output: Output| -> serde_json::Value {
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
    };
    let run = |arguments: &[&str]| ended(invoke_unchecked(patina, directory.path(), arguments));
    // The named command, run as a shell would run it, by the patina under
    // test and with a flag default in the environment the command has to beat.
    let repeat = |envelope: &serde_json::Value| {
        let command = envelope["reproduce"]
            .as_str()
            .unwrap_or_else(|| panic!("no command: {envelope:#}"))
            .replacen("patina", patina, 1);
        ended(
            Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{command} --format json"))
                .env("PATINA_SEED", "9")
                .current_dir(directory.path())
                .output()
                .unwrap(),
        )
    };
    let ending = |envelope: &serde_json::Value| {
        (
            envelope["result"].clone(),
            envelope["stop"]["reason"].clone(),
            envelope["guest_exit"].clone(),
            envelope["stdout"].clone(),
        )
    };

    let recorded = run(&[
        "run",
        guest,
        "--seed",
        "4",
        "--record",
        "run.patina",
        "--format",
        "json",
        "--",
        "panic",
    ]);
    assert_eq!(
        (&recorded["result"], &recorded["stop"]["reason"]),
        (&"failure".into(), &"panic".into()),
        "{recorded:#}"
    );
    let replayed = repeat(&recorded);
    assert_eq!(ending(&replayed), ending(&recorded));
    assert!(
        replayed["seed"].is_null(),
        "the command is the replay: {replayed:#}"
    );
    assert_eq!(replayed["reproduce"], recorded["reproduce"]);

    // The seed left to its default is spelled out, so the command means the
    // same run wherever it is pasted.
    let exited = run(&["run", guest, "--format", "json", "--", "exit"]);
    assert_eq!(exited["stop"]["reason"], "exit_status", "{exited:#}");
    let repeated = repeat(&exited);
    assert_eq!(ending(&repeated), ending(&exited));
    assert_eq!(repeated["seed"], exited["seed"]);

    let clean = run(&["run", guest, "--format", "json", "--", "ok"]);
    assert!(clean["reproduce"].is_null(), "{clean:#}");
}

/// What patina could not do as asked, before any guest runs: a request error
/// (exit 2), in the envelope and in the process status alike, for a target
/// that does not exist and for a binary patina did not build.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_request_patina_cannot_carry_out_is_an_error_not_a_finding() {
    let directory = tempdir().unwrap();
    let stock = directory.path().join("stock.rs");
    fs::write(&stock, "fn main() {}\n").unwrap();
    let stock_binary = directory.path().join("stock");
    let built = Command::new(active_toolchain_binary("rustc"))
        .arg(&stock)
        .arg("-o")
        .arg(&stock_binary)
        .output()
        .unwrap();
    assert!(built.status.success(), "{built:?}");
    let missing = directory.path().join("no-such-guest");
    for target in [&missing, &stock_binary] {
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            native_workspace(),
            &["run", target.to_str().unwrap(), "--format", "json"],
        );
        let envelope: serde_json::Value = serde_json::from_slice(&ran.stdout)
            .unwrap_or_else(|error| panic!("{target:?}: {error}: {ran:?}"));
        assert_eq!(
            reported(&envelope),
            ("error".to_owned(), Some("request".to_owned()), 2),
            "{target:?}: {envelope:#}"
        );
        assert_eq!(ran.status.code(), Some(2), "{target:?}");
    }
}

/// A guest whose recording outgrows the trace budget (200 MiB of file writes,
/// more than 256 MiB once encoded) before it ends as its argument says:
/// cleanly, or with an exit status of its own.
const OVER_BUDGET_SOURCE: &str = r#"
use std::os::unix::fs::FileExt;

fn main() {
    let chunk = vec![255u8; 8 << 20];
    let file = std::fs::File::create("blob").unwrap();
    for _ in 0..25 {
        file.write_all_at(&chunk, 0).unwrap();
    }
    println!("OVER_BUDGET_DONE");
    if std::env::args().nth(1).as_deref() == Some("exit") {
        std::process::exit(3);
    }
}
"#;

/// A recording that outgrows its budget is dropped, and that is all: the run
/// ends in the class, with the stop and the guest status, of the same run
/// unrecorded, and its result says the recording was not written. RED when a
/// dropped recording was reported only as a line of text.
#[test]
fn a_dropped_recording_leaves_the_runs_outcome_as_it_was() {
    let guest = native_build::source_guest("over_budget", OVER_BUDGET_SOURCE);
    let trace = guest.dir.path().join("over-budget.patina");
    let run = |mode: &str, record: bool| -> serde_json::Value {
        let mut arguments = vec!["--seed", "1", "--format", "json"];
        if record {
            arguments.extend(["--record", trace.to_str().unwrap()]);
        }
        arguments.extend(["--", mode]);
        let output = guest.command("run", &arguments);
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "no result for {mode}: {error}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    };
    let outcome = |result: &serde_json::Value| {
        (
            result["result"].clone(),
            result.get("attribution").cloned(),
            result["exit_code"].clone(),
            result["guest_exit"].clone(),
            result.get("stop").cloned(),
            result["stdout"].clone(),
        )
    };
    for (mode, class, exit) in [("ok", "ok", 0), ("exit", "failure", 1)] {
        let plain = run(mode, false);
        assert_eq!(
            (&plain["result"], &plain["exit_code"]),
            (&class.into(), &exit.into()),
            "{plain:#}"
        );
        assert!(plain.get("trace_incomplete").is_none(), "{plain:#}");
        let recorded = run(mode, true);
        assert_eq!(outcome(&recorded), outcome(&plain), "{recorded:#}");
        assert_eq!(
            recorded["trace_incomplete"]["reason"], "resource_limit",
            "{recorded:#}"
        );
        assert!(recorded.get("trace").is_none(), "{recorded:#}");
        assert!(!trace.exists(), "a dropped recording leaves no file");
    }
}

/// A worker that waits for good in a loop of timed sleeps, a hang the
/// no-progress watchdog catches.
const HALTED_WORKER_SOURCE: &str = r#"
use std::time::Duration;

fn main() {
    let worker = std::thread::spawn(|| loop {
        eprintln!("halting writes");
        std::thread::sleep(Duration::from_millis(100));
    });
    worker.join().unwrap();
}
"#;

/// A liveness stop keeps its recording, and the recording replays to the
/// same stop. RED when the stop aborted without writing the trace (an empty
/// file, `trace_incomplete`), and when a replay, without the watchdog, ran
/// past the end of the trace.
#[test]
fn a_liveness_stop_is_recorded_and_replays_to_the_same_stop() {
    let guest = native_build::source_guest("halted_worker", HALTED_WORKER_SOURCE);
    let trace = guest.dir.path().join("halted.patina");
    let trace = trace.to_str().unwrap();
    let json = |output: &std::process::Output| -> serde_json::Value {
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}\n{}", String::from_utf8_lossy(&output.stderr)))
    };
    let outcome = |result: &serde_json::Value| {
        (
            result["result"].clone(),
            result["exit_code"].clone(),
            result["runtime_findings"][0]["vtime_ns"].clone(),
        )
    };
    // Under PCT too, whose decisions a replay consumes rather than makes.
    for policy in [&[][..], &["--sched-pct", "3"]] {
        let _ = std::fs::remove_file(trace);
        let mut arguments = vec![
            "--seed",
            "1",
            "--liveness-watchdog",
            "600000000000",
            "--record",
            trace,
            "--format",
            "json",
        ];
        arguments.extend_from_slice(policy);
        let recorded = json(&guest.command("run", &arguments));
        assert_eq!(
            (&recorded["result"], &recorded["exit_code"]),
            (&"liveness".into(), &1.into()),
            "{recorded:#}"
        );
        assert!(recorded.get("trace_incomplete").is_none(), "{recorded:#}");
        let replayed = json(&guest.command("replay", &[trace, "--format", "json"]));
        assert_eq!(outcome(&replayed), outcome(&recorded), "{replayed:#}");
    }
}

/// A guest whose first argument picks the thread that calls `exit(7)` while
/// the other is still running. The exiting thread registers an atexit
/// handler and leaves bytes in C stdio's buffer first.
const EXIT_WITH_A_LIVE_THREAD_SOURCE: &str = r#"
use std::ffi::c_char;
use std::sync::mpsc;

unsafe extern "C" {
    fn atexit(handler: extern "C" fn()) -> i32;
    fn printf(format: *const c_char, ...) -> i32;
}

extern "C" fn at_exit() {
    println!("atexit");
}

struct Local;
impl Drop for Local {
    fn drop(&mut self) {
        println!("thread-local dropped");
    }
}
thread_local! { static LOCAL: Local = const { Local }; }

fn exit_here() -> ! {
    LOCAL.with(|_| {});
    unsafe {
        atexit(at_exit);
        printf(c"buffered".as_ptr());
    }
    std::process::exit(7)
}

fn main() {
    let worker_exits = std::env::args().nth(1).as_deref() == Some("worker");
    let (sender, receiver) = mpsc::channel::<u32>();
    std::thread::spawn(move || {
        while receiver.recv().is_ok() {
            if worker_exits {
                exit_here();
            }
        }
    });
    sender.send(1).unwrap();
    if worker_exits {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    exit_here()
}
"#;

/// `exit` from either thread while the other runs ends the run with the
/// status it gave, as on Linux: the exiting thread's thread-local
/// destructors, then the atexit handlers, then C stdio's flush, and nothing
/// else; the recording replays to the same end. RED when an exit from a
/// thread that is not `main`'s was a scheduling operation after `main`
/// returned (`internal`).
#[test]
fn exit_with_another_thread_running_ends_with_its_status() {
    let guest = native_build::source_guest("exit_live_thread", EXIT_WITH_A_LIVE_THREAD_SOURCE);
    let trace = guest.dir.path().join("exit.patina");
    let trace = trace.to_str().unwrap();
    let json = |output: &std::process::Output| -> serde_json::Value {
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)))
    };
    let outcome = |result: &serde_json::Value| {
        (
            result["result"].clone(),
            result["guest_exit"]["code"].clone(),
            result["stdout"].clone(),
        )
    };
    for who in ["main", "worker"] {
        for seed in ["0", "1"] {
            let _ = std::fs::remove_file(trace);
            let recorded = json(&guest.command(
                "run",
                &[
                    "--seed", seed, "--record", trace, "--format", "json", "--", who,
                ],
            ));
            assert_eq!(
                (&recorded["result"], &recorded["guest_exit"]["code"]),
                (&"failure".into(), &7.into()),
                "{who} seed {seed}: {recorded:#}"
            );
            if cfg!(target_os = "linux") {
                assert_eq!(
                    recorded["stdout"], "thread-local dropped\natexit\nbuffered",
                    "{who} seed {seed}: {recorded:#}"
                );
            }
            let replayed = json(&guest.command("replay", &[trace, "--format", "json"]));
            assert_eq!(outcome(&replayed), outcome(&recorded), "{replayed:#}");
        }
    }
}
