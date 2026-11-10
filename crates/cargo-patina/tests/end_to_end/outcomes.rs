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
