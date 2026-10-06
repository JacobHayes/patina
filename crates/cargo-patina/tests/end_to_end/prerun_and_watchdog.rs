//! The compute watchdog's private startup and the native pre-run gate's
//! campaign classification.

use super::*;

/// Class detector for private watchdog startup entering the guest scheduler.
/// Point pairing: native_harness_selects_same_named_library_binary_and_integration_test.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_watchdog_helpers_leave_guest_scheduling_and_panics_alone() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("observer_startup.rs");
    fs::write(
        &source,
        r#"
fn main() {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || tx.send(42).unwrap());
    assert_eq!(rx.recv().unwrap(), 42);
    worker.join().unwrap();
    println!("guest reached its panic");
    panic!("deliberate guest panic");
}
"#,
    )
    .unwrap();
    let guest = directory.path().join("observer-startup");
    invoke(
        native_workspace(),
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
    );
    let mut baseline = None;
    // Fresh processes restart the private helpers. Same-seed records and replay
    // must preserve the guest's ordinary panic, with no observer task admitted.
    for attempt in 0..4 {
        let trace = directory.path().join(format!("panic-{attempt}.patina"));
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let envelope: serde_json::Value = serde_json::from_slice(&recorded.stdout).unwrap();
        assert_eq!(recorded.status.code(), Some(101), "{envelope}");
        assert_eq!(envelope["exit_code"], 101, "{envelope}");
        assert!(envelope["refusal"].is_null(), "{envelope}");
        assert!(
            envelope["stdout"]
                .as_str()
                .unwrap()
                .contains("guest reached its panic"),
            "{envelope}"
        );
        let bytes = fs::read(&trace).unwrap();
        if let Some(expected) = &baseline {
            assert_eq!(&bytes, expected, "private startup changed the trace");
        } else {
            baseline = Some(bytes);
        }
        let replay = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "replay",
                guest.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let replayed: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
        assert_eq!(replay.status.code(), Some(101), "{replayed}");
        assert!(replayed["refusal"].is_null(), "{replayed}");
        assert_eq!(envelope["stdout"], replayed["stdout"]);
        assert_eq!(envelope["stderr"], replayed["stderr"]);
    }
}

// Gate: a guest the pre-run default-deny gate refuses is sweepable through the
// same hatches `run` offers, and — the non-vacuity half — WITHOUT them the
// campaign still files the child refusal as INFRA, its existing class, rather
// than regressing to UNCLASSIFIED. macOS-only for the same reason the pre-run
// gate test is: the Mach semaphore is the still-uninterposed blocking
// representative (`PLANTED_ESCAPE_SOURCE`).
#[cfg(target_os = "macos")]
#[test]
fn campaign_forwards_the_prerun_gate_hatches_to_every_generation() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted_escape.rs");
    fs::write(&source, PLANTED_ESCAPE_SOURCE).unwrap();
    let guest = directory.path().join("planted-escape-campaign");
    invoke(
        native_workspace(),
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
        ],
    );

    // Prove the fixture still reaches the pre-run gate, before classifying it.
    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &["run", guest.to_str().unwrap(), "--format", "json"],
    );
    let refusal: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refused.status.code(), Some(2), "{refusal}");
    assert_eq!(
        refusal["refusal"]["class"], "native_prerun_audit",
        "{refusal}"
    );
    assert!(
        refusal["guest_exit"].is_null(),
        "the guest must not launch: {refusal}"
    );
    assert!(
        refusal["message"]
            .as_str()
            .unwrap()
            .contains("semaphore_wait"),
        "{refusal}"
    );

    // RED: default-deny. Every generation is the child's pre-run refusal, filed
    // as INFRA (harness/infrastructure failure, not a SUT finding) — pinned here
    // so a forwarding change cannot quietly turn a known refusal into an
    // unrecognized outcome.
    let denied = campaign_run(&directory.path().join("red"), &guest, &[]);
    assert!(!denied.status.success(), "the gate must deny every child");
    let envelope = campaign_json_stdout(&denied);
    assert_eq!(envelope["classes"]["INFRA"], 2, "{}", envelope["classes"]);
    assert_eq!(envelope["classes"]["UNCLASSIFIED"], serde_json::Value::Null);

    // GREEN (a): the blanket hatch.
    let hatched = campaign_run(
        &directory.path().join("green-all"),
        &guest,
        &["--allow-unsupported-symbols", "all"],
    );
    assert!(
        hatched.status.success(),
        "--allow-unsupported-symbols must reach every generation:\nstderr:\n{}",
        String::from_utf8_lossy(&hatched.stderr)
    );
    assert_eq!(campaign_json_stdout(&hatched)["classes"]["OK"], 2);

    // GREEN (b): the repeatable known-safe list, every occurrence forwarded (one
    // symbol alone still fails closed on the other, so a truncated list cannot
    // pass this).
    let allowed = campaign_run(
        &directory.path().join("green-allow"),
        &guest,
        &["--allow", "semaphore_wait", "--allow", "semaphore_signal"],
    );
    assert!(
        allowed.status.success(),
        "both --allow occurrences must reach every generation:\nstderr:\n{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(campaign_json_stdout(&allowed)["classes"]["OK"], 2);

    let partial = campaign_run(
        &directory.path().join("partial"),
        &guest,
        &["--allow", "semaphore_wait"],
    );
    assert!(
        !partial.status.success(),
        "a truncated allow list must still fail closed"
    );
}
