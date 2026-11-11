//! The compute watchdog's private startup and the native pre-run gate's
//! campaign classification.

use super::*;

/// Class detector for private watchdog startup entering the guest scheduler.
/// Point pairing: native_harness_selects_same_named_library_binary_and_integration_test.
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
    for attempt in 0..2 {
        let trace = directory.path().join(format!("panic-{attempt}.patina"));
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
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
        assert_eq!(recorded.status.code(), Some(1), "{envelope}");
        assert_eq!(
            (&envelope["result"], &envelope["guest_exit"]["code"]),
            (&"failure".into(), &101.into()),
            "{envelope}"
        );
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
            env!("CARGO_BIN_EXE_patina"),
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
        assert_eq!(replay.status.code(), Some(1), "{replayed}");
        assert_eq!(replayed["result"], "failure", "{replayed}");
        assert_eq!(envelope["stdout"], replayed["stdout"]);
        assert_eq!(envelope["stderr"], replayed["stderr"]);
    }
}

/// A compute stop names where the guest was spinning: the function its
/// sampled PC is in and, with debug info, the source file, read from the
/// executable rather than left as a raw address for the reader to resolve.
#[test]
fn a_compute_stop_names_the_function_the_guest_spins_in() {
    const SPINNER: &str = "spin_without_calls";
    let directory = tempdir().unwrap();
    let source = directory.path().join("spin_site.rs");
    fs::write(
        &source,
        format!(
            r#"
use std::sync::atomic::{{AtomicBool, Ordering}};
static DONE: AtomicBool = AtomicBool::new(false);
#[inline(never)]
fn {SPINNER}() {{
    while !DONE.load(Ordering::Relaxed) {{
        std::hint::spin_loop();
    }}
}}
fn main() {{
    {SPINNER}();
}}
"#
        ),
    )
    .unwrap();
    let guest = directory.path().join("spin-site");
    invoke(
        native_workspace(),
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            guest.to_str().unwrap(),
            "--release",
            "--",
            "-g",
        ],
    );
    // The sampler may lose its bounded handshake on a loaded host and then
    // names no PC; any one of a few runs must name the site.
    let mut runs = Vec::new();
    let located = (0..3).find_map(|_| {
        let output = invoke_with_deadline(
            env!("CARGO_BIN_EXE_patina"),
            native_workspace(),
            &[
                "run",
                guest.to_str().unwrap(),
                "--compute-watchdog-ms",
                "200",
                "--format",
                "json",
            ],
            Duration::from_secs(60),
        )
        .expect("the compute watchdog must end the run");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["result"], "timeout", "{envelope:#}");
        let location = envelope["stop"].get("location").cloned();
        runs.push(envelope);
        location
    });
    let location = located.unwrap_or_else(|| panic!("no run named its stop site: {runs:#?}"));
    let function = location["function"].as_str().unwrap();
    assert_eq!(function.rsplit("::").next(), Some(SPINNER), "{location:#}");
    // macOS keeps the debug info in the object files or a dSYM, which the
    // symbolizer does not read: there the location is the function alone.
    if cfg!(target_os = "linux") {
        let file = location["file"].as_str().unwrap();
        assert_eq!(
            Path::new(file).file_name(),
            source.file_name(),
            "{location:#}"
        );
        assert!(location["line"].as_u64().is_some(), "{location:#}");
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
        env!("CARGO_BIN_EXE_patina"),
        native_workspace(),
        &["run", guest.to_str().unwrap(), "--format", "json"],
    );
    let refusal: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refused.status.code(), Some(2), "{refusal}");
    assert_eq!(
        (&refusal["result"], &refusal["stop"]["reason"]),
        (&"unsupported".into(), &"prerun_audit".into()),
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
    // as `unsupported` (what patina does not model, not a SUT finding) — pinned
    // here so a forwarding change cannot quietly turn a known refusal into an
    // unrecognized outcome.
    let denied = campaign_run(&directory.path().join("red"), &guest, &[]);
    assert!(!denied.status.success(), "the gate must deny every child");
    let envelope = campaign_json_stdout(&denied);
    assert_eq!(
        envelope["classes"]["unsupported"], 2,
        "{}",
        envelope["classes"]
    );
    assert_eq!(envelope["classes"]["failure"], serde_json::Value::Null);

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
    assert_eq!(campaign_json_stdout(&hatched)["classes"]["ok"], 2);

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
    assert_eq!(campaign_json_stdout(&allowed)["classes"]["ok"], 2);

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
