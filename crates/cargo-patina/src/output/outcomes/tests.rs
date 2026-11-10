//! Regression tests for outcomes.

use super::*;

// Class-level pairing: signals-family M4 direct-termination conformance;
// exercise both wait-status core bits for the SAME signal, not a signal table.
#[test]
fn guest_exit_reports_the_core_flag() {
    use std::os::unix::process::ExitStatusExt;
    const SIGABRT: i32 = 6;
    const WCOREDUMP: i32 = 0x80;
    for (raw, expected_signal, expected_core) in [
        (SIGABRT, Some(SIGABRT), Some(false)),
        (SIGABRT | WCOREDUMP, Some(SIGABRT), Some(true)),
        (134 << 8, None, None),
    ] {
        let status = std::process::ExitStatus::from_raw(raw);
        let crate::NativeChildStatus {
            exit_code: code,
            signal,
            core,
        } = crate::native_child_status(status);
        assert_eq!(signal, expected_signal);
        assert_eq!(core, status.core_dumped());
        let mut env = Envelope::new("run", RunClass::Failure);
        env.guest_exit = Some(GuestExit { code, signal, core });
        let json = env.to_json();
        assert_eq!(json["schema"], ENVELOPE_SCHEMA);
        assert_eq!(
            json["guest_exit"]
                .get("core")
                .and_then(serde_json::Value::as_bool),
            expected_core
        );
        // The signal the exit code cannot express is named; a guest that
        // deliberately returns 134 is NOT a signal death, and the envelope
        // keeps the two apart.
        match signal {
            Some(_) => assert_eq!(json["guest_exit"]["signal_name"], "SIGABRT"),
            None => assert!(json["guest_exit"].get("signal").is_none()),
        }
    }
}

/// One finished run's evidence, and the class it must land in.
struct Case {
    name: &'static str,
    exit_code: i32,
    signal: Option<i32>,
    facts: Option<serde_json::Value>,
    crash_replay_diverged: bool,
    crash_failed: bool,
    runtime_started: bool,
    channel_defect: Option<&'static str>,
    trace_lost: Option<&'static str>,
    class: RunClass,
}

impl Case {
    fn exited(name: &'static str, exit_code: i32, class: RunClass) -> Self {
        Self {
            name,
            exit_code,
            signal: None,
            facts: None,
            crash_replay_diverged: false,
            crash_failed: false,
            runtime_started: true,
            channel_defect: None,
            trace_lost: None,
            class,
        }
    }

    fn signalled(name: &'static str, signal: i32, class: RunClass) -> Self {
        Self {
            signal: Some(signal),
            ..Self::exited(name, 128 + signal, class)
        }
    }

    fn facts(mut self, facts: serde_json::Value) -> Self {
        self.facts = Some(facts);
        self
    }

    /// The shim's stop record for this run.
    fn stopped(self, class: &str, reason: &str) -> Self {
        self.facts(serde_json::json!({
            "stop": {"class": class, "reason": reason, "detail": "what was reached"}
        }))
    }
}

fn cases() -> Vec<Case> {
    use RunClass::*;
    const SIGABRT: i32 = 6;
    const SIGSEGV: i32 = 11;
    let violation = serde_json::json!({"verdicts": [{"kind": "violation", "label": "ledger"}]});
    let liveness = serde_json::json!({
        "runtime_findings": [{"source": "liveness", "kind": "converge", "detail": "wedged"}]
    });
    let compute_bound = serde_json::json!({
        "runtime_findings": [{"source": "liveness", "detail": "compute-bound", "known_limit": true}]
    });
    vec![
        Case::exited("a clean exit", 0, Ok),
        // An armed watchdog that did not fire, and a `pass` verdict, are no
        // findings.
        Case::exited("a clean exit with unremarkable facts", 0, Ok).facts(serde_json::json!({
            "fault_reports": {}, "verdicts": [{"kind": "pass", "label": "drained"}]
        })),
        Case::exited("a panic or a nonzero exit", 101, Failure),
        // Guest text cannot make a finding: with no structured fact a nonzero
        // exit is a plain failure whatever the exit code is.
        Case::exited("an exit status patina also uses", 2, Failure),
        Case::signalled("the guest's own abort", SIGABRT, Crash),
        Case::signalled("a segmentation fault", SIGSEGV, Crash),
        // A violation is one whatever the guest's exit status says.
        Case::exited("a violation verdict, then a clean exit", 0, Violation).facts(violation.clone()),
        Case::signalled("an always! violation", SIGABRT, Violation).facts(serde_json::json!({
            "verdicts": [{"kind": "violation", "label": "ledger"}],
            "stop": {"class": "violation", "reason": "always", "detail": ""}
        })),
        Case::signalled("an SDK contract the guest broke", SIGABRT, Violation)
            .stopped("violation", "sdk_misuse"),
        Case::signalled("the liveness watchdog", SIGABRT, Liveness).facts(liveness.clone()),
        Case::signalled("a deadlock", SIGABRT, Liveness).stopped("liveness", "deadlock"),
        Case::signalled("the compute bound", SIGABRT, Timeout).facts(compute_bound.clone()),
        Case::signalled("the step budget", SIGABRT, Timeout).stopped("timeout", "step_budget"),
        Case::signalled("an operation patina does not model", SIGABRT, Unsupported)
            .stopped("unsupported", "not_modeled"),
        Case::signalled("a shim invariant", SIGABRT, Internal).stopped("internal", "shim_fatal"),
        // A fault inside the shim dies on the fault's own signal; its stop
        // record keeps it from reading as the guest's crash.
        Case::signalled("a fault inside the shim", SIGSEGV, Internal)
            .stopped("internal", "shim_fault"),
        Case::signalled("a host kill", 9, Internal),
        // A terminating signal no instruction raises: the guest's own when
        // the virtual kernel's default action left its record, else sent
        // from outside the run.
        Case::signalled("the guest's own SIGTERM", 15, Crash).stopped("crash", "signal"),
        Case::signalled(
            "a SIGTERM with no record",
            15,
            if guest_signals_are_modeled() {
                Internal
            } else {
                Crash
            },
        ),
        // Evidence patina could not read leaves even a clean exit unjudged.
        Case {
            channel_defect: Some("the stop pipe carried bytes that are not JSON"),
            ..Case::exited("an unreadable channel", 0, Internal)
        },
        Case::signalled("a stop the supervisor cannot read", SIGABRT, Internal)
            .stopped("no-such-class", "x"),
        // A replay that left its trace is judged first: nothing after the
        // divergence describes the recorded run, a verdict included.
        Case::signalled("a replay divergence", SIGABRT, Nondeterministic).facts(serde_json::json!({
            "replay_divergence": "operation_mismatch",
            "verdicts": [{"kind": "violation", "label": "ledger"}],
            "stop": {"class": "internal", "reason": "shim_fatal", "detail": ""}
        })),
        Case {
            crash_replay_diverged: true,
            ..Case::exited("a crash-restart replay divergence", 0, Nondeterministic)
        },
        // A crash patina could not carry out, whose incarnation died on a
        // signal before it could say so.
        Case {
            crash_failed: true,
            ..Case::signalled("a crash that could not be carried out", 25, Internal)
        },
        // A process that never got as far as patina's runtime is not the
        // guest crashing, whatever it died of; one that exits clean is clean.
        Case {
            runtime_started: false,
            ..Case::signalled("a death before the runtime started", SIGSEGV, Internal)
        },
        Case {
            runtime_started: false,
            ..Case::exited("a failed load", 127, Internal)
        },
        Case {
            runtime_started: false,
            ..Case::exited("a clean exit before the runtime started", 0, Ok)
        },
        // The guest's own finding outlives a later stop of patina's.
        Case::signalled("a violation, then the compute bound", SIGABRT, Violation).facts(
            serde_json::json!({
                "verdicts": [{"kind": "violation", "label": "ledger"}],
                "runtime_findings": [{"source": "liveness", "known_limit": true}],
                "stop": {"class": "timeout", "reason": "compute_bound", "detail": ""}
            }),
        ),
        // Patina's finalization failing after the guest finished: its own
        // failure when the guest was clean, the guest's when it had failed.
        Case::signalled("a shutdown failure of a clean guest", SIGABRT, Internal).facts(
            serde_json::json!({"stop": {
                "class": "internal", "reason": "shutdown_failure", "detail": "", "guest_exit_code": 0
            }}),
        ),
        Case::signalled("a shutdown failure of a failed guest", SIGABRT, Failure).facts(
            serde_json::json!({"stop": {
                "class": "internal", "reason": "shutdown_failure", "detail": "", "guest_exit_code": 3
            }}),
        ),
        Case {
            trace_lost: Some("the scratch file vanished"),
            ..Case::exited("a recording lost under a clean guest", 0, Internal)
        },
        Case {
            trace_lost: Some("the scratch file vanished"),
            ..Case::exited("a recording lost under a failed guest", 3, Failure)
        },
    ]
}

/// The one classification, over every way a run ends: each lands in its
/// class, and the class alone decides the attribution and the exit status.
#[test]
fn every_way_a_run_ends_lands_in_one_class() {
    for case in cases() {
        let outcome = classify(&RunEvidence {
            exit_code: case.exit_code,
            signal: case.signal,
            facts: case.facts.as_ref(),
            crash_replay_diverged: case.crash_replay_diverged,
            crash_failed: case.crash_failed,
            runtime_started: case.runtime_started,
            channel_defect: case.channel_defect,
            trace_lost: case.trace_lost,
        });
        assert_eq!(outcome.class, case.class, "{}", case.name);
        // A run that did not end clean always says what stopped it.
        assert_eq!(
            outcome.stop.is_some(),
            case.class.is_failure(),
            "{}",
            case.name
        );
        let mut env = Envelope::new("run", outcome.class);
        env.stop = outcome.stop;
        let json = env.to_json();
        assert_eq!(json["exit_code"], case.class.exit_code(), "{}", case.name);
        assert_eq!(
            json.get("attribution").and_then(serde_json::Value::as_str),
            case.class
                .attribution()
                .map(|attribution| attribution.as_str()),
            "{}",
            case.name
        );
    }
}

/// A recording lost under a guest that failed on its own leaves the finding
/// standing and says its trace is gone.
#[test]
fn a_lost_recording_marks_the_guests_own_failure_unreplayable() {
    let failed_guest = |trace_lost| {
        classify(&RunEvidence {
            exit_code: 3,
            signal: None,
            facts: None,
            crash_replay_diverged: false,
            crash_failed: false,
            runtime_started: true,
            channel_defect: None,
            trace_lost,
        })
    };
    assert!(failed_guest(Some("gone")).trace_unusable);
    assert!(!failed_guest(None).trace_unusable);
}
