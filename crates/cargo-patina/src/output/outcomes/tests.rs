//! Regression tests for outcomes.

use super::*;

// Class-level pairing: signals-family M4 direct-termination conformance;
// exercise both wait-status core bits for the SAME signal, not a signal table.
#[cfg(unix)]
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
        let mut env = Envelope::new("run", "failure", code);
        env.guest_exit = Some(GuestExit { code, signal, core });
        let json = env.to_json();
        assert_eq!(json["schema"], "patina.result/v1");
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

#[test]
fn refusal_attributes_patinas_own_fail_closed_aborts() {
    let attributed = refusal(
            134,
            "",
            "patina: the deterministic runtime failed to initialize: trace fingerprint mismatch: runtime is a, trace is b",
        )
        .expect("a fingerprint mismatch is patina refusing");
    assert_eq!(attributed.class, "fingerprint_mismatch");
    assert!(attributed.message.contains("fingerprint mismatch"));

    assert_eq!(
            refusal(134, "", "patina: this binary was built with `cargo patina build` and must run under `cargo patina run`")
                .expect("no runtime installed is a refusal")
                .class,
            "no_runtime_installed"
        );
    assert_eq!(
        refusal(2, "", "PATINA_BUGGIFY_DUPLICATE_LABEL label=x")
            .expect("a duplicate buggify label is a refusal")
            .class,
        "buggify_duplicate_label"
    );
    // With patina's refusals attributed, an UNATTRIBUTED SIGABRT is the
    // guest's own doing, and a clean run is never a refusal whatever it
    // printed.
    assert!(refusal(134, "APP_INVARIANT_BROKEN detail=ledger", "").is_none());
    assert!(refusal(0, "", "fingerprint mismatch").is_none());
    // A failed trace CHANNEL is patina's own refusal under one fixed prefix, carrying the status
    // the GUEST reached; the incomplete trace a DYING guest leaves is a consequence of the run, not
    // a refusal.
    {
        let line = format!(
            "{} guest_exit_code=0 — the trace could not be written",
            crate::TRACE_CHANNEL_UNAVAILABLE
        );
        let refused = refusal(2, "", &line).expect("a failed trace channel is a refusal");
        assert_eq!(refused.class, "trace_unavailable");
        assert_eq!(refused.guest_exit_code, Some(0));

        // RED twin: the truncated trace a DYING guest leaves is a consequence of
        // the run, not a refusal — attributing it to patina would make every
        // guest abort mid-record look like patina's fault.
        assert!(
            refusal(
                134,
                "",
                "PATINA_INFRA native_run signal=6 trace=incomplete trace_path=\"t.patina\"                  reason=\"empty trace file; record finalization did not complete\""
            )
            .is_none(),
            "a trace left incomplete by a dying guest must not be attributed to patina"
        );
    }
}
