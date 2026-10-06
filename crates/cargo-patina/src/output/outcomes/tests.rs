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
    }
}

#[test]
fn guest_exit_names_the_signal_the_exit_code_cannot_express() {
    let mut env = Envelope::new("run", "failure", 134);
    env.guest_exit = Some(GuestExit {
        code: 134,
        signal: Some(6),
        core: false,
    });
    let json = env.to_json();
    assert_eq!(json["guest_exit"]["code"], 134);
    assert_eq!(json["guest_exit"]["signal"], 6);
    assert_eq!(json["guest_exit"]["signal_name"], "SIGABRT");

    // A guest that deliberately returns 134 is NOT a signal death, and the
    // envelope must keep the two apart — that split is what lets a campaign
    // tell a fail-closed abort from an ordinary exit status.
    let mut plain = Envelope::new("run", "failure", 134);
    plain.guest_exit = Some(GuestExit {
        code: 134,
        signal: None,
        core: false,
    });
    let json = plain.to_json();
    assert_eq!(json["guest_exit"]["code"], 134);
    assert!(json["guest_exit"].get("signal").is_none());
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
}

/// A failed trace CHANNEL is patina's own operational condition and says so
/// in one fixed sentence, carrying the status the GUEST reached. The fixed
/// prefix is what makes every such run share a class — and therefore a
/// signature — instead of one novel finding per scratch path.
#[test]
fn a_failed_trace_channel_is_patinas_own_refusal_and_names_the_guests_status() {
    let line = format!(
        "{} guest_exit_code=0 — the trace could not be written",
        crate::TRACE_CHANNEL_UNAVAILABLE
    );
    let refused = refusal(2, "", &line).expect("a failed trace channel is a refusal");
    assert_eq!(refused.class, "trace_unavailable");
    assert_eq!(refused.guest_exit_code, Some(0));

    let failing_guest = refusal(
        101,
        "",
        &format!(
            "{} guest_exit_code=101 — the trace could not be written",
            crate::TRACE_CHANNEL_UNAVAILABLE
        ),
    )
    .expect("a failed trace channel is a refusal");
    assert_eq!(failing_guest.guest_exit_code, Some(101));

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

#[test]
fn refusal_is_absent_for_a_guests_own_abort() {
    // The design point of §4.4: with patina's refusals attributed, an
    // UNATTRIBUTED SIGABRT is the guest's own doing. If this ever starts
    // returning Some, the campaign classifier would file a guest's deliberate
    // abort as patina infrastructure again.
    assert!(refusal(134, "APP_INVARIANT_BROKEN detail=ledger", "").is_none());
    // And a clean run is never a refusal, whatever it printed.
    assert!(refusal(0, "", "fingerprint mismatch").is_none());
    // The trap this closes: a guest that aborts under `--record` ALWAYS
    // leaves an incomplete trace, and the supervisor always says so. Reading
    // that consequence as a refusal attributed every single guest abort to
    // patina, which made the campaign's `GUEST_ABORT` class unreachable.
    assert!(
        refusal(
            134,
            "",
            "PATINA_INFRA native_run signal=6 trace=incomplete trace_path=\"g.patina\" \
reason=\"incomplete trace .g.patina.tmp: empty trace file; record finalization did not complete\""
        )
        .is_none(),
        "an incomplete trace left by a dying guest is a consequence, not a patina refusal"
    );
}

#[test]
fn a_malformed_verdict_line_is_dropped_not_half_decoded() {
    // Truncated (no detail) and unknown-kind lines must not become verdicts:
    // a partially understood result is worse than no result.
    let stderr =
        "PATINA_VERDICT seq=1 kind=pass label=x\nPATINA_VERDICT seq=2 kind=nope label=x detail=\n";
    assert!(extract_verdicts("", stderr).is_empty());
}
