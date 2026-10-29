//! Native verdict ABI recording, replay, and envelope delivery, and
//! the native SDK verdict guest the minimize tests share.

use super::*;

/// An SDK guest whose first argument picks how it reports:
///
/// * none: print a line, then fail an `always!` invariant;
/// * `verdicts`: report a passing, a violating and an abort-intent verdict,
///   one with spaces in its label and detail, which the marker-line escaping
///   has to carry into the envelope;
/// * `parked`: fail the invariant while a parked worker holds std's stderr
///   lock, so finalization must not wait on a lock a guest thread can hold.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const VERDICT_SDK_MAIN: &str = r#"
use std::sync::atomic::{AtomicBool, Ordering};

use patina_dst::VerdictKind;

static HOLDING: AtomicBool = AtomicBool::new(false);

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("verdicts") => {
            patina_dst::verdict(VerdictKind::Pass, "setup-complete", "");
            patina_dst::verdict(VerdictKind::Violation, "two leaders", "{\"term\": 4}");
            patina_dst::verdict(VerdictKind::AbortIntent, "checksum-mismatch", "page=7");
            println!("PATINA_RESULT verdicts=3");
            return;
        }
        Some("parked") => {
            std::thread::spawn(|| {
                let _stderr = std::io::stderr().lock();
                HOLDING.store(true, Ordering::Release);
                loop {
                    std::thread::yield_now();
                }
            });
            while !HOLDING.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
        _ => println!("GUEST_BEFORE"),
    }
    patina_dst::always!(std::env::args().count() > 64, "never-holds");
    println!("UNREACHABLE");
}
"#;

/// The [`VERDICT_SDK_MAIN`] guest.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn verdict_guest() -> PathBuf {
    super::run_facts::shared_sdk_guest("verdict-guest", VERDICT_SDK_MAIN)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::verdict_guest;

    // ---------------------------------------------------------------------------
    // The verdict ABI (outcome-channel arc, Wave A): one shim verb, recorded as
    // trace events and surfaced in `patina.result/v1`.
    // ---------------------------------------------------------------------------

    /// The `PATINA_VERDICT` lines in a stderr stream, in order.
    fn verdict_lines_in(stderr: &str) -> Vec<String> {
        stderr
            .lines()
            .filter(|line| line.starts_with("PATINA_VERDICT "))
            .map(str::to_string)
            .collect()
    }

    /// The run's `PATINA_VERDICT` lines, in order. Note `--format json` folds the
    /// guest's stderr into the envelope instead of re-emitting it, so a JSON run's
    /// lines come from `envelope["stderr"]`, not from here.
    fn verdict_lines(output: &Output) -> Vec<String> {
        verdict_lines_in(&String::from_utf8_lossy(&output.stderr))
    }

    // The native half of the verdict ABI end to end: `patina_dst::verdict` reaches
    // the shim's single `patina_verdict` verb, every call becomes a trace event, the
    // run's `patina.result/v1` envelope carries the structured `verdicts[]`, and a
    // replay reproduces the verdict stream byte-identically.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_verdict_abi_records_replays_and_reaches_the_envelope() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let bin = verdict_guest();

        // The envelope carries the verdicts structurally, in call order.
        let trace = directory.path().join("verdict.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "4",
                "--record",
                trace.to_str().unwrap(),
                "--format",
                "json",
                "--",
                "verdicts",
            ],
        );
        let stdout = String::from_utf8_lossy(&recorded.stdout);
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("envelope was not one JSON object: {error}\n{stdout}"));
        let verdicts = value["verdicts"]
            .as_array()
            .unwrap_or_else(|| panic!("envelope carried no verdicts[]: {value}"));
        assert_eq!(verdicts.len(), 3, "{value}");
        assert_eq!(verdicts[0]["seq"], 0);
        assert_eq!(verdicts[0]["kind"], "pass");
        assert_eq!(verdicts[0]["label"], "setup-complete");
        assert_eq!(verdicts[0]["detail"], "");
        assert_eq!(verdicts[1]["seq"], 1);
        assert_eq!(verdicts[1]["kind"], "violation");
        // Spaces in the label and the detail survive the escaped wire format.
        assert_eq!(verdicts[1]["label"], "two leaders");
        assert_eq!(verdicts[1]["detail"], "{\"term\": 4}");
        assert_eq!(verdicts[2]["kind"], "abort_intent");
        assert_eq!(verdicts[2]["label"], "checksum-mismatch");

        // Every call is a recorded trace event, not merely a printed line.
        let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
        let events: Vec<_> = bundle
            .resolved_timeline("main")
            .unwrap()
            .into_iter()
            .filter(|event| matches!(event.operation, patina_dst_abi::Operation::Verdict { .. }))
            .collect();
        assert_eq!(
            events.len(),
            3,
            "expected three recorded verdict events, got {events:?}"
        );

        // Replay reproduces the verdict stream byte-identically, flag-free. The
        // recording ran under `--format json`, which folds guest stderr into the
        // envelope rather than re-emitting it, so its lines come from there.
        let recorded_lines = verdict_lines_in(value["stderr"].as_str().unwrap_or_default());
        let replayed = invoke(
            workspace,
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            recorded_lines,
            verdict_lines(&replayed),
            "replayed verdict stream diverged from the recording"
        );
        assert_eq!(
            recorded_lines.len(),
            3,
            "replay must not be vacuously verdict-free"
        );
    }

    /// A recorded run of the verdict guest that fails its `always!`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct AlwaysRecording {
        _directory: tempfile::TempDir,
        bin: PathBuf,
        trace: PathBuf,
        recorded: Output,
    }

    /// Record one seeded run of the verdict guest in `mode`, which must fail
    /// and leave a trace holding exactly one violation verdict.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn record_always_violation(mode: &[&str]) -> AlwaysRecording {
        let directory = tempdir().unwrap();
        let bin = verdict_guest();
        let trace = directory.path().join("always.patina");
        let mut arguments = vec![
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ];
        arguments.extend_from_slice(mode);
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &arguments,
        );
        let stderr = String::from_utf8_lossy(&recorded.stderr);
        assert!(
            !recorded.status.success(),
            "an always! violation must fail the run:\n{stderr}"
        );
        let bundle = patina_dst_trace::TraceBundle::load(&trace)
            .unwrap_or_else(|error| panic!("the violation left no trace: {error}\n{stderr}"));
        let violations = bundle
            .resolved_timeline("main")
            .unwrap()
            .into_iter()
            .filter(|event| {
                matches!(
                    event.operation,
                    patina_dst_abi::Operation::Verdict {
                        verdict_kind: patina_dst_abi::VerdictKind::Violation,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            violations, 1,
            "the trace must hold the violation verdict:\n{stderr}"
        );
        AlwaysRecording {
            _directory: directory,
            bin,
            trace,
            recorded,
        }
    }

    /// A flag-free replay of `recording` ends the way the recording did and
    /// reproduces its output byte for byte.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_replays_identically(recording: &AlwaysRecording) {
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "replay",
                recording.bin.to_str().unwrap(),
                recording.trace.to_str().unwrap(),
            ],
        );
        assert_eq!(
            replayed.status.code(),
            recording.recorded.status.code(),
            "replay must end the way the recording did:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        assert_eq!(recording.recorded.stdout, replayed.stdout);
        assert_eq!(recording.recorded.stderr, replayed.stderr);
        assert_eq!(verdict_lines(&replayed).len(), 1);
    }

    // An `always!` violation lowers to a `VIOLATION` verdict on the same label, and
    // that verdict is the failure's ONLY announcement: Wave B of the outcome-channel
    // arc deleted the embedder's legacy `PATINA_ALWAYS_VIOLATION` marker once the
    // campaign classifier started reading the envelope instead of grepping.
    //
    // A failing `always!` finalizes the run before it aborts, so the failure the
    // oracle exists to find leaves a trace: the trace holds the violation as a
    // recorded verdict, a flag-free replay reproduces the run byte for byte, and
    // both runs still fail with the same status.
    //
    // A replay that stops at the violation with recorded events still unconsumed
    // has diverged from the recording. That must surface as the shim fatal the
    // minimizer's divergence check reads, never as the finding alone, or a
    // reducer would accept a candidate that no longer reproduces the run.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_always_violation_is_one_verdict_whose_trace_replays_and_detects_divergence() {
        let recording = record_always_violation(&[]);
        let stdout = String::from_utf8_lossy(&recording.recorded.stdout);
        let stderr = String::from_utf8_lossy(&recording.recorded.stderr);
        assert!(
            stdout.contains("GUEST_BEFORE"),
            "the guest's output before the violation must reach stdout"
        );
        let lines = verdict_lines(&recording.recorded);
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one verdict from the violation:\n{stderr}"
        );
        assert!(
            lines[0].contains("kind=violation") && lines[0].contains("label=never-holds"),
            "verdict did not carry the violated invariant's label: {}",
            lines[0]
        );
        // No second channel: the verdict is the source, so the legacy marker is gone.
        assert!(
            !stderr.contains("PATINA_ALWAYS_VIOLATION"),
            "the legacy always-violation marker must no longer print:\n{stderr}"
        );
        assert!(
            !stdout.contains("UNREACHABLE") && !stderr.contains("UNREACHABLE"),
            "the violation must abort before the guest continues:\n{stdout}\n{stderr}"
        );
        assert_replays_identically(&recording);

        // One more recorded decision than the run makes: the replay reaches the
        // violation with it unconsumed.
        let mut bundle = patina_dst_trace::TraceBundle::load(&recording.trace).unwrap();
        let timeline = &mut bundle.timelines[0];
        let mut trailing = timeline.decisions.last().unwrap().clone();
        trailing.sequence += 1;
        trailing.order += 1;
        for marker in &mut timeline.lifecycle {
            if marker.order >= trailing.order {
                marker.order += 1;
            }
        }
        timeline.decisions.push(trailing);
        bundle.write_atomic(&recording.trace).unwrap();

        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "replay",
                recording.bin.to_str().unwrap(),
                recording.trace.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let stdout = String::from_utf8_lossy(&replayed.stdout);
        let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("envelope was not one JSON object: {error}\n{stdout}"));
        assert!(!replayed.status.success(), "{envelope:#}");
        assert_eq!(
            envelope["verdicts"][0]["kind"], "violation",
            "the replay must still reach the violation: {envelope:#}"
        );
        assert_eq!(
            envelope["refusal"]["class"], "shim_fatal",
            "the unconsumed trace must fail the replay as a divergence: {envelope:#}"
        );

        // Finalization prints the end-of-run reports after the runtime is gone,
        // so it must not wait on a lock a guest thread can hold: here a worker
        // is parked holding std's stderr lock when main fails its invariant.
        assert_replays_identically(&record_always_violation(&["--", "parked"]));
    }
}
