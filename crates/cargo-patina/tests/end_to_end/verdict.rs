//! Native and WASI verdict ABI recording, replay, and envelope delivery.

#[cfg(test)]
mod tests {
    use super::super::*;

    // ---------------------------------------------------------------------------
    // The verdict ABI (outcome-channel arc, Wave A): one shim verb / one WASI
    // import, recorded as trace events and surfaced in `patina.result/v1`.
    // ---------------------------------------------------------------------------

    // A guest that reports both a passing and a violating verdict, plus one whose
    // label and detail contain spaces — the marker-line escaping has to survive the
    // round trip into the envelope.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const VERDICT_SDK_MAIN: &str = r#"
use patina_dst::VerdictKind;

fn main() {
    patina_dst::verdict(VerdictKind::Pass, "setup-complete", "");
    patina_dst::verdict(VerdictKind::Violation, "two leaders", "{\"term\": 4}");
    patina_dst::verdict(VerdictKind::AbortIntent, "checksum-mismatch", "page=7");
    println!("PATINA_RESULT verdicts=3");
}
"#;

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
        let pkg = directory.path().join("pkg");
        write_sdk_fixture(&pkg, VERDICT_SDK_MAIN);
        let workspace = native_workspace();
        let bin = directory.path().join("verdict-guest");
        invoke(
            workspace,
            &[
                "build",
                pkg.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

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

        // Same seed twice: byte-identical, verdict lines included.
        let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "4"]);
        let second = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "4"]);
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(first.stderr, second.stderr);
        assert_eq!(verdict_lines(&first).len(), 3);
    }

    // An `always!` violation lowers to a `VIOLATION` verdict on the same label, and
    // that verdict is the failure's ONLY announcement: Wave B of the outcome-channel
    // arc deleted the embedder's legacy `PATINA_ALWAYS_VIOLATION` marker once the
    // campaign classifier started reading the envelope instead of grepping.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_always_violation_lowers_to_a_verdict_and_prints_no_legacy_marker() {
        let directory = tempdir().unwrap();
        let pkg = directory.path().join("pkg");
        write_sdk_fixture(
            &pkg,
            r#"
fn main() {
    patina_dst::always!(1 + 1 == 3, "arithmetic-holds");
    println!("UNREACHABLE");
}
"#,
        );
        let workspace = native_workspace();
        let bin = directory.path().join("always-verdict");
        invoke(
            workspace,
            &[
                "build",
                pkg.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let violated = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !violated.status.success(),
            "an always! violation must fail the run"
        );
        let stderr = String::from_utf8_lossy(&violated.stderr);
        let lines = verdict_lines(&violated);
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one verdict from the violation:\n{stderr}"
        );
        assert!(
            lines[0].contains("kind=violation") && lines[0].contains("label=arithmetic-holds"),
            "verdict did not carry the violated invariant's label: {}",
            lines[0]
        );
        // No second channel: the verdict is the source, so the legacy marker is gone.
        assert!(
            !stderr.contains("PATINA_ALWAYS_VIOLATION"),
            "the legacy always-violation marker must no longer print:\n{stderr}"
        );
        assert!(
            !stderr.contains("UNREACHABLE"),
            "the violation must abort before the guest continues:\n{stderr}"
        );
    }

    // The WASI half: the `patina_sdk` `verdict` import is backed by the same runtime
    // entry, so a wasip1 guest's verdicts reach the envelope identically to native.
    // An unknown kind traps rather than being reclassified.
    #[test]
    fn wasi_verdict_import_records_and_refuses_an_unknown_kind() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("verdict.wasm");
        fs::write(
            &module,
            wat::parse_str(
                r#"(module
                (import "patina_sdk" "verdict"
                    (func $verdict (param i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "two leaders")
                (data (i32.const 16) "term=4")
                (func (export "_start")
                    (drop (call $verdict (i32.const 1)
                        (i32.const 0) (i32.const 11) (i32.const 16) (i32.const 6)))))"#,
            )
            .unwrap(),
        )
        .unwrap();

        let run = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &[
                "run",
                module.to_str().unwrap(),
                "--seed",
                "1",
                "--format",
                "json",
            ],
        );
        let stdout = String::from_utf8_lossy(&run.stdout);
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("envelope was not one JSON object: {error}\n{stdout}"));
        let verdicts = value["verdicts"]
            .as_array()
            .unwrap_or_else(|| panic!("wasip1 run carried no verdicts[]: {value}"));
        assert_eq!(verdicts.len(), 1, "{value}");
        assert_eq!(verdicts[0]["kind"], "violation");
        assert_eq!(verdicts[0]["label"], "two leaders");
        assert_eq!(verdicts[0]["detail"], "term=4");

        // An out-of-range kind is refused, not defaulted: a guest built against a
        // newer verdict ABI must fail closed rather than report a wrong kind.
        let unknown = directory.path().join("unknown-kind.wasm");
        fs::write(
            &unknown,
            wat::parse_str(
                r#"(module
                (import "patina_sdk" "verdict"
                    (func $verdict (param i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (drop (call $verdict (i32.const 99)
                        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))))"#,
            )
            .unwrap(),
        )
        .unwrap();
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", unknown.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !refused.status.success(),
            "an unknown verdict kind must fail the run"
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("unknown verdict kind 99"),
            "the refusal must name the unknown kind:\n{stderr}"
        );
    }
}
