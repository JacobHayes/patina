//! Runtime-owned envelope facts, refusal attribution, liveness, and WASI traps.

#[cfg(test)]
mod tests {
    use super::super::*;

    // ---------------------------------------------------------------------------
    // Outcome channel (docs/arcs/outcome-channel.md §4.2): the `patina.result/v1`
    // envelope's runtime-owned facts. `fault_reports`/`runtime_findings` come from
    // the runtime's own `patina.runfacts/v1` document — the same report structs the
    // `PATINA_*_REPORT` lines are formatted from — while `refusal`/`guest_exit` are
    // constructed by the supervising process, which is all a dying child leaves it.
    // ---------------------------------------------------------------------------

    /// A guest that gives the fs fault knobs plenty of eligible traffic.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FACTS_FS_SOURCE: &str = r#"
use std::fs;

fn main() {
    let mut ok = 0u32;
    let mut errs = 0u32;
    for index in 0..40u32 {
        match fs::write(format!("/entry-{index}"), b"payload") {
            Ok(()) => ok += 1,
            Err(_) => errs += 1,
        }
    }
    println!("PATINA_RESULT ok={ok} errs={errs}");
}
"#;

    /// A guest that deliberately aborts on its own invariant, printing nothing
    /// patina owns. Per §4.4 this must NOT read as a patina refusal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FACTS_ABORT_SOURCE: &str = r#"
fn main() {
    println!("APP_INVARIANT_BROKEN detail=ledger-does-not-balance");
    std::process::abort();
}
"#;

    /// A guest that churns on virtual time without making progress, so the liveness
    /// watchdog fires and the shim aborts the process before `finish` — the case a
    /// finalization-only facts channel would lose.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FACTS_WEDGE_SOURCE: &str = r#"
use std::time::Duration;

fn main() {
    for _ in 0..10_000 {
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("PATINA_RESULT unreachable=1");
}
"#;

    /// Parse the whitespace-delimited `k=v` fields of a `PATINA_*` report line. Used
    /// ONLY by the test, to prove the structured plane and the printed line describe
    /// the same run — patina itself never reads a line back.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn report_line_fields(stderr: &str, marker: &str) -> BTreeMap<String, String> {
        let line = stderr
            .lines()
            .find(|line| line.trim_start().starts_with(marker))
            .unwrap_or_else(|| panic!("missing {marker} line:\n{stderr}"));
        line.split_whitespace()
            .skip(1)
            .filter_map(|token| token.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_envelope_carries_the_runtime_owned_fault_planes_and_repeats_identically() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "facts-fs-guest", FACTS_FS_SOURCE);

        let arguments = [
            "run",
            guest.to_str().unwrap(),
            "--seed",
            "7",
            "--fs-error-permille",
            "300",
            "--format",
            "json",
        ];
        let first = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &arguments,
        );
        assert!(
            first.status.success(),
            "guest failed:\n{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
        let plane = &envelope["fault_reports"]["fs"];
        assert!(
            !plane.is_null(),
            "the fs plane must reach the envelope:\n{envelope:#}"
        );

        // The structured plane and the human line describe the same run, field for
        // field — including the per-op-kind breakdown and the vacuity bit.
        let printed = report_line_fields(
            envelope["stderr"].as_str().unwrap(),
            "PATINA_FS_FAULT_REPORT",
        );
        assert_eq!(
            plane["eligible_ops"].as_u64().unwrap().to_string(),
            printed["eligible_ops"]
        );
        assert_eq!(
            plane["errors_injected"].as_u64().unwrap().to_string(),
            printed["errors_injected"]
        );
        assert_eq!(
            u8::from(plane["vacuous"].as_bool().unwrap()).to_string(),
            printed["vacuous"]
        );
        assert!(
            plane["errors_injected"].as_u64().unwrap() > 0,
            "the error knob must have fired for this run to prove anything:\n{envelope:#}"
        );
        let structured_kinds: BTreeMap<String, String> = plane["errors_by_op"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(kind, count)| (kind.clone(), count.to_string()))
            .collect();
        let printed_kinds: BTreeMap<String, String> = printed["errors_by_op"]
            .split(',')
            .filter_map(|token| token.split_once(':'))
            .map(|(kind, count)| (kind.to_string(), count.to_string()))
            .collect();
        assert_eq!(structured_kinds, printed_kinds);

        // Determinism: the same seed produces a byte-identical envelope, new fields
        // and all (no map iteration order leaks into the JSON).
        let repeated = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &arguments,
        );
        assert_eq!(
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&repeated.stdout),
            "the envelope must be a deterministic function of the run"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_envelope_attributes_a_patina_refusal_and_leaves_a_guest_abort_unattributed() {
        let directory = tempdir().unwrap();

        // A guest that aborts on its OWN invariant: structurally a signal death, and
        // deliberately NOT a patina refusal. That absence is what lets a classifier
        // file it as the guest's finding instead of patina infrastructure.
        let aborter = build_facts_guest(directory.path(), "facts-abort-guest", FACTS_ABORT_SOURCE);
        let aborted = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                aborter.to_str().unwrap(),
                "--seed",
                "1",
                "--format",
                "json",
            ],
        );
        let envelope: serde_json::Value = serde_json::from_slice(&aborted.stdout).unwrap();
        assert_eq!(envelope["guest_exit"]["signal"], 6);
        assert_eq!(envelope["guest_exit"]["signal_name"], "SIGABRT");
        assert!(
            envelope.get("refusal").is_none(),
            "a guest's own abort must carry no patina refusal:\n{envelope:#}"
        );

        // Patina refusing, on the other hand, is attributed by class. A trace whose
        // recorded fingerprint does not match the runtime's is the canonical case.
        let fs_guest = build_facts_guest(directory.path(), "facts-refusal-guest", FACTS_FS_SOURCE);
        let trace = directory.path().join("refusal.patina");
        invoke(
            native_workspace(),
            &[
                "run",
                fs_guest.to_str().unwrap(),
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let recorded = fs::read_to_string(&trace).unwrap();
        let tampered = recorded.replace("\"patina-native\"", "\"patina-native+yieldpoints\"");
        assert_ne!(
            recorded, tampered,
            "the trace fingerprint was not rewritten"
        );
        fs::write(&trace, tampered).unwrap();
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "replay",
                fs_guest.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let envelope: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(
            envelope["refusal"]["class"], "fingerprint_mismatch",
            "patina's own refusal must be attributed:\n{envelope:#}"
        );
        assert!(
            envelope["refusal"]["message"]
                .as_str()
                .unwrap()
                .contains("fingerprint mismatch"),
            "the refusal must carry the line that announced it:\n{envelope:#}"
        );
        assert_eq!(envelope["guest_exit"]["signal_name"], "SIGABRT");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_liveness_violation_reaches_the_envelope_despite_the_abort_that_follows_it() {
        // The watchdog fires mid-run and the shim aborts the process, so `finish` —
        // where the facts document is normally written — never runs. The finding has
        // to survive that anyway, or the structured channel would be silent about
        // exactly the failures it exists to report.
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "facts-wedge-guest", FACTS_WEDGE_SOURCE);
        let wedged = invoke_with_deadline(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                "1",
                "--liveness-watchdog=1000000000",
                "--format",
                "json",
            ],
            Duration::from_secs(20),
        )
        .expect("the liveness refusal must terminate, not deadlock in its diagnostic");
        let envelope: serde_json::Value = serde_json::from_slice(&wedged.stdout).unwrap();
        let findings = envelope["runtime_findings"]
            .as_array()
            .unwrap_or_else(|| panic!("no runtime findings:\n{envelope:#}"));
        let liveness = findings
            .iter()
            .find(|finding| finding["source"] == "liveness")
            .unwrap_or_else(|| panic!("no liveness finding:\n{envelope:#}"));
        assert_eq!(liveness["kind"], "liveness");
        assert_eq!(liveness["detail"], "no-progress");
        // The same numbers the interface-contract line carries.
        let printed = report_line_fields(envelope["stderr"].as_str().unwrap(), "PATINA_VIOLATION");
        assert_eq!(
            liveness["budget_ns"].as_u64().unwrap().to_string(),
            printed["budget_ns"]
        );
        assert_eq!(
            liveness["vtime_ns"].as_u64().unwrap().to_string(),
            printed["vtime_ns"]
        );
        assert!(
            envelope.get("refusal").is_none(),
            "a liveness wedge is a finding about the guest, not patina refusing:\n{envelope:#}"
        );
    }

    // A wasip1 module whose `always!` invariant is false. The SDK lowers the failure
    // to a `violation` verdict and then TRAPS the guest, which is the shape the two
    // tests below pin: a guest-side trap is the guest's own outcome, so it must
    // still produce a run envelope carrying the verdict it already reported.
    const WASI_ALWAYS_VIOLATION_MODULE: &str = r#"(module
    (import "patina_sdk" "always"
        (func $always (param i32 i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "must-hold")
    (data (i32.const 16) "wat:inv")
    (func (export "_start")
        (drop (call $always (i32.const 0)
            (i32.const 0) (i32.const 9) (i32.const 16) (i32.const 7)))))"#;

    // A WASI guest that traps is reporting an outcome, not failing to run: the CLI
    // must emit a `patina.result/v1` envelope for it, carrying the verdicts the guest
    // drained before the trap. Before this landed, the trap escaped as a `CliError`
    // and the run produced NO envelope at all — so the `violation` verdict the guest
    // had already reported was discarded with it (docs/arcs/outcome-channel.md,
    // Wave B residue).
    #[test]
    fn wasi_guest_trap_still_emits_a_run_envelope_with_its_verdicts() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("always.wasm");
        fs::write(
            &module,
            wat::parse_str(WASI_ALWAYS_VIOLATION_MODULE).unwrap(),
        )
        .unwrap();

        let trapped = invoke_unchecked(
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
        assert!(
            !trapped.status.success(),
            "an always! violation must fail the run"
        );
        let stdout = String::from_utf8_lossy(&trapped.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&trapped.stderr).into_owned();
        let envelope: serde_json::Value =
            serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
                panic!(
                    "a trapping WASI guest must still emit ONE patina.result/v1 envelope on stdout \
             ({error})\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            });
        assert_eq!(envelope["schema"], "patina.result/v1");
        assert_eq!(
            envelope["verdicts"][0]["kind"], "violation",
            "the verdict the guest reported before trapping must survive the trap:\n{envelope:#}"
        );
        assert_eq!(envelope["verdicts"][0]["label"], "must-hold");
        assert!(
            envelope["guest_exit"].is_object(),
            "a trapping guest still exited: {envelope:#}"
        );
        assert!(
            envelope["refusal"].is_null(),
            "a guest trap is the guest's own doing, not a patina refusal:\n{envelope:#}"
        );
        // The trap message stays loud: it rides the run's stderr, so it reaches the
        // human stream, the envelope, and a campaign's captured output alike.
        assert!(
            envelope["stderr"]
                .as_str()
                .is_some_and(|text| text.contains("wasm trap") || text.contains("unreachable")),
            "the trap must still be reported, not swallowed by the envelope:\n{envelope:#}"
        );
    }

    // The residue's real cost: a WASI campaign generation whose guest violates an
    // `always!` invariant classified INFRA (no envelope => "patina's supervisor never
    // reported a result") instead of VIOLATION, filing a genuine safety finding as
    // harness noise. This is the WASI-campaign coverage the arc noted did not exist.
    #[test]
    fn wasi_campaign_generation_with_an_always_violation_classifies_violation() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("always.wasm");
        fs::write(
            &module,
            wat::parse_str(WASI_ALWAYS_VIOLATION_MODULE).unwrap(),
        )
        .unwrap();

        let out = directory.path().join("campaign-out");
        let swept = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &[
                "campaign",
                module.to_str().unwrap(),
                "--gens",
                "2",
                "--progress-every",
                "1",
                "--out-dir",
                out.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let envelope = campaign_json_stdout(&swept);
        assert_eq!(
            envelope["classes"]["VIOLATION"], 2,
            "a WASI guest's always! violation is a safety finding, not infrastructure: {}",
            envelope["classes"]
        );
        assert_eq!(
            envelope["classes"]["INFRA"],
            serde_json::Value::Null,
            "a guest-side trap is not a harness failure: {}",
            envelope["classes"]
        );
    }
}
