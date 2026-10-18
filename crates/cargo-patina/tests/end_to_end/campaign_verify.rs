//! Campaign reproduction verification: a novel finding's reproduce path runs
//! before the finding is reported, a seeded sample of clean generations runs
//! twice, and whatever does not reproduce is NONDETERMINISM.
//!
//! The planted guest (`testbeds/native-boundary/address_leak_probe.rs`) reads
//! its own stack address, which the audit cannot see. Patina fixes the native
//! layout by default, so these campaigns pass `--allow-randomized-address-layout`
//! to keep the host's randomization: the address is then a source patina does
//! not control, and the opt-out reaches every generation, verification replay
//! and rerun the campaign makes. Linux-only: that is where the stack address is
//! measured to differ between runs.

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::*;

    const GUEST: &str = include_str!("../../../../testbeds/native-boundary/address_leak_probe.rs");

    /// The class pairing of these tests: `campaign --selftest`'s verification
    /// checks prove every comparison axis and the infra rule on planted
    /// outcomes; these prove the campaign actually runs the comparison.
    fn campaign(
        guest: &Path,
        out: &Path,
        gens: u64,
        extra: &[&str],
        mode: &str,
    ) -> (Option<i32>, serde_json::Value) {
        let gens = gens.to_string();
        let mut args = vec![
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            &gens,
            "--out-dir",
            out.to_str().unwrap(),
            "--format",
            "json",
        ];
        args.extend_from_slice(extra);
        // A guest without modes (a WASI module, a single-purpose native guest)
        // takes no `--` guest arguments: its mode is "". A moded native guest
        // keeps the host's randomized layout (see the module docs).
        if !mode.is_empty() {
            args.extend(["--allow-randomized-address-layout", "--", mode]);
        }
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &args,
        );
        (output.status.code(), campaign_json_stdout(&output))
    }

    fn signatures(envelope: &serde_json::Value) -> &Vec<serde_json::Value> {
        envelope["signatures"].as_array().unwrap()
    }

    #[test]
    fn a_finding_whose_replay_differs_is_nondeterminism_with_both_outcomes() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let (code, envelope) = campaign(&guest, &directory.path().join("out"), 2, &[], "leak-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["NONDETERMINISM"], 2, "{envelope:#}");
        assert!(
            envelope["classes"].get("UNCLASSIFIED").is_none(),
            "{envelope:#}"
        );
        for record in signatures(&envelope) {
            assert_eq!(record["class"], "NONDETERMINISM", "{record:#}");
            let verification = &record["verification"];
            assert_eq!(verification["path"], "replay", "{record:#}");
            assert_eq!(verification["status"], "nondeterministic", "{record:#}");
            // Both outcomes travel with the class: what the campaign saw, and
            // what its own reproduce command produced.
            assert_eq!(verification["observed"]["class"], "UNCLASSIFIED");
            assert_eq!(verification["reproduction"]["class"], "UNCLASSIFIED");
            assert_ne!(
                verification["observed"]["signature"], verification["reproduction"]["signature"],
                "{record:#}"
            );
            assert!(
                record["reproduce"]
                    .as_str()
                    .unwrap()
                    .starts_with("cargo patina replay"),
                "{record:#}"
            );
        }
        assert_eq!(envelope["verification"]["findings"]["nondeterministic"], 2);
    }

    #[test]
    fn a_failure_that_reproduces_keeps_its_class_and_is_verified_once() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let (code, envelope) = campaign(&guest, &directory.path().join("out"), 3, &[], "det-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["UNCLASSIFIED"], 3, "{envelope:#}");
        assert!(
            envelope["classes"].get("NONDETERMINISM").is_none(),
            "{envelope:#}"
        );
        let records = signatures(&envelope);
        assert_eq!(records.len(), 1, "{envelope:#}");
        assert_eq!(records[0]["count"], 3);
        assert_eq!(
            records[0]["verification"]["status"], "reproduced",
            "{envelope:#}"
        );
        // The repeats are not verified again: the cost is one run per novel
        // signature.
        assert_eq!(
            envelope["verification"]["findings"]["verified"], 1,
            "{envelope:#}"
        );
    }

    #[test]
    fn the_clean_rerun_sample_catches_a_leak_on_a_passing_run() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        // One stride of generations holds exactly one sampled generation.
        let stride = 16;

        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("leak"),
            stride,
            &[],
            "leak-clean",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["NONDETERMINISM"], 1, "{envelope:#}");
        assert_eq!(envelope["classes"]["OK"], stride - 1, "{envelope:#}");
        assert_eq!(
            envelope["verification"]["clean"]["reruns"], 1,
            "{envelope:#}"
        );
        assert_eq!(envelope["verification"]["clean"]["nondeterministic"], 1);
        let caught = envelope["notable_runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| run["class"] == "NONDETERMINISM")
            .unwrap();
        let verification = &caught["verification"];
        assert_eq!(verification["path"], "rerun", "{caught:#}");
        assert_eq!(verification["observed"]["class"], "OK", "{caught:#}");
        assert_eq!(verification["reproduction"]["class"], "OK", "{caught:#}");
        // Only the trace tells the two passing runs apart.
        let observed = verification["observed"]["trace"].as_str().unwrap();
        let reproduced = verification["reproduction"]["trace"].as_str().unwrap();
        assert_ne!(observed, reproduced, "{caught:#}");

        // The deterministic control: the same shape, with scheduling decisions
        // in its trace, reruns byte-identically and stays clean.
        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("det"),
            stride,
            &[],
            "det-clean",
        );
        assert_eq!(code, Some(0), "{envelope:#}");
        assert_eq!(envelope["classes"]["OK"], stride, "{envelope:#}");
        assert_eq!(
            envelope["verification"]["clean"]["reruns"], 1,
            "{envelope:#}"
        );
        assert_eq!(envelope["verification"]["clean"]["nondeterministic"], 0);
    }

    #[test]
    fn a_leak_the_signature_collapses_is_still_nondeterminism() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let out = directory.path().join("out");
        let (code, envelope) = campaign(&guest, &out, 2, &[], "leak-number-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        let record = &signatures(&envelope)[0];
        let verification = &record["verification"];
        // The leaked token is all digits, so both runs share one signature:
        // only the exact outcome tells them apart.
        assert_eq!(
            verification["observed"]["signature"], verification["reproduction"]["signature"],
            "{record:#}"
        );
        assert_eq!(verification["status"], "nondeterministic", "{record:#}");
        assert_eq!(record["class"], "NONDETERMINISM", "{record:#}");
    }

    #[test]
    fn a_replay_that_diverges_after_its_verdict_is_nondeterminism() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        // Each seed reports its own violation label, so every generation is a
        // novel finding and is verified: a divergence surfaces as an
        // unconsumed trace on some replays and an overrun on others, and both
        // must land the same way.
        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("out"),
            6,
            &[],
            "leak-schedule",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        assert!(
            envelope["classes"].get("VIOLATION").is_none(),
            "{envelope:#}"
        );
        for record in signatures(&envelope) {
            let verification = &record["verification"];
            assert_eq!(verification["path"], "replay", "{record:#}");
            assert_eq!(verification["status"], "nondeterministic", "{record:#}");
            assert_eq!(
                verification["reproduction"]["replay_diverged"], true,
                "{record:#}"
            );
        }
    }

    /// Four workers contend on one mutex long enough for PCT's change points
    /// to land, then the guest fails with the same count on every schedule.
    const PCT_COUNTER_GUEST: &str = r#"use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0u64));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                for _ in 0..500 {
                    *counter.lock().unwrap() += 1;
                    thread::yield_now();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    println!("MRE_FAILURE counted {}", *counter.lock().unwrap());
    std::process::exit(4);
}
"#;

    #[test]
    fn a_pct_finding_that_hit_a_change_point_reproduces() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "pct_counter", PCT_COUNTER_GUEST);
        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("out"),
            4,
            &["--sched-pct"],
            "",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        assert!(
            envelope["classes"].get("NONDETERMINISM").is_none(),
            "{envelope:#}"
        );
        let records = signatures(&envelope);
        // Non-vacuity: some generation's seeded schedule hit a change point,
        // which its replay, following recorded selections, never does.
        let bug_depth = |record: &serde_json::Value| -> u64 {
            record["policy"]
                .as_str()
                .and_then(|policy| policy.strip_prefix("bug_depth="))
                .and_then(|depth| depth.parse().ok())
                .unwrap_or_else(|| panic!("no bug depth: {record:#}"))
        };
        assert!(
            records.iter().any(|record| bug_depth(record) > 0),
            "{envelope:#}"
        );
        for record in records {
            let verification = &record["verification"];
            assert_eq!(verification["path"], "replay", "{record:#}");
            assert_eq!(verification["status"], "reproduced", "{record:#}");
        }
    }

    #[test]
    fn minimize_refuses_a_nondeterministic_generation() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let out = directory.path().join("out");
        let (_, envelope) = campaign(&guest, &out, 1, &[], "leak-schedule");
        assert_eq!(envelope["classes"]["NONDETERMINISM"], 1, "{envelope:#}");
        // The generation carries a violation verdict a single-run oracle could
        // target, which would reduce the violation and drop the nondeterminism.
        let output = directory.path().join("minimized.patina");
        let minimized = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "minimize",
                "--generation",
                "0",
                "--out-dir",
                out.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
                "--no-trace-phase",
                "--jobs",
                "1",
            ],
        );
        let stderr = String::from_utf8_lossy(&minimized.stderr);
        assert_eq!(minimized.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains("NONDETERMINISM"), "{stderr}");
        assert!(!output.exists());
    }

    #[test]
    fn a_deterministic_fault_reproduces() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        // The second mode leaves its last stderr line unfinished, so patina's
        // own marker follows guest output on the same stream.
        for mode in ["det-segv", "det-segv-unterminated"] {
            let (code, envelope) = campaign(&guest, &directory.path().join(mode), 2, &[], mode);
            assert_eq!(code, Some(1), "{mode}: {envelope:#}");
            assert!(
                envelope["classes"].get("NONDETERMINISM").is_none(),
                "{mode}: {envelope:#}"
            );
            // Both generations fault the same way, so they share one signature,
            // and its reproduction agrees with it.
            let records = signatures(&envelope);
            assert_eq!(records.len(), 1, "{mode}: {envelope:#}");
            assert_eq!(records[0]["count"], 2, "{mode}: {envelope:#}");
            assert_eq!(
                records[0]["verification"]["status"], "reproduced",
                "{mode}: {envelope:#}"
            );
        }
    }

    #[test]
    fn a_guest_cannot_forge_a_replay_divergence() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("out"),
            1,
            &[],
            "forge-divergence",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        let record = &signatures(&envelope)[0];
        assert_eq!(record["verification"]["status"], "reproduced", "{record:#}");
        assert!(
            record["verification"]["reproduction"]
                .get("replay_diverged")
                .is_none(),
            "{record:#}"
        );
    }

    #[test]
    fn a_guest_line_shaped_like_patinas_marker_keeps_its_evidence() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        for mode in ["forge-marker", "forge-native-run"] {
            let (code, envelope) = campaign(&guest, &directory.path().join(mode), 1, &[], mode);
            assert_eq!(code, Some(1), "{mode}: {envelope:#}");
            let record = &signatures(&envelope)[0];
            assert_eq!(
                record["verification"]["status"], "nondeterministic",
                "{mode}: {record:#}"
            );
        }
    }

    #[test]
    fn a_replay_that_diverges_from_the_time_model_is_nondeterminism() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let (code, envelope) =
            campaign(&guest, &directory.path().join("out"), 1, &[], "leak-clock");
        assert_eq!(code, Some(1), "{envelope:#}");
        let record = &signatures(&envelope)[0];
        let verification = &record["verification"];
        assert_eq!(verification["path"], "replay", "{record:#}");
        assert_eq!(verification["status"], "nondeterministic", "{record:#}");
        assert_eq!(
            verification["reproduction"]["replay_diverged"], true,
            "{record:#}"
        );
    }

    /// A WASI guest that writes a line of output and reports a fixed
    /// violation, then runs `body` with `$mode` set by a custom operation: zero
    /// while recording, nonzero in a replay. A body that skips or changes a
    /// recorded entropy read in the replay makes it diverge, surfacing as a
    /// runtime finalization error, not a trap.
    fn mode_branching_wasi_guest(directory: &Path, name: &str, body: &str) -> PathBuf {
        let wat = format!(
            r#"(module
 (import "patina_sdk" "verdict" (func $verdict (param i32 i32 i32 i32 i32) (result i32)))
 (import "patina_sdk" "custom_op_begin" (func $begin (param i32 i32 i32 i32 i32 i32) (result i32)))
 (import "patina_sdk" "custom_op_record" (func $record (param i32 i32) (result i32)))
 (import "patina_sdk" "custom_op_replay_result" (func $fetch (param i32 i32) (result i32)))
 (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32) (result i32)))
 (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
 (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
 (memory (export "memory") 1)
 (data (i32.const 0) "fixed")
 (data (i32.const 200) "guest-output\n")
 (func (export "_start") (local $mode i32)
  (i32.store (i32.const 80) (i32.const 200))
  (i32.store (i32.const 84) (i32.const 13))
  (drop (call $write (i32.const 1) (i32.const 80) (i32.const 1) (i32.const 100)))
  (drop (call $verdict (i32.const 1) (i32.const 0) (i32.const 5) (i32.const 0) (i32.const 0)))
  (local.set $mode (call $begin (i32.const 0) (i32.const 5) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 64)))
  (if (i32.eqz (local.get $mode))
   (then (drop (call $record (i32.const 0) (i32.const 0))))
   (else (drop (call $fetch (i32.const 0) (i32.const 0)))))
  {body}))"#
        );
        let path = directory.join(format!("{name}.wasm"));
        fs::write(&path, wat::parse_str(&wat).unwrap()).unwrap();
        path
    }

    #[test]
    fn a_wasi_replay_that_diverges_at_finalization_is_nondeterminism() {
        let directory = tempdir().unwrap();
        for (name, body) in [
            // The replay skips the recorded read: events are left over.
            (
                "under",
                "(if (i32.eqz (local.get $mode)) (then (drop (call $random (i32.const 128) (i32.const 1)))))",
            ),
            // The replay asks for a different length: the operation differs.
            (
                "mismatch",
                "(drop (call $random (i32.const 128) (i32.add (i32.const 1) (local.get $mode))))",
            ),
        ] {
            let guest = mode_branching_wasi_guest(directory.path(), name, body);
            let (code, envelope) = campaign(&guest, &directory.path().join(name), 1, &[], "");
            assert_eq!(code, Some(1), "{name}: {envelope:#}");
            let record = &signatures(&envelope)[0];
            assert_eq!(
                record["verification"]["status"], "nondeterministic",
                "{name}: {record:#}"
            );
        }
    }

    #[test]
    fn a_wasi_exit_status_is_compared_past_eight_bits() {
        let directory = tempdir().unwrap();
        // Exit 3 while recording and 259 in the replay: one byte apart only
        // above the eight bits a process status carries.
        let guest = mode_branching_wasi_guest(
            directory.path(),
            "exit-bits",
            "(drop (call $random (i32.const 128) (i32.const 1))) \
             (call $exit (i32.add (i32.const 3) (i32.mul (local.get $mode) (i32.const 256))))",
        );
        let (code, envelope) = campaign(&guest, &directory.path().join("out"), 1, &[], "");
        assert_eq!(code, Some(1), "{envelope:#}");
        let record = &signatures(&envelope)[0];
        assert_eq!(
            record["verification"]["status"], "nondeterministic",
            "{record:#}"
        );
    }

    #[test]
    fn a_wasi_replay_that_diverges_at_finalization_keeps_the_guests_evidence() {
        let directory = tempdir().unwrap();
        let skip_read = "(if (i32.eqz (local.get $mode)) (then (drop (call $random (i32.const 128) (i32.const 1)))))";
        for (name, ending, guest_code) in [
            ("returns", "", 0),
            ("exits", "(call $exit (i32.const 17))", 17),
        ] {
            let guest =
                mode_branching_wasi_guest(directory.path(), name, &format!("{skip_read} {ending}"));
            let trace = directory.path().join(format!("{name}.patina"));
            let workspace = native_workspace();
            let cli = env!("CARGO_BIN_EXE_cargo-patina");
            let guest_arg = guest.to_str().unwrap();
            let trace_arg = trace.to_str().unwrap();
            invoke_unchecked(
                cli,
                workspace,
                &["run", guest_arg, "--seed", "7", "--record", trace_arg],
            );
            assert!(trace.is_file(), "{name}: the recording left no trace");
            let output = invoke_unchecked(
                cli,
                workspace,
                &["replay", guest_arg, trace_arg, "--format", "json"],
            );
            let envelope = campaign_json_stdout(&output);
            assert!(
                envelope["replay_divergence"].is_string(),
                "{name}: {envelope:#}"
            );
            // The run still fails...
            assert_ne!(output.status.code(), Some(0), "{name}: {envelope:#}");
            // ...and keeps what the guest did before the divergence surfaced.
            assert_eq!(envelope["stdout"], "guest-output\n", "{name}: {envelope:#}");
            assert_eq!(
                envelope["verdicts"][0]["label"], "fixed",
                "{name}: {envelope:#}"
            );
            assert_eq!(
                envelope["guest_exit"]["code"], guest_code,
                "{name}: {envelope:#}"
            );
        }
    }

    #[test]
    fn no_verify_reports_each_generation_as_observed() {
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(directory.path(), "address_leak", GUEST);
        let out = directory.path().join("out");
        let (code, envelope) = campaign(&guest, &out, 2, &["--no-verify"], "leak-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["UNCLASSIFIED"], 2, "{envelope:#}");
        assert!(
            envelope["classes"].get("NONDETERMINISM").is_none(),
            "{envelope:#}"
        );
        assert!(
            signatures(&envelope)
                .iter()
                .all(|record| record.get("verification").is_none()),
            "{envelope:#}"
        );
        assert_eq!(envelope["verification"]["state"], "off");
        // The opt-out is campaign shape: recorded, so a continuation keeps it.
        let state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("campaign-state.json")).unwrap())
                .unwrap();
        assert_eq!(state["spec"]["verify"], false);
    }
}
