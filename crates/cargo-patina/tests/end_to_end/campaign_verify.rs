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

    /// The planted address-leak guest, built once per run.
    fn address_leak() -> PathBuf {
        super::super::run_facts::shared_guest("address-leak", |directory| {
            build_facts_guest(directory, "address_leak", GUEST)
        })
    }

    /// The class pairing of these tests: the campaign unit tests' verification
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
        // A guest without modes (a single-purpose native guest) takes no `--`
        // guest arguments: its mode is "". A moded native guest keeps the host's
        // randomized layout (see the module docs).
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

    /// A novel finding's reproduce path runs once: a failure that reproduces
    /// keeps its class and its repeats are not verified again, a failure whose
    /// replay differs is NONDETERMINISM carrying both outcomes (compared
    /// exactly, so a leak the signature collapses still counts), and
    /// `--no-verify` reports what it observed and records the opt-out.
    #[test]
    fn a_novel_finding_is_verified_once_and_a_leak_is_nondeterminism_with_both_outcomes() {
        let directory = tempdir().unwrap();
        let guest = address_leak();

        let (code, envelope) = campaign(&guest, &directory.path().join("det"), 2, &[], "det-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["UNCLASSIFIED"], 2, "{envelope:#}");
        assert!(
            envelope["classes"].get("NONDETERMINISM").is_none(),
            "{envelope:#}"
        );
        let records = signatures(&envelope);
        assert_eq!(records.len(), 1, "{envelope:#}");
        assert_eq!(records[0]["count"], 2);
        assert_eq!(
            records[0]["verification"]["status"], "reproduced",
            "{envelope:#}"
        );
        // The repeat is not verified again: the cost is one run per novel
        // signature.
        assert_eq!(
            envelope["verification"]["findings"]["verified"], 1,
            "{envelope:#}"
        );

        // The leaked token is all digits, so both runs share one signature:
        // only the exact outcome tells them apart.
        let (code, envelope) = campaign(
            &guest,
            &directory.path().join("leak"),
            1,
            &[],
            "leak-number-exit",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["NONDETERMINISM"], 1, "{envelope:#}");
        assert!(
            envelope["classes"].get("UNCLASSIFIED").is_none(),
            "{envelope:#}"
        );
        let record = &signatures(&envelope)[0];
        assert_eq!(record["class"], "NONDETERMINISM", "{record:#}");
        let verification = &record["verification"];
        assert_eq!(verification["path"], "replay", "{record:#}");
        assert_eq!(verification["status"], "nondeterministic", "{record:#}");
        // Both outcomes travel with the class: what the campaign saw, and what
        // its own reproduce command produced.
        assert_eq!(verification["observed"]["class"], "UNCLASSIFIED");
        assert_eq!(verification["reproduction"]["class"], "UNCLASSIFIED");
        assert_eq!(
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
        assert_eq!(envelope["verification"]["findings"]["nondeterministic"], 1);

        let out = directory.path().join("unverified");
        let (code, envelope) = campaign(&guest, &out, 1, &["--no-verify"], "leak-number-exit");
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["UNCLASSIFIED"], 1, "{envelope:#}");
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

    #[test]
    fn the_clean_rerun_sample_catches_a_leak_on_a_passing_run() {
        let directory = tempdir().unwrap();
        // The campaign seed picks which generation of each stride is sampled;
        // seed base 2 samples generation 1, so two generations hold one
        // sampled generation and one that is not. That one sample per stride
        // is the unit tests' `clean-rerun-sample-is-one-per-stride` check.
        let gens = 2;
        let (code, envelope) = campaign(
            &address_leak(),
            &directory.path().join("leak"),
            gens,
            &["--seed-start", "2"],
            "leak-clean",
        );
        assert_eq!(code, Some(1), "{envelope:#}");
        assert_eq!(envelope["classes"]["NONDETERMINISM"], 1, "{envelope:#}");
        assert_eq!(envelope["classes"]["OK"], gens - 1, "{envelope:#}");
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
    }

    /// Each seed reports its own violation label, so every generation is a
    /// novel finding and is verified: the replayed write carries other bytes,
    /// so the replay diverges after the verdict. `minimize --generation` then refuses the class rather than reduce
    /// the violation verdict a single-run oracle could target.
    #[test]
    fn a_replay_that_diverges_after_its_verdict_is_nondeterminism_minimize_refuses() {
        let directory = tempdir().unwrap();
        let out = directory.path().join("out");
        let (code, envelope) = campaign(&address_leak(), &out, 6, &[], "leak-after-verdict");
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
                "--jobs",
                "1",
            ],
        );
        let stderr = String::from_utf8_lossy(&minimized.stderr);
        assert_eq!(minimized.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains("NONDETERMINISM"), "{stderr}");
        assert!(!output.exists());
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

    /// Guest output cannot move a verification verdict either way: a
    /// deterministic fault whose last guest line is unterminated still
    /// reproduces (patina's marker follows guest output on the same stream), a
    /// guest spelling a divergence in a custom-op label does not forge one, and
    /// a guest line shaped like patina's marker keeps the evidence that the
    /// leak beside it is nondeterministic.
    #[test]
    fn guest_output_cannot_forge_or_hide_a_verification_outcome() {
        let directory = tempdir().unwrap();
        let guest = address_leak();
        for (mode, status) in [
            ("det-segv-unterminated", "reproduced"),
            ("forge-divergence", "reproduced"),
            ("forge-marker", "nondeterministic"),
            ("forge-native-run", "nondeterministic"),
        ] {
            let (code, envelope) = campaign(&guest, &directory.path().join(mode), 1, &[], mode);
            assert_eq!(code, Some(1), "{mode}: {envelope:#}");
            let record = &signatures(&envelope)[0];
            assert_eq!(
                record["verification"]["status"], status,
                "{mode}: {record:#}"
            );
            if status == "reproduced" {
                assert!(
                    envelope["classes"].get("NONDETERMINISM").is_none(),
                    "{mode}: {envelope:#}"
                );
                assert!(
                    record["verification"]["reproduction"]
                        .get("replay_diverged")
                        .is_none(),
                    "{mode}: {record:#}"
                );
            }
        }
    }
}
