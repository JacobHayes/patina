//! Campaign outcome detection, swarm coherence, and non-vacuity.

#[cfg(test)]
mod tests {
    use super::super::*;

    fn sometimes_gate_wat(label: &str, satisfied: bool) -> Vec<u8> {
        let bit = if satisfied { 1 } else { 0 };
        let wat = format!(
            r#"(module
    (import "patina_sdk" "sometimes"
        (func $sometimes (param i32 i32 i32 i32 i32) (result i32)))
    (import "patina_sdk" "lifecycle_setup_complete" (func $setup (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 0) "{label}")
    (data (i32.const 32) "wat:sometimes")
    (func (export "_start")
        (drop (call $setup))
        (drop (call $sometimes (i32.const {bit})
            (i32.const 0) (i32.const {label_len}) (i32.const 32) (i32.const 13)))))"#,
            label_len = label.len()
        );
        wat::parse_str(&wat).unwrap()
    }

    #[test]
    fn campaign_sometimes_gate_fails_unmet_accepts_met_and_waives_threshold() {
        let directory = tempdir().unwrap();
        let unmet = directory.path().join("never-green.wasm");
        let met = directory.path().join("met.wasm");
        fs::write(&unmet, sometimes_gate_wat("never-green", false)).unwrap();
        fs::write(&met, sometimes_gate_wat("met-green", true)).unwrap();

        let run = |module: &Path, out: &Path, extra: &[&str], inherited_report: Option<&str>| {
            let mut args = vec![
                "campaign".to_string(),
                module.to_str().unwrap().to_string(),
                "--gens".to_string(),
                "5".to_string(),
                "--progress-every".to_string(),
                "1".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ];
            args.extend(extra.iter().map(|arg| arg.to_string()));
            let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
            command.current_dir(native_workspace()).args(&args);
            if let Some(value) = inherited_report {
                command.env("PATINA_SDK_REPORT", value);
            }
            command.output().unwrap()
        };

        let unmet_out = directory.path().join("unmet");
        let unmet_run = run(&unmet, &unmet_out, &[], Some("0"));
        let unmet_stdout = String::from_utf8_lossy(&unmet_run.stdout);
        assert_eq!(
            unmet_run.status.code(),
            Some(1),
            "never-satisfied sometimes! must fail the campaign even when PATINA_SDK_REPORT=0 is inherited\nstdout:\n{unmet_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&unmet_run.stderr)
        );
        assert!(
            unmet_stdout.contains("UNMET sometimes 'never-green'")
                && unmet_stdout.contains(
                    "PATINA_CAMPAIGN_COVERAGE oracle_sites=1 satisfied=0 unmet=1 gate=fail"
                ),
            "unmet campaign did not surface the coverage gate:\n{unmet_stdout}"
        );
        let unmet_sites: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(unmet_out.join("sites.json")).unwrap())
                .unwrap();
        assert_eq!(unmet_sites["schema"], "patina.campaign.sites/v1");
        assert_eq!(unmet_sites["generations_observed"], 5);
        assert_eq!(unmet_sites["sites"][0]["label"], "never-green");
        assert_eq!(unmet_sites["sites"][0]["registered_gens"], 5);
        assert_eq!(unmet_sites["sites"][0]["satisfied_gens"], 0);

        let met_out = directory.path().join("met");
        let met_run = run(&met, &met_out, &[], None);
        let met_stdout = String::from_utf8_lossy(&met_run.stdout);
        assert!(
            met_run.status.success(),
            "satisfied sometimes! campaign should stay green\nstdout:\n{met_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&met_run.stderr)
        );
        assert!(
            met_stdout
                .contains("PATINA_CAMPAIGN_COVERAGE oracle_sites=1 satisfied=1 unmet=0 gate=pass"),
            "met campaign did not report a passing coverage gate:\n{met_stdout}"
        );

        let waived_out = directory.path().join("waived");
        let waived_run = run(&unmet, &waived_out, &["--allow-unmet-sometimes=10"], None);
        let waived_stdout = String::from_utf8_lossy(&waived_run.stdout);
        assert!(
            waived_run.status.success()
                && waived_stdout.contains("gate=waived")
                && waived_stdout.contains("UNMET sometimes 'never-green'"),
            "threshold waiver below MIN_GENS should report but not fail:\nstdout:\n{waived_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&waived_run.stderr)
        );

        let enforced_out = directory.path().join("enforced");
        let enforced_run = run(&unmet, &enforced_out, &["--allow-unmet-sometimes=5"], None);
        assert_eq!(
            enforced_run.status.code(),
            Some(1),
            "threshold waiver must enforce at observed generations >= MIN_GENS\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&enforced_run.stdout),
            String::from_utf8_lossy(&enforced_run.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // End-to-end coverage for `cargo patina campaign` + the liveness watchdog: build
    // the buggify-driven planted-bug guest (`testbeds/liveness-campaign`), sweep it,
    // and prove the campaign catches the planted liveness violation, deduplicates the
    // signature across the generations that fire it, records a working reproduce
    // command, and produces byte-identical outcomes/signatures on a deterministic
    // re-run. Native (single-threaded guest), so it does not touch the known
    // main-thread TLS-teardown race.
    #[test]
    fn campaign_catches_planted_liveness_bug_dedups_and_reproduces() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = directory.path().join("liveness-guest");

        // Build the planted-bug guest once; the campaign sweeps this same binary.
        build_liveness_guest(&guest);

        let out = directory.path().join("camp");
        let campaign_args = |out: &Path| {
            vec![
                "campaign".to_string(),
                guest.to_str().unwrap().to_string(),
                "--gens".to_string(),
                "12".to_string(),
                // Restore the full per-generation stream: this test asserts on the
                // per-generation OK/LIVENESS lines and their determinism, which the
                // summary-first default (novel/failing + periodic heartbeat) elides.
                "--progress-every".to_string(),
                "1".to_string(),
                "--buggify".to_string(),
                "--liveness-watchdog".to_string(),
                "600000000000".to_string(),
                "--out-dir".to_string(),
                out.to_str().unwrap().to_string(),
            ]
        };
        let owned1 = campaign_args(&out);
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &owned1.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let stdout = String::from_utf8_lossy(&ran.stdout);
        // A campaign with failures exits nonzero.
        assert_eq!(
            ran.status.code(),
            Some(1),
            "campaign should report failures (exit 1)\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        // A genuine mix: the planted bug fires on some generations and not others.
        let liveness_gens = stdout.matches("class=LIVENESS").count();
        let ok_gens = stdout.matches("class=OK").count();
        assert!(
            liveness_gens >= 1 && ok_gens >= 1,
            "expected a mix of LIVENESS and OK generations, got liveness={liveness_gens} ok={ok_gens}\n{stdout}"
        );

        // The signature store deduplicates the planted liveness bug into ONE signature
        // whose count equals the number of generations that fired it, and flags it as
        // first seen exactly once (NOVEL appears once).
        assert_eq!(
            stdout.matches("NOVEL").count(),
            1,
            "the single planted bug must produce exactly one NOVEL signature\n{stdout}"
        );
        let store: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("signatures.json")).unwrap())
                .unwrap();
        let signatures = store["signatures"].as_array().unwrap();
        assert_eq!(
            signatures.len(),
            1,
            "expected exactly one deduplicated signature: {store:#}"
        );
        let signature = &signatures[0];
        assert_eq!(signature["class"], "LIVENESS");
        assert_eq!(
            signature["count"].as_u64().unwrap() as usize,
            liveness_gens,
            "signature count must equal the number of LIVENESS generations"
        );
        let state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("campaign-state.json")).unwrap())
                .unwrap();
        assert_eq!(state["schema"], "patina.campaign.state/v2");
        assert_eq!(state["generations_done"], 12);
        assert_eq!(state["artifact"]["path"], guest.to_str().unwrap());
        assert!(state["artifact"]["sha256"].as_str().unwrap().len() == 64);
        assert_eq!(state["signatures"], store["signatures"]);
        assert_eq!(state["invocations"].as_array().unwrap().len(), 1);

        // The recorded reproduce command deterministically re-triggers the violation.
        let reproduce = signature["reproduce"].as_str().unwrap();
        let repro_args: Vec<&str> = reproduce
            .strip_prefix("cargo patina ")
            .unwrap()
            .split(' ')
            .collect();
        let reproduced =
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &repro_args);
        assert!(
            !reproduced.status.success()
                && String::from_utf8_lossy(&reproduced.stderr)
                    .contains("PATINA_VIOLATION liveness "),
            "reproduce command did not re-trigger the liveness violation: {reproduce}\nstderr:\n{}",
            String::from_utf8_lossy(&reproduced.stderr)
        );

        // Determinism: a re-run with the same spec yields byte-identical per-generation
        // outcomes and an identical signature store.
        let out2 = directory.path().join("camp2");
        let owned2 = campaign_args(&out2);
        let ran2 = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &owned2.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(
            campaign_gen_lines(&stdout),
            campaign_gen_lines(&String::from_utf8_lossy(&ran2.stdout)),
            "a deterministic re-run must produce identical per-generation outcomes"
        );
        assert_eq!(
            fs::read_to_string(out.join("signatures.json")).unwrap(),
            fs::read_to_string(out2.join("signatures.json")).unwrap(),
            "a deterministic re-run must produce an identical signature store"
        );
        assert_eq!(
            fs::read_to_string(out.join("sites.json")).unwrap(),
            fs::read_to_string(out2.join("sites.json")).unwrap(),
            "a deterministic re-run must produce an identical sites.json store"
        );
        assert_eq!(
            campaign_state_without_invocations(&out.join("campaign-state.json")),
            campaign_state_without_invocations(&out2.join("campaign-state.json")),
            "a deterministic re-run must produce identical persisted state except audit invocations"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // Swarm fault-class deselection stays coherent end to end (SlateDB feedback item
    // 9). `--swarm` applies a seed-derived subset of the enabled classes, so some
    // generations run WITHOUT buggify even though the operator asked for it. That
    // masked state used to keep `+buggify` in the run fingerprint while disarming
    // buggify, which the coherence guard then refused — a legitimate generation died
    // with "fingerprint declares +buggify but buggify is not enabled".
    //
    // This proves the three things the fix owes:
    //   1. a masked generation RUNS, and its trace declares the effective state
    //      (no `+buggify`, no buggify config, swarm names it a dropped candidate);
    //   2. a masked generation is DISTINGUISHABLE from "buggify was never requested"
    //      — the ambiguity that sent the original bug report after the wrong cause;
    //   3. an unmasked swarm generation still carries `+buggify`, and genuine
    //      incoherence (declaring `+buggify` with no buggify at all) still refuses.
    #[test]
    fn swarm_deselection_stays_coherent_with_fingerprint_and_metadata() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = directory.path().join("swarm-guest");
        build_liveness_guest(&guest);

        // Find one generation that drops buggify and one that keeps it by reading
        // each run's own PATINA_SWARM_REPORT rather than re-deriving the mask here. A
        // wedged generation (the fixture's planted liveness bug) is skipped: this
        // test is about configuration coherence, not the planted bug.
        let mut dropped: Option<(u64, std::path::PathBuf, String)> = None;
        let mut kept: Option<(u64, std::path::PathBuf, String)> = None;
        for seed in 0..24u64 {
            if dropped.is_some() && kept.is_some() {
                break;
            }
            let trace = directory.path().join(format!("swarm-{seed}.patina"));
            let ran = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "run",
                    guest.to_str().unwrap(),
                    "--seed",
                    &seed.to_string(),
                    "--swarm",
                    "--buggify=372",
                    "--record",
                    trace.to_str().unwrap(),
                ],
            );
            let stderr = String::from_utf8_lossy(&ran.stderr).to_string();
            if !ran.status.success() {
                assert!(
                    !stderr.contains("fingerprint declares +buggify"),
                    "seed {seed}: a swarm-masked generation must not abort on the \
                 buggify coherence guard\nstderr:\n{stderr}"
                );
                continue;
            }
            let swarm_line = stderr
                .lines()
                .find(|line| line.starts_with("PATINA_SWARM_REPORT "))
                .unwrap_or_else(|| panic!("seed {seed}: no swarm report\nstderr:\n{stderr}"))
                .to_string();
            if swarm_line.contains("class=buggify|0") {
                dropped.get_or_insert((seed, trace, stderr));
            } else if swarm_line.contains("class=buggify|1") {
                kept.get_or_insert((seed, trace, stderr));
            }
        }
        let (dropped_seed, dropped_trace, dropped_stderr) =
            dropped.expect("no seed in 0..24 deselected buggify");
        let (_kept_seed, kept_trace, kept_stderr) =
            kept.expect("no seed in 0..24 selected buggify");

        // (1) The masked run's trace declares the effective configuration.
        let info = invoke(
            workspace,
            &["trace", "info", dropped_trace.to_str().unwrap()],
        );
        let info = String::from_utf8_lossy(&info.stdout).to_string();
        assert!(
            info.contains("fingerprint: patina-native+swarm"),
            "a masked run must not declare +buggify:\n{info}"
        );
        assert!(
            !info.contains("\nbuggify:"),
            "a masked run must record no buggify config:\n{info}"
        );
        assert!(
            info.contains("swarm: candidates=buggify selected=(none) deselected=buggify"),
            "the trace must name buggify as a dropped candidate:\n{info}"
        );

        // (2) Distinguishable from "never requested". Both report `enabled=0`; only
        // the masked one reports `swarm_deselected=1`.
        assert!(
            dropped_stderr.contains("PATINA_SDK_REPORT enabled=0 swarm_deselected=1"),
            "a masked run must report swarm_deselected=1\nstderr:\n{dropped_stderr}"
        );
        let never_asked = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                &dropped_seed.to_string(),
            ],
        );
        let never_asked = String::from_utf8_lossy(&never_asked.stderr).to_string();
        assert!(
            never_asked.contains("PATINA_SDK_REPORT enabled=0 swarm_deselected=0"),
            "a run that never asked for buggify must report swarm_deselected=0\nstderr:\n{never_asked}"
        );

        // Replay of the masked trace reproduces the run: the fingerprint check holds
        // in both directions (the replay recomputes `+swarm` without `+buggify` from
        // the metadata), and the diagnostics are identical to the recording's.
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                guest.to_str().unwrap(),
                dropped_trace.to_str().unwrap(),
            ],
        );
        assert!(
            replayed.status.success(),
            "replaying a swarm-masked trace failed:\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        let replayed = String::from_utf8_lossy(&replayed.stderr).to_string();
        let reports = |stderr: &str| -> Vec<String> {
            stderr
                .lines()
                .filter(|line| {
                    line.starts_with("PATINA_SWARM_REPORT ")
                        || line.starts_with("PATINA_SDK_REPORT ")
                })
                .map(str::to_string)
                .collect()
        };
        assert_eq!(
            reports(&dropped_stderr),
            reports(&replayed),
            "record and replay of a masked run must report the same swarm/SDK state"
        );

        // (3) An unmasked swarm generation is untouched: `+buggify` and the buggify
        // config both stand.
        assert!(
            kept_stderr.contains("PATINA_SDK_REPORT enabled=1 swarm_deselected=0"),
            "an unmasked swarm run must keep buggify armed\nstderr:\n{kept_stderr}"
        );
        let info = invoke(workspace, &["trace", "info", kept_trace.to_str().unwrap()]);
        let info = String::from_utf8_lossy(&info.stdout).to_string();
        assert!(
            info.contains("fingerprint: patina-native+buggify+swarm"),
            "an unmasked swarm run must keep +buggify:\n{info}"
        );
        assert!(
            info.contains("swarm: candidates=buggify selected=buggify deselected=(none)"),
            "the trace must name buggify as selected:\n{info}"
        );

        // Genuine incoherence — a fingerprint declaring `+buggify` on a run that
        // never armed buggify — still fails closed, exactly as before.
        let incoherent = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                "0",
                "--fingerprint",
                "patina-native+buggify",
                "--record",
                directory.path().join("incoherent.patina").to_str().unwrap(),
            ],
        );
        assert!(!incoherent.status.success());
        assert!(
            String::from_utf8_lossy(&incoherent.stderr)
                .contains("fingerprint declares +buggify but buggify is not enabled"),
            "the coherence guard must still refuse genuine incoherence:\nstderr:\n{}",
            String::from_utf8_lossy(&incoherent.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // A `--buggify --swarm` campaign is the shape that made item 9 look like a broken
    // flag: the campaign emits both flags on every generation, so each generation
    // whose seed dropped buggify aborted on the coherence guard. Before the fix an
    // eight generation sweep of the planted-bug fixture reported FAIL_CLOSED_ABORT on
    // six of them; it must now report only the planted liveness bug.
    #[test]
    fn campaign_with_swarm_and_buggify_has_no_coherence_aborts() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = directory.path().join("swarm-campaign-guest");
        build_liveness_guest(&guest);

        let out = directory.path().join("camp");
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "12",
                "--buggify",
                "--swarm",
                "--liveness-watchdog",
                "600000000000",
                "--progress-every",
                "1",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        let stdout = String::from_utf8_lossy(&ran.stdout).to_string();
        assert!(
            !stdout.contains("FAIL_CLOSED_ABORT"),
            "a swarm+buggify campaign must not abort on configuration incoherence\n{stdout}"
        );
        // The sweep still does its job: it finds the planted liveness bug and has
        // clean generations too, so "no aborts" is not "nothing ran".
        assert!(
            stdout.contains("class=LIVENESS") && stdout.contains("class=OK"),
            "the sweep must still find the planted bug and have clean generations\n{stdout}"
        );

        // Non-vacuous: the sweep really did drop buggify on some of its generations
        // and keep it on others, so the coherence path was exercised both ways. The
        // swarm draw is a function of the run seed alone, so replaying the campaign's
        // own generation seeds reports the same decision each generation made.
        let mut dropped = 0usize;
        let mut kept = 0usize;
        for line in stdout.lines() {
            let Some(seed) = line.strip_prefix("PATINA_CAMPAIGN_GEN ").and_then(|rest| {
                rest.split_whitespace()
                    .find_map(|f| f.strip_prefix("seed="))
            }) else {
                continue;
            };
            let ran = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "run",
                    guest.to_str().unwrap(),
                    "--seed",
                    seed,
                    "--swarm",
                    "--buggify=372",
                    // `run` takes the optional-value form with `=`; the space form is
                    // a usage error, which would silently make this check vacuous.
                    "--liveness-watchdog=600000000000",
                ],
            );
            assert!(
                ran.status.code() != Some(2),
                "seed {seed}: usage error re-running a campaign generation:\n{}",
                String::from_utf8_lossy(&ran.stderr)
            );
            let stderr = String::from_utf8_lossy(&ran.stderr);
            if stderr.contains("class=buggify|0") {
                dropped += 1;
            } else if stderr.contains("class=buggify|1") {
                kept += 1;
            }
        }
        assert!(
            dropped > 0 && kept > 0,
            "the sweep must exercise both swarm outcomes, got dropped={dropped} kept={kept}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // `--swarm` selects a seed-derived SUBSET of the fault classes a run enabled, so
    // a run that enabled none has nothing to select from: the draw keeps and drops
    // nothing, and the generation explores exactly what it would have explored
    // without `--swarm`. That is an inert knob, and an inert knob must not read as
    // coverage. This is the planted zero-candidate fixture for the detector: the
    // runtime reports `vacuous=1` and warns, and the campaign classifies the
    // generation `VACUOUS_SWARM` and fails — while the same guest with one class
    // armed is a clean, non-vacuous swarm run, so the detector is not always-on.
    #[test]
    fn swarm_with_zero_candidate_classes_is_reported_and_classified_vacuous() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let source = directory.path().join("swarm_zero.rs");
        fs::write(
            &source,
            r#"fn main() {
    println!("SWARM_ZERO_OK");
}
"#,
        )
        .unwrap();
        let guest = directory.path().join("swarm-zero");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
            ],
        );

        // (1) The run itself reports the inert draw and warns.
        let inert = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", guest.to_str().unwrap(), "--seed", "1", "--swarm"],
        );
        let stderr = String::from_utf8_lossy(&inert.stderr).to_string();
        assert!(
            inert.status.success(),
            "an inert --swarm warns; it does not fail the run\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("PATINA_SWARM_REPORT candidates=0 selected=0 deselected=0 vacuous=1"),
            "missing the vacuous swarm report\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("PATINA WARNING: swarm fault-class selection inert"),
            "an inert --swarm must warn\nstderr:\n{stderr}"
        );

        // Non-vacuity control: one armed class gives the draw something to choose
        // among, and the same knob on the same guest then reports `vacuous=0`.
        let armed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                guest.to_str().unwrap(),
                "--seed",
                "1",
                "--swarm",
                "--buggify=372",
            ],
        );
        let armed_stderr = String::from_utf8_lossy(&armed.stderr).to_string();
        assert!(
            armed_stderr.contains("PATINA_SWARM_REPORT candidates=1")
                && armed_stderr.contains("vacuous=0"),
            "an armed class must make the swarm draw non-vacuous\nstderr:\n{armed_stderr}"
        );
        assert!(
            !armed_stderr.contains("swarm fault-class selection inert"),
            "a live swarm draw must not warn\nstderr:\n{armed_stderr}"
        );

        // (2) The campaign classifies such a generation and FAILS: a campaign that
        // asked for fault-subset exploration and got none is not a covered clean run.
        let out = directory.path().join("swarm-zero-campaign");
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "2",
                "--swarm",
                "--progress-every",
                "1",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        let stdout = String::from_utf8_lossy(&ran.stdout).to_string();
        assert!(
            stdout.contains("class=VACUOUS_SWARM"),
            "a zero-candidate --swarm generation must be classified\nstdout:\n{stdout}"
        );
        assert!(
            !ran.status.success(),
            "a campaign whose --swarm explored nothing must fail\nstdout:\n{stdout}"
        );
    }
}
