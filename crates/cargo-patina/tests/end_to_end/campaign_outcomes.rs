//! Campaign outcome detection, swarm coherence, and non-vacuity.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// The planted-liveness-bug guest (`testbeds/liveness-campaign`), built once
    /// per run.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn liveness_guest() -> PathBuf {
        super::super::run_facts::shared_guest("liveness-guest", |directory| {
            let guest = directory.join("liveness-guest");
            build_liveness_guest(&guest);
            guest
        })
    }

    /// An SDK guest with one `sometimes!` site, satisfied or never satisfied.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn sometimes_gate_guest(label: &str, satisfied: bool) -> PathBuf {
        let main = format!(
            "fn main() {{\n    patina_dst::lifecycle::setup_complete();\n    patina_dst::sometimes!(std::hint::black_box({satisfied}), \"{label}\");\n}}\n"
        );
        super::super::run_facts::shared_sdk_guest(&format!("sometimes-{label}"), &main)
    }

    /// A declared `always!` no generation evaluates is reported, never gated: the
    /// campaign stays green and the store lists it as unregistered.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_reports_a_never_evaluated_always_without_gating() {
        let main = "fn main() {\n    patina_dst::lifecycle::setup_complete();\n    patina_dst::always!(true, \"evaluated-always\");\n    if std::hint::black_box(false) {\n        patina_dst::always!(true, \"dormant-always\");\n    }\n}\n";
        let guest = super::super::run_facts::shared_sdk_guest("dormant-always", main);
        let directory = tempdir().unwrap();
        let out = directory.path().join("campaign");
        let run = Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .current_dir(native_workspace())
            .args([
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "3",
                "--out-dir",
            ])
            .arg(&out)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success(),
            "an unevaluated always! must not gate\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(
            stdout.contains("UNEVALUATED always 'dormant-always'")
                && !stdout.contains("UNEVALUATED always 'evaluated-always'"),
            "campaign output must name only the dormant always!:\n{stdout}"
        );
        let sites: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("sites.json")).unwrap()).unwrap();
        let registered = |label: &str| {
            sites["sites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|site| site["label"] == label)
                .unwrap_or_else(|| panic!("missing {label}: {sites:#}"))["registered_gens"]
                .as_u64()
                .unwrap()
        };
        assert_eq!(registered("dormant-always"), 0);
        assert!(registered("evaluated-always") > 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_sometimes_gate_fails_unmet_accepts_met_and_waives_threshold() {
        let directory = tempdir().unwrap();
        let unmet = sometimes_gate_guest("never-green", false);
        let met = sometimes_gate_guest("met-green", true);

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
    // End-to-end coverage for `cargo patina campaign` + the liveness watchdog over
    // the buggify-driven planted-bug guest, under `--buggify --swarm`: the campaign
    // catches the planted liveness violation, deduplicates the signature across the
    // generations that fire it, verifies it and records a working reproduce
    // command. Swarm drops buggify on some generations, which must run rather than
    // abort on the fingerprint coherence guard (FAIL_CLOSED_ABORT). Native
    // (single-threaded guest), so it does not touch the known main-thread
    // TLS-teardown race.
    #[test]
    fn campaign_catches_planted_liveness_bug_under_swarm_dedups_and_reproduces() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = liveness_guest();

        let out = directory.path().join("camp");
        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "12",
                // The full per-generation stream: the assertions read the
                // per-generation OK/LIVENESS lines, which the summary-first
                // default (novel/failing + periodic heartbeat) elides.
                "--progress-every",
                "1",
                "--buggify",
                "--swarm",
                "--liveness-watchdog",
                "600000000000",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        let stdout = String::from_utf8_lossy(&ran.stdout).to_string();
        // A campaign with failures exits nonzero.
        assert_eq!(
            ran.status.code(),
            Some(1),
            "campaign should report failures (exit 1)\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(
            !stdout.contains("FAIL_CLOSED_ABORT"),
            "a swarm+buggify campaign must not abort on configuration incoherence\n{stdout}"
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

        // The campaign ran that traceless failure's seeded re-run itself before
        // reporting it, and it reproduced: the deterministic twin of the
        // planted address leak in `campaign_verify`.
        assert_eq!(signature["verification"]["path"], "rerun", "{signature:#}");
        assert_eq!(
            signature["verification"]["status"], "reproduced",
            "{signature:#}"
        );

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

        // Non-vacuous: the sweep really did drop buggify on some of its generations
        // and keep it on others, so the coherence path was exercised both ways. The
        // swarm draw is a function of the run seed alone, so re-running the
        // campaign's own generation seeds reports the same decision each
        // generation made.
        let (mut dropped, mut kept) = (false, false);
        for line in stdout.lines() {
            if dropped && kept {
                break;
            }
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
            dropped |= stderr.contains("class=buggify|0");
            kept |= stderr.contains("class=buggify|1");
        }
        assert!(
            dropped && kept,
            "the sweep must exercise both swarm outcomes, got dropped={dropped} kept={kept}"
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
    //   3. an unmasked swarm generation still carries `+buggify`.
    //
    // And the other end of the draw: a run that enabled NO class has nothing to
    // select from, so `--swarm` is an inert knob, and an inert knob must not read
    // as coverage. The runtime reports `vacuous=1` and warns, while the armed
    // runs above report `vacuous=0`, so the detector is not always-on; a
    // campaign that enables nothing for swarm to mask is refused up front.
    #[test]
    fn swarm_deselection_stays_coherent_and_an_empty_draw_is_vacuous() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = liveness_guest();

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

        // A live draw is not vacuous and does not warn.
        assert!(
            kept_stderr.contains("PATINA_SWARM_REPORT candidates=1")
                && kept_stderr.contains("vacuous=0")
                && !kept_stderr.contains("swarm fault-class selection inert"),
            "an armed class must make the swarm draw non-vacuous\nstderr:\n{kept_stderr}"
        );
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

        // A campaign that asks for fault-subset exploration with nothing to
        // subset is a usage error, before any generation runs.
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
        assert_eq!(
            ran.status.code(),
            Some(2),
            "a campaign whose --swarm has nothing to mask must be refused\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(!out.exists(), "a refused campaign runs no generation");
    }
}
