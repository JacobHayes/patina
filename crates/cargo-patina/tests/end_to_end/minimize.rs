//! Schedule and campaign-generation minimization through replay oracles.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Schedule reduction end to end: record a three-task run whose failure depends
    // on the interleaving (task b runs before task a completes), then minimize it
    // with a replay oracle. The oracle accepts a candidate only when the replayed
    // program itself exits with the failure's exact code and marker, so a candidate
    // whose rewritten schedule merely breaks replay is rejected rather than
    // mistaken for the failure. The minimized trace must still replay to the same
    // failure with no more context switches than the original.
    #[cfg(unix)]
    #[test]
    fn minimize_canonicalizes_a_recorded_schedule_via_replay_oracle() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("fixture");
        create_schedule_fixture(&fixture);

        let trace = directory.path().join("sched.patina");
        let mut original = None;
        for seed in 0..32u64 {
            let seed_string = seed.to_string();
            let recorded = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                &fixture,
                &[
                    "run",
                    "--seed",
                    &seed_string,
                    "--record",
                    trace.to_str().unwrap(),
                ],
            );
            if recorded.status.code() == Some(3) {
                original = Some(schedule_line(&recorded));
                break;
            }
        }
        let original = original.expect("no seed in 0..32 interleaved b before a completed");
        assert!(original.contains("interleaved=true"));
        let original_switches = switch_count(&original);

        let oracle = directory.path().join("oracle.sh");
        fs::write(
        &oracle,
        format!(
            "#!/bin/sh\nout=$(\"{}\" replay \"{}\" \"$PATINA_MINIMIZE_TRACE\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 3 ] && printf '%s' \"$out\" | grep -q 'interleaved=true'; then\n  exit 1\nfi\nexit 0\n",
            env!("CARGO_BIN_EXE_cargo-patina"),
            fixture.to_str().unwrap(),
        ),
    )
    .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let minimized_path = directory.path().join("sched-min.patina");
        let minimized = invoke(
            &fixture,
            &[
                "minimize",
                trace.to_str().unwrap(),
                "--output",
                minimized_path.to_str().unwrap(),
                "--",
                oracle.to_str().unwrap(),
            ],
        );
        assert!(
            String::from_utf8_lossy(&minimized.stdout).contains("PATINA_MINIMIZE_COMPLETE"),
            "missing completion line:\n{}",
            String::from_utf8_lossy(&minimized.stdout)
        );

        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &["replay", ".", minimized_path.to_str().unwrap()],
        );
        assert_eq!(
            replayed.status.code(),
            Some(3),
            "minimized trace no longer reproduces the failure:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&replayed.stderr)
        );
        let reduced = schedule_line(&replayed);
        assert!(reduced.contains("interleaved=true"));
        assert!(
            switch_count(&reduced) <= original_switches,
            "schedule reduction increased context switches: {original} -> {reduced}"
        );
    }

    /// A guest that fails only on a SHORT WRITE. Every other fault the campaign
    /// draws — I/O errors, latency, the whole network and entropy surface — is
    /// handled or irrelevant here, so a campaign generation that catches this bug
    /// carries one knob that matters and a dozen that do not, which is exactly the
    /// haystack `minimize --generation` exists to reduce.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SHORT_WRITE_SOURCE: &str = r#"
use std::fs::OpenOptions;
use std::io::Write;

fn main() {
    let mut file = match OpenOptions::new().write(true).create(true).truncate(true).open("/log") {
        Ok(file) => file,
        Err(error) => { println!("GUEST_OPEN_FAILED {error}"); return; }
    };
    for round in 0..8u32 {
        match file.write(&[b'x'; 64]) {
            Ok(64) => {}
            Ok(short) => {
                eprintln!("GUEST_TORN round={round} wrote={short} of 64");
                std::process::exit(3);
            }
            Ok(_) => unreachable!(),
            Err(error) => { println!("GUEST_WRITE_ERROR {error}"); return; }
        }
    }
    println!("GUEST_OK");
}
"#;

    /// The same planted short-write bug, announced through the VERDICT ABI instead
    /// of printed.
    ///
    /// The guest calls `patina_verdict` directly rather than through the SDK, both
    /// because a single-source guest links no crates and because it is the surface a
    /// non-Rust guest would use. It prints nothing a marker could match on the
    /// failing path, so a `minimize --generation` that reduces this campaign can
    /// only have derived its target from the recorded verdicts.
    ///
    /// The `pass` verdict on the way in is load-bearing for the test: the catching
    /// generation reports BOTH a pass and a violation, and the auto-derived target
    /// must contain only the violation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SHORT_WRITE_VERDICT_SOURCE: &str = r#"
use std::fs::OpenOptions;
use std::io::Write;

unsafe extern "C" {
    fn patina_verdict(
        kind: u32,
        label: *const u8,
        label_len: usize,
        detail: *const u8,
        detail_len: usize,
    ) -> i32;
}

const VIOLATION: u32 = 1;
const PASS: u32 = 2;

fn verdict(kind: u32, label: &str, detail: &str) {
    unsafe {
        patina_verdict(kind, label.as_ptr(), label.len(), detail.as_ptr(), detail.len());
    }
}

fn main() {
    let mut file = match OpenOptions::new().write(true).create(true).truncate(true).open("/log") {
        Ok(file) => file,
        Err(error) => { println!("GUEST_OPEN_FAILED {error}"); return; }
    };
    verdict(PASS, "log-opened", "");
    for round in 0..8u32 {
        match file.write(&[b'x'; 64]) {
            Ok(64) => {}
            Ok(short) => {
                verdict(VIOLATION, "torn-write", &format!("round={round} wrote={short}"));
                std::process::exit(3);
            }
            Ok(_) => unreachable!(),
            Err(error) => { println!("GUEST_WRITE_ERROR {error}"); return; }
        }
    }
    verdict(PASS, "write-loop-complete", "");
    println!("GUEST_OK");
}
"#;

    /// `minimize --generation` with NO `--marker`: the campaign recognized the
    /// generation through the verdict ABI, so the reducer targets what it recognized
    /// (outcome-channel arc §4.5).
    ///
    /// The guest prints nothing on the failing path, so there is no text a marker
    /// could have matched — the reduction can only work if the target came from the
    /// recorded verdicts. Three things are asserted beyond "it ran": the target
    /// carries the violation and NOT the pass verdict the same generation reported,
    /// the fault vector actually shrank to the knob that matters, and two runs of
    /// the same reduction agree byte for byte.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn minimize_generation_targets_the_campaigns_own_verdicts_without_a_marker() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let source = directory.path().join("short_write_verdict.rs");
        fs::write(&source, SHORT_WRITE_VERDICT_SOURCE).unwrap();
        let guest = directory.path().join("verdict-guest");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
                "--release",
            ],
        );

        let out = directory.path().join("camp");
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "24",
                "--faults",
                "--timeout-secs",
                "30",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );

        // The catching generation is read straight off the recorded state: the
        // campaign persists each notable run's verdicts, which is what makes the
        // auto-target possible at all. No replay, no grep.
        let state = campaign_state_without_invocations(&out.join("campaign-state.json"));
        let caught = state["notable_runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| {
                run["verdicts"].as_array().is_some_and(|verdicts| {
                    verdicts.iter().any(|verdict| {
                        verdict["kind"] == "violation" && verdict["label"] == "torn-write"
                    })
                })
            })
            .unwrap_or_else(|| {
                panic!(
                    "no generation recorded a torn-write violation verdict in 24 generations:\n{}",
                    serde_json::to_string_pretty(&state["notable_runs"]).unwrap()
                )
            });
        assert_eq!(
            caught["class"], "VIOLATION",
            "a generation with a violation verdict must classify VIOLATION"
        );
        let generation = caught["generation"].as_u64().unwrap().to_string();
        let flag_tokens = caught["flags"].as_array().unwrap().len();
        assert!(
            flag_tokens > 4,
            "the campaign drew only {flag_tokens} flag tokens, so there is no vector to reduce"
        );

        let minimize = |output: &Path| -> Output {
            invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "minimize",
                    "--generation",
                    &generation,
                    "--out-dir",
                    out.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                    "--jobs",
                    "1",
                ],
            )
        };

        let first_output = directory.path().join("first.patina");
        let first = minimize(&first_output);
        let stdout = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            first.status.success(),
            "minimize --generation with no --marker failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let line = stdout
            .lines()
            .find(|line| line.starts_with("PATINA_MINIMIZE_GENERATION_COMPLETE"))
            .expect("missing the generation completion line")
            .to_owned();

        // The target is the generation's failure verdict, and only that: the `pass`
        // the same run reported is not something a reduction should preserve.
        assert!(
            line.contains("target=verdicts[violation:torn-write]"),
            "the target was not auto-derived from the recorded verdicts: {line}"
        );
        assert!(
            !line.contains("pass:"),
            "a `pass` verdict must not enter the target: {line}"
        );

        let field = |name: &str| -> u64 {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix(name))
                .unwrap_or_else(|| panic!("{line} has no {name}"))
                .parse()
                .unwrap()
        };
        let (before, after) = (field("knobs_before="), field("knobs_after="));
        assert!(
            after < before,
            "nothing was reduced: {before} knobs in, {after} out\n{line}"
        );

        let repro =
            fs::read_to_string(out.join(format!("minimized/generation-{generation}.repro")))
                .expect("the reproduction command must be written into the out-dir");
        assert!(
            repro.contains("--fs-short-permille"),
            "the reduced command dropped the knob the bug needs: {repro}"
        );

        // Determinism: the same generation reduced twice is the same reduction. Both
        // the reported counts and the trace bytes have to agree — a target derived
        // from recorded data cannot be allowed to drift between runs.
        let second_output = directory.path().join("second.patina");
        let second = minimize(&second_output);
        assert!(
            second.status.success(),
            "the second minimize run failed:\n{}",
            String::from_utf8_lossy(&second.stderr)
        );
        let second_line = String::from_utf8_lossy(&second.stdout)
            .lines()
            .find(|line| line.starts_with("PATINA_MINIMIZE_GENERATION_COMPLETE"))
            .expect("missing the generation completion line")
            .to_owned();
        assert_eq!(
            line.replace(first_output.to_str().unwrap(), "OUT"),
            second_line.replace(second_output.to_str().unwrap(), "OUT"),
            "two reductions of the same generation disagreed"
        );
        assert_eq!(
            fs::read(&first_output).unwrap(),
            fs::read(&second_output).unwrap(),
            "two reductions of the same generation produced different traces"
        );
    }

    /// `minimize --generation` end to end: a campaign catches the planted
    /// short-write bug under a wide fault vector, and the reducer must strip that
    /// vector down to the knob that matters, hand back a standalone command that
    /// still fails, and produce the same answer however many candidates it
    /// evaluates at once.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn minimize_generation_reduces_the_fault_vector_to_the_knob_that_matters() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let source = directory.path().join("short_write.rs");
        fs::write(&source, SHORT_WRITE_SOURCE).unwrap();
        let guest = directory.path().join("short-write-guest");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                guest.to_str().unwrap(),
                "--release",
            ],
        );

        let out = directory.path().join("camp");
        let campaign = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "24",
                "--faults",
                "--timeout-secs",
                "30",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        assert_eq!(
            campaign.status.code(),
            Some(1),
            "campaign found no failure to reduce:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&campaign.stdout),
            String::from_utf8_lossy(&campaign.stderr)
        );

        // Pick the first generation whose saved trace really replays to the planted
        // marker: the campaign's other failure classes (a drawn crash point, an I/O
        // error path) are different bugs and are not what this test reduces.
        let state = campaign_state_without_invocations(&out.join("campaign-state.json"));
        let mut caught = None;
        for run in state["notable_runs"].as_array().unwrap() {
            let generation = run["generation"].as_u64().unwrap();
            let trace = out.join(format!("failures/generation-{generation}.patina"));
            if !trace.exists() {
                continue;
            }
            let replayed = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &["replay", guest.to_str().unwrap(), trace.to_str().unwrap()],
            );
            if String::from_utf8_lossy(&replayed.stderr).contains("GUEST_TORN") {
                caught = Some((generation, run["flags"].as_array().unwrap().len()));
                break;
            }
        }
        let (generation, flag_tokens) = caught.expect(
        "no generation reproduced GUEST_TORN; the short-write band never fired in 24 generations",
    );
        assert!(
            flag_tokens > 4,
            "the campaign drew only {flag_tokens} flag tokens, so there is no vector to reduce"
        );

        let generation = generation.to_string();
        let minimize = |output: &Path, extra: &[&str]| -> Output {
            let mut arguments = vec![
                "minimize",
                "--generation",
                &generation,
                "--out-dir",
                out.to_str().unwrap(),
                "--marker",
                "GUEST_TORN",
                "--output",
                output.to_str().unwrap(),
            ];
            arguments.extend_from_slice(extra);
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &arguments)
        };

        let serial_output = directory.path().join("serial.patina");
        let serial = minimize(&serial_output, &["--jobs", "1"]);
        let stdout = String::from_utf8_lossy(&serial.stdout).into_owned();
        assert!(
            serial.status.success(),
            "minimize --generation failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&serial.stderr)
        );
        let line = stdout
            .lines()
            .find(|line| line.starts_with("PATINA_MINIMIZE_GENERATION_COMPLETE"))
            .expect("missing the generation completion line");
        let field = |name: &str| -> u64 {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix(name))
                .unwrap_or_else(|| panic!("{line} has no {name}"))
                .parse()
                .unwrap()
        };
        let (before, after) = (field("knobs_before="), field("knobs_after="));
        assert!(
            after < before,
            "nothing was reduced: {before} knobs in, {after} out\n{line}"
        );

        // The reduction's real output is the standalone command, so run it: it must
        // still fail with the marker on a machine that has no campaign out-dir.
        let repro =
            fs::read_to_string(out.join(format!("minimized/generation-{generation}.repro")))
                .expect("the reproduction command must be written into the out-dir");
        let tokens: Vec<&str> = repro.split_whitespace().collect();
        assert_eq!(
            &tokens[..2],
            &["cargo", "patina"],
            "unexpected repro: {repro}"
        );
        assert!(
            tokens.contains(&"--fs-short-permille"),
            "the reduced command dropped the knob the bug needs: {repro}"
        );
        let reproduced =
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &tokens[2..]);
        assert!(
            String::from_utf8_lossy(&reproduced.stderr).contains("GUEST_TORN"),
            "the reduced command no longer reproduces:\n{repro}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&reproduced.stdout),
            String::from_utf8_lossy(&reproduced.stderr)
        );

        // Parallel candidate evaluation is throughput, not a different search: the
        // reduced trace must be byte-identical to the serial one.
        let parallel_output = directory.path().join("parallel.patina");
        let parallel = minimize(&parallel_output, &["--jobs", "8"]);
        assert!(
            parallel.status.success(),
            "minimize --jobs 8 failed:\n{}",
            String::from_utf8_lossy(&parallel.stderr)
        );
        assert_eq!(
            fs::read(&serial_output).unwrap(),
            fs::read(&parallel_output).unwrap(),
            "--jobs 8 produced a different reduced trace than --jobs 1"
        );

        // Non-vacuity: the marker is what decides every verdict, so a marker the
        // generation never prints must be refused rather than "reduced" to nothing.
        let wrong = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "minimize",
                "--generation",
                &generation,
                "--out-dir",
                out.to_str().unwrap(),
                "--marker",
                "NO_SUCH_MARKER_ANYWHERE",
                "--output",
                directory.path().join("wrong.patina").to_str().unwrap(),
            ],
        );
        assert!(!wrong.status.success(), "a wrong marker was accepted");
        assert!(
            String::from_utf8_lossy(&wrong.stderr).contains("does not reproduce"),
            "a wrong marker was not refused by name:\n{}",
            String::from_utf8_lossy(&wrong.stderr)
        );

        // This guest only PRINTS its failure — it reports nothing through the verdict
        // ABI — so there is no target to auto-derive. Dropping --marker must refuse
        // and name both ways forward, never fall back to reducing against a guess.
        let no_target = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "minimize",
                "--generation",
                &generation,
                "--out-dir",
                out.to_str().unwrap(),
                "--output",
                directory.path().join("no-target.patina").to_str().unwrap(),
            ],
        );
        let refusal = String::from_utf8_lossy(&no_target.stderr).into_owned();
        assert!(
            !no_target.status.success(),
            "a generation with no verdicts was minimized without a target"
        );
        assert!(
            refusal.contains("no failure verdict to target")
                && refusal.contains("patina_dst::verdict")
                && refusal.contains("--marker"),
            "the refusal must name both ways forward:\n{refusal}"
        );
    }

    #[cfg(unix)]
    fn schedule_line(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("PATINA_SCHED_RESULT"))
            .unwrap_or_else(|| {
                panic!(
                    "missing PATINA_SCHED_RESULT in stdout:\n{}",
                    String::from_utf8_lossy(&output.stdout)
                )
            })
            .to_owned()
    }

    #[cfg(unix)]
    fn switch_count(line: &str) -> u64 {
        line.split("switches=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing switches= in {line}"))
    }

    // A fixture that drives the explicit scheduler API: three tasks of four rounds
    // each, selected by recorded `SchedulerNext` decisions. The schedule-dependent
    // failure — task b selected before task a has completed — exits the process
    // with code 3 so a replay oracle can demand the exact failure rather than any
    // nonzero exit.
    #[cfg(unix)]
    fn create_schedule_fixture(path: &Path) {
        fs::create_dir_all(path.join("src")).unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let runtime_path = workspace.join("crates/patina-runtime");
        let runtime_path = runtime_path.to_string_lossy().replace('\\', "\\\\");
        fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-sched-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-runtime = {{ path = \"{runtime_path}\" }}\n"
        ),
    )
    .unwrap();
        fs::write(
        path.join("src/main.rs"),
        r#"use std::collections::BTreeMap;

use patina_dst_runtime::RuntimeError;

fn scenario() -> Result<(String, bool), RuntimeError> {
    patina_dst_runtime::run(|context| {
        let a = context.task_spawn("a")?;
        let b = context.task_spawn("b")?;
        let c = context.task_spawn("c")?;
        let mut remaining = BTreeMap::from([(a, 4_u32), (b, 4), (c, 4)]);
        let mut order = Vec::new();
        let mut interleaved = false;
        while let Some(task) = context.scheduler_next()? {
            order.push(task.0);
            if task == b && remaining.contains_key(&a) {
                interleaved = true;
            }
            let rounds = remaining.get_mut(&task).expect("selected task is live");
            *rounds -= 1;
            if *rounds == 0 {
                remaining.remove(&task);
                context.task_complete(task)?;
            } else {
                context.task_yield(task)?;
            }
        }
        let switches = order.windows(2).filter(|pair| pair[0] != pair[1]).count();
        let line = format!(
            "PATINA_SCHED_RESULT seed={} order={order:?} switches={switches} interleaved={interleaved}",
            context.root_seed()
        );
        Ok((line, interleaved))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (line, interleaved) = scenario()?;
    println!("{line}");
    if interleaved {
        std::process::exit(3);
    }
    Ok(())
}
"#,
    )
    .unwrap();
    }
}
