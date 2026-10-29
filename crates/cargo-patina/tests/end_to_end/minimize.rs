//! Campaign-generation minimization: knob reduction and the flag-free recorded trace.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// A guest that fails only on a SHORT WRITE, and announces it twice: through
    /// the VERDICT ABI and on stderr. Every other fault the campaign draws — I/O
    /// errors, latency, the whole network and entropy surface — is handled or
    /// irrelevant here, so a campaign generation that catches this bug carries
    /// one knob that matters and a dozen that do not, which is exactly the
    /// haystack `minimize --generation` exists to reduce.
    ///
    /// The guest calls `patina_verdict` directly rather than through the SDK, both
    /// because a single-source guest links no crates and because it is the surface a
    /// non-Rust guest would use. The `pass` verdict on the way in is load-bearing:
    /// the catching generation reports BOTH a pass and a violation, and the
    /// auto-derived target must contain only the violation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SHORT_WRITE_SOURCE: &str = r#"
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
                eprintln!("GUEST_TORN round={round} wrote={short} of 64");
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

    /// The generation completion line of a successful `minimize --generation`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn completion_line(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "minimize --generation failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
            .lines()
            .find(|line| line.starts_with("PATINA_MINIMIZE_GENERATION_COMPLETE"))
            .expect("missing the generation completion line")
            .to_owned()
    }

    /// `minimize --generation` end to end with NO `--marker`: a campaign catches
    /// the planted short-write bug under a wide fault vector and recognizes it
    /// through the verdict ABI, so the reducer targets what the campaign
    /// recognized (outcome-channel arc §4.5). The target carries the violation
    /// and NOT the pass the same generation reported, the vector shrinks to the
    /// knob that matters, the standalone command it hands back still fails, and
    /// the answer is the same however many candidates it evaluates at once.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn minimize_generation_reduces_the_fault_vector_to_the_campaigns_own_verdict() {
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
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                // The planted short write fires within the first three
                // generations of the default seed base; a generation is a
                // pure function of the seed and its index.
                "--gens",
                "3",
                "--faults",
                "--timeout-secs",
                "30",
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );

        // The catching generation is read straight off the recorded state: the
        // campaign persists each notable run's verdicts, which is what makes the
        // auto-target possible at all.
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
                    "no generation recorded a torn-write violation verdict in 3 generations:\n{}",
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

        let minimize = |output: &Path, extra: &[&str]| -> Output {
            let mut arguments = vec![
                "minimize",
                "--generation",
                &generation,
                "--out-dir",
                out.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ];
            arguments.extend_from_slice(extra);
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &arguments)
        };

        let serial_output = directory.path().join("serial.patina");
        let line = completion_line(&minimize(&serial_output, &["--jobs", "1"]));
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

        // The reduction's real output is the standalone command, so run it: it must
        // still fail on a machine that has no campaign out-dir.
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

        // The recorded minimal-knob trace is the flag-free form of the same
        // reproduction: replaying it needs none of the knobs.
        let flag_free = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                guest.to_str().unwrap(),
                serial_output.to_str().unwrap(),
            ],
        );
        assert!(
            String::from_utf8_lossy(&flag_free.stderr).contains("GUEST_TORN"),
            "the minimized trace no longer replays the failure:\nstderr:\n{}",
            String::from_utf8_lossy(&flag_free.stderr)
        );

        // Parallel candidate evaluation is throughput, not a different search: the
        // reduced trace must be byte-identical to the serial one.
        let parallel_output = directory.path().join("parallel.patina");
        completion_line(&minimize(&parallel_output, &["--jobs", "8"]));
        assert_eq!(
            fs::read(&serial_output).unwrap(),
            fs::read(&parallel_output).unwrap(),
            "--jobs 8 produced a different reduced trace than --jobs 1"
        );

        // Non-vacuity: a marker decides every verdict it is given, so a marker the
        // generation never prints must be refused rather than "reduced" to nothing.
        let wrong = minimize(
            &directory.path().join("wrong.patina"),
            &["--marker", "NO_SUCH_MARKER_ANYWHERE"],
        );
        assert!(!wrong.status.success(), "a wrong marker was accepted");
        assert!(
            String::from_utf8_lossy(&wrong.stderr).contains("does not reproduce"),
            "a wrong marker was not refused by name:\n{}",
            String::from_utf8_lossy(&wrong.stderr)
        );
    }

    /// A campaign generation that fails an `always!` classifies VIOLATION, saves a
    /// trace its reproduce command replays, and minimizes to a knob-reduced
    /// trace that replays flag-free: the run is finalized before the violation
    /// aborts it, so the reducer's recording of the reduced knobs is a trace like
    /// any other.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn minimize_generation_reduces_an_always_violation() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = super::super::verdict::verdict_guest();

        let out = directory.path().join("camp");
        let campaign = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "campaign",
                guest.to_str().unwrap(),
                "--gens",
                "1",
                "--out-dir",
                out.to_str().unwrap(),
                "--format",
                "json",
            ],
        );
        let envelope = campaign_json_stdout(&campaign);
        assert_eq!(
            envelope["classes"]["VIOLATION"], 1,
            "an always! failure is a safety finding: {}",
            envelope["classes"]
        );
        let saved = out.join("failures/generation-0.patina");
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["replay", guest.to_str().unwrap(), saved.to_str().unwrap()],
        );
        let replayed_stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            !replayed.status.success()
                && replayed_stderr
                    .lines()
                    .any(|line| line.starts_with("PATINA_VERDICT ")),
            "the saved generation trace must replay to the violation:\n{replayed_stderr}"
        );

        let output = directory.path().join("minimized.patina");
        let minimized = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
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
        assert!(
            minimized.status.success(),
            "minimize --generation failed on an always! violation:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&minimized.stdout),
            String::from_utf8_lossy(&minimized.stderr)
        );
        // The recorded minimal-knob trace replays the violation with no flags.
        let flag_free = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["replay", guest.to_str().unwrap(), output.to_str().unwrap()],
        );
        assert!(
            !flag_free.status.success()
                && String::from_utf8_lossy(&flag_free.stderr)
                    .lines()
                    .any(|line| line.starts_with("PATINA_VERDICT ")),
            "the minimized trace must replay to the violation without flags:\n{}",
            String::from_utf8_lossy(&flag_free.stderr)
        );
    }

    /// A guest that prints the marker, exits 3 when a filesystem fault reaches
    /// it, and otherwise leaves a custom operation open at exit, which the
    /// runtime refuses at shutdown on every platform.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CUSTOM_OP_SOURCE: &str = r#"
use std::io::Write;

unsafe extern "C" {
    fn patina_custom_op_begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32;
}

/// Begin one custom operation; whether this pass is a replay.
fn begin(label: &str) -> bool {
    let mut len = 0usize;
    unsafe { patina_custom_op_begin(label.as_ptr(), label.len(), [].as_ptr(), 0, 0, &mut len) != 0 }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("fault-or-refusal") => {
            println!("FAIL_MARK");
            let faulted = match std::fs::File::create("/x") {
                Ok(mut file) => !matches!(file.write(&[0; 64]), Ok(64)),
                Err(_) => true,
            };
            if faulted {
                std::process::exit(3);
            }
            begin("lookup");
        }
        other => panic!("unknown mode {other:?}"),
    }
}
"#;

    /// The [`CUSTOM_OP_SOURCE`] guest.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn custom_op_guest() -> PathBuf {
        super::super::run_facts::shared_guest("minimize-custom-op", |directory| {
            build_facts_guest(directory, "custom_op", CUSTOM_OP_SOURCE)
        })
    }

    /// Run a one-generation campaign of the custom-op guest in `mode`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn custom_op_campaign(
        guest: &Path,
        out: &Path,
        extra: &[&str],
        mode: &str,
    ) -> serde_json::Value {
        let mut arguments = vec![
            "campaign",
            guest.to_str().unwrap(),
            "--gens",
            "1",
            "--out-dir",
            out.to_str().unwrap(),
            "--format",
            "json",
        ];
        arguments.extend_from_slice(extra);
        arguments.extend(["--", mode]);
        campaign_json_stdout(&invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &arguments,
        ))
    }

    /// A knob candidate that still prints the marker but ends in a patina
    /// refusal is not the generation's failure: dropping the fault knob must not
    /// be accepted on the strength of the marker alone.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn minimize_keeps_the_knob_whose_removal_ends_in_a_refusal() {
        let workspace = native_workspace();
        let directory = tempdir().unwrap();
        let guest = custom_op_guest();

        // Campaign seeds and knobs are a pure function of `--seed-start` and
        // the generation, and generation 0 of this seed start draws a fault
        // that reaches the guest.
        let out = directory.path().join("camp");
        let envelope = custom_op_campaign(
            &guest,
            &out,
            &["--seed-start", "5", "--faults"],
            "fault-or-refusal",
        );
        assert_eq!(envelope["classes"]["UNCLASSIFIED"], 1, "{envelope:#}");
        let generation = "0";

        let output = directory.path().join("minimized.patina");
        let minimized = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "minimize",
                "--generation",
                generation,
                "--out-dir",
                out.to_str().unwrap(),
                "--marker",
                "FAIL_MARK",
                "--output",
                output.to_str().unwrap(),
                "--jobs",
                "1",
            ],
        );
        let report = format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&minimized.stdout),
            String::from_utf8_lossy(&minimized.stderr)
        );
        assert!(minimized.status.success(), "{report}");
        // Both the reduced command and the trace it recorded still end the
        // way the generation did: the guest's own exit 3, with no refusal.
        let repro = fs::read_to_string(
            out.join("minimized")
                .join(format!("generation-{generation}.repro")),
        )
        .unwrap();
        let mut rerun: Vec<&str> = repro
            .split_whitespace()
            .skip_while(|word| *word != "run")
            .collect();
        // After the verb and the guest, before any guest arguments.
        rerun.splice(2..2, ["--format", "json"]);
        let replay_args = [
            "replay",
            guest.to_str().unwrap(),
            output.to_str().unwrap(),
            "--format",
            "json",
        ];
        for args in [&rerun[..], &replay_args[..]] {
            let ran = invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, args);
            let ended = campaign_json_stdout(&ran);
            assert_eq!(
                ended["guest_exit"]["code"], 3,
                "{args:?}: {ended:#}\n{report}"
            );
            assert!(ended.get("refusal").is_none(), "{args:?}: {ended:#}");
        }
    }
}
