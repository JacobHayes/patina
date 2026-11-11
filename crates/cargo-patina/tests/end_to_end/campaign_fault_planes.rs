//! Campaign fault-plane selection: `--vary PLANE,...` draws only the named
//! planes, the out-dir records the subset, and a continuation keeps it.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// Opens a file and writes it 32 times. Exit 3 means a filesystem fault
    /// reached the guest (a failed open or write, or a short write); otherwise it
    /// exits 7, so every generation is a notable run whose drawn flags the
    /// campaign records.
    const FS_WRITER: &str = r#"
use std::io::Write;

fn main() {
    let Ok(mut file) = std::fs::File::create("/file") else {
        std::process::exit(3);
    };
    for _ in 0..32 {
        if file.write(b"abcdefgh").ok() != Some(8) {
            std::process::exit(3);
        }
    }
    std::process::exit(7);
}
"#;

    /// A generation in which an fs fault reached the guest is a VIOLATION.
    const FS_FAULT_IS_A_VIOLATION: &str = r#"{"classify": {"exit_codes": {"violation": [3]}}}"#;

    struct Fixture {
        _directory: tempfile::TempDir,
        module: PathBuf,
        spec: PathBuf,
        cwd: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        let module = build_facts_guest(directory.path(), "fs-writer", FS_WRITER);
        let spec = directory.path().join("spec.json");
        fs::write(&spec, FS_FAULT_IS_A_VIOLATION).unwrap();
        Fixture {
            cwd: directory.path().to_path_buf(),
            _directory: directory,
            module,
            spec,
        }
    }

    fn campaign(cwd: &Path, args: &[&str]) -> Output {
        let mut argv = vec!["campaign"];
        argv.extend_from_slice(args);
        invoke_unchecked(env!("CARGO_BIN_EXE_patina"), cwd, &argv)
    }

    fn fresh(fixture: &Fixture, out: &Path, gens: &str, vary: &str) -> serde_json::Value {
        let output = campaign(
            &fixture.cwd,
            &[
                fixture.module.to_str().unwrap(),
                "--gens",
                gens,
                "--vary",
                vary,
                "--spec",
                fixture.spec.to_str().unwrap(),
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        assert_ran(&output);
        campaign_state_without_invocations(&out.join("campaign-state.json"))
    }

    /// A campaign whose generations all fail exits 1; anything else is a
    /// refusal or a crash.
    fn assert_ran(output: &Output) {
        assert_eq!(
            output.status.code(),
            Some(1),
            "campaign did not run to completion\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn runs(state: &serde_json::Value) -> &Vec<serde_json::Value> {
        state["notable_runs"].as_array().unwrap()
    }

    fn drew(run: &serde_json::Value, prefix: &str) -> bool {
        run["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|flag| flag.as_str().unwrap().starts_with(prefix))
    }

    /// The valid dimensions, from the registry's own `--vary` grammar.
    fn registry_dimensions(cwd: &Path) -> Vec<String> {
        let help = campaign(cwd, &["--help", "--format", "json"]);
        let help: serde_json::Value = serde_json::from_slice(&help.stdout).unwrap();
        help["verb"]["flag_groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["flags"].as_array().unwrap())
            .find(|flag| flag["name"] == "--vary")
            .expect("--vary is registered")["choices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|plane| plane.as_str().unwrap().to_string())
            .collect()
    }

    /// A `--vary sleep,net` campaign draws and fires only those planes (the
    /// every-plane control shows fs faults do reach this guest), the out-dir
    /// records the subset, a continuation keeps it and refuses a new one, and
    /// an unknown dimension is a usage error naming the valid ones.
    #[test]
    fn a_plane_subset_never_draws_another_plane_and_a_continuation_keeps_it() {
        let fixture = fixture();
        let every = fresh(&fixture, &fixture.cwd.join("every"), "4", "faults");
        assert!(
            runs(&every)
                .iter()
                .any(|run| run["class"] == "violation" && drew(run, "--fs-")),
            "no every-plane generation faulted the guest's fs, so the subset run below \
             would prove nothing:\n{:#}",
            every["notable_runs"]
        );

        let out = fixture.cwd.join("camp");
        let recorded = fresh(&fixture, &out, "2", "sleep,net");
        assert_eq!(
            recorded["spec"]["vary"],
            serde_json::json!(["net", "sleep"])
        );
        assert_ran(&campaign(
            &fixture.cwd,
            &["--gens", "4", "--out-dir", out.to_str().unwrap()],
        ));
        let extended = campaign_state_without_invocations(&out.join("campaign-state.json"));
        assert_eq!(extended["spec"]["vary"], recorded["spec"]["vary"]);
        assert_eq!(runs(&extended).len(), 4, "every generation is recorded");
        for run in runs(&extended) {
            assert!(!drew(run, "--fs-"), "an fs knob was drawn: {run:#}");
            assert!(drew(run, "--net-") && drew(run, "--sleep-"), "{run:#}");
            assert_ne!(run["class"], "violation", "an fs fault fired: {run:#}");
        }
        let classes = extended["classes"].as_object().unwrap();
        assert!(
            classes.keys().all(|class| !class.starts_with("vacuous")),
            "a plane counted as vacuous: {classes:?}"
        );

        let module = fixture.module.to_str().unwrap();
        let spec = fixture.spec.to_str().unwrap();
        for continuation in [
            vec!["--gens", "5", "--vary", "fs"],
            vec!["--vary", "net,sleep"],
            vec![module, "--gens", "5", "--spec", spec, "--vary", "fs"],
            vec![module, "--gens", "5", "--spec", spec, "--vary", "faults"],
        ] {
            let mut args = continuation.clone();
            args.extend(["--out-dir", out.to_str().unwrap()]);
            let refused = campaign(&fixture.cwd, &args);
            assert_eq!(
                refused.status.code(),
                Some(2),
                "{continuation:?} was accepted"
            );
        }
        assert_eq!(
            campaign_state_without_invocations(&out.join("campaign-state.json")),
            extended,
            "a refused continuation changed the out-dir"
        );

        let dimensions = registry_dimensions(&fixture.cwd);
        assert!(!dimensions.is_empty());
        let unknown_out = fixture.cwd.join("unknown");
        let refused = campaign(
            &fixture.cwd,
            &[
                fixture.module.to_str().unwrap(),
                "--vary=net,disk",
                "--out-dir",
                unknown_out.to_str().unwrap(),
            ],
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(2), "accepted:\n{stderr}");
        // The message, without the synopsis a usage error appends.
        let message = stderr.split("\n\n").next().unwrap();
        for dimension in &dimensions {
            assert!(
                message.contains(dimension.as_str()),
                "{dimension} unnamed:\n{stderr}"
            );
        }
        assert!(!unknown_out.exists(), "a refused campaign wrote an out-dir");
    }

    /// The generation log records every generation once, across a
    /// continuation (even after a torn last record), with the seed, flags and
    /// class the campaign used: here every generation is notable, so each
    /// record must equal its notable run.
    #[test]
    fn the_generation_log_records_every_generation_as_the_campaign_ran_it() {
        let fixture = fixture();
        let out = fixture.cwd.join("logged");
        let output = campaign(
            &fixture.cwd,
            &[
                fixture.module.to_str().unwrap(),
                "--gens",
                "3",
                "--vary",
                "faults",
                "--spec",
                fixture.spec.to_str().unwrap(),
                "--out-dir",
                out.to_str().unwrap(),
            ],
        );
        assert_ran(&output);
        // A run killed mid-record leaves a torn last line; the continuation
        // must not glue its first record onto it.
        let log_path = out.join("generations.jsonl");
        let mut torn = fs::read(&log_path).unwrap();
        torn.extend_from_slice(b"{\"generation\":");
        fs::write(&log_path, torn).unwrap();
        assert_ran(&campaign(
            &fixture.cwd,
            &["--gens", "5", "--out-dir", out.to_str().unwrap()],
        ));
        let state = campaign_state_without_invocations(&out.join("campaign-state.json"));
        let log: Vec<serde_json::Value> = fs::read_to_string(out.join("generations.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let generations: Vec<u64> = log
            .iter()
            .map(|record| record["generation"].as_u64().unwrap())
            .collect();
        assert_eq!(generations, vec![0, 1, 2, 3, 4]);
        assert_eq!(runs(&state).len(), log.len());
        for (record, run) in log.iter().zip(runs(&state)) {
            for key in ["generation", "seed", "flags", "class"] {
                assert_eq!(record[key], run[key], "{key} differs:\n{record:#}\n{run:#}");
            }
        }
    }
}
