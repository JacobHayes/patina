//! Configuration precedence, provenance, refusal, and child isolation.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// Run defaults come from flags, then `PATINA_*`, then the project config,
    /// each provenanced in the envelope and all ignored under `--no-config`. A
    /// config value that matches an explicit one leaves the trace's bytes alone,
    /// a replay refuses config defaults (the trace is authoritative), and a bad
    /// config is a loud error naming its line that blocks neither help nor
    /// `--no-config`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_config_defaults_are_provenanced_loud_and_stay_out_of_traces_and_replays() {
        let directory = tempdir().unwrap();
        let module = build_facts_guest(directory.path(), "noop", NOOP_GUEST);
        let config = directory.path().join(".patina/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, "[defaults.run]\nseed = 3\n").unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();
        let run = |args: &[&str], env: &[(&str, &str)]| {
            invoke_unchecked_clean_env(patina, directory.path(), args, env)
        };

        let from_config = json_output(&run(&["run", module, "--format", "json"], &[]));
        assert_eq!(from_config["seed"], 3, "{from_config:#}");
        assert_eq!(from_config["config"]["applied"][0]["source"], "config");

        let from_env = json_output(&run(
            &["run", module, "--format", "json"],
            &[("PATINA_SEED", "4")],
        ));
        assert_eq!(from_env["seed"], 4, "{from_env:#}");
        assert_eq!(from_env["config"]["applied"][0]["source"], "env");

        let from_flag = json_output(&run(
            &["run", module, "--seed", "5", "--format", "json"],
            &[("PATINA_SEED", "4")],
        ));
        assert_eq!(from_flag["seed"], 5, "{from_flag:#}");
        assert!(
            from_flag["config"].get("applied").is_none(),
            "explicit flag should leave lower-priority defaults unapplied: {from_flag:#}"
        );

        let no_config = json_output(&run(
            &["run", "--no-config", module, "--format", "json"],
            &[],
        ));
        assert_eq!(no_config["seed"], 0, "{no_config:#}");
        assert!(no_config.get("config").is_none(), "{no_config:#}");

        let config_trace = directory.path().join("config.patina");
        let explicit_trace = directory.path().join("explicit.patina");
        for recorded in [
            run(
                &["run", module, "--record", config_trace.to_str().unwrap()],
                &[],
            ),
            run(
                &[
                    "run",
                    "--no-config",
                    module,
                    "--seed",
                    "3",
                    "--record",
                    explicit_trace.to_str().unwrap(),
                ],
                &[],
            ),
        ] {
            assert!(
                recorded.status.success(),
                "record failed:\nstderr:\n{}",
                String::from_utf8_lossy(&recorded.stderr)
            );
        }
        assert_eq!(
            fs::read(&config_trace).unwrap(),
            fs::read(&explicit_trace).unwrap(),
            "config provenance must not enter traces when effective values match"
        );

        fs::write(&config, "[defaults.replay]\ntimeline = \"other\"\n").unwrap();
        let replayed = run(&["replay", module, config_trace.to_str().unwrap()], &[]);
        assert!(!replayed.status.success());
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(stderr.contains("trace-authoritative"), "{stderr}");
        assert!(stderr.contains("config.toml:2:1"), "{stderr}");

        fs::write(&config, "[defaults.run]\nseed = \"abc\"\n").unwrap();
        let bad = run(&["run", module], &[]);
        assert!(!bad.status.success());
        let stderr = String::from_utf8_lossy(&bad.stderr);
        assert!(stderr.contains("seed"), "{stderr}");
        assert!(stderr.contains("config.toml:2:1"), "{stderr}");
        let help = run(&["run", "--help"], &[]);
        assert!(
            help.status.success(),
            "help must not be blocked by a bad project config:\nstderr:\n{}",
            String::from_utf8_lossy(&help.stderr)
        );
        let ignored = json_output(&run(
            &["run", "--no-config", module, "--format", "json"],
            &[],
        ));
        assert_eq!(ignored["seed"], 0, "{ignored:#}");
    }

    // A campaign's child `run` processes are driven entirely by the derived flags, so
    // `[defaults.run]` and the `PATINA_*` run env defaults must never reach them. Both
    // probes are run-only surfaces the CAMPAIGN verb does not register — `PATINA_BUDGET`
    // deliberately, since a leaked `--budget 1` would exhaust the guest's step budget
    // and turn the sweep red, which is what makes this assertion able to fail.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn campaign_children_scrub_run_config_and_env_defaults() {
        let directory = tempdir().unwrap();
        let module = build_facts_guest(directory.path(), "noop", NOOP_GUEST);
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[defaults.campaign]\ngenerations = 1\n\n[defaults.run]\nharness = true\n",
        )
        .unwrap();
        let out_dir = directory.path().join("campaign-out");
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let output = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &[
                "campaign",
                module.to_str().unwrap(),
                "--out-dir",
                out_dir.to_str().unwrap(),
                "--format",
                "json",
            ],
            &[("PATINA_BUDGET", "1")],
        );
        assert!(
            output.status.success(),
            "campaign child should ignore run defaults from config/env:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let json = json_output(&output);
        assert_eq!(json["generations"], 1, "{json:#}");
        assert_eq!(json["config"]["applied"][0]["key"], "generations");
    }

    #[test]
    fn sites_config_groups_apply_to_rollups() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("src")).unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"site-groups\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
        directory.path().join("src/lib.rs"),
        "macro_rules! always { ($cond:expr, $label:literal) => {}; }\npub fn check() { always!(true, \"ledger-check\"); assert!(true); }\n",
    )
    .unwrap();
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[groups.durability]\npaths = [\"src/**\"]\nlabels = [\"ledger-*\"]\n",
        )
        .unwrap();
        let output = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["sites", "--no-cache", "--all", "--format", "json"],
            &[],
        );
        assert!(
            output.status.success(),
            "sites failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let json = json_output(&output);
        assert!(
        json["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["name"] == "durability" && group["sites"].as_u64().unwrap() >= 1),
        "{json:#}"
    );
        assert!(
            json["sites"]
                .as_array()
                .unwrap()
                .iter()
                .any(|site| site["groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|g| g == "durability")),
            "{json:#}"
        );
    }

    /// A guest whose one file write gives a leaked `--budget 1` something to bound.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const NOOP_GUEST: &str = "fn main() { let _ = std::fs::write(\"/budget\", b\"x\"); }";

    fn json_output(output: &Output) -> serde_json::Value {
        assert!(
            output.status.success(),
            "command failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "stdout was not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }
}
