//! Configuration precedence, provenance, refusal, and child isolation.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn config_precedence_and_no_config_are_provenanced() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        write_noop_wasm(&module);
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[defaults.run]\nseed = 3\n",
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();

        let from_config = json_output(&invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", module, "--format", "json"],
            &[],
        ));
        assert_eq!(from_config["seed"], 3, "{from_config:#}");
        assert_eq!(from_config["config"]["applied"][0]["source"], "config");

        let from_env = json_output(&invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", module, "--format", "json"],
            &[("PATINA_SEED", "4")],
        ));
        assert_eq!(from_env["seed"], 4, "{from_env:#}");
        assert_eq!(from_env["config"]["applied"][0]["source"], "env");

        let from_flag = json_output(&invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", module, "--seed", "5", "--format", "json"],
            &[("PATINA_SEED", "4")],
        ));
        assert_eq!(from_flag["seed"], 5, "{from_flag:#}");
        assert!(
            from_flag["config"].get("applied").is_none(),
            "explicit flag should leave lower-priority defaults unapplied: {from_flag:#}"
        );

        let no_config = json_output(&invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", "--no-config", module, "--format", "json"],
            &[],
        ));
        assert_eq!(no_config["seed"], 0, "{no_config:#}");
        assert!(no_config.get("config").is_none(), "{no_config:#}");
    }

    #[test]
    fn config_effective_values_do_not_change_trace_bytes() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        write_noop_wasm(&module);
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[defaults.run]\nseed = 9\n",
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();
        let config_trace = directory.path().join("config.patina");
        let explicit_trace = directory.path().join("explicit.patina");

        let config_record = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", module, "--record", config_trace.to_str().unwrap()],
            &[],
        );
        assert!(
            config_record.status.success(),
            "config record failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&config_record.stdout),
            String::from_utf8_lossy(&config_record.stderr)
        );
        let explicit_record = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &[
                "run",
                "--no-config",
                module,
                "--seed",
                "9",
                "--record",
                explicit_trace.to_str().unwrap(),
            ],
            &[],
        );
        assert!(
            explicit_record.status.success(),
            "explicit record failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&explicit_record.stdout),
            String::from_utf8_lossy(&explicit_record.stderr)
        );
        assert_eq!(
            fs::read(config_trace).unwrap(),
            fs::read(explicit_trace).unwrap(),
            "config provenance must not enter traces when effective values match"
        );
    }

    #[test]
    fn bad_config_is_loud_and_no_config_ignores_it() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        write_noop_wasm(&module);
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[defaults.run]\nseed = \"abc\"\n",
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();

        let bad = invoke_unchecked_clean_env(patina, directory.path(), &["run", module], &[]);
        assert!(!bad.status.success());
        let stderr = String::from_utf8_lossy(&bad.stderr);
        assert!(stderr.contains("seed"), "{stderr}");
        assert!(stderr.contains("config.toml:2:1"), "{stderr}");

        let help = invoke_unchecked_clean_env(patina, directory.path(), &["run", "--help"], &[]);
        assert!(
            help.status.success(),
            "help must not be blocked by a bad project config:\nstderr:\n{}",
            String::from_utf8_lossy(&help.stderr)
        );

        let ignored = json_output(&invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["run", "--no-config", module, "--format", "json"],
            &[],
        ));
        assert_eq!(ignored["seed"], 0, "{ignored:#}");
    }

    #[test]
    fn replay_config_defaults_are_refused() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        write_noop_wasm(&module);
        let trace = directory.path().join("run.patina");
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let recorded = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &[
                "run",
                "--no-config",
                module.to_str().unwrap(),
                "--record",
                trace.to_str().unwrap(),
            ],
            &[],
        );
        assert!(recorded.status.success());
        fs::create_dir_all(directory.path().join(".patina")).unwrap();
        fs::write(
            directory.path().join(".patina/config.toml"),
            "[defaults.replay]\ntimeline = \"other\"\n",
        )
        .unwrap();

        let replayed = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["replay", module.to_str().unwrap(), trace.to_str().unwrap()],
            &[],
        );
        assert!(!replayed.status.success());
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(stderr.contains("trace-authoritative"), "{stderr}");
        assert!(stderr.contains("config.toml:2:1"), "{stderr}");
    }

    // A campaign's child `run` processes are driven entirely by the derived flags, so
    // `[defaults.run]` and the `PATINA_*` run env defaults must never reach them. Both
    // probes are run-only surfaces the CAMPAIGN verb does not register — `PATINA_FUEL`
    // deliberately, since a leaked `--fuel 1` would exhaust the guest and turn the
    // sweep red, which is what makes this assertion able to fail.
    #[test]
    fn campaign_children_scrub_run_config_and_env_defaults() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        write_noop_wasm(&module);
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
            &[("PATINA_FUEL", "1")],
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

    fn write_noop_wasm(path: &Path) {
        fs::write(
            path,
            wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
                .unwrap(),
        )
        .unwrap();
    }

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
