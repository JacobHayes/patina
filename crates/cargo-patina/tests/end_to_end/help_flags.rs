//! CLI help/registry, routing, literal arguments, and cross-family controls.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn the_cargo_family_accepts_buggify_flags_and_scrubs_an_ambient_control_plane() {
        // Buggify was reachable from the Cargo family only through PATINA_RT_BUGGIFY* in
        // the caller's environment: the runtime path was always family-neutral, but
        // the parser omitted the flags. Now `run`/`test` carry them like every other
        // family — and, like the fault knobs, scrub the ambient control plane so a
        // stale variable cannot enable buggify in a run that did not ask for it.
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("fixture");
        create_fixture(&fixture);
        let patina = env!("CARGO_BIN_EXE_cargo-patina");

        let enabled = invoke_unchecked_clean_env(
            patina,
            &fixture,
            &[
                "run",
                "--seed",
                "7",
                "--buggify=400",
                "--buggify-cutoff-nanos",
                "5000",
            ],
            &[],
        );
        let stderr = String::from_utf8_lossy(&enabled.stderr);
        assert!(
            stderr.contains("PATINA_SDK_REPORT enabled=1") && stderr.contains("fire_permille=400"),
            "cargo-family --buggify did not reach the guest runtime:\n{stderr}"
        );
        assert!(
            stderr.contains("cutoff_nanos=5000"),
            "cargo-family buggify detail knobs did not reach the guest:\n{stderr}"
        );

        // `replay` registers no buggify flag — the trace is authoritative — so an
        // ambient PATINA_RT_BUGGIFY has no CLI meaning there. Before the scrub it would
        // still have reached the guest's own control-plane read and buggified a
        // replay of a buggify-free recording, which is a corrupted reproduction.
        let trace = directory.path().join("clean.patina");
        let recorded = invoke_unchecked_clean_env(
            patina,
            &fixture,
            &["run", "--seed", "7", "--record", trace.to_str().unwrap()],
            &[],
        );
        assert!(recorded.status.success());
        let replayed = invoke_unchecked_clean_env(
            patina,
            &fixture,
            &["replay", ".", trace.to_str().unwrap()],
            &[("PATINA_RT_BUGGIFY", "900")],
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            replayed.status.success(),
            "replay under an ambient PATINA_RT_BUGGIFY failed:\n{stderr}"
        );
        assert!(
            !stderr.contains("PATINA_SDK_REPORT enabled=1"),
            "an ambient PATINA_RT_BUGGIFY buggified a replay of a buggify-free trace:\n{stderr}"
        );
    }

    // `run` and `audit` recognize a native binary by its leading magic bytes.
    // Options and the artifact may appear in any order (the `cargo run`
    // ergonomic): a registered flag before the binary runs identically to the
    // binary-leading spelling; a real artifact stranded behind an UNKNOWN flag is
    // a loud routing error; and a nonexistent path-like artifact fails closed with
    // a usage error rather than falling through to a confusing `cargo run`. A
    // `--help` after `--` is guest argv and runs the guest; before `--` it is
    // Patina help. `--budget` bounds recorded boundary operations, and one
    // operation is below any real guest's needs, so an honored budget shows up as
    // the explicit StepBudgetExceeded failure.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_and_audit_route_a_native_artifact() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");

        let source = directory.path().join("noop.rs");
        // The file write gives `--budget` boundary operations to bound.
        fs::write(
            &source,
            "fn main() { let _ = std::fs::write(\"/budget\", b\"x\"); println!(\"NATIVE_OK\"); }",
        )
        .unwrap();
        let bin = directory.path().join("noop-native");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        // The pre-run gate auto-allows the shim control-plane vehicle; a standalone
        // audit names it explicitly. The whole control plane is the single `dlsym`
        // host-alias primitive on both platforms.
        let control_plane: &[&str] = &["dlsym"];
        let mut audit_args = vec!["audit", bin.to_str().unwrap()];
        for symbol in control_plane {
            audit_args.push("--allow");
            audit_args.push(symbol);
        }
        invoke(workspace, &audit_args);
        let module = bin.to_str().unwrap();
        let run = |args: &[&str]| invoke_unchecked(patina, workspace, args);

        // Artifact leads.
        let leading = run(&["run", module, "--seed", "7"]);
        assert!(
            leading.status.success(),
            "binary-leading run failed: {}",
            String::from_utf8_lossy(&leading.stderr)
        );
        assert!(String::from_utf8_lossy(&leading.stdout).contains("NATIVE_OK"));
        // A registered flag leads the artifact: identical success.
        let flag_first = run(&["run", "--seed", "7", module]);
        assert!(
            flag_first.status.success(),
            "flag-leading run failed: {}",
            String::from_utf8_lossy(&flag_first.stderr)
        );

        // A real artifact stranded behind an unknown flag is a loud routing error
        // naming the flag, never a silent Cargo fallthrough.
        let stranded = run(&["run", "--frob", module]);
        assert!(!stranded.status.success());
        assert!(
            String::from_utf8_lossy(&stranded.stderr).contains("--frob"),
            "stranded-artifact error should name the unknown flag: {}",
            String::from_utf8_lossy(&stranded.stderr)
        );

        for missing in [
            &["run", "./definitely-missing"][..],
            &["run", "--seed", "1", "./does-not-exist"][..],
        ] {
            let output = run(missing);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{missing:?}: expected a usage-error exit"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("no such file"),
                "{missing:?}: nonexistent artifact should fail closed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // After `--`: the guest runs and exits 0; Patina help is NOT shown.
        let guest = run(&["run", module, "--", "--help"]);
        assert!(
            guest.status.success(),
            "run -- --help failed: {}\n{}",
            guest.status,
            String::from_utf8_lossy(&guest.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&guest.stdout).contains("cargo patina run"),
            "a --help after -- wrongly triggered Patina help"
        );
        // Before `--`: the bare `--help` is intercepted and prints run help (exit 0).
        let help = run(&["run", module, "--help"]);
        assert!(help.status.success(), "run --help should exit 0");
        assert!(
            String::from_utf8_lossy(&help.stdout).contains("cargo patina run"),
            "--help should show run help:\n{}",
            String::from_utf8_lossy(&help.stdout)
        );

        let budgeted = run(&["run", module, "--budget", "1"]);
        assert!(!budgeted.status.success());
        assert!(
            String::from_utf8_lossy(&budgeted.stderr).contains("step budget of 1"),
            "native run ignored --budget:\n{}",
            String::from_utf8_lossy(&budgeted.stderr)
        );
    }

    // The registry-driven help system: a per-verb `--help` prints that verb's
    // focused section and exits 0 (regression for the wall-dump / `--help`-consumed-
    // as-a-positional bug where `campaign --help` errored with "failed to read
    // artifact --help"), and `--help --format json` emits the machine-readable
    // registry covering every verb.
    #[test]
    fn per_verb_help_and_json_registry() {
        let directory = tempdir().unwrap();

        // `cargo patina campaign --help` exits 0 with the campaign synopsis + --gens.
        let help = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["campaign", "--help"],
        );
        assert!(
            help.status.success(),
            "campaign --help exited {}\nstderr:\n{}",
            help.status,
            String::from_utf8_lossy(&help.stderr)
        );
        let stdout = String::from_utf8_lossy(&help.stdout);
        assert!(
            stdout.contains("cargo patina campaign"),
            "campaign --help missing synopsis:\n{stdout}"
        );
        assert!(
            stdout.contains("--gens"),
            "campaign --help missing --gens:\n{stdout}"
        );
        // The old bug's error string must be gone.
        assert!(
            !stdout.contains("failed to read artifact"),
            "campaign --help still consumes --help as a positional"
        );

        // `cargo patina --help --format json` exits 0 and parses as the compact INDEX:
        // schema patina.help/v2, every verb as {summary, forms} but NO flag_groups,
        // the global flags + environment protocol, and a per-verb command pointer.
        let index_out = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["--help", "--format", "json"],
        );
        assert!(
            index_out.status.success(),
            "--help --format json exited {}",
            index_out.status
        );
        let index: serde_json::Value = serde_json::from_slice(&index_out.stdout)
            .expect("--help --format json emits valid JSON");
        assert_eq!(index["schema"], "patina.help/v2", "index schema tag");
        assert!(
            index["environment"].is_array(),
            "index carries the environment protocol"
        );
        assert!(
            index["verb_detail"]["command_template"]
                .as_str()
                .is_some_and(|t| t.contains("{verb}")),
            "index carries a substitutable per-verb command template:\n{}",
            String::from_utf8_lossy(&index_out.stdout)
        );
        let verbs = index["verbs"].as_object().expect("verbs object");
        for verb in [
            "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize",
        ] {
            assert!(
                verbs.contains_key(verb),
                "JSON index missing verb {verb}:\n{}",
                String::from_utf8_lossy(&index_out.stdout)
            );
            assert!(
                verbs[verb].get("flag_groups").is_none(),
                "index must not carry flag_groups for {verb}"
            );
        }

        // `cargo patina run --help --format json` emits ONLY run's detail: run's own
        // flags (its unique --harness) but NOT another verb's unique flag (campaign's
        // --gens), and no environment block. Absent-field defaults hold: --release is
        // native to build; run's repeatable --param carries `repeatable: true`.
        let run_out = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", "--help", "--format", "json"],
        );
        assert!(
            run_out.status.success(),
            "run --help --format json exited {}",
            run_out.status
        );
        let run: serde_json::Value = serde_json::from_slice(&run_out.stdout)
            .expect("run --help --format json emits valid JSON");
        assert_eq!(run["schema"], "patina.help/v2", "verb-scoped schema tag");
        assert_eq!(run["verb"]["name"], "run", "scoped payload names its verb");
        assert!(
            run.get("verbs").is_none() && run.get("environment").is_none(),
            "scoped payload carries neither the verbs index nor the environment block"
        );
        let run_flags = e2e_flag_names(&run["verb"]["flag_groups"]);
        assert!(
            run_flags.contains("--harness"),
            "run's payload should carry its own --harness flag"
        );
        assert!(
            !run_flags.contains("--gens"),
            "run's payload leaked campaign's unique --gens flag"
        );
        let param = e2e_find_flag(&run["verb"]["flag_groups"], "--param").expect("run has --param");
        assert_eq!(
            param["repeatable"], true,
            "a repeatable flag emits repeatable: true"
        );
        assert!(
            param.get("short").is_none(),
            "a short-less flag omits the `short` key entirely (absent means none)"
        );
    }

    /// Every flag defaults from its `PATINA_<FLAG>` variable: a typed flag wins,
    /// then a non-empty variable, then the built-in default. `trace events` on a
    /// committed fixture observes this without building anything.
    #[test]
    fn flag_env_defaults_yield_to_typed_flags() {
        let directory = tempdir().unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../patina-trace/tests/fixtures/current-crash-restart.patina"
        );
        let events = |arguments: &[&str], envs: &[(&str, &str)]| -> Vec<String> {
            let mut all = vec!["trace", "events", fixture];
            all.extend_from_slice(arguments);
            let output = invoke_unchecked_clean_env(patina, directory.path(), &all, envs);
            assert!(
                output.status.success(),
                "trace events {arguments:?} with {envs:?} failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        };

        let all = events(&[], &[]);
        assert!(
            all.len() > 2,
            "fixture too small to observe --first: {all:?}"
        );
        // Env over default.
        assert_eq!(events(&[], &[("PATINA_FIRST", "2")]), all[..2]);
        // Typed over env.
        assert_eq!(
            events(&["--first", "1"], &[("PATINA_FIRST", "2")]),
            all[..1]
        );
        // A typed flag also beats a variable it is mutually exclusive with.
        assert_eq!(
            events(&["--last", "1"], &[("PATINA_FIRST", "2")]),
            all[all.len() - 1..]
        );
        // An empty variable is unset.
        assert_eq!(events(&[], &[("PATINA_FIRST", "")]), all);
        // A switch: false-y is off, anything else is on.
        let notable = events(&["--notable"], &[]);
        assert_ne!(notable, all, "fixture cannot tell --notable apart");
        assert_eq!(events(&[], &[("PATINA_NOTABLE", "off")]), all);
        assert_eq!(events(&[], &[("PATINA_NOTABLE", "1")]), notable);
        // A pre-pass global flag reads its variable too, and still yields.
        let json = events(&[], &[("PATINA_FORMAT", "json")]);
        assert!(
            json.iter()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()),
            "PATINA_FORMAT=json did not select JSON: {json:?}"
        );
        assert_eq!(
            events(&["--format", "human"], &[("PATINA_FORMAT", "json")]),
            all
        );

        // A selector's default routes like the typed selector: `--generation`
        // takes no `-- <ORACLE>`, so the reduction reaches its out-dir check.
        let missing = directory.path().join("no-campaign");
        let routed = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["minimize", "--out-dir", missing.to_str().unwrap()],
            &[("PATINA_GENERATION", "14")],
        );
        let typed = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &[
                "minimize",
                "--generation",
                "14",
                "--out-dir",
                missing.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(routed.stderr, typed.stderr);

        // A malformed default names the variable it came from.
        let bad = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["trace", "events", fixture],
            &[("PATINA_FIRST", "many")],
        );
        assert!(!bad.status.success());
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("PATINA_FIRST"),
            "a malformed env default did not name its variable:\n{}",
            String::from_utf8_lossy(&bad.stderr)
        );
    }

    /// Help shows each flag's environment variable, in both renderings.
    #[test]
    fn help_names_each_flags_env_variable() {
        let directory = tempdir().unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let human = invoke_unchecked_clean_env(patina, directory.path(), &["trace", "--help"], &[]);
        assert!(human.status.success());
        assert!(String::from_utf8_lossy(&human.stdout).contains("PATINA_FIRST"));

        let json = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["trace", "--help", "--format", "json"],
            &[],
        );
        assert!(json.status.success());
        let payload: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        let groups = &payload["verb"]["flag_groups"];
        let first = e2e_find_flag(groups, "--first").expect("trace --first");
        assert_eq!(first["env"], "PATINA_FIRST");
    }

    /// Every flag `name` across an array of `{title, flags}` groups.
    fn e2e_flag_names(flag_groups: &serde_json::Value) -> std::collections::BTreeSet<String> {
        let mut names = std::collections::BTreeSet::new();
        for group in flag_groups.as_array().into_iter().flatten() {
            for flag in group["flags"].as_array().into_iter().flatten() {
                if let Some(name) = flag["name"].as_str() {
                    names.insert(name.to_string());
                }
            }
        }
        names
    }

    /// The first flag object named `name` across an array of `{title, flags}` groups.
    fn e2e_find_flag(flag_groups: &serde_json::Value, name: &str) -> Option<serde_json::Value> {
        for group in flag_groups.as_array().into_iter().flatten() {
            for flag in group["flags"].as_array().into_iter().flatten() {
                if flag["name"].as_str() == Some(name) {
                    return Some(flag.clone());
                }
            }
        }
        None
    }
}
