//! CLI help/registry, routing, literal arguments, and cross-family controls.

#[cfg(test)]
mod tests {
    use super::super::*;

    // The package's second binary is the tool as a Cargo subcommand: Cargo
    // passes the subcommand's own name first, and the rest is the tool's own
    // command line. The tool itself has no verb of that name.
    #[test]
    fn the_cargo_subcommand_binary_is_the_same_tool() {
        let workspace = native_workspace();
        let tool = invoke(workspace, &["syscalls"]);
        let subcommand = invoke_with(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["patina", "syscalls"],
        );
        assert!(!tool.stdout.is_empty());
        assert!(tool.stdout == subcommand.stdout);
        let doubled = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            workspace,
            &["patina", "syscalls"],
        );
        assert!(!doubled.status.success());
    }

    // `run` and `audit` recognize a native binary by its leading magic bytes.
    // Options and the artifact may appear in any order (the `cargo run`
    // ergonomic): a registered flag before the binary runs identically to the
    // binary-leading spelling; a real artifact behind an UNKNOWN flag is a usage
    // error naming the flag; and a nonexistent artifact fails closed with a usage
    // error. A
    // `--help` after `--` is guest argv and runs the guest; before `--` it is
    // Patina help. `--budget` bounds recorded boundary operations, and one
    // operation is below any real guest's needs, so an honored budget shows up as
    // the explicit StepBudgetExceeded failure.
    #[test]
    fn run_and_audit_route_a_native_artifact() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let patina = env!("CARGO_BIN_EXE_patina");

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

        // A real artifact behind an unknown flag is a usage error naming the flag.
        let stranded = run(&["run", "--frob", module]);
        assert!(!stranded.status.success());
        assert!(
            String::from_utf8_lossy(&stranded.stderr).contains("--frob"),
            "stranded-artifact error should name the unknown flag: {}",
            String::from_utf8_lossy(&stranded.stderr)
        );

        let missing = run(&["run", "--seed", "1", "./does-not-exist"]);
        assert_eq!(
            missing.status.code(),
            Some(2),
            "a nonexistent artifact should fail closed: {}",
            String::from_utf8_lossy(&missing.stderr)
        );

        // After `--`: the guest runs and exits 0; Patina help is NOT shown.
        let guest = run(&["run", module, "--", "--help"]);
        assert!(
            guest.status.success(),
            "run -- --help failed: {}\n{}",
            guest.status,
            String::from_utf8_lossy(&guest.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&guest.stdout).contains("patina run"),
            "a --help after -- wrongly triggered Patina help"
        );
        // Before `--`: the bare `--help` is intercepted and prints run help (exit 0).
        let help = run(&["run", module, "--help"]);
        assert!(help.status.success(), "run --help should exit 0");
        assert!(
            String::from_utf8_lossy(&help.stdout).contains("patina run"),
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

        // `patina campaign --help` exits 0 with the campaign synopsis + --gens.
        let help = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
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
            stdout.contains("patina campaign"),
            "campaign --help missing synopsis:\n{stdout}"
        );
        assert!(
            stdout.contains("--gens"),
            "campaign --help missing --gens:\n{stdout}"
        );
        // The machine-readable registry reaches the binary: the index and a
        // verb-scoped payload both parse. Their shape is tested in `src/tests.rs`.
        for (arguments, scope) in [
            (&["--help", "--format", "json"][..], None),
            (&["run", "--help", "--format", "json"][..], Some("run")),
        ] {
            let output =
                invoke_unchecked(env!("CARGO_BIN_EXE_patina"), directory.path(), arguments);
            assert!(
                output.status.success(),
                "{arguments:?} exited {}",
                output.status
            );
            let payload: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("help JSON parses");
            match scope {
                None => assert!(payload["verbs"].is_object()),
                Some(verb) => assert_eq!(payload["verb"]["name"], verb),
            }
        }
    }

    /// `PATINA_FORMAT` defaults `--format`: a typed flag wins, then a
    /// non-empty variable, then the built-in default, and a malformed value
    /// names its variable. A variable named after any other flag defaults
    /// nothing. `trace events` on a committed fixture observes this without
    /// building anything.
    #[test]
    fn env_defaults_yield_to_typed_flags() {
        let directory = tempdir().unwrap();
        let patina = env!("CARGO_BIN_EXE_patina");
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
        assert_eq!(events(&[], &[("PATINA_FORMAT", "")]), all);
        assert_eq!(events(&[], &[("PATINA_FIRST", "2")]), all);

        let bad = invoke_unchecked_clean_env(
            patina,
            directory.path(),
            &["trace", "events", fixture],
            &[("PATINA_FORMAT", "xml")],
        );
        assert!(!bad.status.success());
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("PATINA_FORMAT"),
            "a malformed env default did not name its variable:\n{}",
            String::from_utf8_lossy(&bad.stderr)
        );
    }
}
