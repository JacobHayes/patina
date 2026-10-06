//! CLI help/registry, routing, literal arguments, and cross-family controls.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Options and the artifact may appear in any order (the `cargo run` ergonomic):
    // a registered flag before the module runs identically to the module-leading
    // spelling; a real artifact stranded behind an UNKNOWN flag is a loud routing
    // error; and a nonexistent artifact reached after a registered flag fails closed.
    #[test]
    fn run_accepts_options_before_the_wasi_artifact() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        fs::write(
            &module,
            wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
                .unwrap(),
        )
        .unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();

        // Artifact leads.
        let leading = invoke_unchecked(patina, directory.path(), &["run", module, "--seed", "7"]);
        assert!(
            leading.status.success(),
            "module-leading run failed: {}",
            String::from_utf8_lossy(&leading.stderr)
        );
        // A registered flag leads the artifact: identical success.
        let flag_first =
            invoke_unchecked(patina, directory.path(), &["run", "--seed", "7", module]);
        assert!(
            flag_first.status.success(),
            "flag-leading run failed: {}",
            String::from_utf8_lossy(&flag_first.stderr)
        );

        // A real artifact stranded behind an unknown flag is a loud routing error
        // naming the flag — never a silent Cargo fallthrough.
        let stranded = invoke_unchecked(patina, directory.path(), &["run", "--frob", module]);
        assert!(!stranded.status.success());
        assert!(
            String::from_utf8_lossy(&stranded.stderr).contains("--frob"),
            "stranded-artifact error should name the unknown flag: {}",
            String::from_utf8_lossy(&stranded.stderr)
        );

        // A path-like artifact that does not exist, reached after a registered flag,
        // fails closed rather than falling through to a confusing `cargo run`.
        let missing = invoke_unchecked(
            patina,
            directory.path(),
            &["run", "--seed", "1", "does-not-exist.wasm"],
        );
        assert!(!missing.status.success());
        assert!(
            String::from_utf8_lossy(&missing.stderr).contains("no such file"),
            "nonexistent artifact should fail closed: {}",
            String::from_utf8_lossy(&missing.stderr)
        );
    }

    #[test]
    fn the_cargo_family_accepts_buggify_flags_and_scrubs_an_ambient_control_plane() {
        // Buggify was reachable from the Cargo family only through PATINA_BUGGIFY* in
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
        // ambient PATINA_BUGGIFY has no CLI meaning there. Before the scrub it would
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
            &[("PATINA_BUGGIFY", "900")],
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            replayed.status.success(),
            "replay under an ambient PATINA_BUGGIFY failed:\n{stderr}"
        );
        assert!(
            !stderr.contains("PATINA_SDK_REPORT enabled=1"),
            "an ambient PATINA_BUGGIFY buggified a replay of a buggify-free trace:\n{stderr}"
        );
    }

    #[test]
    fn the_boundary_operation_budget_reaches_the_wasi_and_native_families() {
        // `--budget` bounds recorded boundary operations, which every family
        // performs; it was registered for the Cargo family alone, so a WASI or native
        // guest could not be bounded at all (wasip1's `--fuel` bounds wasm execution,
        // a different thing). One operation is below any real guest's needs, so an
        // honored budget shows up as the explicit StepBudgetExceeded failure.
        let directory = tempdir().unwrap();
        let module = directory.path().join("latency.wasm");
        fs::write(&module, wat::parse_str(WASI_FS_LATENCY).unwrap()).unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let budgeted = invoke_unchecked(
            patina,
            directory.path(),
            &["run", module.to_str().unwrap(), "--budget", "1"],
        );
        assert!(!budgeted.status.success());
        assert!(
            String::from_utf8_lossy(&budgeted.stderr).contains("step budget of 1"),
            "WASI run ignored --budget:\n{}",
            String::from_utf8_lossy(&budgeted.stderr)
        );

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let source = directory.path().join("fs_fault.rs");
            fs::write(&source, FS_FAULT_SOURCE).unwrap();
            let workspace = native_workspace();
            let bin = directory.path().join("budgeted");
            invoke(
                workspace,
                &[
                    "build",
                    source.to_str().unwrap(),
                    "--output",
                    bin.to_str().unwrap(),
                ],
            );
            let budgeted = invoke_unchecked(
                patina,
                workspace,
                &[
                    "run",
                    bin.to_str().unwrap(),
                    "--budget",
                    "1",
                    "--",
                    "latency",
                ],
            );
            assert!(!budgeted.status.success());
            assert!(
                String::from_utf8_lossy(&budgeted.stderr).contains("step budget of 1"),
                "native run ignored --budget:\n{}",
                String::from_utf8_lossy(&budgeted.stderr)
            );
        }
    }

    // `run` and `audit` infer the target family from the artifact's leading magic
    // bytes, and a capability used on the wrong family is refused up front, naming
    // the flag and the target.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_and_audit_infer_target_and_reject_cross_target_flags() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();

        // A hand-written WASI module (magic `\0asm`): `audit` lists its imports and
        // `run` executes it, both inferred from the magic bytes with no `--target`.
        let module = directory.path().join("noop.wasm");
        fs::write(
            &module,
            wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
                .unwrap(),
        )
        .unwrap();
        invoke(workspace, &["audit", module.to_str().unwrap()]);
        invoke(workspace, &["run", module.to_str().unwrap(), "--seed", "1"]);

        // `--allow` is native-only, so auditing a WASI module with it is refused.
        let allow_on_wasm = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "audit",
                module.to_str().unwrap(),
                "--allow",
                "clock_gettime",
            ],
        );
        assert!(!allow_on_wasm.status.success());
        let allow_stderr = String::from_utf8_lossy(&allow_on_wasm.stderr);
        assert!(
            allow_stderr.contains("--allow") && allow_stderr.contains("WASI"),
            "missing --allow-on-wasm diagnostic:\n{allow_stderr}"
        );

        // Native crash-restart lifecycle is not wired through WASI yet. Refuse the
        // selector by name instead of preserving the old rollback-and-continue
        // hybrid, even for a no-op guest that would never reach the selector.
        let crash_on_wasm = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", module.to_str().unwrap(), "--fs-crash-at", "close:1"],
        );
        assert!(!crash_on_wasm.status.success());
        let crash_stderr = String::from_utf8_lossy(&crash_on_wasm.stderr);
        assert!(
            crash_stderr.contains("--fs-crash-at") && crash_stderr.contains("WASI"),
            "missing --fs-crash-at-on-wasm diagnostic:\n{crash_stderr}"
        );

        // `--sleep-jitter-nanos` is now honored on a WASI `run`: the wasip1 host
        // applies the seeded jitter at its single sleep entry (`Preview1Host::
        // sleep_until`, also covering `poll_oneoff` timeouts), so a knob the no-op
        // guest never triggers simply runs clean rather than being refused.
        invoke(
            workspace,
            &[
                "run",
                module.to_str().unwrap(),
                "--sleep-jitter-nanos",
                "1..2",
            ],
        );

        // A native binary (Mach-O/ELF magic): `build` (default `--target native`),
        // `audit`, and `run` all infer the native path.
        let source = directory.path().join("noop.rs");
        fs::write(&source, "fn main() { println!(\"NATIVE_OK\"); }").unwrap();
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
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert!(String::from_utf8_lossy(&ran.stdout).contains("NATIVE_OK"));

        // `build --target wasi` is package-only and thread-free: a `.rs` source and
        // `--yield-points` are both refused before any toolchain work.
        let wasi_single = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["build", source.to_str().unwrap(), "--target", "wasi"],
        );
        assert!(!wasi_single.status.success());
        assert!(String::from_utf8_lossy(&wasi_single.stderr).contains("native-only"));

        let wasi_yield = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["build", "somepkg", "--target", "wasi", "--yield-points"],
        );
        assert!(!wasi_yield.status.success());
        let yield_stderr = String::from_utf8_lossy(&wasi_yield.stderr);
        assert!(
            yield_stderr.contains("--yield-points") && yield_stderr.contains("wasip1"),
            "missing yield-points-on-wasi diagnostic:\n{yield_stderr}"
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

    // Phase 2: `--arg=--help` is the only way to deliver a literal `--help` to a WASI
    // guest, because a bare `--help` before `--` is intercepted as Patina help. This
    // pins both halves: the inline form runs the guest; the space form shows help.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn inline_arg_delivers_literal_help_while_space_form_shows_help() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("noop.wasm");
        fs::write(
            &module,
            wat::parse_str("(module (func (export \"_start\")))").unwrap(),
        )
        .unwrap();
        let module = module.to_str().unwrap();

        // Inline: the guest runs and exits 0; Patina help is NOT shown.
        let inline = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", module, "--arg=--help"],
        );
        assert!(
            inline.status.success(),
            "inline --arg=--help failed: {}\n{}",
            inline.status,
            String::from_utf8_lossy(&inline.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&inline.stdout).contains("cargo patina run"),
            "inline --arg=--help wrongly triggered Patina help"
        );

        // Space form: the bare `--help` is intercepted and prints run help (exit 0).
        let spaced = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", module, "--arg", "--help"],
        );
        assert!(spaced.status.success(), "run --arg --help should exit 0");
        assert!(
            String::from_utf8_lossy(&spaced.stdout).contains("cargo patina run"),
            "space-form --help should show run help:\n{}",
            String::from_utf8_lossy(&spaced.stdout)
        );
    }

    // Phase 2: a path-like positional that does not exist fails closed with a clear
    // "no such file" (exit 2), instead of falling through to a confusing `cargo run`.
    #[test]
    fn nonexistent_wasm_positional_fails_closed() {
        let directory = tempdir().unwrap();
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", "definitely-missing.wasm"],
        );
        assert_eq!(output.status.code(), Some(2), "expected a usage-error exit");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("no such file"),
            "missing the fail-closed message:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
