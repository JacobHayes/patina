//! Campaign fault-plane selection: `--faults=PLANE,...` draws only the named
//! planes, the out-dir records the subset, and a continuation keeps it.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// Opens a file and writes it 32 times. Exit 3 means a filesystem fault
    /// reached the guest (a failed open or write, or a short write); otherwise it
    /// exits 7, so every generation is a notable run whose drawn flags the
    /// campaign records.
    const FS_WRITER: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 16) "abcdefgh")
  (func (export "_start")
    (local $fd i32) (local $round i32)
    (if (i32.ne
          (call $path_open
            (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4)
            (i32.const 1) (i64.const 66) (i64.const 0) (i32.const 0) (i32.const 100))
          (i32.const 0))
      (then (call $proc_exit (i32.const 3))))
    (local.set $fd (i32.load (i32.const 100)))
    (i32.store (i32.const 64) (i32.const 16))
    (i32.store (i32.const 68) (i32.const 8))
    (loop $writes
      (if (i32.ne
            (call $fd_write (local.get $fd) (i32.const 64) (i32.const 1) (i32.const 80))
            (i32.const 0))
        (then (call $proc_exit (i32.const 3))))
      (if (i32.ne (i32.load (i32.const 80)) (i32.const 8))
        (then (call $proc_exit (i32.const 3))))
      (local.set $round (i32.add (local.get $round) (i32.const 1)))
      (br_if $writes (i32.lt_u (local.get $round) (i32.const 32))))
    (call $proc_exit (i32.const 7))))"#;

    /// A generation in which an fs fault reached the guest is a VIOLATION.
    const FS_FAULT_IS_A_VIOLATION: &str = r#"{"classify": {"exit_codes": {"VIOLATION": [3]}}}"#;

    struct Fixture {
        _directory: tempfile::TempDir,
        module: PathBuf,
        spec: PathBuf,
        cwd: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        let module = directory.path().join("fs-writer.wasm");
        fs::write(&module, wat::parse_str(FS_WRITER).unwrap()).unwrap();
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
        invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), cwd, &argv)
    }

    fn fresh(fixture: &Fixture, out: &Path, gens: &str, faults: &str) -> serde_json::Value {
        let output = campaign(
            &fixture.cwd,
            &[
                fixture.module.to_str().unwrap(),
                "--gens",
                gens,
                faults,
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

    /// The valid planes, from the registry's own `--faults` grammar.
    fn registry_planes(cwd: &Path) -> Vec<String> {
        let help = campaign(cwd, &["--help", "--format", "json"]);
        let help: serde_json::Value = serde_json::from_slice(&help.stdout).unwrap();
        help["verb"]["flag_groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["flags"].as_array().unwrap())
            .find(|flag| flag["name"] == "--faults")
            .expect("--faults is registered")["choices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|plane| plane.as_str().unwrap().to_string())
            .collect()
    }

    /// A `--faults=sleep,net` campaign draws and fires only those planes (the
    /// every-plane control shows fs faults do reach this guest), the out-dir
    /// records the subset, a continuation keeps it and refuses a new one, and
    /// an unknown plane is a usage error naming the valid planes.
    #[test]
    fn a_plane_subset_never_draws_another_plane_and_a_continuation_keeps_it() {
        let fixture = fixture();
        let every = fresh(&fixture, &fixture.cwd.join("every"), "4", "--faults");
        assert!(
            runs(&every)
                .iter()
                .any(|run| run["class"] == "VIOLATION" && drew(run, "--fs-")),
            "no every-plane generation faulted the guest's fs, so the subset run below \
             would prove nothing:\n{:#}",
            every["notable_runs"]
        );

        let out = fixture.cwd.join("camp");
        let recorded = fresh(&fixture, &out, "2", "--faults=sleep,net");
        assert_eq!(
            recorded["spec"]["faults"],
            serde_json::json!(["net", "sleep"])
        );
        assert_ran(&campaign(
            &fixture.cwd,
            &["--extend", "2", "--out-dir", out.to_str().unwrap()],
        ));
        let extended = campaign_state_without_invocations(&out.join("campaign-state.json"));
        assert_eq!(extended["spec"]["faults"], recorded["spec"]["faults"]);
        assert_eq!(runs(&extended).len(), 4, "every generation is recorded");
        for run in runs(&extended) {
            assert!(!drew(run, "--fs-"), "an fs knob was drawn: {run:#}");
            assert!(drew(run, "--net-") && drew(run, "--sleep-"), "{run:#}");
            assert_ne!(run["class"], "VIOLATION", "an fs fault fired: {run:#}");
        }
        let classes = extended["classes"].as_object().unwrap();
        assert!(
            classes.keys().all(|class| !class.starts_with("VACUOUS_")),
            "a plane counted as vacuous: {classes:?}"
        );

        for continuation in [
            vec!["--extend", "1", "--faults=fs"],
            vec!["--extend", "1", "--faults"],
            vec!["--resume", "--faults=net,sleep"],
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

        let planes = registry_planes(&fixture.cwd);
        assert!(!planes.is_empty());
        let unknown_out = fixture.cwd.join("unknown");
        let refused = campaign(
            &fixture.cwd,
            &[
                fixture.module.to_str().unwrap(),
                "--faults=net,disk",
                "--out-dir",
                unknown_out.to_str().unwrap(),
            ],
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(2), "accepted:\n{stderr}");
        // The message, without the synopsis a usage error appends.
        let message = stderr.split("\n\n").next().unwrap();
        for plane in &planes {
            assert!(
                message.contains(plane.as_str()),
                "{plane} unnamed:\n{stderr}"
            );
        }
        assert!(!unknown_out.exists(), "a refused campaign wrote an out-dir");
    }
}
