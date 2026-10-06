//! Native environment, working-directory, and fault-free replay configuration.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A guest that touches the deterministic filesystem, so its first effect
    // boundary routes through `ensure_runtime` (a guest that only writes stdout is
    // captured without a runtime check and would never observe a failed init). The
    // fault-config conflict is resolved at runtime init, before this body runs, so
    // under a conflicting replay the filesystem write never executes — the boundary
    // aborts with the runtime's diagnostic first.
    const FS_TOUCH_SOURCE: &str = r#"
use std::fs;

fn main() {
    fs::write("/probe", b"x").unwrap();
    println!("TOUCH_ok");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_env_injection_records_replays_and_tempdir_is_seed_stable() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("env_tmp_guest");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            r#"[package]
name = "env-tmp-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
tempfile = "3"
"#,
        )
        .unwrap();
        fs::write(
            package.join("src/main.rs"),
            r#"fn main() {
    let value = std::env::var("PATINA_TEST_ENV").unwrap_or_else(|_| "<missing>".to_string());
    let dir = tempfile::Builder::new()
        .prefix("patina-env-")
        .tempdir()
        .expect("tempdir under deterministic /tmp");
    let file = dir.path().join("value.txt");
    std::fs::write(&file, value.as_bytes()).unwrap();
    let read_back = std::fs::read_to_string(&file).unwrap();
    println!(
        "NATIVE_ENV_TMP value={} path={} read={}",
        value,
        dir.path().display(),
        read_back
    );
}
"#,
        )
        .unwrap();

        let workspace = native_workspace();
        let bin = directory.path().join("env-tmp-bin");
        invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap();

        let empty_a = invoke(workspace, &["run", bin, "--seed", "7"]);
        let empty_b = invoke(workspace, &["run", bin, "--seed", "7"]);
        assert_eq!(
            empty_a.stdout, empty_b.stdout,
            "tempfile path must be same-seed deterministic with an empty guest env"
        );
        let empty_stdout = String::from_utf8_lossy(&empty_a.stdout);
        assert!(empty_stdout.contains("value=<missing>"), "{empty_stdout}");
        assert!(empty_stdout.contains("path=/tmp/"), "{empty_stdout}");

        let trace = directory.path().join("env-tmp.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "7",
                "--env",
                "PATINA_TEST_ENV=alpha",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            recorded.stdout, replayed.stdout,
            "native replay must restore --env and tempfile effects flag-free"
        );
        let recorded_stdout = String::from_utf8_lossy(&recorded.stdout);
        assert!(recorded_stdout.contains("value=alpha"), "{recorded_stdout}");
        assert!(recorded_stdout.contains("read=alpha"), "{recorded_stdout}");
        assert!(recorded_stdout.contains("path=/tmp/"), "{recorded_stdout}");

        let trace_text = fs::read_to_string(&trace).unwrap();
        assert!(trace_text.contains("\"guest_env\":{"), "{trace_text}");
        assert!(
            trace_text.contains("\"PATINA_TEST_ENV\":\"alpha\""),
            "{trace_text}"
        );

        let conflict = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                bin,
                trace.to_str().unwrap(),
                "--env",
                "PATINA_TEST_ENV=beta",
            ],
        );
        assert!(!conflict.status.success());
        let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
        assert!(
            conflict_stderr.contains("does not accept --env")
                && conflict_stderr.contains("trace is authoritative"),
            "native replay conflict should refuse re-supplied --env:\n{conflict_stderr}"
        );
    }

    // The working directory is modeled process state: `run --cwd` sets the starting
    // point (recorded into trace metadata and restored flag-free on replay), a
    // relative path resolves against it, `set_current_dir` moves it, and
    // `current_dir` reports the directory's CURRENT name. RED before F3: `chdir`
    // was a process-class deny-trap and `getcwd` a constant "/".
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_cwd_flag_records_replays_and_relative_paths_resolve_against_it() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("cwd_guest.rs");
        fs::write(
            &source,
            r#"fn main() {
    let start = std::env::current_dir().unwrap();
    std::fs::write("relative.txt", b"from the cwd").unwrap();
    let absolute = start.join("relative.txt");
    let read_back = std::fs::read_to_string(&absolute).unwrap();
    std::fs::create_dir("nested").unwrap();
    std::env::set_current_dir("nested").unwrap();
    let moved = std::env::current_dir().unwrap();
    let parent_file = std::fs::read_to_string("../relative.txt").unwrap();
    std::env::set_current_dir("/").unwrap();
    let root = std::env::current_dir().unwrap();
    println!(
        "NATIVE_CWD start={} read={} moved={} parent={} root={}",
        start.display(),
        read_back,
        moved.display(),
        parent_file,
        root.display()
    );
}
"#,
        )
        .unwrap();

        let workspace = native_workspace();
        let bin = directory.path().join("cwd-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap();

        // The default working directory is the root of the deterministic image.
        let at_root = invoke(workspace, &["run", bin, "--seed", "3"]);
        let at_root_stdout = String::from_utf8_lossy(&at_root.stdout);
        assert!(
            at_root_stdout.contains(
                "NATIVE_CWD start=/ read=from the cwd moved=/nested parent=from the cwd root=/"
            ),
            "{at_root_stdout}"
        );

        let trace = directory.path().join("cwd.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "3",
                "--cwd",
                "/tmp",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let recorded_stdout = String::from_utf8_lossy(&recorded.stdout);
        assert!(
        recorded_stdout.contains(
            "NATIVE_CWD start=/tmp read=from the cwd moved=/tmp/nested parent=from the cwd root=/"
        ),
        "{recorded_stdout}"
    );
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            recorded.stdout, replayed.stdout,
            "native replay must restore --cwd flag-free"
        );
        let trace_text = fs::read_to_string(&trace).unwrap();
        assert!(
            trace_text.contains("\"guest_cwd\":\"/tmp\""),
            "{trace_text}"
        );

        // Replay refuses a re-supplied --cwd: the trace is authoritative.
        let conflict = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["replay", bin, trace.to_str().unwrap(), "--cwd", "/"],
        );
        assert!(!conflict.status.success());
        let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
        assert!(
            conflict_stderr.contains("does not accept --cwd")
                && conflict_stderr.contains("trace is authoritative"),
            "native replay conflict should refuse re-supplied --cwd:\n{conflict_stderr}"
        );

        // A --cwd that is not a directory in the image refuses the run by name
        // rather than answering ENOENT to every relative path.
        let missing = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin, "--seed", "3", "--cwd", "/no/such/dir"],
        );
        assert!(!missing.status.success());
        let missing_stderr = String::from_utf8_lossy(&missing.stderr);
        assert!(
            missing_stderr.contains("--cwd \"/no/such/dir\" is not a directory"),
            "a missing --cwd must be refused by name:\n{missing_stderr}"
        );
        let relative = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin, "--seed", "3", "--cwd", "relative/dir"],
        );
        assert!(!relative.status.success());
        let relative_stderr = String::from_utf8_lossy(&relative.stderr);
        assert!(
            relative_stderr.contains("must be an absolute virtual path"),
            "a relative --cwd must be refused:\n{relative_stderr}"
        );
    }

    // Guest-driven environment mutation is a deterministic in-process operation, so
    // `setenv`/`unsetenv` succeed and every reader agrees: the `getenv` interposer,
    // the `environ` array std::env::vars walks, and the seeded `--env` map share one
    // source of truth. Mutations are derived from guest control flow rather than the
    // host, so nothing is recorded per mutation — only the initial `--env` set lives
    // in the trace metadata — and replay reproduces the whole sequence byte for byte.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_guest_env_mutation_is_coherent_and_replays() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("env_mutation.rs");
        fs::write(
            &source,
            r#"fn scan() -> String {
    let mut entries: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    entries.sort();
    entries.join(",")
}

fn main() {
    let seeded = std::env::var("SEEDED").unwrap_or_else(|_| "<missing>".to_string());
    println!("start seeded={seeded} scan=[{}]", scan());

    unsafe { std::env::set_var("ALPHA", "one") };
    println!(
        "set alpha={} scan=[{}]",
        std::env::var("ALPHA").unwrap(),
        scan()
    );

    unsafe { std::env::set_var("ALPHA", "two") };
    println!(
        "overwrite alpha={} scan=[{}]",
        std::env::var("ALPHA").unwrap(),
        scan()
    );

    unsafe { std::env::set_var("SEEDED", "replaced") };
    println!("reseed seeded={} scan=[{}]", std::env::var("SEEDED").unwrap(), scan());

    unsafe { std::env::remove_var("ALPHA") };
    println!(
        "remove alpha_missing={} scan=[{}]",
        std::env::var_os("ALPHA").is_none(),
        scan()
    );

    unsafe { std::env::remove_var("SEEDED") };
    unsafe { std::env::remove_var("NEVER_SET") };
    println!("drain scan=[{}]", scan());
}
"#,
        )
        .unwrap();

        let workspace = native_workspace();
        let bin = directory.path().join("env-mutation");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap();

        let seeded_run = invoke(
            workspace,
            &["run", bin, "--seed", "11", "--env", "SEEDED=from-flag"],
        );
        let stdout = String::from_utf8_lossy(&seeded_run.stdout);
        // The seeded `--env` map is visible to BOTH readers from the first line: the
        // getenv interposer and the environ array std::env::vars walks.
        assert!(
            stdout.contains("start seeded=from-flag scan=[SEEDED=from-flag]"),
            "{stdout}"
        );
        // set_var is visible to getenv and to the rebuilt environ array.
        assert!(
            stdout.contains("set alpha=one scan=[ALPHA=one,SEEDED=from-flag]"),
            "{stdout}"
        );
        assert!(
            stdout.contains("overwrite alpha=two scan=[ALPHA=two,SEEDED=from-flag]"),
            "{stdout}"
        );
        // A guest overwrite of a `--env`-seeded key wins over the seeded value; the
        // trace metadata still records only what `--env` supplied.
        assert!(
            stdout.contains("reseed seeded=replaced scan=[ALPHA=two,SEEDED=replaced]"),
            "{stdout}"
        );
        assert!(
            stdout.contains("remove alpha_missing=true scan=[SEEDED=replaced]"),
            "{stdout}"
        );
        // Removing every key — including one that was never set — leaves an empty
        // environ, exactly as the run started before `--env`.
        assert!(stdout.contains("drain scan=[]"), "{stdout}");

        // Same seed, same bytes: mutation is a pure function of guest control flow.
        let repeat = invoke(
            workspace,
            &["run", bin, "--seed", "11", "--env", "SEEDED=from-flag"],
        );
        assert_eq!(
            seeded_run.stdout, repeat.stdout,
            "guest env mutation must be byte-identical across same-seed runs"
        );

        let trace = directory.path().join("env-mutation.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "11",
                "--env",
                "SEEDED=from-flag",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            recorded.stdout, replayed.stdout,
            "replay must reproduce a guest that mutates its environment, flag-free"
        );
        assert_eq!(
            seeded_run.stdout, replayed.stdout,
            "the recorded/replayed run must match the seeded run byte for byte"
        );

        // Only the initial `--env` set is metadata; the guest's later overwrite of
        // SEEDED and its ALPHA writes leave no per-mutation record.
        let trace_text = fs::read_to_string(&trace).unwrap();
        assert!(
            trace_text.contains("\"SEEDED\":\"from-flag\""),
            "{trace_text}"
        );
        assert!(
            !trace_text.contains("replaced") && !trace_text.contains("ALPHA"),
            "guest env mutations must not be recorded as trace events:\n{trace_text}"
        );

        // Re-recording produces a byte-identical trace: no mutation-derived state
        // leaks into the recorded stream.
        let trace_again = directory.path().join("env-mutation-again.patina");
        invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "11",
                "--env",
                "SEEDED=from-flag",
                "--record",
                trace_again.to_str().unwrap(),
            ],
        );
        assert_eq!(
            fs::read(&trace).unwrap(),
            fs::read(&trace_again).unwrap(),
            "repeat records of an env-mutating guest must be byte-identical"
        );
    }

    // The trace is authoritative for the fault configuration, so `replay` exposes no
    // fault knobs at all: a flag-free `replay` reproduces the recorded fault run, and
    // supplying a fault knob is refused UP FRONT (a CLI usage error naming the flag),
    // never silently applied. The underlying runtime reconcile-conflict fail-closed
    // path is covered directly by patina-dst-runtime's
    // `reconcile_replay_faults_enforces_the_authoritative_trace_contract`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_replay_rejects_fault_knobs_and_reproduces_flag_free() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("fs_touch.rs");
        fs::write(&source, FS_TOUCH_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("fs-touch");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let trace = directory.path().join("faults.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "0",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "trivial-faults",
                "--net-latency-nanos",
                "1000",
            ],
        );

        // Flag-free replay reproduces the recorded fault run — the fault config comes
        // from the trace, not the command line.
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "trivial-faults",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&recorded.stdout),
            "flag-free replay must reproduce the recorded fault run"
        );

        // Supplying a fault knob to `replay` is refused up front (the trace is
        // authoritative), naming the flag — never silently applied.
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "trivial-faults",
                "--net-latency-nanos",
                "2000",
            ],
        );
        let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            !rejected.status.success(),
            "replay must reject a fault knob:\nstderr:\n{rejected_stderr}"
        );
        assert!(
            rejected_stderr.contains("--net-latency-nanos")
                && rejected_stderr.contains("does not accept"),
            "the rejection must name the offending flag:\nstderr:\n{rejected_stderr}"
        );
    }
}
