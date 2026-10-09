//! Native filesystem fault injection, reporting, and flag-free replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_fault_errors_and_shorts_are_deterministic_replayable_and_reported() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("fs_fault.rs");
        fs::write(&source, FS_FAULT_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("fs-fault");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap().to_owned();

        let trace1 = directory.path().join("eio1.patina");
        let trace2 = directory.path().join("eio2.patina");
        // The seeds pick a fault schedule whose first injected error lands on the
        // operation under test (the read / the write), not on the setup write or
        // the open before it; the schedule is a function of the whole operation
        // stream, which the resolver's per-path metadata lookups are part of.
        let eio_args = |trace: &Path| {
            vec![
                "run".to_string(),
                bin.clone(),
                "--seed".to_string(),
                "58".to_string(),
                "--record".to_string(),
                trace.to_str().unwrap().to_string(),
                "--fs-error-permille".to_string(),
                "100".to_string(),
                "--".to_string(),
                "eio_read".to_string(),
            ]
        };
        let run_vec = |args: Vec<String>| {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            invoke(workspace, &refs)
        };
        let eio1 = run_vec(eio_args(&trace1));
        let eio2 = run_vec(eio_args(&trace2));
        let eio_line = stdout_line_with(&eio1, "NATIVE_FS_FAULT_RESULT");
        assert_eq!(eio_line, stdout_line_with(&eio2, "NATIVE_FS_FAULT_RESULT"));
        assert_eq!(fs::read(&trace1).unwrap(), fs::read(&trace2).unwrap());
        let eio_stderr = String::from_utf8_lossy(&eio1.stderr);
        assert!(
            eio_stderr.contains("PATINA_FS_FAULT_REPORT") && eio_stderr.contains("vacuous=0"),
            "fs fault report must prove the read EIO was non-vacuous:\n{eio_stderr}"
        );

        let replayed = invoke(workspace, &["replay", &bin, trace1.to_str().unwrap()]);
        assert_eq!(
            eio_line,
            stdout_line_with(&replayed, "NATIVE_FS_FAULT_RESULT"),
            "flag-free replay must reproduce the fs error"
        );
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                &bin,
                trace1.to_str().unwrap(),
                "--fs-short-permille",
                "1",
            ],
        );
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("--fs-short-permille"));

        let enospc = invoke(
            workspace,
            &[
                "run",
                &bin,
                "--seed",
                "60",
                "--fs-error-permille",
                "100",
                "--",
                "enospc_write",
            ],
        );
        assert!(stdout_line_with(&enospc, "NATIVE_FS_FAULT_RESULT").contains("errno=28"));

        for mode in ["short_write", "short_read"] {
            let output = invoke(
                workspace,
                &[
                    "run",
                    &bin,
                    "--seed",
                    "5",
                    "--fs-short-permille",
                    "1000",
                    "--",
                    mode,
                ],
            );
            let line = stdout_line_with(&output, "NATIVE_FS_FAULT_RESULT");
            assert!(
                line.contains(mode),
                "missing short-I/O result for {mode}: {line}"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
                "short-I/O run should be non-vacuous for {mode}:\n{stderr}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_latency_is_observable_in_the_guest_and_replays_flag_free() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("fs_fault.rs");
        fs::write(&source, FS_FAULT_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("fs-latency");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bin = bin.to_str().unwrap().to_owned();
        let elapsed_of = |output: &std::process::Output| -> u128 {
            stdout_line_with(output, "NATIVE_FS_FAULT_RESULT")
                .rsplit_once('=')
                .expect("elapsed_nanos=N")
                .1
                .parse()
                .expect("elapsed nanos")
        };

        // Control: a knob-free run advances virtual time across the operation
        // by the calls' own charges alone (well under a microsecond each).
        let clean = invoke(workspace, &["run", &bin, "--seed", "4", "--", "latency"]);
        let charged = elapsed_of(&clean);
        assert!(
            charged < 10_000,
            "a knob-free run must not delay fs ops: {charged}"
        );

        // MUST delay: the same fixed 1ms latency the WASI leg asserts, seen by the
        // native guest as virtual elapsed time — the two families share the ONE
        // Context-side application site, so neither doubles it nor misses it.
        let trace = directory.path().join("fs-latency.patina");
        let args = vec![
            "run".to_string(),
            bin.clone(),
            "--seed".to_string(),
            "4".to_string(),
            "--record".to_string(),
            trace.to_str().unwrap().to_string(),
            "--fs-latency-nanos".to_string(),
            "1000000..1000000".to_string(),
            "--".to_string(),
            "latency".to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let delayed = invoke(workspace, &refs);
        let elapsed = elapsed_of(&delayed);
        // The same calls, each fs op now 1 ms later.
        let delayed_by = elapsed - charged;
        assert!(
            delayed_by >= 1_000_000 && delayed_by % 1_000_000 == 0,
            "native guest saw {elapsed}ns across the fs op, not whole 1ms latencies"
        );
        let stderr = String::from_utf8_lossy(&delayed.stderr);
        assert!(
            stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
            "fs fault report must prove the latency knob was non-vacuous:\n{stderr}"
        );

        // Flag-free replay restores the latency from the trace and reproduces it.
        let replayed = invoke(workspace, &["replay", &bin, trace.to_str().unwrap()]);
        assert_eq!(elapsed_of(&replayed), elapsed);

        // Re-supplying the knob on replay is refused: the trace is authoritative.
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                &bin,
                trace.to_str().unwrap(),
                "--fs-latency-nanos",
                "1..2",
            ],
        );
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("--fs-latency-nanos"));
    }
}
