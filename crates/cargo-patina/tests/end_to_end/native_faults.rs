//! Native filesystem fault injection, reporting, and flag-free replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Errors, short transfers and latency on the native family, each seen by the
    // guest, reported non-vacuous on stderr, and reproduced by a flag-free replay.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_faults_and_latency_reach_the_guest_report_and_replay() {
        let guest = native_build::source_guest("fs_fault", FS_FAULT_SOURCE);
        let bin = guest.binary.to_str().unwrap();
        let workspace = native_workspace();
        let assert_non_vacuous = |output: &Output, what: &str| {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
                "the fs fault report must prove {what} was non-vacuous:\n{stderr}"
            );
        };

        // The seed picks a fault schedule whose first injected error lands on the
        // read under test, not on the setup write or the open before it; the
        // schedule is a function of the guest's own filesystem operations, so two
        // recordings at the seed are byte-identical.
        let record = |name: &str| {
            let trace = guest.dir.path().join(name);
            let output = invoke(
                workspace,
                &[
                    "run",
                    bin,
                    "--seed",
                    "70",
                    "--record",
                    trace.to_str().unwrap(),
                    "--fs-error-permille",
                    "100",
                    "--",
                    "eio_read",
                ],
            );
            (output, trace)
        };
        let (eio, trace) = record("eio1.patina");
        let (repeat, repeat_trace) = record("eio2.patina");
        let eio_line = stdout_line_with(&eio, "NATIVE_FS_FAULT_RESULT");
        assert_eq!(
            eio_line,
            stdout_line_with(&repeat, "NATIVE_FS_FAULT_RESULT")
        );
        assert_eq!(fs::read(&trace).unwrap(), fs::read(&repeat_trace).unwrap());
        assert_non_vacuous(&eio, "the read EIO");
        let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            eio_line,
            stdout_line_with(&replayed, "NATIVE_FS_FAULT_RESULT"),
            "flag-free replay must reproduce the fs error"
        );

        let enospc = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "29",
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
                    bin,
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
            assert_non_vacuous(&output, mode);
        }

        let elapsed_of = |output: &Output| -> u128 {
            stdout_line_with(output, "NATIVE_FS_FAULT_RESULT")
                .rsplit_once('=')
                .expect("elapsed_nanos=N")
                .1
                .parse()
                .expect("elapsed nanos")
        };
        // Control: a knob-free run advances virtual time across the operation by
        // the calls' own charges alone (well under a microsecond each).
        let charged = elapsed_of(&invoke(
            workspace,
            &["run", bin, "--seed", "4", "--", "latency"],
        ));
        assert!(
            charged < 10_000,
            "a knob-free run must not delay fs ops: {charged}"
        );

        // A fixed 1 ms latency, seen by the guest as virtual elapsed time: the
        // Context-side application site charges it exactly once.
        let latency_trace = guest.dir.path().join("fs-latency.patina");
        let delayed = invoke(
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "4",
                "--record",
                latency_trace.to_str().unwrap(),
                "--fs-latency-nanos",
                "1000000..1000000",
                "--",
                "latency",
            ],
        );
        let elapsed = elapsed_of(&delayed);
        let delayed_by = elapsed - charged;
        assert!(
            delayed_by >= 1_000_000 && delayed_by % 1_000_000 == 0,
            "native guest saw {elapsed}ns across the fs op, not whole 1ms latencies"
        );
        assert_non_vacuous(&delayed, "the latency knob");
        let replayed = invoke(workspace, &["replay", bin, latency_trace.to_str().unwrap()]);
        assert_eq!(elapsed_of(&replayed), elapsed);
    }
}
