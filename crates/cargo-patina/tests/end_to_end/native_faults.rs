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

    /// A targeted writeback failure lands on the operation it names at every
    /// seed, is recorded in the trace and replayed flag-free, and leaves what
    /// Linux leaves: the failing `fsync` reports EIO and its retry succeeds,
    /// another description reports it once through a `WAIT`ing
    /// `sync_file_range` and once through `syncfs`; a failed `sync(2)`
    /// reports nothing and leaves the error for a later open's `fsync` and
    /// for `syncfs`. Either way a store that fails closed and re-reads after
    /// `DONTNEED` sees the durable page, not the write the failure dropped.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_targeted_writeback_failure_lands_at_any_seed_and_a_reread_sees_the_disk() {
        let guest = native_build::source_guest("writeback", WRITEBACK_SOURCE);
        let bin = guest.binary.to_str().unwrap();
        let workspace = native_workspace();
        let run = |seed: &str, target: &str, mode: &str, record: Option<&Path>| {
            let mut arguments = vec!["run", bin, "--seed", seed, "--fs-error-at", target];
            if let Some(trace) = record {
                arguments.extend(["--record", trace.to_str().unwrap()]);
            }
            arguments.extend(["--", mode]);
            invoke(workspace, &arguments)
        };
        let saw = |output: &Output| stdout_line_with(output, "NATIVE_WRITEBACK");

        let expected = [
            (
                "sync:2",
                "fsync",
                "fsync=5,0 wait=5,0 syncfs=5,0 reread=durable",
            ),
            ("sync_all:1", "sync", "fsync=5,0 syncfs=5,0 reread=durable"),
        ];
        for (target, mode, seen) in expected {
            let trace = guest.dir.path().join(format!("{mode}.patina"));
            let recorded = run("1", target, mode, Some(&trace));
            assert!(saw(&recorded).ends_with(seen), "{mode}: {}", saw(&recorded));
            let stderr = String::from_utf8_lossy(&recorded.stderr);
            assert!(
                stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
                "{mode}: the target must have landed:\n{stderr}"
            );
            assert_eq!(saw(&run("2", target, mode, None)), saw(&recorded));
            let replayed = invoke(workspace, &["replay", bin, trace.to_str().unwrap()]);
            assert_eq!(saw(&replayed), saw(&recorded), "{mode}: flag-free replay");
        }

        // A target past the guest's last fsync never lands, and says so.
        let missed = run("1", "sync:50", "fsync", None);
        assert!(saw(&missed).contains("fsync=0,0"));
        let stderr = String::from_utf8_lossy(&missed.stderr);
        assert!(
            stderr.contains("vacuous=1"),
            "a target that never landed must be vacuous:\n{stderr}"
        );
    }
}
