//! Cargo-family seeded processes and record/replay identity.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn separate_processes_repeat_record_and_replay() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("fixture");
        create_fixture(&fixture);

        let first = invoke(&fixture, &["run", "--seed", "123"]);
        let repeated = invoke(&fixture, &["run", "--seed", "123"]);
        let different = invoke(&fixture, &["run", "--seed", "124"]);
        let first_result = result_line(&first);
        assert_eq!(result_line(&repeated), first_result);
        assert!(first_result.contains("cfg=true"));
        // Wall time is epoch + uptime; both clocks advance by the 10ns slept.
        let uptime = patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS + 10;
        let default_wall = patina_dst_runtime::DEFAULT_REALTIME_EPOCH_NANOS + uptime;
        let configured_wall = 1_000_000_000_000_000_000 + uptime;
        assert!(
            first_result.contains(&format!(" time={uptime} wall={default_wall} host=patina ")),
            "{first_result}"
        );
        assert_ne!(result_line(&different), first_result);
        let parameterized = invoke(&fixture, &["run", "--seed", "123", "--param", "zone=a"]);
        assert!(result_line(&parameterized).contains("zone=Some(\"a\")"));

        // `--realtime-epoch` and `--hostname` move the guest's wall clock and node
        // name and nothing else.
        let facts_args = [
            "run",
            "--seed",
            "123",
            "--realtime-epoch",
            "2001-09-09T01:46:40Z",
            "--hostname",
            "db-1",
        ];
        let shifted = result_line(&invoke(&fixture, &facts_args)).to_string();
        assert!(
            shifted.contains(&format!(" wall={configured_wall} host=db-1 ")),
            "{shifted}"
        );
        assert_eq!(
            shifted.replace(
                &format!(" wall={configured_wall} host=db-1 "),
                &format!(" wall={default_wall} host=patina ")
            ),
            first_result
        );
        // Recorded into the trace, restored by a flag-free replay, and immune to
        // ambient control-plane values (the Cargo family scrubs them).
        let facts_trace = directory.path().join("facts.patina");
        let mut record_args = facts_args.to_vec();
        record_args.extend(["--record", facts_trace.to_str().unwrap()]);
        assert_eq!(result_line(&invoke(&fixture, &record_args)), shifted);
        let metadata = patina_dst_trace::TraceBundle::load(&facts_trace)
            .unwrap()
            .metadata;
        assert_eq!(metadata.realtime_epoch_nanos, 1_000_000_000_000_000_000);
        assert_eq!(metadata.hostname, "db-1");
        let replayed_facts = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &["replay", ".", facts_trace.to_str().unwrap()],
            &[
                ("PATINA_REALTIME_EPOCH_NANOS", "7"),
                ("PATINA_GUEST_HOSTNAME", "ambient"),
            ],
        );
        assert!(
            replayed_facts.status.success(),
            "{}",
            String::from_utf8_lossy(&replayed_facts.stderr)
        );
        assert_eq!(result_line(&replayed_facts), shifted);
        for (flag, value) in [
            ("--realtime-epoch", "2001-09-09T01:46:40Z"),
            ("--hostname", "db-1"),
        ] {
            let refused = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                &fixture,
                &["replay", ".", facts_trace.to_str().unwrap(), flag, value],
            );
            assert!(!refused.status.success(), "replay accepted {flag}");
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains(flag),
                "{}",
                String::from_utf8_lossy(&refused.stderr)
            );
        }

        let budgeted = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &["run", "--seed", "123", "--budget", "1"],
        );
        assert!(!budgeted.status.success());
        assert!(String::from_utf8_lossy(&budgeted.stderr).contains("StepBudgetExceeded"));

        let trace = directory.path().join("run.patina");
        let recorded = invoke(
            &fixture,
            &["run", "--seed", "123", "--record", trace.to_str().unwrap()],
        );
        assert!(trace.is_file());
        // Replaying a recording is the `replay` verb's job now. `.` is the package
        // positional (the fixture is the invocation's working directory), and the
        // trace positional replaces the old `--replay` PATH; the run's semantics are
        // restored from the trace, so replay is flag-free.
        let replayed = invoke(&fixture, &["replay", ".", trace.to_str().unwrap()]);
        assert_eq!(result_line(&recorded), result_line(&replayed));
        assert_eq!(result_line(&replayed), first_result);

        let branched = invoke(
            &fixture,
            &[
                "replay",
                ".",
                trace.to_str().unwrap(),
                "--branch",
                "--from",
                "1",
                "--branch-seed",
                "999",
                "--branch-id",
                "branch-999",
            ],
        );
        assert_ne!(result_line(&branched), first_result);
        let replayed_branch = invoke(
            &fixture,
            &[
                "replay",
                ".",
                trace.to_str().unwrap(),
                "--timeline",
                "branch-999",
            ],
        );
        assert_eq!(result_line(&replayed_branch), result_line(&branched));

        invoke(&fixture, &["test", "--seed", "123"]);

        writeln!(
            OpenOptions::new()
                .append(true)
                .open(fixture.join("src/main.rs"))
                .unwrap(),
            "// changed after recording"
        )
        .unwrap();
        let incompatible = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &["replay", ".", trace.to_str().unwrap()],
        );
        assert!(!incompatible.status.success());
        let stderr = String::from_utf8_lossy(&incompatible.stderr);
        assert!(
            stderr.contains("FingerprintMismatch") || stderr.contains("fingerprint mismatch"),
            "missing fingerprint diagnostic in stderr:\n{stderr}"
        );
    }
}
