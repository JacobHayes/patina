//! Native virtual-time calibration and the step budget.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A calibration busy-wait converges on virtual time (the failure mode is a
    // hang) and replays, and the same spin stopped by `--budget` under `--record`
    // still leaves a truncated but loadable trace: the stop flushes the
    // recording before it aborts.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_calibration_busy_wait_converges_and_a_budget_stop_keeps_its_trace() {
        let guest = native_build::source_guest("calibration_spin", CALIBRATION_SPIN_SOURCE);
        let output = guest.assert_run_success(1, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let field = |prefix: &str| -> u64 {
            let line = stdout
                .lines()
                .find(|line| line.starts_with(prefix))
                .unwrap();
            line[prefix.len()..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        // It converges just past the window: the escalation token ends each step
        // at most 1 ms on, and the reads' own charges add the rest.
        let elapsed = field("CALIBRATION elapsed_ns=");
        assert!(
            (10_000_000..11_000_000).contains(&elapsed),
            "unexpected derived elapsed:\n{stdout}"
        );
        // Both sides of the ratio come from the same clock, so the derived rate is
        // the 1 GHz mapping, to within the reads charged between the two sides.
        let hz = field("CALIBRATION hz=");
        assert!(
            hz.abs_diff(1_000_000_000) < 1_000_000,
            "calibration did not derive 1 GHz:\n{stdout}"
        );

        let trace = guest.dir.path().join("budget.patina");
        let stopped = guest.command(
            "run",
            &[
                "--seed",
                "1",
                "--budget",
                "5000",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let stderr = String::from_utf8_lossy(&stopped.stderr).into_owned();
        assert!(
            !stopped.status.success() && stderr.contains("step budget of 5000"),
            "the budget must stop this run:\n{stderr}"
        );
        let bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(&trace).unwrap()).expect("truncated trace must parse");
        let events = bundle["timelines"][0]["decisions"].as_array().unwrap();
        assert_eq!(
            events.len(),
            5000,
            "the truncated trace should hold every op performed before the stop"
        );
    }
}
