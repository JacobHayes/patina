//! Native virtual-time calibration and the step budget.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A calibration busy-wait converges on virtual time (the failure mode is a
    // hang) and replays, and the same spin stopped by `--budget` under `--record`
    // still leaves a truncated but loadable trace: the stop flushes the
    // recording before it aborts.
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

    // A busy-wait whose only exit is the monotonic clock passing a deadline
    // of its own, `ms` milliseconds away.
    const CLOCK_BUSY_WAIT_SOURCE: &str = r#"
use std::time::{Duration, Instant};

fn main() {
    let ms: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let start = Instant::now();
    let until = start + Duration::from_millis(ms);
    while Instant::now() < until {}
    println!("BUSY_WAIT elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    /// The `u64` after `prefix` on the stdout line that starts with it.
    fn stdout_field(output: &Output, prefix: &str) -> u64 {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix} line:\n{stdout}"));
        line[prefix.len()..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    // The loop's exit depends on the clock alone, so it ends when virtual
    // time reaches its deadline, wherever that is: no later than half a
    // percent of the wait past it (a millisecond for a short one), on every
    // seed, recorded and replayed alike. RED when a poll streak was stopped
    // as churn after a fixed number of escalations: every wait past a
    // quarter of a second was.
    #[test]
    fn a_clock_busy_wait_ends_at_its_own_deadline() {
        let guest = native_build::source_guest("clock_busy_wait", CLOCK_BUSY_WAIT_SOURCE);
        let on_time = |output: &Output, ms: u64| {
            let elapsed = stdout_field(output, "BUSY_WAIT elapsed_ns=");
            let deadline = ms * 1_000_000;
            assert!(
                (deadline..=deadline + (deadline / 200).max(1_000_000) + 100_000)
                    .contains(&elapsed),
                "a {ms} ms busy-wait took {elapsed} ns"
            );
        };
        on_time(&guest.assert_run_success(0, &["--", "300"]), 300);
        // Another seed, and a longer wait, past where the token starts to
        // follow the streak.
        for (seed, ms) in [("1", 300), ("0", 2_000)] {
            let output = guest.command("run", &["--seed", seed, "--", &ms.to_string()]);
            assert!(output.status.success());
            on_time(&output, ms);
        }
    }

    // CPU-bound work that reads the clock now and then, beside a thread in a
    // 60 s timed wait.
    const CLOCK_READING_WORK_SOURCE: &str = r#"
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

fn main() {
    let done = Arc::new(AtomicBool::new(false));
    let (_keep, never) = mpsc::channel::<()>();
    let seen = done.clone();
    let start = Instant::now();
    let waiter = std::thread::spawn(move || {
        let _ = never.recv_timeout(Duration::from_secs(60));
        println!(
            "WAITER work_done={} waited_ns={}",
            seen.load(Ordering::SeqCst),
            start.elapsed().as_nanos()
        );
    });
    let mut x = 1u64;
    for i in 0..20_000u64 {
        for _ in 0..50 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        }
        if i % 4 == 0 {
            let _ = Instant::now();
        }
    }
    done.store(true, Ordering::SeqCst);
    println!("WORK elapsed_ns={} x={x}", start.elapsed().as_nanos());
    waiter.join().unwrap();
}
"#;

    // The work costs its metered computation and the CPU time of its reads,
    // far under a second,
    // and the 60 s wait ends at 60 s, after it. RED when a poll streak was
    // charged up to the earliest pending deadline: the work took 60 s and
    // the waiter timed out before it ended.
    #[test]
    fn work_that_reads_the_clock_does_not_make_a_peers_timeout_pass() {
        let guest = native_build::source_guest("clock_reading_work", CLOCK_READING_WORK_SOURCE);
        for seed in [0, 1] {
            let output = guest.assert_run_success(seed, &[]);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let work = stdout_field(&output, "WORK elapsed_ns=");
            assert!(work < 1_000_000_000, "the work took {work} ns:\n{stdout}");
            assert!(
                stdout.contains("WAITER work_done=true "),
                "the wait ended before the work:\n{stdout}"
            );
            let waited = stdout_field(&output, "WAITER work_done=true waited_ns=");
            assert!(
                (60_000_000_000..60_010_000_000).contains(&waited),
                "the 60 s wait took {waited} ns"
            );
        }
    }

    // A thread that only yields until a peer, asleep for `ms` milliseconds,
    // sets a flag; with no argument nobody ever does, and the loop reads the
    // clock instead.
    const POLL_LOOP_SOURCE: &str = r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn main() {
    let flag = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    match std::env::args().nth(1) {
        Some(ms) => {
            let ms: u64 = ms.parse().unwrap();
            let set = flag.clone();
            let sleeper = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(ms));
                set.store(true, Ordering::Release);
            });
            while !flag.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            sleeper.join().unwrap();
            println!("YIELD_WAIT elapsed_ns={}", start.elapsed().as_nanos());
        }
        None => {
            while !flag.load(Ordering::Acquire) {
                std::hint::black_box(Instant::now());
            }
        }
    }
}
"#;

    // A loop of yields is a poll streak like a loop of clock reads: time
    // passes for it faster than the yields' own charges, so the sleeper's
    // deadline arrives inside a budget those charges alone would run out of
    // (a quarter-microsecond a yield is 800,000 yields to 200 ms). And a poll
    // loop that nothing will ever end stops as a liveness finding once it
    // has been charged the no-progress horizon, never a hang.
    #[test]
    fn a_poll_loop_reaches_a_sleeping_peer_and_one_nothing_ends_is_a_finding() {
        let guest = native_build::source_guest("poll_loop", POLL_LOOP_SOURCE);
        let output = guest.assert_run_success(1, &["--budget", "1000000", "--", "200"]);
        let elapsed = stdout_field(&output, "YIELD_WAIT elapsed_ns=");
        assert!(
            (200_000_000..202_000_000).contains(&elapsed),
            "the 200 ms sleep was seen as {elapsed} ns"
        );

        let stuck = guest.command("run", &["--seed", "1", "--format", "json"]);
        let result: serde_json::Value = serde_json::from_slice(&stuck.stdout).unwrap();
        assert_eq!(
            (
                &result["result"],
                &result["attribution"],
                &result["exit_code"]
            ),
            (&"liveness".into(), &"guest".into(), &1.into()),
            "{result:#}"
        );
        let finding = &result["runtime_findings"][0];
        assert_eq!(finding["detail"], "no-progress", "{result:#}");
        // The whole horizon went by in virtual time before the stop.
        assert!(
            finding["vtime_ns"].as_u64().unwrap() - patina_dst_abi::DEFAULT_BOOT_ORIGIN_NANOS
                >= 600_000_000_000,
            "{result:#}"
        );
    }
}
