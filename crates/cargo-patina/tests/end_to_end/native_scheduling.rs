//! Native virtual-time calibration and seeded lock scheduling.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_calibration_busy_wait_converges_and_replays_identically() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("calibration_spin.rs");
        fs::write(&source, CALIBRATION_SPIN_SOURCE).unwrap();
        let bin = directory.path().join("calibration-spin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let patina = env!("CARGO_BIN_EXE_cargo-patina");

        // (a) It converges at all — the RED half of this test is a hang, so any
        // completion is the signal. And it converges to the EXACT virtual time the
        // token schedule predicts: ten escalating rescues (1_023_000 ns) plus nine
        // at the 1 ms ceiling is the least cumulative advance past the 10 ms window.
        let first = invoke_unchecked(
            patina,
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            first.status.success(),
            "the calibration spin did not converge\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        let stdout = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            stdout.contains("CALIBRATION elapsed_ns=10023000"),
            "unexpected derived elapsed:\n{stdout}"
        );
        // Both sides of the ratio come from the same clock, so the derived rate is
        // exact — the 1 GHz mapping, confirmed to the digit.
        assert!(
            stdout.contains("CALIBRATION hz=1000000000"),
            "calibration did not derive exactly 1 GHz:\n{stdout}"
        );

        // (b) Same seed, byte-identical.
        let second = invoke_unchecked(
            patina,
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert_eq!(
            first.stdout, second.stdout,
            "a same-seed repeat of the calibration spin diverged"
        );

        // (c) record -> replay identity: the rescue is a recorded `SleepUntil`, so a
        // replay re-derives the same answer from the trace rather than re-deciding.
        let trace = directory.path().join("calibration.patina");
        let recorded = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "7",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "calibration-spin",
            ],
        );
        assert!(
            recorded.status.success(),
            "recording the calibration spin failed:\n{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        let replayed = invoke_unchecked(
            patina,
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "calibration-spin",
            ],
        );
        assert!(
            replayed.status.success(),
            "replaying the calibration spin failed:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        assert_eq!(
            recorded.stdout, replayed.stdout,
            "replay of the calibration spin diverged from the recording"
        );
    }

    // Two threads contending on a std::sync::RwLock. On the toolchain in use std's
    // queue-based RwLock takes its contended `write()` path through
    // lock_contended → thread::park → dispatch_semaphore_wait — i.e. the interposed
    // Darwin Parker. Each thread holds the write lock across a scheduling point, so
    // the other writers PARK on it; the acquisition order is therefore chosen by
    // DetScheduler. The total is schedule-invariant (correctly locked, no lost
    // updates), the order is byte-identical per seed, and the winning thread order
    // varies across seeds — this is the load-bearing piece for reaching a
    // lock-contention race (e.g. rung 1's lost-update) deterministically.
    const RWLOCK_CONTENTION_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn main() {
    let log = Arc::new(RwLock::new(Vec::<u32>::new()));
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let log = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                let mut g = log.write().unwrap();
                g.push(id);
                thread::sleep(Duration::from_nanos(1));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_log = log.read().unwrap();
    let sum: u32 = final_log.iter().sum();
    println!("RWLOCK_RESULT len={} sum={} order={:?}", final_log.len(), sum, &*final_log);
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_rwlock_contention_is_seed_deterministic_and_varies_across_seeds() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("rwlock.rs");
        fs::write(&source, RWLOCK_CONTENTION_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("rwlock");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let mut outputs = std::collections::BTreeSet::new();
        for seed in ["1", "2", "3", "4", "5", "6"] {
            let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
            // Schedule-invariant total (correctly locked, no lost updates).
            assert!(
                baseline.contains("RWLOCK_RESULT len=12 sum=12"),
                "unexpected rwlock output at seed {seed}: {baseline}"
            );
            for _ in 0..2 {
                let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
                assert_eq!(
                    baseline,
                    String::from_utf8_lossy(&again.stdout),
                    "rwlock contention order is not byte-identical across runs at seed {seed}"
                );
            }
            outputs.insert(baseline);
        }
        // The acquisition order is scheduler-controlled, so it must actually vary
        // across seeds — a fixed order would mean the schedule isn't seed-driven.
        assert!(
            outputs.len() >= 2,
            "rwlock acquisition order did not vary across seeds: {outputs:?}"
        );

        let trace = directory.path().join("rwlock.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "3",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "rwlock-contention",
            ],
        );
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "rwlock-contention",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "rwlock record and strict replay diverged"
        );
    }
}
