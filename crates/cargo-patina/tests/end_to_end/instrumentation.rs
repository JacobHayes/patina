//! Native yield points, coverage, teardown, and report controls.

#[cfg(test)]
mod tests {
    use super::super::*;

    // Two threads incrementing a shared counter through the atomics-only
    // `std::sync::RwLock` fast path — the classic lost-update shape. Reads no
    // argv/env, so it audits clean without `--allow-unsupported-symbols`.
    const YIELD_POINTS_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;

fn main() {
    let cell = Arc::new(RwLock::new(0u64));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for _ in 0..50 {
                    let current = *cell.read().unwrap();
                    *cell.write().unwrap() = current + 1;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    println!("YP_RESULT total={}", *cell.read().unwrap());
}
"#;

    // A `--yield-points` binary schedules under a denser policy than a plain build,
    // so their traces are different guests. `native-run` folds the yield-point
    // marker into the compatibility fingerprint, so a trace recorded from an
    // instrumented binary must fail closed when replayed against a plain one (and
    // the reverse), never produce a silently different run. The instrumented binary
    // replays its own trace exactly.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_yield_points_trace_fails_closed_against_plain_binary() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("yp.rs");
        fs::write(&source, YIELD_POINTS_SOURCE).unwrap();
        let workspace = native_workspace();
        let plain = directory.path().join("plain");
        let instrumented = directory.path().join("instrumented");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                plain.to_str().unwrap(),
            ],
        );
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                instrumented.to_str().unwrap(),
                "--yield-points",
            ],
        );

        let yp_trace = directory.path().join("yp.patina");
        invoke(
            workspace,
            &[
                "run",
                instrumented.to_str().unwrap(),
                "--seed",
                "3",
                "--record",
                yp_trace.to_str().unwrap(),
            ],
        );

        // The instrumented binary replays its own trace exactly.
        let self_replay = invoke(
            workspace,
            &[
                "replay",
                instrumented.to_str().unwrap(),
                yp_trace.to_str().unwrap(),
            ],
        );
        assert!(
            self_replay.status.success(),
            "an instrumented binary must replay its own yield-points trace"
        );

        // The plain binary must refuse the yield-points trace: the fingerprint suffix
        // makes the policies incompatible, so replay fails closed rather than running
        // a silently different schedule.
        let rejected = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                plain.to_str().unwrap(),
                yp_trace.to_str().unwrap(),
            ],
        );
        let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            !rejected.status.success(),
            "a yield-points trace must not replay against a plain binary; got success\nstdout:\n{}\nstderr:\n{rejected_stderr}",
            String::from_utf8_lossy(&rejected.stdout),
        );
        // Fail-closed, but say WHY: the shim surfaces the runtime's fingerprint
        // mismatch instead of the generic "no runtime installed" abort.
        assert!(
            rejected_stderr.contains("failed to initialize")
                && rejected_stderr.contains("fingerprint mismatch"),
            "cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_stderr}"
        );

        // And the reverse: a plain trace must not replay against the instrumented
        // binary.
        let plain_trace = directory.path().join("plain.patina");
        invoke(
            workspace,
            &[
                "run",
                plain.to_str().unwrap(),
                "--seed",
                "3",
                "--record",
                plain_trace.to_str().unwrap(),
            ],
        );
        let rejected_reverse = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                instrumented.to_str().unwrap(),
                plain_trace.to_str().unwrap(),
            ],
        );
        let rejected_reverse_stderr = String::from_utf8_lossy(&rejected_reverse.stderr);
        assert!(
            !rejected_reverse.status.success(),
            "a plain trace must not replay against a yield-points binary:\nstderr:\n{rejected_reverse_stderr}"
        );
        assert!(
            rejected_reverse_stderr.contains("failed to initialize")
                && rejected_reverse_stderr.contains("fingerprint mismatch"),
            "reverse cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_reverse_stderr}"
        );
    }

    // Wave-A coverage detector/determinism gate. `--coverage-out` is legal only on
    // the yield-point build (D1 plain-binary refusal); a yield-point run writes the
    // `patina.covmap/v1` artifact, emits the numeric report, and the full map is
    // byte-identical for same-seed repeats and record→replay at two seeds.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_coverage_out_writes_covmap_and_is_byte_identical() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("yp_cov.rs");
        fs::write(&source, YIELD_POINTS_SOURCE).unwrap();
        let workspace = native_workspace();
        let plain = directory.path().join("plain-cov");
        let instrumented = directory.path().join("instrumented-cov");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                plain.to_str().unwrap(),
            ],
        );
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                instrumented.to_str().unwrap(),
                "--yield-points",
            ],
        );

        let refused_map = directory.path().join("plain.covmap");
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                plain.to_str().unwrap(),
                "--seed",
                "1",
                "--coverage-out",
                refused_map.to_str().unwrap(),
            ],
        );
        let refused_stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            !refused.status.success()
                && refused_stderr.contains("--coverage-out requires")
                && refused_stderr.contains("cargo patina build --yield-points"),
            "D1 plain-binary coverage request should fail closed with the yield-points hint:\n{refused_stderr}"
        );

        for seed in [3u64, 7] {
            let seed = seed.to_string();
            let first_map = directory.path().join(format!("seed-{seed}-a.covmap"));
            let first = invoke(
                workspace,
                &[
                    "run",
                    instrumented.to_str().unwrap(),
                    "--seed",
                    &seed,
                    "--coverage-out",
                    first_map.to_str().unwrap(),
                ],
            );
            assert_covmap_has_magic_and_report(&first_map, &first);

            let second_map = directory.path().join(format!("seed-{seed}-b.covmap"));
            let second = invoke(
                workspace,
                &[
                    "run",
                    instrumented.to_str().unwrap(),
                    "--seed",
                    &seed,
                    "--coverage-out",
                    second_map.to_str().unwrap(),
                ],
            );
            assert_covmap_has_magic_and_report(&second_map, &second);
            assert_eq!(
                fs::read(&first_map).unwrap(),
                fs::read(&second_map).unwrap(),
                "same-seed coverage maps must be byte-identical for seed {seed}"
            );

            let trace = directory.path().join(format!("seed-{seed}.patina"));
            let record_map = directory.path().join(format!("seed-{seed}-record.covmap"));
            let recorded = invoke(
                workspace,
                &[
                    "run",
                    instrumented.to_str().unwrap(),
                    "--seed",
                    &seed,
                    "--record",
                    trace.to_str().unwrap(),
                    "--coverage-out",
                    record_map.to_str().unwrap(),
                ],
            );
            assert_covmap_has_magic_and_report(&record_map, &recorded);

            let replay_map = directory.path().join(format!("seed-{seed}-replay.covmap"));
            let replayed = invoke(
                workspace,
                &[
                    "replay",
                    instrumented.to_str().unwrap(),
                    trace.to_str().unwrap(),
                    "--coverage-out",
                    replay_map.to_str().unwrap(),
                ],
            );
            assert_covmap_has_magic_and_report(&replay_map, &replayed);
            assert_eq!(
                fs::read(&record_map).unwrap(),
                fs::read(&replay_map).unwrap(),
                "record→replay coverage maps must be byte-identical for seed {seed}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_covmap_has_magic_and_report(path: &Path, output: &Output) {
        let bytes =
            fs::read(path).unwrap_or_else(|error| panic!("missing covmap {path:?}: {error}"));
        assert!(
            bytes.starts_with(b"patina.covmap/v1"),
            "coverage map {path:?} missing magic"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("PATINA_COVERAGE_REPORT edges_total=")
                && stderr.contains("PATINA_COVERAGE map=")
                && stderr.contains("covered_permille="),
            "coverage run should emit report + pointer lines; stderr:\n{stderr}"
        );
    }

    // A guest that produces every end-of-run diagnostic a single native run can:
    // concurrent workers (schedule report) and fault-eligible filesystem traffic
    // (fs-fault report), with the swarm/liveness/policy/SDK reports armed by flags.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const REPORT_KNOB_SOURCE: &str = r#"
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0u64));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                *counter.lock().unwrap() += 1;
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    for index in 0..8 {
        let path = format!("/tmp/report-probe-{index}");
        let _ = fs::write(&path, b"payload");
        let _ = fs::read(&path);
    }
    println!("REPORT_KNOBS total={}", *counter.lock().unwrap());
}
"#;

    // Every end-of-run report knob must actually suppress its report on the NATIVE
    // family, and suppressing it must not change a single recorded byte.
    //
    // Native is the family where this cannot work by accident. The supervisor clears
    // the guest's environment, so a knob reaches the guest only if it is forwarded
    // explicitly; and the shim scrubs `environ` at startup, so by finalization the
    // interposed `getenv` returns NULL for everything and a late `std::env` read
    // cannot tell "suppressed" from "unset". Both halves were missing: only
    // `PATINA_COVERAGE_REPORT` was forwarded, and the runtime read the remaining
    // knobs from the process environment at `Context::finish` — so on this whole
    // family every documented suppressor was silently inert.
    //
    // The trace comparison is the other half of the contract: suppression is
    // presentation, never run semantics, so the recorded bytes — and with them the
    // fingerprint and everything replay reconciles — must be identical whether the
    // reports printed or not.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_report_knobs_suppress_every_report_without_touching_the_trace() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("reports.rs");
        fs::write(&source, REPORT_KNOB_SOURCE).unwrap();

        // Each knob with the line prefix it silences. `PATINA_SCHEDULE_POLICY_REPORT`
        // gates a line named `PATINA_SCHEDULE_POLICY`, so knob and prefix are spelled
        // out separately rather than derived from one another.
        let armed: &[(&str, &str)] = &[
            ("PATINA_SCHEDULE_REPORT", "PATINA_SCHEDULE_REPORT "),
            ("PATINA_SWARM_REPORT", "PATINA_SWARM_REPORT "),
            ("PATINA_LIVENESS_REPORT", "PATINA_LIVENESS_REPORT "),
            ("PATINA_SDK_REPORT", "PATINA_SDK_REPORT "),
            ("PATINA_FS_FAULT_REPORT", "PATINA_FS_FAULT_REPORT "),
            ("PATINA_SCHEDULE_POLICY_REPORT", "PATINA_SCHEDULE_POLICY "),
        ];
        let loud_trace = directory.path().join("loud.patina");
        let quiet_trace = directory.path().join("quiet.patina");
        let run = |trace: &Path, envs: &[(&str, &str)]| {
            let output = invoke_unchecked_clean_env(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &[
                    "run",
                    source.to_str().unwrap(),
                    "--seed",
                    "1",
                    "--record",
                    trace.to_str().unwrap(),
                    "--fs-error-permille",
                    "100",
                    "--swarm",
                    "--liveness-watchdog",
                    "--sched-pct",
                    "--buggify",
                ],
                envs,
            );
            assert!(
                output.status.success(),
                "native report-knob run failed with {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };

        let loud = run(&loud_trace, &[]);
        let loud_stderr = String::from_utf8_lossy(&loud.stderr).into_owned();
        for (knob, prefix) in armed {
            assert!(
                loud_stderr.contains(prefix),
                "{knob}'s report is missing from an unsuppressed run, so suppressing it \
             would prove nothing; stderr:\n{loud_stderr}"
            );
        }

        let silenced: Vec<(&str, &str)> = armed.iter().map(|(knob, _)| (*knob, "0")).collect();
        let quiet = run(&quiet_trace, &silenced);
        let quiet_stderr = String::from_utf8_lossy(&quiet.stderr).into_owned();
        for (knob, prefix) in armed {
            assert!(
                !quiet_stderr.contains(prefix),
                "{knob}=0 did not suppress its report on the native family; stderr:\n{quiet_stderr}"
            );
        }
        // The guest's own line only: the surrounding `PATINA_BUILD_ON_RUN` line names
        // a per-invocation temporary artifact path.
        let guest_line = |output: &Output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| line.starts_with("REPORT_KNOBS "))
                .unwrap_or_else(|| panic!("guest produced no output line"))
                .to_string()
        };
        assert_eq!(
            guest_line(&loud),
            guest_line(&quiet),
            "report suppression must not change the guest's own output"
        );
        assert_eq!(
            fs::read(&loud_trace).unwrap(),
            fs::read(&quiet_trace).unwrap(),
            "report suppression is presentation only: the recorded trace must be byte-identical"
        );

        // A replay reconciles against a recording made under different suppression
        // settings and reproduces the same guest output — suppression reaches neither
        // the fingerprint nor anything replay checks.
        let replayed = invoke_unchecked_clean_env(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                source.to_str().unwrap(),
                loud_trace.to_str().unwrap(),
            ],
            &silenced,
        );
        assert!(
            replayed.status.success(),
            "replay of a loud recording under suppressed reports must reconcile; stderr:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        assert!(
            String::from_utf8_lossy(&replayed.stdout).contains("REPORT_KNOBS total=60"),
            "replayed guest output changed under suppression:\n{}",
            String::from_utf8_lossy(&replayed.stdout)
        );
    }

    // A worker that uses `mpsc::recv_timeout` initializes a thread-local `Thread`
    // handle whose destructor runs at pthread exit. Under `--yield-points` that
    // destructor is instrumented std code monomorphized into the guest crate, so it
    // runs the yield hook AFTER `thread_finish` completed the task — the regression
    // that aborted with "scheduler task 2 does not exist" on a multi-thread guest. The
    // program itself is trivial and must run to completion, deterministically.
    const YIELD_TEARDOWN_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let handle = thread::spawn(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let _ = rx.recv_timeout(Duration::from_millis(5));
    });
    handle.join().unwrap();
    println!("TEARDOWN_ok");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_yield_points_survive_thread_local_teardown() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("teardown.rs");
        fs::write(&source, YIELD_TEARDOWN_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("teardown");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
                "--yield-points",
            ],
        );

        // Before the fix this aborted at thread exit; it must now run to completion.
        let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            baseline.contains("TEARDOWN_ok"),
            "yield-points teardown run did not complete: {baseline}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stderr)
        );

        // Deterministic across repeats and exactly replayable.
        for _ in 0..2 {
            let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "yield-points teardown output is not byte-identical across runs"
            );
        }
        let trace = directory.path().join("teardown.patina");
        invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replayed = invoke(
            workspace,
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert!(
            String::from_utf8_lossy(&replayed.stdout).contains("TEARDOWN_ok"),
            "replay of the yield-points teardown trace did not complete"
        );
    }

    // A `--yield-points` guest whose MAIN thread owns a thread-local with an
    // instrumented `Drop`, plus a worker thread that recreates the joined-task /
    // still-exiting-host-thread teardown window. Under `--yield-points` the main
    // thread's thread-local destructor runs instrumented code AFTER `main` returns —
    // inside the C runtime's `exit()`, which (on glibc) drives `__call_tls_dtors`
    // BEFORE the atexit-registered `patina_shutdown`. Before the `exit`-interposer
    // teardown flag, those late yields were recorded as trailing, host-teardown-
    // ordering-dependent `TaskYield`s on the ROOT task (which, unlike a worker, has
    // no `thread_finish` completion sentinel), so a record run and a replay run could
    // disagree on a final yield and abort the replay with "trace ended before
    // operation N; actual operation was TaskYield { task: TaskId(1) }" + a signal
    // death. The root task must now record exactly ZERO teardown yields, so
    // record/replay is byte-identical across repeats. On macOS (where the natural
    // `main` return keeps libSystem's own `exit` and the root task's teardown
    // yields stay recorded) the same guest exposed a second race: the joiner's
    // `Arc<thread::Inner>` drop against the worker's still-exiting host thread,
    // worth ±2 root-task yields under host load. `patina_thread_join` reaps the
    // worker's host thread on every platform, so that drop ordering is fixed and
    // the count is load-independent.
    const MAIN_TLS_TEARDOWN_SOURCE: &str = r#"
use std::cell::Cell;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct Noisy(Cell<u64>);
impl Drop for Noisy {
    fn drop(&mut self) {
        // Instrumented teardown work: enough edges that the --yield-points hook
        // fires while the main thread destroys its thread-local, at process exit.
        let mut acc = self.0.get();
        for i in 0..128u64 {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
        self.0.set(acc);
        // Keep the loop and the drop observable so neither is elided.
        if acc == 0 {
            std::process::abort();
        }
    }
}

thread_local! {
    static MAIN_LOCAL: Noisy = Noisy(Cell::new(1));
}

fn main() {
    // Initialize the main thread's thread-local so its Drop runs at exit.
    MAIN_LOCAL.with(|noisy| noisy.0.set(42));
    // A worker recreates the joined-task / still-exiting-host-thread window.
    let worker = thread::spawn(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let _ = rx.recv_timeout(Duration::from_millis(5));
    });
    worker.join().unwrap();
    println!("MAIN_TLS_ok");
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_yield_points_main_thread_tls_teardown_is_deterministic() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("main_tls.rs");
        fs::write(&source, MAIN_TLS_TEARDOWN_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("main-tls");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
                "--yield-points",
            ],
        );

        let first = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            baseline.contains("MAIN_TLS_ok"),
            "main-thread TLS teardown run did not complete: {baseline}\nstderr:\n{}",
            String::from_utf8_lossy(&first.stderr)
        );

        // Record once, then replay several times: with the root task recording ZERO
        // teardown yields, replay never exhausts the trace on a trailing teardown
        // yield. Before the fix this replay aborted (fail-closed) on Linux.
        let trace = directory.path().join("main_tls.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        for _ in 0..4 {
            let replayed = invoke(
                workspace,
                &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
            );
            assert_eq!(
                String::from_utf8_lossy(&recorded.stdout),
                String::from_utf8_lossy(&replayed.stdout),
                "main-thread TLS teardown replay diverged from the recording"
            );
        }

        // Re-record and replay repeatedly: a nondeterministic trailing teardown yield
        // would surface as a fresh recording whose own replay fails closed.
        for _ in 0..4 {
            let again = invoke(
                workspace,
                &[
                    "run",
                    bin.to_str().unwrap(),
                    "--seed",
                    "1",
                    "--record",
                    trace.to_str().unwrap(),
                ],
            );
            let replay = invoke(
                workspace,
                &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
            );
            assert_eq!(
                String::from_utf8_lossy(&again.stdout),
                String::from_utf8_lossy(&replay.stdout),
                "re-recorded main-thread TLS teardown replay diverged"
            );
        }
    }

    // Detection for the yield-accounting failure class: a `--yield-points` replay
    // whose guard-driven TaskYield stream stops matching the recording must fail
    // with the classified diagnostic — per-task record-vs-replay yield accounting
    // plus the instrumented guest site of the unmatched yield — never the bare
    // "trace ended before operation N" cursor error. Doctoring a recording by
    // dropping its final TaskYield(+scheduler_next) pair synthesizes the exact
    // on-disk shape the Darwin join-teardown race produced (a recording one root
    // yield short of what replay executes), so this proves the detector on the
    // class without needing the host-timing race to fire.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_yield_points_divergence_reports_accounting_and_site() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("main_tls.rs");
        fs::write(&source, MAIN_TLS_TEARDOWN_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("main-tls");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
                "--yield-points",
            ],
        );
        let trace = directory.path().join("full.patina");
        invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let short = directory.path().join("short.patina");
        drop_trailing_task_yield(&trace, &short);

        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["replay", bin.to_str().unwrap(), short.to_str().unwrap()],
        );
        assert!(
            !replayed.status.success(),
            "replaying a yield-short recording must fail closed"
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            stderr.contains("yield-point replay divergence on task"),
            "divergence must be classified with yield accounting, not a bare trace error:\n{stderr}"
        );
        assert!(
            stderr.contains("TaskYield operations for it"),
            "the diagnostic must report the recording's per-task yield count:\n{stderr}"
        );
        assert!(
            stderr.contains("divergent yield point: guest pc"),
            "the diagnostic must name the instrumented site of the unmatched yield:\n{stderr}"
        );
    }

    // Rewrite `source` into `dest` with the final TaskYield decision (and the
    // scheduler_next recorded after it) removed, synthesizing a recording whose
    // root-task yield count is one short of what a faithful replay executes.
    // Traces are compact, greppable JSON, so editing the decision list directly is
    // a faithful stand-in for a genuinely divergent recording.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn drop_trailing_task_yield(source: &Path, dest: &Path) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
        let timeline = &mut value["timelines"][0];
        assert_eq!(timeline["id"], "main", "expected the main timeline first");
        let decisions = timeline["decisions"].as_array_mut().unwrap();
        let next = decisions.pop().unwrap();
        assert_eq!(
            next["operation"]["kind"], "scheduler_next",
            "expected the recording to end with a scheduler_next decision"
        );
        let yielded = decisions.pop().unwrap();
        assert_eq!(
            yielded["operation"]["kind"], "task_yield",
            "expected a trailing task_yield decision before the final scheduler_next"
        );
        fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}
