//! Native edge hooks (coverage and yield stride), teardown, and report controls.

#[cfg(test)]
mod tests {
    use super::super::*;

    // An `--instrument` guest, run at `--yield-stride 1`, whose MAIN thread owns a
    // thread-local with an instrumented `Drop`, plus a worker thread that recreates
    // the joined-task / still-exiting-host-thread teardown window. At stride 1 the main
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
        // Instrumented teardown work: enough edges that the edge hook
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

    // One `--instrument` build of the teardown guest, run at `--yield-stride 1`,
    // carries the instrumented binary's contracts:
    //
    // * the root task records zero teardown yields and a worker's thread-local
    //   teardown runs no hook after its task finished, so the run completes and
    //   record/replay is byte-identical (a trailing, host-ordering-dependent yield
    //   would make a recording whose own replay fails closed);
    // * `--coverage-out` writes the `patina.covmap/v1` artifact and the numeric
    //   report, and the map is byte-identical across same-seed runs and between a
    //   record and its replay;
    // * a replay whose guard-driven TaskYield stream stops matching the recording
    //   fails with the classified diagnostic (per-task yield accounting plus the
    //   instrumented guest site), never the bare "trace ended before operation N"
    //   cursor error. Dropping the recording's final TaskYield(+scheduler_next)
    //   pair synthesizes the on-disk shape the Darwin join-teardown race produced,
    //   so this proves the detector without needing the race to fire.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_yield_stride_tears_down_covers_and_classifies_divergence() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("main_tls.rs");
        fs::write(&source, MAIN_TLS_TEARDOWN_SOURCE).unwrap();
        let workspace = native_workspace();
        let binary = dir.path().join("main-tls");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
                "--instrument",
            ],
        );
        let guest = common::native::Guest { dir, binary };
        let (output, trace) = guest.assert_recorded(1, &["--yield-stride", "1"]);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("MAIN_TLS_ok"),
            "main-thread TLS teardown run did not complete:\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let directory = guest.dir.path();
        let bin = guest.binary.to_str().unwrap();
        let covered = |verb: &str, args: &[&str], name: &str| {
            let map = directory.join(name);
            let mut argv = vec![verb, bin];
            argv.extend_from_slice(args);
            argv.extend(["--coverage-out", map.to_str().unwrap()]);
            let output = invoke(workspace, &argv);
            assert_covmap_has_magic_and_report(&map, &output);
            fs::read(&map).unwrap()
        };
        let cov_trace = directory.join("covered.patina");
        let recorded = covered(
            "run",
            &[
                "--seed",
                "3",
                "--yield-stride",
                "1",
                "--record",
                cov_trace.to_str().unwrap(),
            ],
            "record.covmap",
        );
        assert_eq!(
            recorded,
            covered(
                "run",
                &["--seed", "3", "--yield-stride", "1"],
                "repeat.covmap"
            ),
            "same-seed coverage maps must be byte-identical"
        );
        assert_eq!(
            recorded,
            covered("replay", &[cov_trace.to_str().unwrap()], "replay.covmap"),
            "record and replay coverage maps must be byte-identical"
        );

        let short = directory.join("short.patina");
        drop_trailing_task_yield(&trace, &short);
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["replay", bin, short.to_str().unwrap()],
        );
        assert!(
            !replayed.status.success(),
            "replaying a yield-short recording must fail closed"
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        for detail in [
            "yield-point replay divergence on task",
            "TaskYield operations for it",
            "divergent yield point: guest pc",
        ] {
            assert!(
                stderr.contains(detail),
                "the divergence must be classified with yield accounting and the guest site; missing {detail:?}:\n{stderr}"
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
        let guest = native_build::source_guest("reports", REPORT_KNOB_SOURCE);
        let directory = &guest.dir;
        let workspace = native_workspace();
        let bin = guest.binary.to_str().unwrap();

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
                    bin,
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
            &["replay", bin, loud_trace.to_str().unwrap()],
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

        // `--coverage-out` is legal only on an `--instrument` build: the plain
        // binary fails closed with the build hint.
        let refused_map = directory.path().join("plain.covmap");
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                bin,
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
                && refused_stderr.contains("cargo patina build --instrument"),
            "plain-binary coverage request should fail closed with the build hint:\n{refused_stderr}"
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
            next[0]["kind"], "scheduler_next",
            "expected the recording to end with a scheduler_next decision"
        );
        let yielded = decisions.pop().unwrap();
        assert_eq!(
            yielded[0]["kind"], "task_yield",
            "expected a trailing task_yield decision before the final scheduler_next"
        );
        fs::write(dest, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    // A lost update in atomics-only code: each worker reads the counter, passes
    // the value through a function (an instrumented edge, so a scheduling point
    // can fall between the read and the write), and writes it back plus one. No
    // interposed call sits in the window, so it is reachable only through the
    // edge hook's scheduling points.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const ATOMICS_RACE_SOURCE: &str = r#"
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

static COUNT: AtomicU64 = AtomicU64::new(0);

#[inline(never)]
fn carry(value: u64) -> u64 {
    std::hint::black_box(value)
}

fn main() {
    let workers: Vec<_> = (0..2)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..50 {
                    let seen = carry(COUNT.load(Ordering::Relaxed));
                    COUNT.store(seen + 1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let total = COUNT.load(Ordering::Relaxed);
    if total != 100 {
        println!("LOST_UPDATE total={total}");
        std::process::exit(3);
    }
    println!("RACE_CLEAN");
}
"#;

    // One instrumented binary, two strides: at stride 0 the window is
    // unreachable at every seed, at stride 1 some seed loses an update, and
    // that seed's recording replays to the same failure from the trace alone.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_yield_stride_reaches_an_atomics_only_race_that_stride_zero_cannot() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("race.rs");
        fs::write(&source, ATOMICS_RACE_SOURCE).unwrap();
        let workspace = native_workspace();
        let binary = dir.path().join("race");
        let bin = binary.to_str().unwrap();
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin,
                "--instrument",
            ],
        );
        let run =
            |args: &[&str]| invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, args);
        let lost =
            |output: &Output| String::from_utf8_lossy(&output.stdout).contains("LOST_UPDATE");
        let seeds: Vec<String> = (0..8).map(|seed| seed.to_string()).collect();
        for seed in &seeds {
            let output = run(&["run", bin, "--seed", seed]);
            assert!(
                output.status.success() && !lost(&output),
                "stride 0 must leave the window unreachable (seed {seed}):\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        let failing = seeds
            .iter()
            .find(|seed| lost(&run(&["run", bin, "--seed", seed, "--yield-stride", "1"])))
            .expect("stride 1 must reach the lost update at some seed");
        let trace = dir.path().join("lost.patina");
        let recorded = run(&[
            "run",
            bin,
            "--seed",
            failing,
            "--yield-stride",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ]);
        assert!(lost(&recorded));
        let replayed = run(&["replay", bin, trace.to_str().unwrap()]);
        assert_eq!(
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&recorded.stdout),
            "the replay takes the recorded stride and loses the same update:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
    }
}
