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
                "-v",
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
                &["-v", "--seed", "3", "--yield-stride", "1"],
                "repeat.covmap"
            ),
            "same-seed coverage maps must be byte-identical"
        );
        assert_eq!(
            recorded,
            covered(
                "replay",
                &["-v", cov_trace.to_str().unwrap()],
                "replay.covmap"
            ),
            "record and replay coverage maps must be byte-identical"
        );

        let short = directory.join("short.patina");
        drop_trailing_task_yield(&trace, &short);
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            workspace,
            &["replay", "-v", bin, short.to_str().unwrap()],
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
                env!("CARGO_BIN_EXE_patina"),
                workspace,
                &[
                    "run",
                    "-v",
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
            env!("CARGO_BIN_EXE_patina"),
            workspace,
            &["replay", "-v", bin, loud_trace.to_str().unwrap()],
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
            env!("CARGO_BIN_EXE_patina"),
            workspace,
            &[
                "run",
                "-v",
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
                && refused_stderr.contains("patina build --instrument"),
            "plain-binary coverage request should fail closed with the build hint:\n{refused_stderr}"
        );
    }

    // Rewrite `source` into `dest` with the final TaskYield decision (and the
    // scheduler_next recorded after it) removed, synthesizing a recording whose
    // root-task yield count is one short of what a faithful replay executes.
    // Traces are compact, greppable JSON, so editing the decision list directly is
    // a faithful stand-in for a genuinely divergent recording.
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
        let run = |args: &[&str]| invoke_unchecked(env!("CARGO_BIN_EXE_patina"), workspace, args);
        let lost =
            |output: &Output| String::from_utf8_lossy(&output.stdout).contains("LOST_UPDATE");
        let seeds: Vec<String> = (0..8).map(|seed| seed.to_string()).collect();
        for seed in &seeds {
            let output = run(&["run", "-v", bin, "--seed", seed]);
            assert!(
                output.status.success() && !lost(&output),
                "stride 0 must leave the window unreachable (seed {seed}):\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        let failing = seeds
            .iter()
            .find(|seed| {
                lost(&run(&[
                    "run",
                    "-v",
                    bin,
                    "--seed",
                    seed,
                    "--yield-stride",
                    "1",
                ]))
            })
            .expect("stride 1 must reach the lost update at some seed");
        let trace = dir.path().join("lost.patina");
        let recorded = run(&[
            "run",
            "-v",
            bin,
            "--seed",
            failing,
            "--yield-stride",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ]);
        assert!(lost(&recorded));
        let replayed = run(&["replay", "-v", bin, trace.to_str().unwrap()]);
        assert_eq!(
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&recorded.stdout),
            "the replay takes the recorded stride and loses the same update:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
    }

    // One thread spins without calls (re-sending to its own channel) until
    // a peer, asleep for a millisecond, sets a flag.
    const SPIN_BESIDE_SLEEPER_SOURCE: &str = r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let start = Instant::now();
    let woke = Arc::new(AtomicBool::new(false));
    let set = woke.clone();
    let sleeper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1));
        set.store(true, Ordering::Release);
    });
    let spinner = thread::spawn(move || {
        let (tx, rx) = mpsc::channel::<u64>();
        let mut resent = 0u64;
        while !woke.load(Ordering::Acquire) {
            tx.send(resent).unwrap();
            resent = rx.try_recv().unwrap() + 1;
        }
    });
    sleeper.join().unwrap();
    spinner.join().unwrap();
    println!("SPIN_BESIDE_SLEEPER elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    /// Build `source` as an instrumented guest named `name` in `dir`.
    fn instrumented(dir: &Path, name: &str, source: &str) -> PathBuf {
        let path = dir.join(format!("{name}.rs"));
        fs::write(&path, source).unwrap();
        let binary = dir.join(name);
        invoke(
            native_workspace(),
            &[
                "build",
                path.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
                "--instrument",
            ],
        );
        binary
    }

    /// The `--format json` result of `patina <arguments>`, which must end
    /// within a minute.
    fn result_of(arguments: &[&str]) -> serde_json::Value {
        let output = invoke_with_deadline(
            env!("CARGO_BIN_EXE_patina"),
            native_workspace(),
            arguments,
            Duration::from_secs(60),
        )
        .unwrap_or_else(|| panic!("the run never ended: {arguments:?}"));
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "no result for {arguments:?}: {error}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    /// The class and exit status of a result.
    fn class_of(result: &serde_json::Value) -> (String, i64) {
        (
            result["result"].as_str().unwrap().to_owned(),
            result["exit_code"].as_i64().unwrap(),
        )
    }

    /// The value of `key=` on the guest's stdout line.
    fn reported(result: &serde_json::Value, key: &str) -> u64 {
        let stdout = result["stdout"].as_str().unwrap();
        stdout
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} in {stdout:?}"))
            .parse()
            .unwrap()
    }

    // An instrumented spinner's edges are computation, charged as virtual
    // time, and it yields to a runnable peer once it has computed a 1 ms
    // slice. So the sleeper's millisecond passes and the run ends cleanly,
    // with or without a yield stride, on every seed, and the guest sees the
    // millisecond it slept and the slices it waited for its turn. RED under time model 5: the edges charged
    // nothing, time stood still, and the host-time bound ended the run as a
    // timeout.
    #[test]
    fn a_spinner_beside_a_sleeper_proceeds() {
        let dir = tempdir().unwrap();
        let binary = instrumented(
            dir.path(),
            "spin_beside_sleeper",
            SPIN_BESIDE_SLEEPER_SOURCE,
        );
        let bin = binary.to_str().unwrap();
        for stride in ["0", "300"] {
            for seed in ["1", "2", "3"] {
                let result = result_of(&[
                    "run",
                    "-v",
                    bin,
                    "--yield-stride",
                    stride,
                    "--seed",
                    seed,
                    "--format",
                    "json",
                ]);
                assert_eq!(
                    class_of(&result),
                    ("ok".to_owned(), 0),
                    "stride {stride} seed {seed}: {result:#}"
                );
                // The sleeper waits for its turn among the runnable tasks,
                // a slice at a time, then sleeps its millisecond.
                let elapsed = reported(&result, "elapsed_ns");
                assert!(
                    (1_000_000..50_000_000).contains(&elapsed),
                    "stride {stride} seed {seed}: the 1 ms sleep took {elapsed} ns"
                );
            }
        }
    }

    // A spinner that waits for a flag nothing sets, beside a peer that wakes
    // every millisecond and goes back to sleep: time passes (the spinner's
    // edges are charged), the peer keeps running, and nothing makes
    // progress. The CPU time the spinner is charged reaches the no-progress
    // horizon and the run is a liveness finding there, the same stop on
    // replay. RED under time model 5: the host-time bound's timeout.
    const SPIN_BESIDE_PERIODIC_SOURCE: &str = r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

fn main() {
    let never = Arc::new(AtomicBool::new(false));
    let flag = never.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1));
    });
    let spinner = thread::spawn(move || {
        let mut turns = 0u64;
        while !flag.load(Ordering::Acquire) {
            turns = turns.wrapping_add(1);
            std::hint::black_box(turns);
        }
    });
    spinner.join().unwrap();
    println!("SPIN_ENDED");
}
"#;

    #[test]
    fn a_spinner_beside_a_periodic_sleeper_is_a_liveness_finding_at_the_horizon() {
        let dir = tempdir().unwrap();
        let binary = instrumented(dir.path(), "spin_periodic", SPIN_BESIDE_PERIODIC_SOURCE);
        let bin = binary.to_str().unwrap();
        let trace = dir.path().join("spin_periodic.patina");
        // A 200 ms horizon: the default's ten minutes of edges take minutes
        // of host time.
        let budget = 200_000_000u64;
        let watchdog = format!("--liveness-watchdog={budget}");
        let recorded = result_of(&[
            "run",
            bin,
            "--seed",
            "1",
            &watchdog,
            "--record",
            trace.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(
            class_of(&recorded),
            ("liveness".to_owned(), 1),
            "{recorded:#}"
        );
        let finding = &recorded["runtime_findings"][0];
        assert_eq!(finding["detail"], "no-progress", "{recorded:#}");
        // The stop came once the horizon's CPU time had been charged: no
        // sooner, and within a slice of it.
        let elapsed =
            finding["vtime_ns"].as_u64().unwrap() - patina_dst_abi::DEFAULT_BOOT_ORIGIN_NANOS;
        assert!(
            (budget..budget + 50_000_000).contains(&elapsed),
            "stopped {elapsed} ns in: {recorded:#}"
        );
        let replayed = result_of(&["replay", bin, trace.to_str().unwrap(), "--format", "json"]);
        assert_eq!(class_of(&replayed), class_of(&recorded), "{replayed:#}");
        assert_eq!(
            replayed["runtime_findings"][0]["vtime_ns"], finding["vtime_ns"],
            "{replayed:#}"
        );
        // Under PCT, whose priorities defer the sleeper again and again,
        // the horizon is reached the same way.
        let pct = result_of(&[
            "run",
            bin,
            "--seed",
            "1",
            "--sched-pct=3",
            &watchdog,
            "--format",
            "json",
        ]);
        assert_eq!(class_of(&pct), ("liveness".to_owned(), 1), "{pct:#}");
    }

    // Two threads that only yield to each other until a flag is set: by a
    // peer asleep for a millisecond (`set`), or by nobody (`never`). Their
    // yields are polls (nothing else happens between them), so time passes
    // for them: the sleeper's millisecond arrives, and with no sleeper the
    // run reaches the no-progress horizon in seconds instead of yielding for
    // good. RED under time model 5: a yield beside a runnable peer was no
    // poll, so `never` ran on, its calls charging 250 ns a turn.
    const MUTUAL_YIELD_SOURCE: &str = r#"
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let set = std::env::args().nth(1).unwrap() == "set";
    let start = Instant::now();
    let flag = Arc::new(AtomicBool::new(false));
    let setter = flag.clone();
    let sleeper = thread::spawn(move || {
        if set {
            thread::sleep(Duration::from_millis(1));
            setter.store(true, Ordering::Release);
        }
    });
    let yielders: Vec<_> = (0..2)
        .map(|_| {
            let flag = flag.clone();
            thread::spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    thread::yield_now();
                }
            })
        })
        .collect();
    sleeper.join().unwrap();
    for yielder in yielders {
        yielder.join().unwrap();
    }
    println!("YIELDERS_DONE elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    #[test]
    fn two_mutual_yield_spinners_end() {
        let dir = tempdir().unwrap();
        let binary = instrumented(dir.path(), "mutual_yield", MUTUAL_YIELD_SOURCE);
        let bin = binary.to_str().unwrap();
        // A 10 s horizon: the default's ten minutes take a minute of yields.
        let run = |mode: &str| {
            result_of(&[
                "run",
                bin,
                "--seed",
                "1",
                "--liveness-watchdog=10000000000",
                "--format",
                "json",
                "--",
                mode,
            ])
        };
        let result = run("set");
        assert_eq!(class_of(&result), ("ok".to_owned(), 0), "{result:#}");
        let elapsed = reported(&result, "elapsed_ns");
        assert!(
            (1_000_000..3_000_000).contains(&elapsed),
            "the 1 ms sleep took {elapsed} ns"
        );
        let result = run("never");
        assert_eq!(class_of(&result), ("liveness".to_owned(), 1), "{result:#}");
        assert_eq!(result["runtime_findings"][0]["detail"], "no-progress");
    }

    // A long computation with no call: `steps` rounds of a hash. Under the
    // edge meter its virtual duration is a count of edges, so it is the
    // same on every run and every host, whatever the host's speed or load,
    // and a host-time bound far shorter than the host takes does not stop
    // it. One that never ends is stopped at the compute budget, a virtual
    // bound, at the same edge on record and replay; what it left in C's
    // stdout buffer, unflushed, is still in its output on both.
    const LONG_COMPUTE_SOURCE: &str = r#"
use std::time::Instant;

unsafe extern "C" {
    fn printf(format: *const std::ffi::c_char, ...) -> i32;
}

fn main() {
    let steps: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    if steps == 0 {
        assert!(unsafe { printf(c"BUFFERED_C_STDOUT".as_ptr()) } > 0);
    }
    let start = Instant::now();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut step = 0u64;
    while steps == 0 || step < steps {
        hash = (hash ^ step).wrapping_mul(0x100_0000_01b3);
        step += 1;
        std::hint::black_box(hash);
    }
    println!("COMPUTED hash={hash} elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    #[test]
    fn a_long_computation_takes_the_same_virtual_time_on_any_host_and_its_budget_is_virtual() {
        let dir = tempdir().unwrap();
        let binary = instrumented(dir.path(), "long_compute", LONG_COMPUTE_SOURCE);
        let bin = binary.to_str().unwrap();
        let trace = dir.path().join("long_compute.patina");
        // Twenty million rounds: tens of host milliseconds or more, over a
        // compute budget of a virtual second.
        let run = |extra: &[&str]| {
            let mut arguments = vec![
                "run",
                bin,
                "--seed",
                "1",
                "--compute-watchdog-ms",
                "1000",
                "--format",
                "json",
            ];
            arguments.extend_from_slice(extra);
            arguments.extend_from_slice(&["--", "20000000"]);
            result_of(&arguments)
        };
        let first = run(&["--record", trace.to_str().unwrap()]);
        assert_eq!(class_of(&first), ("ok".to_owned(), 0), "{first:#}");
        let elapsed = reported(&first, "elapsed_ns");
        assert!(
            elapsed > 10_000_000,
            "{elapsed} ns for twenty million rounds"
        );
        // Again, while the host is busy with other work on every CPU: the
        // same virtual duration.
        struct Load(Vec<std::process::Child>);
        impl Drop for Load {
            fn drop(&mut self) {
                for child in &mut self.0 {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let load = Load(
            (0..std::thread::available_parallelism().map_or(2, usize::from))
                .map(|_| {
                    std::process::Command::new("sh")
                        .args(["-c", "while :; do :; done"])
                        .spawn()
                        .unwrap()
                })
                .collect(),
        );
        let loaded = run(&[]);
        drop(load);
        assert_eq!(reported(&loaded, "elapsed_ns"), elapsed, "{loaded:#}");
        let replayed = result_of(&["replay", bin, trace.to_str().unwrap(), "--format", "json"]);
        assert_eq!(replayed["stdout"], first["stdout"], "{replayed:#}");

        // Never ending: stopped at a 50 ms compute budget, in virtual time.
        let budget = 50u64;
        let stop_trace = dir.path().join("forever.patina");
        let stopped = result_of(&[
            "run",
            bin,
            "--seed",
            "1",
            "--compute-watchdog-ms",
            &budget.to_string(),
            "--record",
            stop_trace.to_str().unwrap(),
            "--format",
            "json",
            "--",
            "0",
        ]);
        assert_eq!(class_of(&stopped), ("timeout".to_owned(), 2), "{stopped:#}");
        assert_eq!(stopped["stop"]["reason"], "compute_bound", "{stopped:#}");
        let finding = &stopped["runtime_findings"][0];
        assert_eq!(finding["known_limit"], false, "{stopped:#}");
        let computed = finding["compute_ns"].as_u64().unwrap();
        // Stopped at the first batch past the budget.
        assert!(
            (budget * 1_000_000..budget * 1_000_000 + 100_000).contains(&computed),
            "{stopped:#}"
        );
        let replayed = result_of(&[
            "replay",
            bin,
            stop_trace.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(class_of(&replayed), class_of(&stopped), "{replayed:#}");
        assert_eq!(replayed["runtime_findings"][0]["compute_ns"], computed);
        for result in [&stopped, &replayed] {
            assert_eq!(result["stdout"], "BUFFERED_C_STDOUT", "{result:#}");
        }
    }

    // A lone thread that computes until a signal handler sets its flag: the
    // alarm is delivered at the batch its time arrives at, though the thread
    // makes no call and has no peer to yield to.
    #[cfg(target_os = "linux")]
    const ALARM_COMPUTE_SOURCE: &str = r#"
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_: i32) {
    FIRED.store(true, Ordering::SeqCst);
}

unsafe extern "C" {
    fn alarm(seconds: u32) -> u32;
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

fn main() {
    let start = Instant::now();
    unsafe {
        signal(14, on_alarm);
        alarm(1);
    }
    let mut hash = 0u64;
    let mut step = 0u64;
    while !FIRED.load(Ordering::Relaxed) {
        hash = (hash ^ step).wrapping_mul(0x100_0000_01b3);
        step += 1;
        std::hint::black_box(hash);
    }
    println!("ALARMED elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lone_computation_receives_its_alarm() {
        let dir = tempdir().unwrap();
        let binary = instrumented(dir.path(), "alarm_compute", ALARM_COMPUTE_SOURCE);
        let bin = binary.to_str().unwrap();
        let trace = dir.path().join("alarm_compute.patina");
        let result = result_of(&[
            "run",
            bin,
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(class_of(&result), ("ok".to_owned(), 0), "{result:#}");
        let elapsed = reported(&result, "elapsed_ns");
        assert!(
            (1_000_000_000..1_010_000_000).contains(&elapsed),
            "the one-second alarm arrived after {elapsed} ns"
        );
        let replayed = result_of(&["replay", bin, trace.to_str().unwrap(), "--format", "json"]);
        assert_eq!(replayed["stdout"], result["stdout"], "{replayed:#}");
    }

    // Computation that reads the clock as it goes, up to a deadline of its
    // own: it ends at that deadline, its edges and clock reads together
    // making the time pass.
    const COMPUTE_TO_DEADLINE_SOURCE: &str = r#"
use std::time::{Duration, Instant};

fn main() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);
    let mut hash = 0u64;
    while Instant::now() < deadline {
        for step in 0..1000u64 {
            hash = (hash ^ step).wrapping_mul(0x100_0000_01b3);
            std::hint::black_box(hash);
        }
    }
    println!("DEADLINE elapsed_ns={}", start.elapsed().as_nanos());
}
"#;

    #[test]
    fn a_computation_bounded_by_a_clock_deadline_ends_at_it() {
        let dir = tempdir().unwrap();
        let binary = instrumented(dir.path(), "to_deadline", COMPUTE_TO_DEADLINE_SOURCE);
        let result = result_of(&[
            "run",
            binary.to_str().unwrap(),
            "--seed",
            "1",
            "--format",
            "json",
        ]);
        assert_eq!(class_of(&result), ("ok".to_owned(), 0), "{result:#}");
        let elapsed = reported(&result, "elapsed_ns");
        assert!(
            (5_000_000..5_500_000).contains(&elapsed),
            "the 5 ms deadline was reached at {elapsed} ns"
        );
    }

    // A spin-wait on an atomic: the spinner makes no call until another
    // thread sets the flag (`set`), or for good (`never`); or it writes to a
    // file at every turn, a call that gets somewhere, until the flag is set
    // (`log`).
    const ATOMIC_SPIN_SOURCE: &str = r#"
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

fn main() {
    let mode = std::env::args().nth(1).unwrap();
    let set = mode != "never";
    let log = mode == "log";
    let flag = Arc::new(AtomicBool::new(false));
    let f = flag.clone();
    let spinner = thread::spawn(move || {
        let mut file = log.then(|| std::fs::File::create("/tmp/spin.log").unwrap());
        while !f.load(Ordering::Acquire) {
            match &mut file {
                Some(file) => file.write_all(b".").unwrap(),
                None => std::hint::spin_loop(),
            }
        }
    });
    let setter = thread::spawn(move || {
        if set {
            flag.store(true, Ordering::Release)
        }
    });
    setter.join().unwrap();
    spinner.join().unwrap();
    println!("SPIN_DONE");
}
"#;

    // Every combination of the scheduling options ends the spin-wait in one
    // outcome. The spinner's slice ends at its edges, so the setter gets its
    // turn (under PCT the spinner would otherwise keep its priority for good)
    // and the run is clean, with or without a yield stride; where nothing can
    // set the flag, the compute budget ends it as a timeout, never a hang.
    #[test]
    fn a_spin_wait_ends_under_every_combination_of_scheduling_options() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("spin.rs");
        fs::write(&source, ATOMIC_SPIN_SOURCE).unwrap();
        let workspace = native_workspace();
        let binary = dir.path().join("spin");
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
        let run = |options: &[&str], mode: &str| -> serde_json::Value {
            let mut arguments = vec!["run", "-v", bin, "--format", "json"];
            arguments.extend_from_slice(options);
            arguments.extend_from_slice(&["--", mode]);
            let output = invoke_with_deadline(
                env!("CARGO_BIN_EXE_patina"),
                workspace,
                &arguments,
                Duration::from_secs(60),
            )
            .unwrap_or_else(|| panic!("the run never ended: {options:?} {mode}"));
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "no result for {options:?} {mode}: {error}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
        };
        let outcome = |result: &serde_json::Value| {
            (
                result["result"].as_str().unwrap().to_owned(),
                result["exit_code"].as_i64().unwrap(),
            )
        };
        let clean = ("ok".to_owned(), 0);
        let timeout = ("timeout".to_owned(), 2);
        for options in [
            &["--seed", "1"][..],
            &["--sched-pct=1", "--seed", "1"],
            &["--yield-stride", "64", "--seed", "1"],
            &["--sched-pct=1", "--yield-stride", "64", "--seed", "1"],
            &["--sched-pct=1", "--yield-stride", "64", "--seed", "2"],
            &["--sched-pct=3", "--yield-stride", "64", "--seed", "1"],
            &["--sched-pct=1", "--yield-stride", "1", "--seed", "1"],
        ] {
            let result = run(options, "set");
            assert_eq!(outcome(&result), clean, "{options:?}: {result:#}");
            assert_eq!(result["stdout"], "SPIN_DONE\n", "{options:?}");
        }
        // A spinner whose every turn is a call that gets somewhere, under
        // PCT, on seeds where it outranks the setter: the setter still runs.
        for seed in ["1", "2", "4"] {
            let options = ["--sched-pct=1", "--seed", seed];
            let result = run(&options, "log");
            assert_eq!(outcome(&result), clean, "{options:?}: {result:#}");
        }
        // No setter: the spinner computes for good, with or without edge
        // yields, and ends at the compute budget, with or without a
        // recording.
        let bound = ["--compute-watchdog-ms", "200", "--seed", "1"];
        let trace = dir.path().join("spin.patina");
        let record = ["--record", trace.to_str().unwrap()];
        for (options, mode) in [
            (&[][..], "never"),
            (&["--yield-stride", "64"], "never"),
            (&["--sched-pct=1", "--yield-stride", "64"], "never"),
            (&["--yield-stride", "64", "--record", record[1]], "never"),
        ] {
            let mut options = options.to_vec();
            options.extend_from_slice(&bound);
            let result = run(&options, mode);
            assert_eq!(outcome(&result), timeout, "{options:?} {mode}: {result:#}");
            assert_eq!(
                result["stop"]["reason"], "compute_bound",
                "{options:?} {mode}"
            );
        }
    }
}
