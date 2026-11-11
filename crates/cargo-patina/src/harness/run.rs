//! List each staged harness's tests and run every selected test, every seed,
//! as its own child `patina run`, `--jobs` at a time.

use super::build::{BuiltTarget, safe_path_segment};
use super::select::Target;
use super::{RunFlags, TestInvocation, Verdict};
use crate::parse::knob_flag_pairs;
use crate::{CliError, cli, output};
use patina_dst_abi::RunClass;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{env, fs};

/// What one child `patina run` reported.
#[derive(Clone)]
pub(crate) struct SeedRun {
    pub(crate) result: RunClass,
    pub(crate) stop: Option<output::Stop>,
    pub(crate) guest_exit: Option<serde_json::Value>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) message: Option<String>,
    // Choke point: a trace is taken only from the child's own receipt, never
    // inferred from a requested path or a file an earlier run left.
    pub(crate) trace: Option<output::TraceFacts>,
    /// The child's `likely_artifacts`: what points at the simulated world
    /// rather than the test, beside its class.
    pub(crate) likely_artifacts: Vec<serde_json::Value>,
}

impl SeedRun {
    /// A run patina could not finish or could not read, filed as its own.
    fn patina_failed(class: RunClass, reason: &str, detail: String) -> Self {
        Self {
            result: class,
            stop: Some(output::Stop::new(reason, detail)),
            guest_exit: None,
            stdout: String::new(),
            stderr: String::new(),
            message: None,
            trace: None,
            likely_artifacts: Vec::new(),
        }
    }
}

/// One test of one staged target.
pub(crate) struct TestCase {
    pub(crate) target: usize,
    /// The test's path within its target, as libtest lists it.
    pub(crate) name: String,
    pub(crate) ignored: bool,
}

/// Everything the run phase found.
pub(crate) struct Suite {
    /// Every selected test and its verdict, in target then name order.
    pub(crate) tests: Vec<(TestCase, Verdict)>,
    /// Ignored tests not run.
    pub(crate) skipped: Vec<TestCase>,
    /// Targets whose harness could not list its tests, by index into the
    /// built targets, and what the listing run came to.
    pub(crate) unlisted: Vec<(usize, SeedRun)>,
    /// Tests listed, before the filter.
    pub(crate) listed: usize,
}

/// The wall-clock backstop's stop reason: the run outlived `--timeout-secs`.
pub(crate) const BACKSTOP_STOP: &str = "wall_clock_backstop";

pub(super) fn run_suite(
    invocation: &TestInvocation,
    built: &[BuiltTarget],
) -> Result<Suite, CliError> {
    let staged: Vec<(usize, &Path)> = built
        .iter()
        .enumerate()
        .filter_map(|(index, built)| built.guest.as_deref().ok().map(|guest| (index, guest)))
        .collect();
    // Two listings a target: every test, then the ignored ones.
    let listings = pool(
        invocation.jobs,
        staged.len() * 2,
        |job| {
            let (_, guest) = staged[job / 2];
            let mut args = vec!["--list"];
            if job % 2 == 1 {
                args.push("--ignored");
            }
            run_child(invocation, list_command(invocation, guest, &args)?)
        },
        |_, _| {},
    )?;
    let mut cases = Vec::new();
    let mut unlisted = Vec::new();
    let mut listed = 0;
    for (position, (index, _)) in staged.iter().enumerate() {
        let all = &listings[position * 2];
        let ignored = &listings[position * 2 + 1];
        let Some(failed) = [all, ignored]
            .into_iter()
            .find(|run| run.result.is_failure())
        else {
            let ignored: Vec<String> = listed_tests(&ignored.stdout);
            for name in listed_tests(&all.stdout) {
                listed += 1;
                cases.push(TestCase {
                    target: *index,
                    ignored: ignored.contains(&name),
                    name,
                });
            }
            continue;
        };
        unlisted.push((*index, failed.clone()));
    }
    let (selected, skipped): (Vec<TestCase>, Vec<TestCase>) = cases
        .into_iter()
        .filter(|case| {
            // libtest's own matching: a substring, or the whole path with
            // `--exact`, for the filter and every `--skip` alike.
            let matches = |pattern: &str| {
                if invocation.exact {
                    case.name == pattern
                } else {
                    case.name.contains(pattern)
                }
            };
            invocation.filter.as_deref().is_none_or(matches)
                && !invocation.skip.iter().any(|skip| matches(skip))
        })
        .partition(|case| invocation.include_ignored || !case.ignored);
    if let Some(filter) = &invocation.filter
        && selected.is_empty()
        && skipped.is_empty()
        && unlisted.is_empty()
    {
        return Err(CliError(format!(
            "no test {} {filter:?} in {}: nothing would run",
            if invocation.exact {
                "named"
            } else {
                "matching"
            },
            staged
                .iter()
                .map(|(index, _)| built[*index].target.label())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let tests = run_tests(invocation, built, selected)?;
    Ok(Suite {
        tests,
        skipped,
        unlisted,
        listed,
    })
}

/// The names a libtest harness's `--list` printed: one `NAME: test` line each
/// (benchmarks are `NAME: bench`, and are not run).
pub(crate) fn listed_tests(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect()
}

/// Run every test on every seed, then record each finding's deciding seed.
fn run_tests(
    invocation: &TestInvocation,
    built: &[BuiltTarget],
    cases: Vec<TestCase>,
) -> Result<Vec<(TestCase, Verdict)>, CliError> {
    let seeds = invocation.seeds.list();
    let guest = |case: &TestCase| -> &Path {
        built[case.target]
            .guest
            .as_deref()
            .expect("only staged targets are listed")
    };
    // The lowest seed each test has failed on so far: a seed above it is not
    // run, since it cannot decide the test. Every seed below still runs, so
    // the deciding seed is the lowest failing one whatever order they finish in.
    let lowest_failure: Vec<AtomicU64> = cases.iter().map(|_| AtomicU64::new(u64::MAX)).collect();
    let mut pending: Vec<usize> = cases.iter().map(|_| seeds.len()).collect();
    let mut runs: Vec<BTreeMap<u64, SeedRun>> = cases.iter().map(|_| BTreeMap::new()).collect();
    let mut passed: Vec<u64> = vec![0; cases.len()];
    let mut seconds: Vec<f64> = vec![0.0; cases.len()];
    let total = cases.len();
    let mut finished = 0;
    let mut failures = 0;
    let started = Instant::now();
    let results = pool(
        invocation.jobs,
        cases.len() * seeds.len(),
        |job| {
            let (index, seed) = (job / seeds.len(), seeds[job % seeds.len()]);
            if seed > lowest_failure[index].load(Ordering::SeqCst) {
                return Ok(None);
            }
            let case = &cases[index];
            let began = Instant::now();
            let run = run_child(
                invocation,
                test_command(invocation, guest(case), case, seed, None)?,
            )?;
            if run.result.is_failure() {
                lowest_failure[index].fetch_min(seed, Ordering::SeqCst);
            }
            Ok(Some((run, began.elapsed().as_secs_f64())))
        },
        |job, result: &Option<(SeedRun, f64)>| {
            let (index, seed) = (job / seeds.len(), seeds[job % seeds.len()]);
            if let Some((run, elapsed)) = result {
                seconds[index] += elapsed;
                if run.result.is_failure() {
                    runs[index].insert(seed, run.clone());
                } else {
                    passed[index] += 1;
                }
            }
            pending[index] -= 1;
            if pending[index] == 0 {
                finished += 1;
                let case = &cases[index];
                let deciding = runs[index].iter().next();
                if deciding.is_some() {
                    failures += 1;
                }
                super::report::progress(
                    finished,
                    total,
                    failures,
                    &built[case.target].target,
                    case,
                    deciding.map(|(seed, run)| (*seed, run)),
                    seconds[index],
                    started.elapsed().as_secs_f64(),
                );
            }
        },
    )?;
    drop(results);
    let mut verdicts: Vec<Verdict> = cases
        .iter()
        .enumerate()
        .map(|(index, _)| match runs[index].iter().next() {
            Some((seed, run)) => Verdict {
                class: run.result,
                seed: *seed,
                seeds_passed: passed[index],
                run: Some(run.clone()),
                recorded: None,
                seconds: seconds[index],
            },
            None => Verdict {
                class: RunClass::Ok,
                seed: seeds[0],
                seeds_passed: passed[index],
                run: None,
                recorded: None,
                seconds: seconds[index],
            },
        })
        .collect();
    // A finding is run once more on its seed, recorded: the trace a replay
    // needs, and a check that the seed ends the same way twice. A finding's
    // guest ran, so there is something to record.
    let findings: Vec<usize> = verdicts
        .iter()
        .enumerate()
        .filter(|(_, verdict)| verdict.class.is_finding())
        .map(|(index, _)| index)
        .collect();
    let recordings = pool(
        invocation.jobs,
        findings.len(),
        |job| {
            let index = findings[job];
            let case = &cases[index];
            let trace = trace_path(&built[case.target], case, verdicts[index].seed)?;
            let began = Instant::now();
            let run = run_child(
                invocation,
                test_command(
                    invocation,
                    guest(case),
                    case,
                    verdicts[index].seed,
                    Some(&trace),
                )?,
            )?;
            Ok((run, began.elapsed().as_secs_f64()))
        },
        |_, _| {},
    )?;
    for (job, (recorded, elapsed)) in recordings.into_iter().enumerate() {
        let verdict = &mut verdicts[findings[job]];
        let first = verdict.run.as_ref().expect("a finding has its run");
        verdict.seconds += elapsed;
        // A retry patina could not finish (a timeout, a host kill, an error
        // of its own) says nothing either way: the finding stands, without a
        // recording. One that ended otherwise must end exactly as the first.
        let inconclusive = matches!(
            recorded.result,
            RunClass::Timeout | RunClass::Internal | RunClass::Error
        ) && recorded.result != first.result;
        if inconclusive {
            continue;
        }
        if recorded.result != first.result || recorded.guest_exit != first.guest_exit {
            verdict.class = RunClass::Nondeterministic;
        }
        verdict.recorded = Some(recorded);
    }
    Ok(cases.into_iter().zip(verdicts).collect())
}

/// Where a finding's recording goes: beside its target's guest, named by the
/// test and the seed. Any earlier file of that name is removed first, so
/// what is there afterwards is this run's or nothing.
fn trace_path(built: &BuiltTarget, case: &TestCase, seed: u64) -> Result<PathBuf, CliError> {
    let guest = built.guest.as_deref().expect("a run target is staged");
    let directory = guest
        .parent()
        .expect("a staged guest has a directory")
        .join("traces");
    fs::create_dir_all(&directory).map_err(|error| {
        CliError(format!(
            "failed to create the trace directory {}: {error}",
            directory.display()
        ))
    })?;
    let trace = directory.join(format!(
        "{}.seed-{seed}.patina",
        safe_path_segment(&case.name)
    ));
    match fs::remove_file(&trace) {
        Ok(()) => Ok(trace),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(trace),
        Err(error) => Err(CliError(format!(
            "failed to remove the previous recording {}: {error}",
            trace.display()
        ))),
    }
}

/// Run `jobs` work items on at most `workers` threads, calling `done` on this
/// thread as each finishes (in completion order), and return every result in
/// job order. The first error stops the rest.
fn pool<T: Send>(
    workers: usize,
    jobs: usize,
    work: impl Fn(usize) -> Result<T, CliError> + Sync,
    mut done: impl FnMut(usize, &T),
) -> Result<Vec<T>, CliError> {
    let next = AtomicUsize::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let mut results: Vec<Option<T>> = (0..jobs).map(|_| None).collect();
    let (sender, receiver) = mpsc::channel::<(usize, Result<T, CliError>)>();
    std::thread::scope(|scope| -> Result<(), CliError> {
        for _ in 0..workers.clamp(1, jobs.max(1)) {
            let sender = sender.clone();
            let (next, failed, work) = (&next, &failed, &work);
            scope.spawn(move || {
                loop {
                    let job = next.fetch_add(1, Ordering::SeqCst);
                    if job >= jobs || failed.load(Ordering::SeqCst) {
                        break;
                    }
                    let result = work(job);
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                    if sender.send((job, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        let mut first_error = None;
        for (job, result) in receiver {
            match result {
                Ok(value) => {
                    done(job, &value);
                    results[job] = Some(value);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    })?;
    Ok(results
        .into_iter()
        .map(|result| result.expect("every job ran"))
        .collect())
}

fn patina_command(args: Vec<OsString>) -> Result<Command, CliError> {
    let executable = env::current_exe().map_err(|error| {
        CliError(format!(
            "failed to locate the running patina executable: {error}"
        ))
    })?;
    let mut command = Command::new(executable);
    // Each child dies with this run, in a process group of its own the
    // backstop can kill whole.
    crate::lifeline::tie(&mut command)?;
    command.args(args);
    // Every child is this same supervisor build, or refuses to run.
    crate::supervisor_identity::expect_this_supervisor(&mut command)?;
    Ok(command)
}

/// A listing run: the harness under the runtime, asked for its tests.
fn list_command(
    invocation: &TestInvocation,
    guest: &Path,
    libtest: &[&str],
) -> Result<Command, CliError> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "--format".into(),
        "json".into(),
        guest.into(),
        "--seed".into(),
        "0".into(),
    ];
    for (key, value) in &invocation.run.env {
        args.push("--env".into());
        args.push(format!("{key}={value}").into());
    }
    if let Some(mount) = &invocation.run.mount {
        args.push("--mount".into());
        args.push(mount.to_arg());
    }
    if invocation.run.allow_randomized_layout {
        args.push("--allow-randomized-address-layout".into());
    }
    args.push("--".into());
    args.extend(libtest.iter().map(OsString::from));
    patina_command(args)
}

/// One test's run on one seed: `patina run` of the target's guest, libtest
/// asked for this test alone on one thread.
fn test_command(
    invocation: &TestInvocation,
    guest: &Path,
    case: &TestCase,
    seed: u64,
    record: Option<&Path>,
) -> Result<Command, CliError> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "--format".into(),
        "json".into(),
        guest.into(),
        "--seed".into(),
        seed.to_string().into(),
    ];
    if let Some(path) = record {
        args.push("--record".into());
        args.push(path.into());
    }
    push_run_flags(&mut args, &invocation.run);
    args.extend(libtest_args(case).into_iter().map(OsString::from));
    patina_command(args)
}

/// What libtest is asked to run one test alone: its exact name, on one
/// thread, its output not captured (so a panic's message reaches the run's
/// stderr), and an ignored test included rather than skipped.
pub(crate) fn libtest_args(case: &TestCase) -> Vec<String> {
    let mut args = vec![
        "--".to_string(),
        "--test-threads=1".to_string(),
        "--exact".to_string(),
        case.name.clone(),
        "--nocapture".to_string(),
    ];
    if case.ignored {
        args.push("--include-ignored".to_string());
    }
    args
}

/// Spawn a child run, wait for it within the backstop, and read its result.
fn run_child(invocation: &TestInvocation, mut command: Command) -> Result<SeedRun, CliError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| CliError(format!("failed to start a child patina run: {error}")))?;
    let drain = |stream: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut stream) = stream {
                let _ = stream.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(child.stdout.take().map(|s| Box::new(s) as _));
    let stderr = drain(child.stderr.take().map(|s| Box::new(s) as _));
    let deadline = (invocation.timeout_secs > 0)
        .then(|| Instant::now() + Duration::from_secs(invocation.timeout_secs));
    let mut timed_out = false;
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| CliError(format!("failed to wait for a child patina run: {error}")))?
        {
            Some(status) => break status,
            None if deadline.is_some_and(|deadline| Instant::now() >= deadline) => {
                crate::campaign::kill_generation_process_tree(&mut child);
                timed_out = true;
                let status = child.wait().map_err(|error| {
                    CliError(format!("failed to reap a child patina run: {error}"))
                })?;
                // The guest the child supervised dies of the same signal on
                // its own schedule; the test is over when it is.
                crate::campaign::await_process_group_exit(
                    child.id(),
                    crate::campaign::KILLED_GROUP_EXIT_BOUND,
                );
                break status;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if timed_out {
        let mut run = SeedRun::patina_failed(
            RunClass::Timeout,
            BACKSTOP_STOP,
            format!(
                "the run did not finish within {} s of host time (--timeout-secs)",
                invocation.timeout_secs
            ),
        );
        run.likely_artifacts = vec![output::limit_artifact(BACKSTOP_STOP)];
        return Ok(run);
    }
    seed_outcome(status, &stdout, &stderr)
}

/// What one child `patina run` reported. A child of another supervisor build
/// stops the whole invocation: its results are not comparable. One whose
/// report cannot be read, or whose exit status disagrees with the class it
/// reported, is patina's own failure, filed as `internal` for that test.
pub(crate) fn seed_outcome(
    status: ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<SeedRun, CliError> {
    let stdout_text = String::from_utf8_lossy(stdout).into_owned();
    let child_stderr = String::from_utf8_lossy(stderr).into_owned();
    if let Some(refusal) =
        crate::supervisor_identity::supervisor_mismatch(&stdout_text, &child_stderr)
    {
        return Err(CliError(format!(
            "stopping: a test ran on another supervisor build than this one, so its result is \
             not comparable. {refusal}"
        )));
    }
    let unreadable = |what: String| {
        Ok(SeedRun::patina_failed(
            RunClass::Internal,
            "unreadable_child",
            format!("{what}; its stderr ends: {}", last_line(&child_stderr)),
        ))
    };
    let Some(code) = status.code() else {
        return unreadable("a child patina run was ended by a signal".to_string());
    };
    let envelope: serde_json::Value = match stdout_text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
    {
        Some(Ok(envelope)) => envelope,
        Some(Err(error)) => {
            return unreadable(format!("a child run's report is not JSON: {error}"));
        }
        None => return unreadable("a child run printed no report".to_string()),
    };
    let Some(result) = envelope
        .get("result")
        .and_then(serde_json::Value::as_str)
        .and_then(RunClass::from_name)
    else {
        return unreadable("a child run's report names no outcome".to_string());
    };
    if code != result.exit_code() {
        return unreadable(format!(
            "a child run reported {result} and exited {code}, so its report cannot be trusted"
        ));
    }
    let field = |key: &str| {
        envelope
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut merged = child_stderr;
    let guest_stderr = field("stderr");
    if !merged.is_empty() && !merged.ends_with('\n') && !guest_stderr.is_empty() {
        merged.push('\n');
    }
    merged.push_str(&guest_stderr);
    Ok(SeedRun {
        result,
        stop: output::Stop::from_envelope(&envelope),
        guest_exit: envelope.get("guest_exit").cloned(),
        stdout: field("stdout"),
        stderr: merged,
        message: envelope
            .get("message")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        trace: envelope
            .get("trace")
            .filter(|trace| !trace.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| CliError(format!("invalid trace receipt in a child run: {error}")))?,
        likely_artifacts: envelope
            .get("likely_artifacts")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default(),
    })
}

fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("(nothing)")
}

/// Every run flag the invocation set, as the child `run` (and a rerun
/// command) takes it. A flag parsed and not re-emitted here would be silently
/// inert in every test.
pub(crate) fn push_run_flags(args: &mut Vec<OsString>, run: &RunFlags) {
    let mut push = |flag: &str, value: String| {
        args.push(flag.into());
        args.push(value.into());
    };
    if let Some(budget) = run.step_budget {
        push("--budget", budget.to_string());
    }
    if let Some(epoch) = &run.realtime_epoch {
        push("--realtime-epoch", epoch.clone());
    }
    if let Some(hostname) = &run.hostname {
        push("--hostname", hostname.clone());
    }
    if let Some(cpus) = run.cpus {
        push("--cpus", cpus.to_string());
    }
    for (key, value) in &run.params {
        push("--param", format!("{key}={value}"));
    }
    for (key, value) in &run.env {
        push("--env", format!("{key}={value}"));
    }
    // Every knob the registry defines, from the shared table, the repeatable
    // ones (`--dns-entry`, `--net-partition`) included.
    for (flag, value) in knob_flag_pairs(&run.knobs) {
        push(flag, value.clone());
    }
    if let Some(buggify) = &run.buggify {
        if let Some(value) = &buggify.activation_permille {
            push("--buggify-activation-permille", value.clone());
        }
        if let Some(value) = &buggify.cutoff_nanos {
            push("--buggify-cutoff-nanos", value.clone());
        }
    }
    if let Some(steps) = &run.schedule.pct_steps {
        push("--sched-pct-steps", steps.clone());
    }
    if run.schedule.yield_stride != 0 {
        push("--yield-stride", run.schedule.yield_stride.to_string());
    }
    if let Some(ms) = &run.liveness.compute_watchdog_ms {
        push("--compute-watchdog-ms", ms.clone());
    }
    if let Some(heal) = &run.liveness.heal_after {
        push("--heal-after", heal.clone());
    }
    if let Some(mount) = &run.mount {
        args.push("--mount".into());
        args.push(mount.to_arg());
    }
    let optional = |flag: &str, value: Option<&str>| {
        value.map(|value| {
            if value.is_empty() {
                OsString::from(flag)
            } else {
                OsString::from(format!("{flag}={value}"))
            }
        })
    };
    args.extend(optional(
        "--buggify",
        run.buggify
            .as_ref()
            .map(|buggify| buggify.fire_permille.as_deref().unwrap_or("")),
    ));
    if run
        .buggify
        .as_ref()
        .is_some_and(|buggify| buggify.after_setup)
    {
        args.push("--buggify-after-setup".into());
    }
    args.extend(optional("--sched-pct", run.schedule.pct.as_deref()));
    if run.schedule.swarm {
        args.push("--swarm".into());
    }
    args.extend(optional(
        "--liveness-watchdog",
        run.liveness.watchdog.as_deref(),
    ));
    args.extend(optional(
        "--converge-within",
        run.liveness.converge.as_deref(),
    ));
    if run.allow_randomized_layout {
        args.push("--allow-randomized-address-layout".into());
    }
}

/// The command that reruns one test alone on one seed, exactly as this
/// invocation ran it.
pub(crate) fn rerun_command(
    invocation: &TestInvocation,
    target: &Target,
    case: &TestCase,
    seed: u64,
) -> String {
    let mut args: Vec<OsString> = vec!["test".into(), invocation.origin.clone().into()];
    args.push("-p".into());
    args.push(target.package.clone().into());
    args.extend(target.cargo_args().into_iter().map(OsString::from));
    args.push(case.name.clone().into());
    args.push("--exact".into());
    if case.ignored {
        args.push("--include-ignored".into());
    }
    args.push("--seed".into());
    args.push(seed.to_string().into());
    args.extend(super::build::build_args(invocation));
    if invocation.timeout_secs != 300 {
        args.push("--timeout-secs".into());
        args.push(invocation.timeout_secs.to_string().into());
    }
    push_run_flags(&mut args, &invocation.run);
    let mut command = String::from("patina");
    for arg in &args {
        command.push(' ');
        command.push_str(&cli::shell_quote(arg));
    }
    // The command carries every input; the operator's flag defaults must not
    // change it.
    cli::without_env_defaults(command)
}

/// Flush stderr after a progress line, so a long run shows each test as it
/// finishes even when stderr is a pipe.
pub(crate) fn flush_stderr() {
    let _ = std::io::stderr().flush();
}
