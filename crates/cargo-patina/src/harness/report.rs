//! What `patina test` prints: a line per test as it finishes (stderr), then a
//! summary (stdout), or one `patina.test/v1` document under `--format json`.

use super::build::BuiltTarget;
use super::run::{SeedRun, Suite, TestCase, flush_stderr, rerun_command};
use super::select::{SkippedTarget, Target};
use super::{TestInvocation, Verdict};
use crate::{cli, output};
use patina_dst_abi::RunClass;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsStr;

/// The schema of the `--format json` document.
pub(crate) const TEST_SCHEMA: &str = "patina.test/v1";

/// One line when a test finishes: its class, the test, and for one that did
/// not pass, its seed and why. Under `--progress` the line is a
/// `test_finished` progress event instead.
#[allow(clippy::too_many_arguments)]
pub(super) fn progress(
    finished: usize,
    total: usize,
    failures: usize,
    target: &Target,
    case: &TestCase,
    deciding: Option<(u64, &SeedRun)>,
    seconds: f64,
    elapsed: f64,
) {
    let class = deciding.map_or(RunClass::Ok, |(_, run)| run.result);
    if output::progress::wanted() {
        output::progress::emit(
            "test_finished",
            json!({
                "test": case.name,
                "target": target.label(),
                "class": class.as_str(),
                "seed": deciding.map(|(seed, _)| seed),
                "seconds": round(seconds),
                "done": finished,
                "total": total,
                "failures": failures,
            }),
        );
        return;
    }
    let width = total.to_string().len();
    let mut line = format!(
        "[{finished:>width$}/{total}] {:<16} {} {} ({seconds:.2}s)",
        class.as_str(),
        target.label(),
        case.name,
    );
    if let Some((seed, run)) = deciding {
        line.push_str(&format!(" seed {seed}: {}", why(run)));
    }
    if finished == total {
        line.push_str(&format!("  [{elapsed:.1}s]"));
    }
    eprintln!("{line}");
    flush_stderr();
}

/// One line of why a run did not pass: a Rust panic's message and place, a
/// `#[should_panic]` test that did not panic, or else what stopped the run.
pub(crate) fn why(run: &SeedRun) -> String {
    let lines: Vec<&str> = run.stderr.lines().chain(run.stdout.lines()).collect();
    for (index, line) in lines.iter().enumerate() {
        // `thread 'NAME' (TID) panicked at FILE:LINE:COL:`, the message on
        // the next line.
        if let Some(position) = line
            .starts_with("thread '")
            .then(|| line.find(" panicked at "))
            .flatten()
        {
            let place = line[position + " panicked at ".len()..].trim_end_matches(':');
            let message = lines
                .get(index + 1)
                .map(|message| message.trim())
                .filter(|message| !message.is_empty())
                .unwrap_or("(no message)");
            return format!("panicked at {place}: {message}");
        }
        if let Some(note) = line.strip_prefix("note: test did not panic as expected") {
            return format!("did not panic as #[should_panic] expected{note}");
        }
    }
    if let Some(stop) = &run.stop
        && !stop.detail.is_empty()
    {
        return stop.detail.lines().next().unwrap_or_default().to_string();
    }
    let last = run
        .stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty());
    match (last, &run.message) {
        (Some(line), _) => line.trim().to_string(),
        (None, Some(message)) => message.lines().next().unwrap_or_default().to_string(),
        (None, None) => run.result.summary().to_string(),
    }
}

/// `--no-run`: every staged guest's path, or why the target has none.
pub(super) fn no_run(built: &[BuiltTarget], skipped: &[SkippedTarget], build_seconds: f64) -> i32 {
    let failed = built.iter().any(|built| built.guest.is_err());
    let class = if failed {
        RunClass::Error
    } else {
        RunClass::Ok
    };
    if output::options().is_json() {
        let document = json!({
            "schema": TEST_SCHEMA,
            "verb": "test",
            "result": class.as_str(),
            "exit_code": class.exit_code(),
            "build_seconds": round(build_seconds),
            "targets": targets_json(built, skipped, &[]),
        });
        println!("{document}");
    } else {
        for built in built {
            match &built.guest {
                Ok(guest) => println!("{}  {}", built.target.label(), guest.display()),
                Err(error) => println!("{}  not built: {error}", built.target.label()),
            }
        }
        for skipped in skipped {
            println!("{}  skipped: {}", skipped.target.label(), skipped.reason);
        }
        eprintln!("built {} target(s) in {build_seconds:.1}s", built.len());
    }
    class.exit_code()
}

fn round(seconds: f64) -> f64 {
    (seconds * 1000.0).round() / 1000.0
}

fn targets_json(
    built: &[BuiltTarget],
    skipped: &[SkippedTarget],
    unlisted: &[(usize, SeedRun)],
) -> Vec<Value> {
    let mut targets: Vec<Value> = built
        .iter()
        .enumerate()
        .map(|(index, built)| {
            let mut entry = target_json(&built.target);
            match &built.guest {
                Ok(guest) => {
                    entry["guest"] = json!(guest.to_string_lossy());
                }
                Err(error) => {
                    entry["build_error"] = json!(error);
                }
            }
            if let Some((_, run)) = unlisted.iter().find(|(unlisted, _)| *unlisted == index) {
                entry["listing"] = run_json(run);
            }
            entry
        })
        .collect();
    targets.extend(skipped.iter().map(|skipped| {
        let mut entry = target_json(&skipped.target);
        entry["skipped"] = json!(skipped.reason);
        entry
    }));
    targets
}

fn target_json(target: &Target) -> Value {
    json!({
        "package": target.package,
        "kind": target.kind.name(),
        "name": target.name,
    })
}

fn run_json(run: &SeedRun) -> Value {
    let mut value = json!({
        "result": run.result.as_str(),
        "why": why(run),
    });
    if let Some(attribution) = run.result.attribution() {
        value["attribution"] = json!(attribution.as_str());
    }
    if let Some(stop) = &run.stop {
        value["stop"] = json!({"reason": stop.reason, "detail": stop.detail});
    }
    if let Some(exit) = &run.guest_exit {
        value["guest_exit"] = exit.clone();
    }
    value
}

/// A test, or a target that could not list its tests, that did not pass.
struct Problem<'a> {
    class: RunClass,
    /// The target, and the test (`None` for a target that did not list).
    target: &'a Target,
    case: Option<&'a TestCase>,
    verdict: Option<&'a Verdict>,
    run: Option<&'a SeedRun>,
    /// A build failure's message, when the target never built.
    build_error: Option<&'a str>,
    accepted: bool,
}

pub(super) struct Outcome<'a> {
    pub(super) invocation: &'a TestInvocation,
    pub(super) built: &'a [BuiltTarget],
    pub(super) skipped_targets: &'a [SkippedTarget],
    pub(super) suite: &'a Suite,
    pub(super) build_seconds: f64,
    pub(super) run_seconds: f64,
}

impl Outcome<'_> {
    /// Whether an unsupported stop is one `--accept-unsupported` names.
    fn accepted(&self, class: RunClass, run: Option<&SeedRun>) -> bool {
        class == RunClass::Unsupported
            && run.and_then(|run| run.stop.as_ref()).is_some_and(|stop| {
                self.invocation
                    .accept_unsupported
                    .iter()
                    .any(|text| stop.detail.contains(text.as_str()))
            })
    }

    fn problems(&self) -> Vec<Problem<'_>> {
        let mut problems = Vec::new();
        for built in self.built {
            if let Err(error) = &built.guest {
                problems.push(Problem {
                    class: RunClass::Error,
                    target: &built.target,
                    case: None,
                    verdict: None,
                    run: None,
                    build_error: Some(error),
                    accepted: false,
                });
            }
        }
        for (index, run) in &self.suite.unlisted {
            problems.push(Problem {
                class: run.result,
                target: &self.built[*index].target,
                case: None,
                verdict: None,
                run: Some(run),
                build_error: None,
                accepted: self.accepted(run.result, Some(run)),
            });
        }
        for (case, verdict) in &self.suite.tests {
            if verdict.class == RunClass::Ok {
                continue;
            }
            let run = verdict.run.as_ref();
            problems.push(Problem {
                class: verdict.class,
                target: &self.built[case.target].target,
                case: Some(case),
                verdict: Some(verdict),
                run,
                build_error: None,
                accepted: self.accepted(verdict.class, run),
            });
        }
        problems
    }

    /// The invocation's exit status: 1 for any finding, else 2 for anything
    /// not run as asked (an accepted unsupported test aside), else 0.
    fn exit_class(problems: &[Problem<'_>]) -> RunClass {
        let deciding = |code: i32| {
            problems
                .iter()
                .filter(|problem| !problem.accepted && problem.class.exit_code() == code)
                .map(|problem| problem.class)
                .min()
        };
        deciding(1).or_else(|| deciding(2)).unwrap_or(RunClass::Ok)
    }

    fn counts(&self, problems: &[Problem<'_>]) -> BTreeMap<RunClass, usize> {
        let mut counts = BTreeMap::new();
        for (_, verdict) in &self.suite.tests {
            *counts.entry(verdict.class).or_insert(0) += 1;
        }
        for problem in problems.iter().filter(|problem| problem.case.is_none()) {
            *counts.entry(problem.class).or_insert(0) += 1;
        }
        counts
    }

    pub(super) fn report(&self) -> i32 {
        let problems = self.problems();
        let class = Self::exit_class(&problems);
        if output::options().is_json() {
            println!("{}", self.json(&problems, class));
        } else {
            self.human(&problems, class);
        }
        class.exit_code()
    }

    fn rerun(&self, problem: &Problem<'_>) -> Option<String> {
        let (case, verdict) = (problem.case?, problem.verdict?);
        Some(rerun_command(
            self.invocation,
            problem.target,
            case,
            verdict.seed,
        ))
    }

    fn replay(&self, problem: &Problem<'_>) -> Option<String> {
        let recorded = problem.verdict?.recorded.as_ref()?;
        let trace = recorded.trace.as_ref()?;
        let guest = self
            .built
            .iter()
            .find(|built| &built.target == problem.target)?
            .guest
            .as_ref()
            .ok()?;
        Some(cli::without_env_defaults(format!(
            "patina replay {} {}{}",
            cli::shell_quote(guest.as_os_str()),
            cli::shell_quote(OsStr::new(&trace.path)),
            if self.invocation.run.allow_randomized_layout {
                " --allow-randomized-address-layout"
            } else {
                ""
            }
        )))
    }

    fn problem_why(problem: &Problem<'_>) -> String {
        if let Some(error) = problem.build_error {
            return error.to_string();
        }
        let why = problem.run.map(why).unwrap_or_default();
        match (problem.case, problem.verdict) {
            (Some(_), Some(verdict)) if verdict.class == RunClass::Nondeterministic => {
                let recorded = verdict
                    .recorded
                    .as_ref()
                    .map_or("?", |run| run.result.as_str());
                format!(
                    "seed {} ended {} and then {recorded} when run again: {why}",
                    verdict.seed,
                    problem.run.map_or("?", |run| run.result.as_str()),
                )
            }
            (None, _) => format!("listing its tests did not finish: {why}"),
            _ => why,
        }
    }

    fn human(&self, problems: &[Problem<'_>], class: RunClass) {
        let counts = self.counts(problems);
        let tests = self.suite.tests.len();
        let targets = self.built.len();
        println!(
            "\npatina test: {tests} test(s) in {targets} target(s); built in {:.1}s, ran in {:.1}s ({} job(s), {})",
            self.build_seconds,
            self.run_seconds,
            self.invocation.jobs,
            match self.invocation.seeds {
                super::Seeds::One(seed) => format!("seed {seed}"),
                super::Seeds::Range(count) => format!("seeds 0..{count}"),
            }
        );
        for (class, count) in &counts {
            let accepted = problems
                .iter()
                .filter(|problem| problem.accepted && problem.class == *class)
                .count();
            if accepted > 0 {
                println!("  {:<16} {count:>6}  ({accepted} accepted)", class.as_str());
            } else {
                println!("  {:<16} {count:>6}", class.as_str());
            }
        }
        if !self.suite.skipped.is_empty() {
            println!(
                "  {:<16} {:>6}  (#[ignore]; --include-ignored runs them)",
                "skipped",
                self.suite.skipped.len()
            );
        }
        for skipped in self.skipped_targets {
            println!(
                "  target {} skipped: {}",
                skipped.target.label(),
                skipped.reason
            );
        }
        if !problems.is_empty() {
            println!();
        }
        for problem in problems {
            let name = problem.case.map_or("(listing)", |case| case.name.as_str());
            let seed = problem
                .verdict
                .map(|verdict| format!(" (seed {})", verdict.seed))
                .unwrap_or_default();
            let accepted = if problem.accepted { " [accepted]" } else { "" };
            println!(
                "{:<16} {} {name}{seed}{accepted}",
                problem.class.as_str(),
                problem.target.label()
            );
            println!("    {}", Self::problem_why(problem));
            if let Some(rerun) = self.rerun(problem) {
                println!("    rerun:  {rerun}");
            }
            if let Some(replay) = self.replay(problem) {
                println!("    replay: {replay}");
            }
        }
        // What kept tests from running, most common first: one line per
        // class and stop, its numbers (a step count, a thread) left out so
        // one cause is one line.
        let mut stops: BTreeMap<(RunClass, String), usize> = BTreeMap::new();
        for problem in problems
            .iter()
            .filter(|problem| matches!(problem.class, RunClass::Unsupported | RunClass::Timeout))
        {
            let key = (problem.class, without_numbers(&Self::problem_why(problem)));
            *stops.entry(key).or_insert(0) += 1;
        }
        if !stops.is_empty() {
            println!("\ncould not run under Patina, by what stopped it:");
            let mut stops: Vec<_> = stops.into_iter().collect();
            stops.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            for ((class, stop), count) in stops {
                println!("  {count:>6}  {:<12} {stop}", class.as_str());
            }
        }
        let not_ok = problems.len();
        let headline = output::Outcome::of(
            class,
            Some(output::Stop::new(
                "test_summary",
                format!(
                    "{not_ok} of {} did not pass",
                    tests
                        + problems
                            .iter()
                            .filter(|problem| problem.case.is_none())
                            .count()
                ),
            )),
        )
        .headline(None);
        match headline {
            Some(headline) => println!("\n{headline}"),
            None if not_ok > 0 => println!(
                "\npatina test: no findings; {not_ok} accepted unsupported test(s) did not run to the end"
            ),
            None => println!("\npatina test: every test passed"),
        }
    }

    fn json(&self, problems: &[Problem<'_>], class: RunClass) -> Value {
        let counts: serde_json::Map<String, Value> = self
            .counts(problems)
            .into_iter()
            .map(|(class, count)| (class.as_str().to_string(), json!(count)))
            .collect();
        let mut tests: Vec<Value> = self
            .suite
            .tests
            .iter()
            .map(|(case, verdict)| {
                let target = &self.built[case.target].target;
                let mut entry = target_json(target);
                entry["target"] = entry["name"].take();
                entry["name"] = json!(case.name);
                entry["result"] = json!(verdict.class.as_str());
                if let Some(attribution) = verdict.class.attribution() {
                    entry["attribution"] = json!(attribution.as_str());
                }
                entry["seed"] = json!(verdict.seed);
                entry["seeds_passed"] = json!(verdict.seeds_passed);
                entry["duration_ms"] = json!((verdict.seconds * 1000.0).round() as u64);
                if case.ignored {
                    entry["ignored"] = json!(true);
                }
                if let Some(run) = &verdict.run {
                    let problem = problems.iter().find(|problem| {
                        problem.case.is_some_and(|other| std::ptr::eq(other, case))
                    });
                    entry["why"] = json!(problem.map_or_else(|| why(run), Self::problem_why));
                    if let Some(stop) = &run.stop {
                        entry["stop"] = json!({"reason": stop.reason, "detail": stop.detail});
                    }
                    if let Some(exit) = &run.guest_exit {
                        entry["guest_exit"] = exit.clone();
                    }
                    if let Some(problem) = problem {
                        entry["accepted"] = json!(problem.accepted);
                        entry["rerun"] = json!(self.rerun(problem));
                        if let Some(replay) = self.replay(problem) {
                            entry["replay"] = json!(replay);
                        }
                    }
                }
                if let Some(trace) = verdict.recorded.as_ref().and_then(|run| run.trace.as_ref()) {
                    entry["trace"] = json!({"path": trace.path, "event_count": trace.event_count});
                }
                entry
            })
            .collect();
        tests.extend(self.suite.skipped.iter().map(|case| {
            let mut entry = target_json(&self.built[case.target].target);
            entry["target"] = entry["name"].take();
            entry["name"] = json!(case.name);
            entry["skipped"] = json!("ignored");
            entry
        }));
        let mut document = json!({
            "schema": TEST_SCHEMA,
            "verb": "test",
            "result": class.as_str(),
            "exit_code": class.exit_code(),
            "counts": counts,
            "skipped": self.suite.skipped.len(),
            "listed": self.suite.listed,
            "build_seconds": round(self.build_seconds),
            "run_seconds": round(self.run_seconds),
            "jobs": self.invocation.jobs,
            "targets": targets_json(self.built, self.skipped_targets, &self.suite.unlisted),
            "tests": tests,
        });
        if let Some(attribution) = class.attribution() {
            document["attribution"] = json!(attribution.as_str());
        }
        document
    }
}

/// `text` with each run of digits read as `N`, so stops that differ only in
/// a count or an id group together.
pub(crate) fn without_numbers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_number = false;
    for character in text.chars() {
        if character.is_ascii_digit() {
            if !in_number {
                out.push('N');
            }
            in_number = true;
        } else {
            out.push(character);
            in_number = false;
        }
    }
    out
}
