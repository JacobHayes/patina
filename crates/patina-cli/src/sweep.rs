//! `patina sweep`: a list of seeds (and optionally cases), each one ordinary `patina run` in
//! a child process into `OUT/seed-N[/K-NAME]`, `-j` at a time, each child pinned to its own CPU.
//! A new finding (one no `--known` entry matches) prints one line at once; progress is a live
//! line on a terminal and a plain line every 10 s otherwise. When the runs are done, the first
//! seed of every new finding is replayed once (a difference makes the group `nondeterministic`), logs are pruned by
//! `--keep`, and the report of `patina report OUT` is printed and written to
//! `OUT/report.json`. `OUT/sweep.json` records what the sweep runs (the program's SHA-256, the
//! resolved settings and command, and patina's own version and hash): running the same sweep
//! again into the same `--out` runs only the runs not there yet (more seeds, an interrupted
//! sweep); any other sweep replaces the directory, so that edit, rebuild and the same command
//! never report an old program's runs.
//!
//! `--branch` runs each seed (and case) once with crashes on and never firing (a base, in
//! `OUT/seed-N`), then once per crash point the base counted, with the crash forced there (a
//! child, `--crash KIND-at:P` in `OUT/seed-N@P`), points ascending and seeds round-robin. A
//! child is its base up to its point, so one that does not crash there is `nondeterministic`.

use crate::cli::{find_flag, Args, Res};
use crate::outcome::Outcome;
use crate::report::{self, SweepHead};
use crate::result::{error_json, read_json, write_json};
use crate::{error, Fail};
use std::collections::{BTreeSet, VecDeque};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    INTERRUPTED.store(true, SeqCst);
}

/// Flags of the sweep itself; every other flag given is passed to each `patina run`.
const OWN: [&str; 13] = [
    "--seeds",
    "--branch",
    "--jobs",
    "--cases",
    "--only-case",
    "--keep",
    "--max-findings",
    "--budget",
    "--allow-unmet",
    "--known",
    "--out",
    "--format",
    "--help",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Fail,
    All,
    None,
    /// Every run the checker judged or did not judge, as a failure is kept (`cut`): what a
    /// checker reads, so that `patina recheck` and a resumed sweep can judge it again.
    Checked,
}

/// `A..B` (inclusive), `N`, comma-separated.
pub fn parse_seeds(s: &str) -> Res<Vec<u64>> {
    let mut out = BTreeSet::new();
    let num = |x: &str| -> Res<u64> {
        x.trim()
            .parse()
            .map_err(|_| format!("--seeds: not a number: {x}"))
    };
    for part in s.split(',').filter(|p| !p.trim().is_empty()) {
        match part.split_once("..") {
            Some((a, b)) => {
                let (a, b) = (num(a)?, num(b)?);
                if a > b {
                    return Err(format!("--seeds {part}: A is larger than B"));
                }
                if b - a >= 10_000_000 {
                    return Err(format!("--seeds {part}: more than 10 million seeds"));
                }
                out.extend(a..=b);
            }
            None => {
                out.insert(num(part)?);
            }
        }
    }
    if out.is_empty() {
        return Err("--seeds: no seeds".into());
    }
    Ok(out.into_iter().collect())
}

/// What a sweep directory records about the sweep that made it.
pub const SWEEP_FILE: &str = "sweep.json";
const SWEEP_SCHEMA: &str = "patina.sweep/v1";

/// What decides every run of a sweep besides its seed and case: patina itself, the program
/// (its SHA-256) and the resolved settings with the command. The seeds, the cases, `-j`,
/// `--keep` and the stopping rules are not part of it: a sweep with more seeds or cases is the
/// same sweep, extended. Nor is the checker: it decides verdicts, not runs. Each run records
/// the checker that judged it (`run.json`); a resumed sweep judges again the runs another
/// checker judged (`have`).
fn identity(
    cfg: &crate::config::Config,
    program: Option<&String>,
    branch: bool,
) -> Res<serde_json::Value> {
    let mut c = cfg.clone();
    c.seed = 0;
    c.host_cpu = None;
    c.allow_unmet.clear();
    c.check = None;
    c.case = None;
    Ok(serde_json::json!({
        "schema": SWEEP_SCHEMA,
        "patina": crate::result::build()?,
        "program": program,
        "config": c,
        "branch": branch,
    }))
}

/// Names that mark a directory as patina's output, which a sweep may replace: a sweep's (any
/// version since 0.6), a run's (`patina run --out`), and an 0.5 campaign's.
const PATINA_OUTPUT: [&str; 5] = [
    SWEEP_FILE,
    "report.json",
    "result.json",
    "run.json",
    "campaign-state.json",
];

/// Other names a run directory holds beside `PATINA_OUTPUT` and `inc-K`.
const RUN_OUTPUT: [&str; 6] = [
    "check.out",
    "replay",
    "replay.json",
    "minimized",
    "case",
    "sandbox.log",
];

/// Why the sweep recorded in `out` is not the one described by `ident`, if it is not.
fn differs(out: &Path, ident: &serde_json::Value) -> Option<String> {
    let Ok(old) = read_json(&out.join(SWEEP_FILE)) else {
        return Some(if out.join("campaign-state.json").exists() {
            "an older patina's campaign".into()
        } else if out.join("result.json").exists() {
            "a single run".into()
        } else {
            format!("no {SWEEP_FILE}: an older layout")
        });
    };
    if old["patina"] != ident["patina"] {
        return Some("another patina build".into());
    }
    if old["program"] != ident["program"] {
        return Some("the program changed".into());
    }
    if old["branch"] != ident["branch"] {
        return Some(if ident["branch"] == true {
            "a sweep without --branch".into()
        } else {
            "a sweep with --branch".into()
        });
    }
    if old["config"] != ident["config"] {
        let keys: Vec<&String> = ident["config"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, v)| old["config"].get(k.as_str()) != Some(v))
            .map(|(k, _)| k)
            .collect();
        let keys: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        return Some(format!("other settings: {}", keys.join(", ")));
    }
    None
}

/// A case run's directory holds its case's text in this file.
pub const CASE_FILE: &str = "case";
/// Longest name a case's directory takes from the case (characters).
const CASE_NAME_MAX: usize = 40;

/// The run settings a case line may give before its command; every other setting is the
/// sweep's.
pub const CASE_FLAGS: [&str; 4] = ["--work", "--mount", "--env", "--stdin"];

/// One line of a `--cases` file.
struct Case {
    /// The line as written: with its settings, what a resumed sweep compares (the `case` file).
    text: String,
    /// The case as a checker gets it, a report shows it and a known pattern's `[CASE]` matches
    /// it: the line after its settings (`case_shown`).
    shown: String,
    /// Its line number in the file.
    line_no: usize,
    /// Its id: its `--name`, or its line number.
    id: String,
    /// The command its run is given.
    cmd: Vec<String>,
    /// Its directory under `seed-N`: `LINE-NAME`, its line number and its `--name` or a short
    /// form of its last word.
    dir: String,
    /// The settings the line gives (`CASE_FLAGS`), as flag and value, in order.
    flags: Vec<(&'static str, String)>,
}

/// A case as a checker gets it and a report shows it: its line after the settings it gives
/// (the text put in `{}`, or the command), so that a pattern written for the case still
/// matches once the line gives settings. The whole line stays in the run's `case` file.
pub fn case_shown(text: &str) -> String {
    case_line(text)
        .map(|l| l.rest.trim().to_string())
        .unwrap_or_else(|_| text.to_string())
}

/// What a case line holds: its settings, a name it gives, and the rest of the line (the
/// command, or the text put in `{}`).
struct Line<'a> {
    flags: Vec<(&'static str, String)>,
    name: Option<String>,
    rest: &'a str,
}

/// Split a case line: a line whose first word starts with `--` gives run settings up to a
/// word `--` (`--work DIR[:GUEST]`, `--mount`, `--env`, `--stdin`, parsed as `patina run`
/// parses them, and `--name NAME` for its directory), then its command.
fn case_line(text: &str) -> Res<Line<'_>> {
    let plain = Line {
        flags: vec![],
        name: None,
        rest: text,
    };
    match next_word(text)? {
        Some((w, _)) if w.starts_with("--") => {}
        _ => return Ok(plain),
    }
    let mut set = vec![];
    let mut rest = text;
    loop {
        match next_word(rest)? {
            None => return Err(
                "settings with no command: end them with a word -- and give the command after it"
                    .into(),
            ),
            Some((w, r)) => {
                rest = r;
                if w == "--" {
                    break;
                }
                set.push(w);
            }
        }
    }
    let rest = rest.trim();
    if rest.is_empty() {
        return Err("no command after --".into());
    }
    // --name is the sweep's own; the rest is parsed as `patina run` parses its flags.
    let mut name = None;
    let mut run = vec![];
    let mut it = set.into_iter();
    while let Some(w) = it.next() {
        match w.strip_prefix("--name") {
            Some("") => name = Some(it.next().ok_or("--name needs NAME")?),
            Some(v) if v.starts_with('=') => name = Some(v[1..].to_string()),
            _ => run.push(w),
        }
    }
    let a = crate::cli::parse(crate::cli::Cmd::Run, &run).map_err(|e| {
        match run.iter().find(|w| {
            let n = w.split('=').next().unwrap_or("");
            crate::cli::find_flag(n).is_some() && !CASE_FLAGS.contains(&n)
        }) {
            Some(w) => sweep_wide(w.split('=').next().unwrap_or("")),
            None => e,
        }
    })?;
    if let Some(p) = a.positional.first() {
        return Err(format!(
            "{p}: not a setting (a case line's settings end with a word --)"
        ));
    }
    let mut flags = vec![];
    for (f, vals) in &a.flags {
        let Some(f) = CASE_FLAGS.iter().find(|c| *c == f) else {
            return Err(sweep_wide(f));
        };
        flags.extend(vals.iter().map(|v| (*f, v.clone())));
    }
    Ok(Line { flags, name, rest })
}

fn sweep_wide(flag: &str) -> String {
    format!(
        "{flag} is a setting of the whole sweep, not of one case: give it to the sweep (a case line may set {} and --name)",
        CASE_FLAGS.join(", ")
    )
}

/// Read a cases file: one case per line; empty lines and lines starting with `#` are
/// skipped. A line may start with run settings (`case_line`). With a command (`cmd`), `{}` in
/// it is replaced by the rest of the line; without one, the rest is the whole command, its
/// words split as a shell would (quotes and backslashes, no expansion).
fn read_cases(f: &Path, cmd: &[String]) -> Res<Vec<Case>> {
    let at = f.display();
    let t = std::fs::read_to_string(f).map_err(|e| format!("--cases {at}: {e}"))?;
    if !cmd.is_empty() && !cmd.iter().any(|x| x.contains("{}")) {
        return Err(format!(
            "--cases {at}: the command has no {{}} to put the case in (or give no command: \
             then each line is a whole command)"
        ));
    }
    let mut out = vec![];
    for (n, line) in t.lines().enumerate() {
        let text = line.trim().to_string();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let bad = |e: String| format!("--cases {at} line {}: {e}", n + 1);
        let l = case_line(&text).map_err(bad)?;
        let run = if cmd.is_empty() {
            words(l.rest).map_err(bad)?
        } else {
            cmd.iter().map(|x| x.replace("{}", l.rest)).collect()
        };
        let name = match &l.name {
            Some(id) => {
                id_ok(id).map_err(|e| bad(format!("--name {id}: {e}")))?;
                if out.iter().any(|c: &Case| c.id == *id) {
                    return Err(bad(format!("--name {id}: another line has this name")));
                }
                id.clone()
            }
            None => case_name(
                &words(l.rest)
                    .unwrap_or_else(|_| l.rest.split_whitespace().map(String::from).collect()),
            ),
        };
        out.push(Case {
            dir: format!("{}-{name}", n + 1),
            id: l.name.clone().unwrap_or_else(|| (n + 1).to_string()),
            line_no: n + 1,
            cmd: run,
            flags: l.flags,
            shown: l.rest.trim().to_string(),
            text,
        });
    }
    if out.is_empty() {
        return Err(format!("--cases {at}: no cases"));
    }
    Ok(out)
}

/// Longest `--name` (characters).
const ID_MAX: usize = 64;

/// Whether a case's `--name` can be its id: one word that names its directory as written, and
/// not a number (a line number is the id of a line without a name).
fn id_ok(id: &str) -> Res<()> {
    let safe = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    if id.is_empty()
        || id.len() > ID_MAX
        || !id.chars().all(safe)
        || id.starts_with(['.', '-'])
        || id.chars().all(|c| c.is_ascii_digit())
    {
        return Err(format!(
            "a case's name is its id and part of its directory: letters, digits, '.', '_' and '-', not starting with '.' or '-', at most {ID_MAX} characters, not a number"
        ));
    }
    Ok(())
}

/// The words of a line as `sh` splits them: whitespace separates, `'...'` is literal,
/// `"..."` keeps `\"`, `\\`, `\$` and `` \` `` escapes, a backslash outside quotes takes the
/// next character. Nothing is expanded.
pub fn words(line: &str) -> Res<Vec<String>> {
    let mut out = vec![];
    let mut rest = line;
    while let Some((w, r)) = next_word(rest)? {
        out.push(w);
        rest = r;
    }
    Ok(out)
}

/// The first word of `line` (as `words` splits) and the text after it, or none if only
/// whitespace is left.
fn next_word(line: &str) -> Res<Option<(String, &str)>> {
    let mut cur = String::new();
    let mut word = false;
    let mut it = line.char_indices();
    while let Some((at, c)) = it.next() {
        match c {
            c if c.is_whitespace() => {
                if word {
                    return Ok(Some((cur, &line[at..])));
                }
            }
            '\'' => {
                word = true;
                loop {
                    match it.next() {
                        Some((_, '\'')) => break,
                        Some((_, x)) => cur.push(x),
                        None => return Err("unterminated '".into()),
                    }
                }
            }
            '"' => {
                word = true;
                loop {
                    match it.next() {
                        Some((_, '"')) => break,
                        Some((_, '\\')) => match it.next() {
                            Some((_, x)) if "\"\\$`".contains(x) => cur.push(x),
                            Some((_, x)) => {
                                cur.push('\\');
                                cur.push(x);
                            }
                            None => return Err("unterminated \"".into()),
                        },
                        Some((_, x)) => cur.push(x),
                        None => return Err("unterminated \"".into()),
                    }
                }
            }
            '\\' => {
                word = true;
                match it.next() {
                    Some((_, x)) => cur.push(x),
                    None => return Err("a backslash at the end of the line".into()),
                }
            }
            c => {
                word = true;
                cur.push(c);
            }
        }
    }
    Ok(word.then_some((cur, "")))
}

/// A short name for a case's directory: its last word that is not an option (else its last
/// word), after the last `/` unless the word holds spaces, with every character but letters,
/// digits, `.`, `_` and `-` made `_`.
fn case_name(words: &[String]) -> String {
    let w = words
        .iter()
        .rev()
        .find(|w| !w.starts_with('-'))
        .or(words.last())
        // A path's last component; a word with spaces in it (a quoted script, JSON) is not
        // a path: its start.
        .map(|w| {
            if w.contains(char::is_whitespace) {
                w.as_str()
            } else {
                w.rsplit('/').next().unwrap_or(w)
            }
        })
        .unwrap_or("");
    let mut n = String::new();
    for c in w.chars() {
        let c = if c.is_ascii_alphanumeric() || "._-".contains(c) {
            c
        } else {
            '_'
        };
        if !(c == '_' && n.ends_with('_')) {
            n.push(c);
        }
        if n.len() >= CASE_NAME_MAX {
            break;
        }
    }
    let n = n.trim_start_matches('.').to_string();
    if n.is_empty() {
        "case".into()
    } else {
        n
    }
}

/// Whether `dir` holds a finished run of this case (its `case` file) and program (its
/// SHA-256 in `run.json`): such a run is kept when a sweep resumes.
fn done_before(dir: &Path, case: Option<&str>, sha: &str) -> bool {
    if !dir.join("result.json").is_file() {
        return false;
    }
    if let Some(c) = case {
        let have = std::fs::read_to_string(dir.join(CASE_FILE)).unwrap_or_default();
        if have.trim_end_matches('\n') != c {
            return false;
        }
        let run = read_json(&dir.join("run.json")).unwrap_or_default();
        if run["program"]["sha256"] != sha {
            return false;
        }
    }
    true
}

/// What a run directory of a resumed sweep holds.
enum Have {
    /// No finished run of this case and program.
    Missing,
    /// One, judged by this sweep's checker (or by none, as this sweep has none).
    Current,
    /// One whose verdict is another checker's (or was left pending), with what a checker reads.
    Stale,
    /// One whose verdict is another checker's, ended ok, and its logs were pruned.
    StalePruned,
}

fn have(dir: &Path, case: Option<&str>, sha: &str, check: &serde_json::Value) -> Have {
    if !done_before(dir, case, sha) {
        return Have::Missing;
    }
    // A run patina refused has no run.json and no verdict: kept, as before.
    let Ok(run) = read_json(&dir.join("run.json")) else {
        return Have::Current;
    };
    let r = read_json(&dir.join("result.json")).unwrap_or_default();
    let current = crate::recheck::same_checker(&run["config"]["check"], check)
        && r["check"]["verdict"] != "pending";
    if current {
        Have::Current
    } else if !check.is_null() && crate::recheck::pruned(dir, &r) {
        Have::StalePruned
    } else {
        Have::Stale
    }
}

/// What a resumed sweep does with a run it already has.
enum Fresh {
    Kept,
    /// Judge it again; the job runs it again if that cannot be done.
    Rejudge(Job),
    /// Run it (again: `true` when its verdict was stale and its logs pruned).
    Run(Job, bool),
}

/// The runs of a resumed sweep whose checker changed.
#[derive(Default)]
struct Judged {
    /// To judge again from their kept logs.
    jobs: Vec<Job>,
    /// Judged again, for the sweep to account as finished runs (`State::account`).
    done: Vec<Job>,
    judged: usize,
    /// Run again: their logs were pruned.
    rerun: usize,
}

impl Judged {
    /// Judge the waiting runs again, `width` at a time; the jobs of those that cannot be.
    fn settle(
        &mut self,
        check: Option<&crate::check::Check>,
        width: usize,
    ) -> Result<Vec<Job>, Fail> {
        let jobs = std::mem::take(&mut self.jobs);
        let dirs: Vec<PathBuf> = jobs
            .iter()
            .map(|j| match j {
                Job::Run { dir, .. } | Job::Replay { dir, .. } => dir.clone(),
            })
            .collect();
        let done = crate::recheck::rejudge_all(&dirs, &|_| Ok(check.cloned()), width);
        let mut again = vec![];
        for (job, (dir, r)) in jobs.into_iter().zip(done) {
            match r.map_err(|e| error(format!("{}: {e}", dir.display())))? {
                crate::recheck::Rejudged::Judged(_) => {
                    self.judged += 1;
                    self.done.push(job);
                }
                crate::recheck::Rejudged::Unmade => {}
                crate::recheck::Rejudged::Pruned => {
                    self.rerun += 1;
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| error(format!("{}: {e}", dir.display())))?;
                    again.push(job);
                }
            }
        }
        Ok(again)
    }

    /// One line, when the checker changed for some runs.
    fn say(&mut self, out: &Path) {
        if self.judged + self.rerun > 0 {
            eprintln!(
                "sweep: {} in {} had another checker's verdict: {} judged again from their logs, {} to run again (their logs were pruned; --keep checked keeps them)",
                report::count(self.judged + self.rerun, "run"),
                out.display(),
                self.judged,
                self.rerun
            );
        }
        self.judged = 0;
        self.rerun = 0;
    }
}

/// Default width: the CPUs this process may use, at most 8 (docs/EVIDENCE.md, "Sweep width").
pub fn default_jobs() -> usize {
    crate::launch::allowed_cpus().len().clamp(1, 8)
}

enum Job {
    Run {
        seed: u64,
        /// Index into the cases.
        case: Option<usize>,
        dir: PathBuf,
        /// Under `--branch`: `Some(0)` for a base, `Some(P)` for the child crashing at point P.
        point: Option<u64>,
    },
    Replay {
        dir: PathBuf,
        out: PathBuf,
    },
}

struct Done {
    job: Job,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// What the pool does after a job: go on, stop launching, or run the job again at half the
/// width.
enum Then {
    Go,
    Stop,
    Again(Job),
}

/// Run `jobs` at most `width` at a time. `event` is called on this thread with each finished
/// job (and with `None` a few times a second), with the number running and the current width.
/// On SIGINT or SIGTERM the running children are terminated and their jobs are not reported.
/// Returns the number of jobs never started.
/// With `serve` (`--check-serve`), each worker keeps one checker server and lends it to the
/// runs it starts; one that died or was killed for a bad answer is started again for the next
/// run, and each is ended with its worker.
fn pool(
    jobs: Vec<Job>,
    width: usize,
    child: &(dyn Fn(&Job) -> Command + Sync),
    serve: Option<&crate::check::Check>,
    mut event: impl FnMut(Option<Done>, usize, usize) -> Then,
) -> usize {
    let queue = Mutex::new(jobs.into_iter().collect::<VecDeque<_>>());
    let running: Mutex<Vec<i32>> = Mutex::new(vec![]);
    let stop = AtomicBool::new(false);
    // Jobs taken from the queue whose event has not been handled (one may come back).
    let pending = AtomicUsize::new(0);
    let now = AtomicUsize::new(width);
    let cpus = crate::launch::allowed_cpus();
    let (tx, rx) = mpsc::channel::<Done>();
    std::thread::scope(|sc| {
        for w in 0..width {
            let (tx, queue, running, stop, pending, now) =
                (tx.clone(), &queue, &running, &stop, &pending, &now);
            let cpu = cpus[w * cpus.len() / width];
            sc.spawn(move || {
                let mut server = Held(None);
                loop {
                    if stop.load(SeqCst) || w >= now.load(SeqCst) {
                        return;
                    }
                    let job = {
                        let mut q = queue.lock().unwrap();
                        let j = q.pop_front();
                        if j.is_some() {
                            pending.fetch_add(1, SeqCst);
                        }
                        j
                    };
                    let Some(job) = job else {
                        if pending.load(SeqCst) == 0 {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    };
                    let mut cmd = child(&job);
                    if let (Some(c), Job::Run { .. }) = (serve, &job) {
                        if !server.0.as_mut().is_some_and(|s| s.alive()) {
                            // A run that finds no server starts its own, and says why it failed.
                            server = Held(crate::check::Server::start(c).ok());
                        }
                        if let Some(s) = &server.0 {
                            s.lend(&mut cmd);
                        }
                    }
                    cmd.stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    unsafe {
                        use std::os::unix::process::CommandExt;
                        cmd.pre_exec(move || {
                            // One CPU: the run's own pinning picks it (launch::default_cpu).
                            let mut set: libc::cpu_set_t = std::mem::zeroed();
                            libc::CPU_SET(cpu, &mut set);
                            libc::sched_setaffinity(
                                0,
                                std::mem::size_of::<libc::cpu_set_t>(),
                                &set,
                            );
                            Ok(())
                        });
                    }
                    let (stdout, stderr) = match cmd.spawn() {
                        Ok(c) => {
                            let pid = c.id() as i32;
                            running.lock().unwrap().push(pid);
                            let o = c.wait_with_output();
                            running.lock().unwrap().retain(|p| *p != pid);
                            match o {
                                Ok(o) => (o.stdout, o.stderr),
                                Err(e) => (vec![], e.to_string().into_bytes()),
                            }
                        }
                        Err(e) => (vec![], format!("spawn patina: {e}").into_bytes()),
                    };
                    // A server whose run did not get a verdict from it (an error: the run killed
                    // it; pending: the run was stopped while asking) is ended and reaped here, so
                    // that no later run of this job meets it or a late answer of it.
                    if let (Some(_), Job::Run { dir, .. }) = (&server.0, &job) {
                        let r = read_json(&dir.join("result.json")).unwrap_or_default();
                        let v = r["check"]["verdict"].as_str();
                        if !matches!(v, None | Some("pass" | "fail" | "not-judged" | "not-run")) {
                            server = Held(None);
                        }
                    }
                    if INTERRUPTED.load(SeqCst) {
                        pending.fetch_sub(1, SeqCst);
                        return;
                    }
                    let _ = tx.send(Done {
                        job,
                        stdout,
                        stderr,
                    });
                }
            });
        }
        drop(tx);
        let mut killed = false;
        loop {
            let d = match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(d) => Some(d),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let got = d.is_some();
            let n = running.lock().unwrap().len();
            match event(d, n, now.load(SeqCst)) {
                Then::Go => {}
                Then::Stop => stop.store(true, SeqCst),
                Then::Again(job) => {
                    let w = now.load(SeqCst);
                    now.store((w / 2).max(1), SeqCst);
                    queue.lock().unwrap().push_front(job);
                }
            }
            if got {
                pending.fetch_sub(1, SeqCst);
            }
            if INTERRUPTED.load(SeqCst) && !killed {
                killed = true;
                stop.store(true, SeqCst);
                for &p in running.lock().unwrap().iter() {
                    unsafe { libc::kill(p, libc::SIGTERM) };
                }
            }
        }
    });
    queue.into_inner().unwrap().len()
}

/// A worker's checker server, ended when the worker ends or replaces it.
struct Held(Option<crate::check::Server>);

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(s) = self.0.take() {
            s.end();
        }
    }
}

/// Remove the logs (`inc-*`) and the checker's output of a run directory, keeping `run.json`
/// and `result.json`.
fn prune(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("inc-") {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let _ = std::fs::remove_file(dir.join(crate::check::OUTPUT));
}

/// A kept run's log over `CUT_OVER` bytes keeps its first and last `CUT_KEEP` (whole records):
/// a sweep of runs that each reach --log-limit stays small. The seed reproduces the whole log.
const CUT_OVER: u64 = 4 << 20;
const CUT_KEEP: u64 = (1 << 20) / proto::rec::REC_SIZE as u64 * proto::rec::REC_SIZE as u64;

/// Cut the large logs of a kept run (`crate::log::Cut`); the operation log of an incarnation
/// over the size goes whole (`patina log ops` needs all of it).
fn cut(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for inc in rd.flatten() {
        if !inc.file_name().to_string_lossy().starts_with("inc-") {
            continue;
        }
        let inc = inc.path();
        let size = |f: &str| std::fs::metadata(inc.join(f)).map(|m| m.len()).unwrap_or(0);
        if size("boundary.log") > CUT_OVER {
            let _ = crate::log::cut(&inc, CUT_KEEP);
        }
        if size("oplog.meta") + size("oplog.data") > CUT_OVER {
            let _ = std::fs::remove_file(inc.join("oplog.meta"));
            let _ = std::fs::remove_file(inc.join("oplog.data"));
        }
    }
}

/// Bytes of the files under `dir`.
fn bytes_under(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => bytes_under(&e.path()),
            _ => e.metadata().map(|m| m.len()).unwrap_or(0),
        })
        .sum()
}

/// Bytes free to this user on the filesystem holding `p`.
fn free_bytes(p: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0).then(|| st.f_bavail * st.f_frsize)
}

fn tail(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .to_string()
}

fn clock(s: f64) -> String {
    let s = s as u64;
    format!("{}:{:02}", s / 60, s % 60)
}

pub fn main(a: &Args) -> Result<ExitCode, Fail> {
    let seeds = parse_seeds(
        a.last("--seeds")
            .ok_or_else(|| error("--seeds is required (A..B, or a list N,M,...)".into()))?,
    )
    .map_err(error)?;
    // The configuration every run resolves to, checked once here rather than failing in
    // every run. With --cases and no command, each line is a whole command.
    let cfg = crate::config::resolve_any(a).map_err(error)?;
    // --branch: the crash kind each base and child is given (the sweep places the crash).
    let kind: Option<String> = if a.has("--branch") {
        match cfg.crash.as_deref() {
            Some(k @ ("machine" | "process")) => Some(k.to_string()),
            None => return Err(error(
                "--branch needs --crash machine or --crash process: it crashes each seed at each of its crash points".into(),
            )),
            Some(c) => return Err(error(format!(
                "--branch needs --crash machine or --crash process without a rate or position, not --crash {c}: it places the crash at each crash point itself"
            ))),
        }
    } else {
        None
    };
    let cases: Option<Vec<Case>> = match a.last("--cases") {
        None => None,
        Some(f) => Some(read_cases(Path::new(f), &cfg.cmd).map_err(error)?),
    };
    if cases.is_none() && cfg.cmd.is_empty() {
        return Err(error(
            "no program: give -- CMD ARGS..., or [run] cmd in patina.toml".into(),
        ));
    }
    let keep = match a.last("--keep").unwrap_or("fail") {
        "fail" => Keep::Fail,
        "all" => Keep::All,
        "none" => Keep::None,
        "checked" if cfg.check.is_none() => {
            return Err(error(
                "--keep checked keeps what a checker reads: give --check or --check-serve (or --keep all)".into(),
            ))
        }
        "checked" => Keep::Checked,
        k => {
            return Err(error(format!(
                "--keep: expected fail, checked, all or none, not {k}"
            )))
        }
    };
    let width = match a.num::<usize>("--jobs").map_err(error)? {
        Some(0) => return Err(error("--jobs is at least 1".into())),
        Some(n) => n,
        None => default_jobs(),
    };
    let max_findings = a.num::<usize>("--max-findings").map_err(error)?;
    // `--known FILE`, else `[sweep] known` in patina.toml.
    let known_file = a
        .last("--known")
        .map(PathBuf::from)
        .or_else(|| cfg.known.clone());
    let known = known_file
        .as_deref()
        .map(report::Known::read)
        .transpose()
        .map_err(error)?;
    let budget = a.num::<u64>("--budget").map_err(error)?;
    let cmd_of = |case: Option<usize>| -> Vec<String> {
        match (case, &cases) {
            (Some(i), Some(c)) => c[i].cmd.clone(),
            _ => cfg.cmd.clone(),
        }
    };
    // Every program the runs start, resolved and hashed once: a run already in the sweep
    // directory is kept only if it ran the same program. A case's own settings are checked
    // here too (the sweep's, with the line's on top), and its mounts may hold its program.
    let mut programs: std::collections::BTreeMap<String, crate::config::Program> =
        Default::default();
    let mut list: Vec<Option<usize>> = match &cases {
        Some(c) => (0..c.len()).map(Some).collect(),
        None => vec![None],
    };
    // --only-case ID,...: those cases of the file alone.
    if let Some(only) = a.last("--only-case") {
        let Some(c) = &cases else {
            return Err(error("--only-case needs --cases".into()));
        };
        let ids: Vec<&str> = only
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .collect();
        if let Some(bad) = ids.iter().find(|id| !c.iter().any(|k| k.id == **id)) {
            return Err(error(format!(
                "--only-case {bad}: no case has this id (a line's --name, or its line number)"
            )));
        }
        list.retain(|i| i.is_some_and(|i| ids.contains(&c[i].id.as_str())));
    }
    let mut program_of: Vec<String> = vec![];
    let mut first_cfg = None;
    for &i in &list {
        let at = |e: String| {
            error(match (i, &cases) {
                (Some(i), Some(c)) => format!("--cases line {}: {e}", c[i].line_no),
                _ => e,
            })
        };
        let ccfg = match (i, &cases) {
            (Some(i), Some(c)) if !c[i].flags.is_empty() => {
                let mut m = Args {
                    flags: a.flags.clone(),
                    positional: vec![],
                    cmd: Some(c[i].cmd.clone()),
                };
                for (f, v) in &c[i].flags {
                    let e = m.flags.entry(f).or_default();
                    if !find_flag(f).is_some_and(|x| x.repeat) {
                        e.clear();
                    }
                    e.push(v.clone());
                }
                crate::config::resolve_any(&m).map_err(at)?
            }
            _ => cfg.clone(),
        };
        let cmd = cmd_of(i);
        let key = format!(
            "{}\n{}",
            cmd[0],
            serde_json::to_string(&ccfg.mounts).unwrap_or_default()
        );
        if !programs.contains_key(&key) {
            let p = crate::config::program(&cmd[0], &ccfg.mounts).map_err(at)?;
            programs.insert(key.clone(), p);
        }
        if first_cfg.is_none() {
            first_cfg = Some((ccfg, key.clone()));
        }
        program_of.push(key);
    }
    let probe_program = {
        let (mut probe, key) = first_cfg.unwrap();
        probe.cmd = cmd_of(list[0]);
        let o = probe.opts_with(programs[&key].clone()).map_err(error)?;
        crate::launch::preflight(&o).map_err(error)?;
        o.program
    };
    let program_key = |case: Option<usize>| -> &String { &program_of[case.unwrap_or(0)] };

    let out = crate::absolute(PathBuf::from(a.last("--out").unwrap_or("patina-out/sweep")));
    if let Ok(rd) = std::fs::read_dir(&out) {
        let names: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        // A sweep's own directory (`sweep.json`) is resumed or replaced as before, and an 0.5
        // campaign's (`campaign-state.json`, beside stores of its own) is replaced. Anything
        // else is replaced only when every entry in it is one patina writes (`run.json` alone
        // is a common name); an entry of another kind is named and nothing is deleted.
        let own = |n: &String| n == SWEEP_FILE || n == "campaign-state.json";
        if !names.is_empty() && !names.iter().any(own) {
            let ours = |n: &String| {
                PATINA_OUTPUT.contains(&n.as_str())
                    || RUN_OUTPUT.contains(&n.as_str())
                    || n.starts_with("seed-")
                    || n.strip_prefix("inc-")
                        .is_some_and(|k| k.parse::<u32>().is_ok())
            };
            let marked = names
                .iter()
                .any(|n| PATINA_OUTPUT.contains(&n.as_str()) || n.starts_with("seed-"));
            if let Some(other) = names.iter().filter(|n| !ours(n)).min() {
                return Err(error(format!(
                    "{}: exists and holds {other:?}, which patina does not write; give another --out",
                    out.display()
                )));
            }
            if !marked {
                return Err(error(format!(
                    "{}: exists and holds no patina output (none of {}, seed-N); give another --out",
                    out.display(),
                    PATINA_OUTPUT.join(", ")
                )));
            }
        }
    }
    // With whole-command cases there is no one program: each run's is checked on resume.
    let ident = identity(
        &cfg,
        (!cfg.cmd.is_empty()).then_some(&probe_program.sha256),
        kind.is_some(),
    )
    .map_err(error)?;
    if out.is_dir() {
        if let Some(why) = differs(&out, &ident) {
            eprintln!(
                "sweep: {} holds another sweep ({why}); replacing it",
                out.display()
            );
            std::fs::remove_dir_all(&out).map_err(|e| error(format!("{}: {e}", out.display())))?;
        }
    }
    std::fs::create_dir_all(&out).map_err(|e| error(format!("{}: {e}", out.display())))?;
    write_json(&out.join(SWEEP_FILE), &ident).map_err(error)?;

    let run_dir = |seed: u64, case: Option<usize>, point: Option<u64>| -> PathBuf {
        let mut dir = out.join(match point {
            Some(p) if p > 0 => format!("seed-{seed}@{p}"),
            _ => format!("seed-{seed}"),
        });
        if let (Some(i), Some(c)) = (case, &cases) {
            dir = dir.join(&c[i].dir);
        }
        dir
    };
    // What a run needs: none when the directory already holds it judged by this checker (a
    // resumed sweep), a new verdict when another checker judged it and its logs are kept, else
    // the run.
    let want_check = cfg
        .check
        .as_ref()
        .map(|c| serde_json::to_value(c).unwrap())
        .unwrap_or_default();
    let fresh = |seed: u64, case: Option<usize>, point: Option<u64>| -> Result<Fresh, Fail> {
        let dir = run_dir(seed, case, point);
        let sha = &programs[program_key(case)].sha256;
        let have = have(
            &dir,
            case.map(|i| cases.as_ref().unwrap()[i].text.as_str()),
            sha,
            &want_check,
        );
        let run = |stale| -> Result<Fresh, Fail> {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| error(format!("{}: {e}", dir.display())))?;
            }
            Ok(Fresh::Run(
                Job::Run {
                    seed,
                    case,
                    dir: dir.clone(),
                    point,
                },
                stale,
            ))
        };
        match have {
            Have::Current => Ok(Fresh::Kept),
            Have::Stale => Ok(Fresh::Rejudge(Job::Run {
                seed,
                case,
                dir: dir.clone(),
                point,
            })),
            Have::StalePruned => run(true),
            Have::Missing => run(false),
        }
    };
    let mut judged_again = Judged::default();
    let mut jobs = vec![];
    let mut total = 0;
    for &seed in &seeds {
        for &case in &list {
            total += 1;
            match fresh(seed, case, kind.as_ref().map(|_| 0))? {
                Fresh::Kept => {}
                Fresh::Rejudge(j) => judged_again.jobs.push(j),
                Fresh::Run(j, stale) => {
                    judged_again.rerun += stale as usize;
                    jobs.push(j);
                }
            }
        }
    }
    jobs.extend(judged_again.settle(cfg.check.as_ref(), width)?);
    judged_again.say(&out);
    let todo = jobs.len();
    let mut unfinished: std::collections::BTreeMap<u64, usize> = Default::default();
    for j in &jobs {
        if let Job::Run { seed, .. } = j {
            *unfinished.entry(*seed).or_default() += 1;
        }
    }

    // What each `patina run` is given besides its seed, directory and command.
    let mut pass: Vec<String> = vec![];
    for (name, vals) in &a.flags {
        if OWN.contains(name) || (kind.is_some() && *name == "--crash") {
            continue;
        }
        let f = find_flag(name).unwrap();
        for v in vals {
            pass.push(name.to_string());
            if !f.value_for(crate::cli::Cmd::Sweep).is_empty() {
                pass.push(v.clone());
            }
        }
    }
    let exe = std::env::current_exe().map_err(|e| error(format!("patina binary: {e}")))?;
    let child = |job: &Job| -> Command {
        let mut c = Command::new(&exe);
        match job {
            Job::Run {
                seed,
                case,
                dir,
                point,
            } => {
                c.arg("run")
                    .arg("--seed")
                    .arg(seed.to_string())
                    .arg("--out")
                    .arg(dir)
                    .args(["--format", "json"])
                    .args(&pass);
                if let Some(k) = &kind {
                    c.arg("--crash").arg(match point {
                        Some(p) if *p > 0 => format!("{k}-at:{p}"),
                        _ => format!("{k}:0"),
                    });
                }
                // The case's own settings, after the sweep's: a later --work or --stdin
                // replaces the sweep's, --mount and --env add to them.
                if let (Some(i), Some(cs)) = (case, &cases) {
                    for (f, v) in &cs[*i].flags {
                        c.arg(f).arg(v);
                    }
                }
                c.arg("--").args(cmd_of(*case));
                // The case, for a checker (`check::CASE_VAR`) and the run's run.json.
                match (case, &cases) {
                    (Some(i), Some(cs)) => c
                        .env(crate::check::CASE_VAR, &cs[*i].shown)
                        .env(crate::check::CASE_NAME_VAR, &cs[*i].dir)
                        .env(crate::check::CASE_ID_VAR, &cs[*i].id)
                        .env(crate::check::CASE_LINE_VAR, &cs[*i].text),
                    _ => c
                        .env_remove(crate::check::CASE_VAR)
                        .env_remove(crate::check::CASE_NAME_VAR)
                        .env_remove(crate::check::CASE_ID_VAR)
                        .env_remove(crate::check::CASE_LINE_VAR),
                };
            }
            Job::Replay { dir, out } => {
                c.arg("replay")
                    .arg(dir)
                    .arg("--out")
                    .arg(out)
                    .args(["--format", "json"]);
            }
        }
        c
    };

    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    let case_text: Vec<String> = cases.iter().flatten().map(|c| c.text.clone()).collect();
    let mut st = State {
        cases: case_text,
        tty: std::io::stderr().is_terminal(),
        t0: Instant::now(),
        last_line: Instant::now(),
        todo,
        done: 0,
        finding_runs: 0,
        known_runs: 0,
        known: known.as_ref(),
        groups: BTreeSet::new(),
        pending: Default::default(),
        unfinished,
        finding_groups: 0,
        stopped: None,
        keep,
        width,
        max_findings,
        budget,
        out: out.clone(),
        run_bytes: (cfg.log_limit << 20) + (64 << 20),
        cut: false,
        bases: Default::default(),
    };
    if todo < total {
        st.say(&format!(
            "sweep: {} of {total} runs of this sweep already in {}; running {todo}",
            total - todo,
            out.display()
        ));
    }
    if let Some(free) = free_bytes(&out).filter(|f| *f < st.run_bytes * width as u64) {
        return Err(error(format!(
            "the filesystem holding {} has {} free; {width} runs at once may write {} each (--log-limit and their output): free space, or lower -j or --log-limit",
            out.display(),
            report::bytes(free),
            report::bytes(st.run_bytes)
        )));
    }
    let serve = cfg.check.as_ref().filter(|k| k.serve);
    // Runs judged again count as finished runs: pruned or cut by --keep, their findings
    // toward --max-findings, which may stop the sweep before it starts a run.
    st.rejudged(std::mem::take(&mut judged_again.done));
    let mut not_started = if st.stopped.is_some() {
        jobs.len()
    } else {
        pool(jobs, width, &child, serve, |d, running, now| {
            st.event(d, running, now)
        })
    };
    st.flush(true);
    if kind.is_some() && st.stopped.is_none() && !INTERRUPTED.load(SeqCst) {
        // The children: each base's crash points, points ascending, seeds (and cases)
        // round-robin.
        let mut most = 0;
        for &seed in &seeds {
            for &case in &list {
                let b = run_dir(seed, case, Some(0));
                let r = read_json(&b.join("result.json")).unwrap_or_default();
                let n = r["faults"]["counts"]["crash"]["eligible"]
                    .as_u64()
                    .unwrap_or(0);
                most = most.max(n);
                st.bases.insert((seed, case), (n, b));
            }
        }
        let points: u64 = st.bases.values().map(|b| b.0).sum();
        st.say(&format!(
            "sweep: {}, {}",
            report::count(
                st.bases.len(),
                if cases.is_some() { "base" } else { "seed" }
            ),
            report::count(points as usize, "crash point")
        ));
        let mut children = vec![];
        let mut have = 0;
        for p in 1..=most {
            for &seed in &seeds {
                for &case in &list {
                    if p <= st.bases[&(seed, case)].0 {
                        match fresh(seed, case, Some(p))? {
                            Fresh::Run(j, stale) => {
                                judged_again.rerun += stale as usize;
                                children.push(j)
                            }
                            Fresh::Kept => have += 1,
                            Fresh::Rejudge(j) => {
                                have += 1;
                                judged_again.jobs.push(j)
                            }
                        }
                    }
                }
            }
        }
        let again = judged_again.settle(cfg.check.as_ref(), st.width)?;
        have -= again.len();
        children.extend(again);
        judged_again.say(&out);
        if have > 0 {
            st.say(&format!(
                "sweep: {have} of {points} children already in {}; running {}",
                out.display(),
                children.len()
            ));
        }
        st.todo += children.len();
        // Children of all seeds run interleaved: announce each group as it is found.
        st.unfinished.clear();
        st.rejudged(std::mem::take(&mut judged_again.done));
        not_started = if st.stopped.is_some() {
            children.len()
        } else {
            pool(children, st.width, &child, serve, |d, running, now| {
                st.event(d, running, now)
            })
        };
        st.flush(true);
    }
    let interrupted = INTERRUPTED.load(SeqCst);
    if interrupted {
        st.stopped = Some("interrupted".into());
        // Runs that were terminated left a directory without a result.
        let rd = std::fs::read_dir(&out).into_iter().flatten().flatten();
        for d in rd.filter(|e| e.file_name().to_string_lossy().starts_with("seed-")) {
            let d = d.path();
            let partial = match &cases {
                None => vec![d],
                Some(c) => c.iter().map(|c| d.join(&c.dir)).collect(),
            };
            for p in partial {
                if p.is_dir() && !p.join("result.json").exists() {
                    let _ = std::fs::remove_dir_all(p);
                }
            }
        }
    }
    if st.tty {
        st.say("");
    }
    if not_started > 0 && st.stopped.is_some() {
        st.say(&format!(
            "sweep: {} not started",
            report::count(not_started, "run")
        ));
    }

    // Replay the first seed of each finding once.
    let runs = report::collect(std::slice::from_ref(&out)).map_err(error)?;
    if !interrupted {
        let (v, _) = report::build(&runs, &[], known.as_ref(), None, "");
        let mut replays = vec![];
        for g in v["groups"].as_array().unwrap() {
            let finding = Outcome::ALL
                .iter()
                .any(|o| g["run_outcome"] == o.name() && o.exit() == 1);
            if finding && g["known"].is_null() && g["replay"].is_null() {
                let dir = PathBuf::from(g["first"]["dir"].as_str().unwrap());
                let rel = dir.strip_prefix(&out).unwrap_or(&dir).to_path_buf();
                replays.push(Job::Replay {
                    dir,
                    out: out.join(".replay").join(rel),
                });
            }
        }
        if !replays.is_empty() {
            st.say(&format!(
                "sweep: replaying the first seed of {}",
                report::count(replays.len(), "finding")
            ));
            pool(replays, st.width, &child, None, |d, _, _| {
                if let Some(d) = d {
                    replayed(d);
                }
                Then::Go
            });
        }
    }
    if keep == Keep::None {
        for r in &runs {
            prune(&r.dir);
        }
    }
    let runs = report::collect(std::slice::from_ref(&out)).map_err(error)?;
    st.say(&format!(
        "sweep: {} kept in {}{}",
        report::bytes(bytes_under(&out)),
        out.display(),
        if st.cut {
            "; logs over 4 MiB keep their first and last MiB (the run's seed reproduces the whole log: patina replay RUNDIR)"
        } else {
            ""
        }
    ));
    let head = SweepHead {
        seconds: st.t0.elapsed().as_secs_f64(),
        jobs: width,
        lowered_to: Some(st.width).filter(|w| *w != width),
        stopped: st.stopped.clone(),
    };
    let mut again = "patina report --group N".to_string();
    if let Some(k) = &known_file {
        again.push_str(&format!(
            " --known {}",
            report::quote(&k.display().to_string())
        ));
    }
    again.push_str(&format!(" {}", report::quote(&out.display().to_string())));
    let (v, text) = report::build(
        &runs,
        a.all("--allow-unmet"),
        known.as_ref(),
        Some(head),
        &again,
    );
    write_json(&out.join("report.json"), &v).map_err(error)?;
    if a.json() {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        print!("{text}");
    }
    if interrupted {
        return Ok(ExitCode::from(Outcome::Error.exit()));
    }
    Ok(ExitCode::from(v["exit"].as_u64().unwrap_or(2) as u8))
}

/// Record a replay's verdict beside the run it replayed (`replay.json`); keep the replay's
/// directory only when it differed.
fn replayed(d: Done) {
    let Job::Replay { dir, out } = &d.job else {
        return;
    };
    let r = read_json(&out.join("result.json"));
    let v = match &r {
        Ok(r) if r["outcome"] == "nondeterministic" => {
            serde_json::json!({"result": "nondeterministic", "message": r["message"], "dir": out})
        }
        Ok(r) if r["stop"] == "check-unstable" => {
            serde_json::json!({"result": "check-unstable", "message": r["message"], "dir": out})
        }
        Ok(_) => serde_json::json!({"result": "identical", "message": ""}),
        Err(_) => serde_json::json!({"result": "error", "message": tail(&d.stderr)}),
    };
    let _ = write_json(&dir.join("replay.json"), &v);
    if v["result"] == "identical" {
        let _ = std::fs::remove_dir_all(out);
    }
}

/// A group's `new:` line waiting to be printed: the seed, branch point, case and directory of the
/// run it names.
type Announce = (u64, Option<u64>, Option<usize>, PathBuf);

/// The sweep's counters and its terminal output.
struct State<'k> {
    /// Each case's text, for its `new:` line and its run directory's `case` file.
    cases: Vec<String>,
    tty: bool,
    t0: Instant,
    last_line: Instant,
    todo: usize,
    done: usize,
    /// New findings (a known entry matches none of them).
    finding_runs: usize,
    /// Findings a known entry matches: counted, not announced.
    known_runs: usize,
    known: Option<&'k report::Known>,
    /// Groups seen: (signature, the case when it is part of the key).
    groups: BTreeSet<(String, Option<String>)>,
    /// Groups found whose `new:` line waits until no lower seed is left to run, so that it
    /// names the group's lowest seed, the one the report calls first: (seed, run directory).
    pending: std::collections::BTreeMap<(String, Option<String>), Announce>,
    /// Runs not finished yet, by seed.
    unfinished: std::collections::BTreeMap<u64, usize>,
    finding_groups: usize,
    stopped: Option<String>,
    keep: Keep,
    /// The width now (lowered on a host limit).
    width: usize,
    max_findings: Option<usize>,
    budget: Option<u64>,
    out: PathBuf,
    /// The most one run writes: its logs' limit and room for the rest.
    run_bytes: u64,
    /// Some kept run's log was cut.
    cut: bool,
    /// Under `--branch`, once the bases ran: each (seed, case)'s crash points and base directory.
    bases: std::collections::BTreeMap<(u64, Option<usize>), (u64, PathBuf)>,
}

impl State<'_> {
    fn status(&self, running: usize) -> String {
        let s = self.t0.elapsed().as_secs_f64();
        format!(
            "{}/{} runs, {} in {}{}, {running} running, {:.1} runs/s, {}",
            self.done,
            self.todo,
            report::count(self.finding_runs, "finding"),
            report::count(self.finding_groups, "group"),
            if self.known_runs > 0 {
                format!(", {} known", self.known_runs)
            } else {
                String::new()
            },
            self.done as f64 / s.max(0.001),
            clock(s)
        )
    }

    /// Print the `new:` lines no lower seed can still take over (all of them with `all`).
    fn flush(&mut self, all: bool) {
        let low = self.unfinished.keys().next().copied();
        let ready: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (seed, ..))| all || low.is_none_or(|l| *seed < l))
            .map(|(k, _)| k.clone())
            .collect();
        for k in ready {
            let (seed, point, _, dir) = self.pending.remove(&k).unwrap();
            let c = k.1.as_ref().map(|c| format!(" [{c}]")).unwrap_or_default();
            self.say(&format!(
                "new{c}: {}   (seed {}: patina replay {})",
                k.0,
                report::run_name(seed, point),
                dir.display()
            ));
        }
    }

    /// One line; on a terminal it replaces the live status line, which the next tick redraws.
    fn say(&self, line: &str) {
        let mut e = std::io::stderr().lock();
        if self.tty {
            let _ = write!(e, "\r\x1b[K");
        }
        if !line.is_empty() {
            let _ = writeln!(e, "{line}");
        }
    }

    fn event(&mut self, d: Option<Done>, running: usize, width: usize) -> Then {
        if let Some(d) = d {
            if let Some(job) = self.finished(d, running, width) {
                return Then::Again(job);
            }
        }
        if let Some(b) = self.budget {
            if self.t0.elapsed().as_secs() >= b && self.stopped.is_none() {
                self.stopped = Some(format!("{b} s passed (--budget)"));
            }
        }
        // Stop launching while the runs at once could still fill the filesystem, rather than
        // have them end disk-full (or fill a disk the host needs).
        if self.stopped.is_none() {
            let left = self.todo.saturating_sub(self.done);
            let need = self.run_bytes * width.min(left) as u64;
            if let Some(free) = free_bytes(&self.out).filter(|f| *f < need) {
                self.stopped = Some(format!(
                    "the filesystem holding {} has {} free, less than {width} runs at once may write ({} each: --log-limit and their output); stopped before it fills",
                    self.out.display(),
                    report::bytes(free),
                    report::bytes(self.run_bytes)
                ));
            }
        }
        if self.tty {
            let mut e = std::io::stderr().lock();
            let _ = write!(e, "\r\x1b[K{}", self.status(running));
            let _ = e.flush();
        } else if self.last_line.elapsed() >= Duration::from_secs(10) {
            self.last_line = Instant::now();
            self.say(&format!("sweep: {}", self.status(running)));
        }
        if self.stopped.is_none() {
            Then::Go
        } else {
            Then::Stop
        }
    }

    /// Count a finished run; the job back if it should run again at half the width.
    fn finished(&mut self, d: Done, running: usize, width: usize) -> Option<Job> {
        let Job::Run {
            seed,
            case: case_index,
            dir,
            point,
        } = &d.job
        else {
            return None;
        };
        let case = case_index.map(|i| self.cases[i].clone());
        if !dir.join("result.json").is_file() {
            // The run ended without a result (a request patina refused): keep its answer.
            let v = serde_json::from_slice::<serde_json::Value>(&d.stdout)
                .ok()
                .filter(|v| v["outcome"].is_string())
                .unwrap_or_else(|| error_json(Outcome::Internal, "internal", &tail(&d.stderr)));
            let _ = std::fs::create_dir_all(dir);
            let _ = write_json(&dir.join("result.json"), &v);
        }
        if let Some(c) = &case {
            let _ = std::fs::write(dir.join(CASE_FILE), format!("{c}\n"));
        }
        let mut r = read_json(&dir.join("result.json")).unwrap_or_default();
        // A host limit shared by every sandbox of this user (the kernel's per-user pipe
        // accounting) says nothing about the guest: fewer runs at once, and this one again.
        // A run that hit it while others were running also runs again.
        if let Some(limit) = crate::report::host_limit(&r).filter(|_| width > 1 || running > 0) {
            let to = (width / 2).max(1);
            if to != width {
                self.say(&format!(
                    "sweep: seed {seed} hit {limit}; lowering -j to {to} (such runs run again)"
                ));
            }
            self.width = to;
            let _ = std::fs::remove_dir_all(dir);
            return Some(d.job);
        }
        if let (Some(p), Some((n, base))) = (
            point.filter(|p| *p > 0),
            self.bases.get(&(*seed, *case_index)),
        ) {
            if let Some(why) = missed_point(&r, p, *n) {
                let was = r.clone();
                r["outcome"] = "nondeterministic".into();
                r["exit"] = Outcome::Nondeterministic.exit().into();
                r["stop"] = "point-missed".into();
                r["signature"] =
                    "nondeterministic: a child did not crash at its crash point".into();
                r["message"] = format!(
                    "{why}; its base {} counted {n} crash points, so this run's prefix differs from the base's",
                    base.display()
                )
                .into();
                r["branch_missed"] = serde_json::json!({
                    "outcome": was["outcome"],
                    "message": was["message"],
                    "base": base,
                });
                let _ = write_json(&dir.join("result.json"), &r);
            }
        }
        self.done += 1;
        if let Some(n) = self.unfinished.get_mut(seed) {
            *n -= 1;
            if *n == 0 {
                self.unfinished.remove(seed);
            }
        }
        self.account(*seed, *case_index, *point, dir, &r);
        None
    }

    /// The runs judged again by this sweep's checker, accounted as finished runs.
    fn rejudged(&mut self, jobs: Vec<Job>) {
        for j in jobs {
            if let Job::Run {
                seed,
                case,
                dir,
                point,
            } = j
            {
                let r = read_json(&dir.join("result.json")).unwrap_or_default();
                self.account(seed, case, point, &dir, &r);
            }
        }
    }

    /// What a finished run (or one judged again) does to the sweep: its logs pruned or cut
    /// by `--keep`, a finding counted, grouped and announced, `--max-findings`.
    fn account(
        &mut self,
        seed: u64,
        case_index: Option<usize>,
        point: Option<u64>,
        dir: &Path,
        r: &serde_json::Value,
    ) {
        let case = case_index.map(|i| case_shown(&self.cases[i]));
        let outcome = r["outcome"].as_str().unwrap_or("internal");
        // A run the checker ran on keeps its logs under --keep checked; a sweep with it has a
        // checker, which runs on every run that ended ok.
        let checked = self.keep == Keep::Checked && r["check"]["verdict"] != "not-run";
        if outcome == "ok" && self.keep != Keep::All && !checked {
            prune(dir);
        }
        if (outcome != "ok" || checked) && self.keep != Keep::All {
            let before = bytes_under(dir);
            cut(dir);
            self.cut |= bytes_under(dir) < before;
        }
        if r["stop"] == "disk-full" && self.stopped.is_none() {
            self.stopped = Some(format!("seed {seed} found the filesystem full"));
        }
        if outcome == "ok" {
            self.flush(false);
            return;
        }
        let finding = report::is_finding(outcome);
        let sig = report::signature_of(r);
        // A known finding is counted, never announced, replayed or counted as a group.
        if finding
            && self
                .known
                .is_some_and(|k| k.id_of(case.as_deref(), r).is_some())
        {
            self.known_runs += 1;
            self.flush(false);
            return;
        }
        if finding {
            self.finding_runs += 1;
        }
        let key = (sig.clone(), report::group_case(&sig, case.as_deref()));
        let at = (
            seed,
            point.filter(|p| *p > 0),
            case_index,
            dir.to_path_buf(),
        );
        if self.groups.insert(key.clone()) {
            if finding {
                self.finding_groups += 1;
            }
            self.pending.insert(key, at);
        } else if let Some(p) = self.pending.get_mut(&key).filter(|p| at < **p) {
            // The run the report calls first: the lowest seed, point and case.
            *p = at;
        }
        self.flush(false);
        if let Some(n) = self.max_findings {
            if self.finding_groups >= n && self.stopped.is_none() {
                self.stopped = Some(format!(
                    "{} findings (--max-findings {n})",
                    self.finding_groups
                ));
            }
        }
    }
}

/// Why a `--branch` child that should have crashed at `point` did not (`None`: it did, or it
/// is not a finished run). `base_points` is the crash points its base counted.
fn missed_point(r: &serde_json::Value, point: u64, base_points: u64) -> Option<String> {
    let injected = r["faults"]["counts"]["crash"]["injected"].as_u64()?;
    if point > base_points {
        return None;
    }
    let at = r["crashes"][0]["point"].as_u64();
    match (injected, at) {
        (0, _) => Some(format!("crash point {point} was not reached")),
        (_, Some(at)) if at != point => Some(format!("crashed at point {at}, not {point}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_child_that_misses_its_point_is_named() {
        let run = |injected: u64, crashed_at: Option<u64>| {
            serde_json::json!({
                "outcome": "ok",
                "faults": {"counts": {"crash": {"eligible": 9, "injected": injected}}},
                "crashes": crashed_at.map(|p| vec![serde_json::json!({"point": p})]).unwrap_or_default(),
            })
        };
        assert_eq!(missed_point(&run(1, Some(5)), 5, 9), None);
        assert!(missed_point(&run(0, None), 5, 9).is_some());
        assert!(missed_point(&run(1, Some(4)), 5, 9).is_some());
        // Past the base's count, or not a finished run: nothing to say.
        assert_eq!(missed_point(&run(0, None), 10, 9), None);
        assert_eq!(
            missed_point(&serde_json::json!({"outcome": "internal"}), 5, 9),
            None
        );
    }

    #[test]
    fn case_lines_split_as_a_shell_would() {
        assert_eq!(
            words(r#"a 'b c' "d \"e\" \$f" g\ h"#).unwrap(),
            v(&["a", "b c", r#"d "e" $f"#, "g h"])
        );
        assert!(words("a 'b").is_err());
        assert_eq!(words("  ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_case_line_gives_its_own_settings() {
        let l = case_line("--work d:/srv --env A=1 --env B=2 --name x1 -- ./t 'a b'").unwrap();
        assert_eq!(
            l.flags,
            vec![
                ("--env", "A=1".to_string()),
                ("--env", "B=2".to_string()),
                ("--work", "d:/srv".to_string())
            ]
        );
        assert_eq!((l.name.as_deref(), l.rest), (Some("x1"), "./t 'a b'"));
        // No settings: the line is the command.
        let l = case_line("./t --work d").unwrap();
        assert!(l.flags.is_empty() && l.rest == "./t --work d");
        // The sweep's own settings, unknown ones, and a line without its command are refused.
        for bad in [
            "--seed 3 -- ./t",
            "--fault fs-error-permille=3 -- ./t",
            "--bogus -- ./t",
            "--work d ./t",
            "--work d --",
        ] {
            assert!(case_line(bad).is_err(), "{bad}");
        }
        assert!(case_line("--crash machine -- ./t")
            .err()
            .is_some_and(|e| e.starts_with("--crash ")));
    }

    #[test]
    fn a_case_is_named_by_its_name_or_its_line() {
        let dir = std::env::temp_dir().join(format!("patina-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("cases.txt");
        let read = |t: &str| {
            std::fs::write(&f, t).unwrap();
            read_cases(&f, &[])
        };
        let c = read("# a comment\n./t a\n\n--name b.1 -- ./t b\n").unwrap();
        let ids: Vec<(&str, &str)> = c.iter().map(|c| (c.id.as_str(), c.dir.as_str())).collect();
        assert_eq!(ids, vec![("2", "2-a"), ("b.1", "4-b.1")]);
        for bad in [
            "--name 12 -- ./t\n",
            "--name 'a b' -- ./t\n",
            "--name .x -- ./t\n",
            "--name x -- ./t\n--name x -- ./u\n",
        ] {
            assert!(read(bad).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn case_names_are_short_and_safe() {
        let n = |s: &str| case_name(&words(s).unwrap());
        assert_eq!(
            n("/t/deps/http_flow-1a2b --exact tests::a::b --test-threads=1"),
            "tests_a_b"
        );
        assert_eq!(
            n("python3 -m unittest test_store.Store.x"),
            "test_store.Store.x"
        );
        assert_eq!(n("../.hidden"), "hidden");
        for s in ["a/b c/d", "x y", "'/' ", "..", "--only"] {
            let c = n(s);
            assert!(
                !c.is_empty() && !c.contains(['/', ' ']) && !c.starts_with('.'),
                "{s}: {c}"
            );
        }
        assert!(n(&"x".repeat(500)).len() <= CASE_NAME_MAX);
        // A word with spaces (a script, JSON) is named by its start, not by its last `/`.
        assert_eq!(
            n(r#"/h/harness '{"script": "cat /rw/a", "dir": "/rw_"}'"#),
            "_script_cat_rw_a_dir_rw_"
        );
    }
}
