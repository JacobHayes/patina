//! `patina sweep`: a list of seeds (and optionally cases), each one ordinary `patina run` in
//! a child process into `OUT/seed-N[/K-NAME]`, `-j` at a time, each child pinned to its own CPU.
//! A new finding prints one line at once; progress is a live line on a terminal and a plain
//! line every 10 s otherwise. When the runs are done, the first seed of every finding is
//! replayed once (a difference makes the group `nondeterministic`), logs are pruned by
//! `--keep`, and the report of `patina report OUT` is printed and written to
//! `OUT/report.json`. `OUT/sweep.json` records what the sweep runs (the program's SHA-256, the
//! resolved settings and command, and patina's own version and hash): running the same sweep
//! again into the same `--out` runs only the runs not there yet (more seeds, an interrupted
//! sweep); any other sweep replaces the directory, so that edit, rebuild and the same command
//! never report an old program's runs.

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
const OWN: [&str; 10] = [
    "--seeds",
    "--jobs",
    "--cases",
    "--keep",
    "--max-findings",
    "--budget",
    "--allow-unmet",
    "--out",
    "--format",
    "--help",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Fail,
    All,
    None,
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
const SWEEP_FILE: &str = "sweep.json";
const SWEEP_SCHEMA: &str = "patina.sweep/v1";

/// What decides every run of a sweep besides its seed and case: patina itself, the program
/// (its SHA-256) and the resolved settings with the command. The seeds, the cases, `-j`,
/// `--keep` and the stopping rules are not part of it: a sweep with more seeds or cases is the
/// same sweep, extended.
fn identity(cfg: &crate::config::Config, program: Option<&String>) -> Res<serde_json::Value> {
    let mut c = cfg.clone();
    c.seed = 0;
    c.host_cpu = None;
    c.allow_unmet.clear();
    let exe = std::env::current_exe().map_err(|e| format!("patina binary: {e}"))?;
    Ok(serde_json::json!({
        "schema": SWEEP_SCHEMA,
        "patina": format!("{} {}", env!("CARGO_PKG_VERSION"), crate::config::sha256_file(&exe)?),
        "program": program,
        "config": c,
    }))
}

/// Why the sweep recorded in `out` is not the one described by `ident`, if it is not.
fn differs(out: &Path, ident: &serde_json::Value) -> Option<String> {
    let Ok(old) = read_json(&out.join(SWEEP_FILE)) else {
        return Some(format!("no {SWEEP_FILE}"));
    };
    if old["schema"] != ident["schema"] {
        return Some(format!("{SWEEP_FILE} of another schema"));
    }
    if old["program"] != ident["program"] {
        return Some("the program changed".into());
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
    if old["patina"] != ident["patina"] {
        return Some("another patina build".into());
    }
    None
}

/// A case run's directory holds its case's text in this file.
pub const CASE_FILE: &str = "case";
/// Longest name a case's directory takes from the case (characters).
const CASE_NAME_MAX: usize = 40;

/// One line of a `--cases` file.
struct Case {
    /// The line as written.
    text: String,
    /// Its line number in the file.
    line_no: usize,
    /// The command its run is given.
    cmd: Vec<String>,
    /// Its directory under `seed-N`: `K-NAME`, K its position among the cases.
    dir: String,
}

/// Read a cases file: one case per line; empty lines and lines starting with `#` are
/// skipped. With a command (`cmd`), `{}` in it is replaced by the line; without one, the line
/// is the whole command, its words split as a shell would (quotes and backslashes, no
/// expansion).
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
        let w = words(&text);
        let run = if cmd.is_empty() {
            match w {
                Ok(w) => w,
                Err(e) => return Err(format!("--cases {at} line {}: {e}", n + 1)),
            }
        } else {
            cmd.iter().map(|x| x.replace("{}", &text)).collect()
        };
        let named =
            words(&text).unwrap_or_else(|_| text.split_whitespace().map(String::from).collect());
        out.push(Case {
            dir: format!("{}-{}", out.len() + 1, case_name(&named)),
            text,
            line_no: n + 1,
            cmd: run,
        });
    }
    if out.is_empty() {
        return Err(format!("--cases {at}: no cases"));
    }
    Ok(out)
}

/// The words of a line as `sh` splits them: whitespace separates, `'...'` is literal,
/// `"..."` keeps `\"`, `\\`, `\$` and `` \` `` escapes, a backslash outside quotes takes the
/// next character. Nothing is expanded.
pub fn words(line: &str) -> Res<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut word = false;
    let mut it = line.chars();
    while let Some(c) = it.next() {
        match c {
            c if c.is_whitespace() => {
                if word {
                    out.push(std::mem::take(&mut cur));
                    word = false;
                }
            }
            '\'' => {
                word = true;
                loop {
                    match it.next() {
                        Some('\'') => break,
                        Some(x) => cur.push(x),
                        None => return Err("unterminated '".into()),
                    }
                }
            }
            '"' => {
                word = true;
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some('\\') => match it.next() {
                            Some(x) if "\"\\$`".contains(x) => cur.push(x),
                            Some(x) => {
                                cur.push('\\');
                                cur.push(x);
                            }
                            None => return Err("unterminated \"".into()),
                        },
                        Some(x) => cur.push(x),
                        None => return Err("unterminated \"".into()),
                    }
                }
            }
            '\\' => {
                word = true;
                match it.next() {
                    Some(x) => cur.push(x),
                    None => return Err("a backslash at the end of the line".into()),
                }
            }
            c => {
                word = true;
                cur.push(c);
            }
        }
    }
    if word {
        out.push(cur);
    }
    Ok(out)
}

/// A short name for a case's directory: its last word that is not an option (else its last
/// word), after the last `/`, with every character but letters, digits, `.`, `_` and `-`
/// made `_`.
fn case_name(words: &[String]) -> String {
    let w = words
        .iter()
        .rev()
        .find(|w| !w.starts_with('-'))
        .or(words.last())
        .map(|w| w.rsplit('/').next().unwrap_or(w))
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

/// Default width: half the CPUs this process may use, at most 8.
fn default_jobs() -> usize {
    (crate::launch::allowed_cpus().len() / 2).clamp(1, 8)
}

enum Job {
    Run {
        seed: u64,
        /// Index into the cases.
        case: Option<usize>,
        dir: PathBuf,
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
fn pool(
    jobs: Vec<Job>,
    width: usize,
    child: &(dyn Fn(&Job) -> Command + Sync),
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
            sc.spawn(move || loop {
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
                cmd.stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || {
                        // One CPU: the run's own pinning picks it (launch::default_cpu).
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(cpu, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
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
                if INTERRUPTED.load(SeqCst) {
                    pending.fetch_sub(1, SeqCst);
                    return;
                }
                let _ = tx.send(Done {
                    job,
                    stdout,
                    stderr,
                });
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

/// Remove the logs (`inc-*`) of a run directory, keeping `run.json` and `result.json`.
fn prune(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("inc-") {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
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
        k => {
            return Err(error(format!(
                "--keep: expected fail, all or none, not {k}"
            )))
        }
    };
    let width = match a.num::<usize>("--jobs").map_err(error)? {
        Some(0) => return Err(error("--jobs is at least 1".into())),
        Some(n) => n,
        None => default_jobs(),
    };
    let max_findings = a.num::<usize>("--max-findings").map_err(error)?;
    let budget = a.num::<u64>("--budget").map_err(error)?;
    let cmd_of = |case: Option<usize>| -> Vec<String> {
        match (case, &cases) {
            (Some(i), Some(c)) => c[i].cmd.clone(),
            _ => cfg.cmd.clone(),
        }
    };
    // Every program the runs start, resolved and hashed once: a run already in the sweep
    // directory is kept only if it ran the same program.
    let mut programs: std::collections::BTreeMap<String, crate::config::Program> =
        Default::default();
    let list: Vec<Option<usize>> = match &cases {
        Some(c) => (0..c.len()).map(Some).collect(),
        None => vec![None],
    };
    for &i in &list {
        let cmd = cmd_of(i);
        if !programs.contains_key(&cmd[0]) {
            let p = crate::config::program(&cmd[0], &cfg.mounts).map_err(|e| {
                error(match (i, &cases) {
                    (Some(i), Some(c)) => format!("--cases line {}: {e}", c[i].line_no),
                    _ => e,
                })
            })?;
            programs.insert(cmd[0].clone(), p);
        }
    }
    let probe_program = {
        let mut probe = cfg.clone();
        probe.cmd = cmd_of(list[0]);
        let o = probe
            .opts_with(programs[&probe.cmd[0]].clone())
            .map_err(error)?;
        crate::launch::preflight(&o).map_err(error)?;
        o.program
    };

    let out = crate::absolute(PathBuf::from(a.last("--out").unwrap_or("patina-out/sweep")));
    if let Ok(rd) = std::fs::read_dir(&out) {
        let names: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !names.is_empty()
            && !names
                .iter()
                .any(|n| n == "report.json" || n == SWEEP_FILE || n.starts_with("seed-"))
        {
            return Err(error(format!(
                "{}: exists and is not a sweep directory; give another --out",
                out.display()
            )));
        }
    }
    // With whole-command cases there is no one program: each run's is checked on resume.
    let ident =
        identity(&cfg, (!cfg.cmd.is_empty()).then_some(&probe_program.sha256)).map_err(error)?;
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

    let mut jobs = vec![];
    let mut total = 0;
    for &seed in &seeds {
        for &case in &list {
            let mut dir = out.join(format!("seed-{seed}"));
            if let (Some(i), Some(c)) = (case, &cases) {
                dir = dir.join(&c[i].dir);
            }
            total += 1;
            let sha = &programs[&cmd_of(case)[0]].sha256;
            if done_before(
                &dir,
                case.map(|i| cases.as_ref().unwrap()[i].text.as_str()),
                sha,
            ) {
                continue;
            }
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| error(format!("{}: {e}", dir.display())))?;
            }
            jobs.push(Job::Run { seed, case, dir });
        }
    }
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
        if OWN.contains(name) {
            continue;
        }
        let f = find_flag(name).unwrap();
        for v in vals {
            pass.push(name.to_string());
            if !f.value.is_empty() {
                pass.push(v.clone());
            }
        }
    }
    let exe = std::env::current_exe().map_err(|e| error(format!("patina binary: {e}")))?;
    let child = |job: &Job| -> Command {
        let mut c = Command::new(&exe);
        match job {
            Job::Run { seed, case, dir } => {
                c.arg("run")
                    .arg("--seed")
                    .arg(seed.to_string())
                    .arg("--out")
                    .arg(dir)
                    .args(["--format", "json"])
                    .args(&pass)
                    .arg("--")
                    .args(cmd_of(*case));
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
        groups: BTreeSet::new(),
        pending: Default::default(),
        unfinished,
        finding_groups: 0,
        stopped: None,
        keep,
        width,
        max_findings,
        budget,
    };
    if todo < total {
        st.say(&format!(
            "sweep: {} of {total} runs of this sweep already in {}; running {todo}",
            total - todo,
            out.display()
        ));
    }
    let not_started = pool(jobs, width, &child, |d, running, now| {
        st.event(d, running, now)
    });
    st.flush(true);
    let interrupted = INTERRUPTED.load(SeqCst);
    if interrupted {
        st.stopped = Some("interrupted".into());
        // Runs that were terminated left a directory without a result.
        for &seed in &seeds {
            let d = out.join(format!("seed-{seed}"));
            if d.is_dir() && !d.join("result.json").exists() {
                let partial = match &cases {
                    None => vec![d],
                    Some(c) => c
                        .iter()
                        .map(|c| d.join(&c.dir))
                        .filter(|x| x.is_dir() && !x.join("result.json").exists())
                        .collect(),
                };
                for p in partial {
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
        let (v, _) = report::build(&runs, &[], None);
        let mut replays = vec![];
        for g in v["groups"].as_array().unwrap() {
            let finding = Outcome::ALL
                .iter()
                .any(|o| g["run_outcome"] == o.name() && o.exit() == 1);
            if finding && g["replay"].is_null() {
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
            pool(replays, st.width, &child, |d, _, _| {
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
    let head = SweepHead {
        seconds: st.t0.elapsed().as_secs_f64(),
        jobs: width,
        lowered_to: Some(st.width).filter(|w| *w != width),
        stopped: st.stopped.clone(),
    };
    let (v, text) = report::build(&runs, a.all("--allow-unmet"), Some(head));
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
        Ok(_) => serde_json::json!({"result": "identical", "message": ""}),
        Err(_) => serde_json::json!({"result": "error", "message": tail(&d.stderr)}),
    };
    let _ = write_json(&dir.join("replay.json"), &v);
    if v["result"] == "identical" {
        let _ = std::fs::remove_dir_all(out);
    }
}

/// The sweep's counters and its terminal output.
struct State {
    /// Each case's text, for its `new:` line and its run directory's `case` file.
    cases: Vec<String>,
    tty: bool,
    t0: Instant,
    last_line: Instant,
    todo: usize,
    done: usize,
    finding_runs: usize,
    groups: BTreeSet<(String, Option<String>)>,
    /// Groups found whose `new:` line waits until no lower seed is left to run, so that it
    /// names the group's lowest seed, the one the report calls first: (seed, run directory).
    pending: std::collections::BTreeMap<(String, Option<String>), (u64, PathBuf)>,
    /// Runs not finished yet, by seed.
    unfinished: std::collections::BTreeMap<u64, usize>,
    finding_groups: usize,
    stopped: Option<String>,
    keep: Keep,
    /// The width now (lowered on a host limit).
    width: usize,
    max_findings: Option<usize>,
    budget: Option<u64>,
}

impl State {
    fn status(&self, running: usize) -> String {
        let s = self.t0.elapsed().as_secs_f64();
        format!(
            "{}/{} runs, {} in {}, {running} running, {:.1} runs/s, {}",
            self.done,
            self.todo,
            report::count(self.finding_runs, "finding"),
            report::count(self.finding_groups, "group"),
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
            .filter(|(_, (seed, _))| all || low.is_none_or(|l| *seed < l))
            .map(|(k, _)| k.clone())
            .collect();
        for k in ready {
            let (seed, dir) = self.pending.remove(&k).unwrap();
            let c = k.1.as_ref().map(|c| format!(" [{c}]")).unwrap_or_default();
            self.say(&format!(
                "new{c}: {}   (seed {seed}: patina replay {})",
                k.0,
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
        let Job::Run { seed, case, dir } = &d.job else {
            return None;
        };
        let case = case.map(|i| self.cases[i].clone());
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
        let r = read_json(&dir.join("result.json")).unwrap_or_default();
        let outcome = r["outcome"].as_str().unwrap_or("internal");
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
        self.done += 1;
        if let Some(n) = self.unfinished.get_mut(seed) {
            *n -= 1;
            if *n == 0 {
                self.unfinished.remove(seed);
            }
        }
        if outcome == "ok" && self.keep != Keep::All {
            prune(dir);
        }
        if outcome == "ok" {
            self.flush(false);
            return None;
        }
        let finding = Outcome::ALL
            .iter()
            .any(|o| o.name() == outcome && o.exit() == 1);
        let sig = r["signature"].as_str().unwrap_or(outcome).to_string();
        if finding {
            self.finding_runs += 1;
        }
        let key = (sig, case.clone());
        if self.groups.insert(key.clone()) {
            if finding {
                self.finding_groups += 1;
            }
            self.pending.insert(key, (*seed, dir.clone()));
        } else if let Some(p) = self.pending.get_mut(&key).filter(|p| *seed < p.0) {
            *p = (*seed, dir.clone());
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
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
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
    }
}
