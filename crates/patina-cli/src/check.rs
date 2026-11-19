//! `--check 'CMD ARGS'`: a checker outside the simulation. After a run that ended `ok`, and
//! after `result.json` is written, `CMD ARGS RUNDIR` runs on the host as the user, outside the
//! sandbox and without network or other restrictions of Patina's: it is the user's own program.
//! Its working directory is the directory patina was started in (recorded), so paths in
//! `ARGS` are relative to it. It gets `PATINA_SEED`, `PATINA_EXIT` (the program's exit
//! status) and, for a sweep's `--cases` run, `PATINA_CASE` (the line) and `PATINA_CASE_NAME`
//! (the case's directory, `ID-NAME` or `NAME`) and `PATINA_CASE_ID`. Its stdout, then its
//! stderr, go to `RUNDIR/check.out`.
//!
//! The words are split as a `--cases` line is (quotes, no expansion; no shell runs unless the
//! user names one). The program is resolved (a path against the recorded directory, a bare
//! name on `PATH`) and recorded with its SHA-256 in `run.json`, so `replay`, `minimize` and
//! `verify` run the same checker, and refuse a changed one.
//!
//! Exit 0 passes; 1 is a finding, named by the first non-empty line of stdout, `LABEL:
//! detail` or `LABEL [KEY]: detail` (`finding`, `signature::violation`); 77 is "not judged"
//! (the run stays `ok`; its first line, `CLASS: detail` or a reason); anything else,
//! a signal, a checker that cannot be started or one still running after `--timeout` seconds
//! (its own, counted from its start) ends the run `error`, stop `check`: a checker that fails
//! is never a pass. The checker's output never reaches the run's logs or its digest.

use crate::cli::Res;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What `run.json` records of a `--check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// The command's words as given.
    pub words: Vec<String>,
    /// Where patina was started: the checker's working directory.
    pub dir: PathBuf,
    /// The program the first word names, absolute.
    pub program: PathBuf,
    pub sha256: String,
    /// A serving checker (`--check-serve`): one process answers a line per run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub serve: bool,
    /// Wall seconds the checker may run (`--check-timeout`).
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// The case of a sweep's `--cases` run (set by the sweep for its runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<Case>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// The line after its settings.
    pub text: String,
    /// Its directory under `seed-N`.
    pub name: String,
    /// Its id: the line's `--name`, or its line number in the cases file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// `--check-timeout`'s default: a checker reads a run directory; one still running after a
/// minute is stuck, and should not hold a sweep for the run's own `--timeout`.
pub const DEFAULT_TIMEOUT: u64 = 60;

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT
}

/// The variables a sweep passes a case in to its runs (and the checker gets).
pub const CASE_VAR: &str = "PATINA_CASE";
pub const CASE_NAME_VAR: &str = "PATINA_CASE_NAME";
pub const CASE_ID_VAR: &str = "PATINA_CASE_ID";
/// The whole case line, settings included, from a sweep to its run (for `run.json`); not
/// passed on to the checker.
pub const CASE_LINE_VAR: &str = "PATINA_CASE_LINE";

/// The checker's output file in the run directory.
pub const OUTPUT: &str = "check.out";

/// The exit status that means "not judged".
const NOT_JUDGED: i32 = 77;

impl Check {
    /// `--check SPEC` (or `[run] check`), given in `dir`.
    pub fn resolve(spec: &str, dir: &Path) -> Res<Check> {
        let words = crate::sweep::words(spec).map_err(|e| format!("--check {spec}: {e}"))?;
        let Some(w0) = words.first() else {
            return Err("--check: no command".into());
        };
        let program = if w0.contains('/') {
            std::path::absolute(dir.join(w0)).unwrap_or_else(|_| dir.join(w0))
        } else {
            let path = std::env::var_os("PATH").unwrap_or_default();
            std::env::split_paths(&path)
                .map(|d| dir.join(d).join(w0))
                .find(|f| executable(f))
                .ok_or_else(|| format!("--check: {w0}: not found on PATH"))?
        };
        Check::at(words, dir.to_path_buf(), program)
    }

    /// The same checker resolved again (`--config run.json`): its words, from its directory.
    pub fn again(&self) -> Res<Check> {
        let mut c = Check::resolve(&join(&self.words), &self.dir)?;
        c.case = self.case.clone();
        c.timeout = self.timeout;
        c.serve = self.serve;
        Ok(c)
    }

    fn at(words: Vec<String>, dir: PathBuf, program: PathBuf) -> Res<Check> {
        let shown = program.display();
        if !program.is_file() {
            return Err(format!("--check: {shown}: no such file"));
        }
        if !executable(&program) {
            return Err(format!("--check: {shown}: not executable"));
        }
        if !dir.is_dir() {
            return Err(format!("--check: its directory {} is gone", dir.display()));
        }
        let sha256 = crate::config::sha256_file(&program)?;
        Ok(Check {
            words,
            dir,
            program,
            sha256,
            serve: false,
            timeout: DEFAULT_TIMEOUT,
            case: None,
        })
    }

    /// Refuse a checker changed since it was recorded (a replay repeats the recorded one).
    pub fn unchanged(&self) -> Res<()> {
        let now = crate::config::sha256_file(&self.program)
            .map_err(|e| format!("checker {} is gone: {e}", self.program.display()))?;
        if now != self.sha256 {
            return Err(format!(
                "checker {} changed since the run (sha256 {} recorded, {} now): a replay judges \
                 with the recorded checker; put it back to replay, or judge the run with the new \
                 one (`patina recheck RUNDIR`, or run the same sweep again)",
                self.program.display(),
                self.sha256,
                now
            ));
        }
        Ok(())
    }
}

/// The words as one `--check` argument that splits back into them.
pub fn join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| crate::report::quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

/// This patina binary, as the checker gets it in `PATINA`.
fn patina_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("patina"))
}

fn executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// What the checker said.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Pass,
    Fail,
    NotJudged,
    Error,
    /// The run did not end `ok`: the checker was not started.
    NotRun,
    /// Written before the checker starts and replaced by its verdict: a run directory left
    /// so (patina interrupted during the check) is an error, never a pass.
    Pending,
}

/// `result.json`'s `check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict: Kind,
    /// The checker's exit status, or the signal that killed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// A finding's name and detail (its first line, `LABEL: detail`), as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Why the checker is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Verdict {
    pub fn not_run() -> Verdict {
        Verdict::new(Kind::NotRun)
    }

    pub fn pending() -> Verdict {
        Verdict {
            message: Some("the checker did not finish: patina was stopped during the check".into()),
            ..Verdict::new(Kind::Pending)
        }
    }

    fn new(verdict: Kind) -> Verdict {
        Verdict {
            verdict,
            exit: None,
            signal: None,
            label: None,
            detail: None,
            message: None,
        }
    }

    fn error(message: String) -> Verdict {
        Verdict {
            message: Some(message),
            ..Verdict::new(Kind::Error)
        }
    }

    /// The line a finding is named by: `LABEL: detail`.
    pub fn line(&self) -> String {
        match (self.label.as_deref().unwrap_or(""), self.detail.as_deref()) {
            (l, Some(d)) if !d.is_empty() => format!("{l}: {d}"),
            (l, _) => l.to_string(),
        }
    }
}

/// The first non-empty line of `text`, trimmed.
fn first_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// The checker's command, without what differs by run: its words, from its directory, with
/// `PATINA`; in its own process group (what it leaves running is ended with it), ended if
/// patina is, with the caller's signal state.
fn command(c: &Check) -> Command {
    let mut cmd = Command::new(&c.program);
    cmd.arg0(&c.words[0])
        .args(&c.words[1..])
        .current_dir(&c.dir)
        // The patina that runs it, for `patina log ...` on the run directory.
        .env("PATINA", patina_exe())
        .env_remove(SERVER_VAR)
        .env_remove(SERVE_VAR)
        .env_remove(CASE_LINE_VAR)
        .process_group(0);
    unsafe {
        cmd.pre_exec(|| {
            // Ended if patina is (its group does not get the terminal's or a sweep's signal).
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            // The caller's signal state, not what `verify --vary env` changed in patina.
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            for sig in 1..32 {
                if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                    libc::signal(sig, libc::SIG_DFL);
                }
            }
            Ok(())
        });
    }
    match &c.case {
        Some(k) => cmd.env(CASE_VAR, &k.text).env(CASE_NAME_VAR, &k.name),
        None => cmd.env_remove(CASE_VAR).env_remove(CASE_NAME_VAR),
    };
    match c.case.as_ref().and_then(|k| k.id.as_ref()) {
        Some(id) => cmd.env(CASE_ID_VAR, id),
        None => cmd.env_remove(CASE_ID_VAR),
    };
    cmd
}

/// A finding's line split into its label and detail: `LABEL: detail`, or `LABEL [KEY]:
/// detail`, whose label is `LABEL [KEY]` (a word, then a key in brackets that may hold `: `),
/// or a line without `: `, all label.
pub fn finding(line: &str) -> (String, String) {
    let keyed = line.split_once(" [").and_then(|(name, rest)| {
        if name.is_empty() || name.contains(char::is_whitespace) {
            return None;
        }
        // The key ends at the first `]` that ends the line or is followed by `: `.
        let mut at = 0;
        while let Some(i) = rest[at..].find(']') {
            let end = at + i;
            let after = &rest[end + 1..];
            if after.is_empty() || after.starts_with(": ") {
                let label = &line[..name.len() + 2 + end + 1];
                return Some((
                    label.to_string(),
                    after.strip_prefix(": ").unwrap_or("").to_string(),
                ));
            }
            at = end + 1;
        }
        None
    });
    keyed.unwrap_or_else(|| match line.split_once(": ") {
        Some((l, d)) => (l.to_string(), d.to_string()),
        None => (line.to_string(), String::new()),
    })
}

/// Run `c` on the run directory `rundir`: its seed, the program's exit status, at most
/// `c.timeout` seconds. A serving checker (`--check-serve`) is asked through the sweep job's
/// server (`SERVER_VAR`), or one started for this run alone.
pub fn run(c: &Check, rundir: &Path, seed: u64, exit: Option<i64>) -> Verdict {
    run_on(c, rundir, seed, exit, None)
}

/// `run`, asking `server` (one this process started) when the checker serves. A server that
/// answered with an error has been killed: the caller starts another.
pub fn run_on(
    c: &Check,
    rundir: &Path,
    seed: u64,
    exit: Option<i64>,
    server: Option<&Server>,
) -> Verdict {
    let r = if c.serve {
        serve_one(c, rundir, seed, exit, server.map(|s| s.channel()))
    } else {
        run_inner(c, rundir, seed, exit, c.timeout)
    };
    match r {
        Ok(v) => v,
        Err(e) => Verdict::error(e),
    }
}

/// `--check-serve`: the checker started once per sweep job, with `PATINA_CHECK_SERVE=1` and
/// no run directory. For each run, one line on its stdin, `{"rundir": DIR, "env":
/// {"PATINA_SEED": ..., "PATINA_EXIT": ..., "PATINA_CASE": ..., "PATINA_CASE_NAME": ...}}`, and
/// one line back on its stdout: `pass`, `fail LABEL: detail`, or `skip REASON` (not judged).
/// Anything else, end of output, or no answer within `--check-timeout` is `error`, and the
/// server is killed (a sweep starts another for its next run). Bytes on its stdout before a
/// request are an error too: a line answers only the request just written. What it writes to
/// stderr while it answers goes to `check.out` after the answer.
pub struct Server {
    child: std::process::Child,
    req: std::fs::File,
    res: std::fs::File,
    err: std::fs::File,
}

/// A sweep job's server, as a `patina run` it starts finds it: `REQ,RES,ERR,PGID`.
pub const SERVER_VAR: &str = "PATINA_CHECK_SERVER";
/// Set (to 1) for a serving checker.
pub const SERVE_VAR: &str = "PATINA_CHECK_SERVE";

impl Server {
    pub fn start(c: &Check) -> Res<Server> {
        let name = c"patina-check-serve-stderr";
        let err =
            crate::sys::cvt_i(unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) })
                .map_err(|e| format!("memfd: {e}"))?;
        let err = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(err) });
        let mut cmd = command(c);
        cmd.env(SERVE_VAR, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(err.try_clone().map_err(|e| e.to_string())?);
        let mut child = cmd.spawn().map_err(|e| {
            format!(
                "the checker {} could not be started: {e}",
                c.program.display()
            )
        })?;
        let req = std::fs::File::from(OwnedFd::from(child.stdin.take().unwrap()));
        let res = std::fs::File::from(OwnedFd::from(child.stdout.take().unwrap()));
        Ok(Server {
            child,
            req,
            res,
            err,
        })
    }

    /// Whether it is still running. An ended one is not reaped here (`WNOWAIT`): its pid, the
    /// group `end` kills, stays reserved until `end` has killed the group.
    pub fn alive(&mut self) -> bool {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        r == 0 && unsafe { info.si_pid() } == 0
    }

    /// Lend it to the `patina run` that `cmd` starts: `SERVER_VAR`, and its descriptors kept
    /// open across that exec (that process marks them close-on-exec again: `channel`).
    pub fn lend(&self, cmd: &mut Command) {
        let fds = [
            self.req.as_raw_fd(),
            self.res.as_raw_fd(),
            self.err.as_raw_fd(),
        ];
        cmd.env(
            SERVER_VAR,
            format!("{},{},{},{}", fds[0], fds[1], fds[2], self.child.id()),
        );
        unsafe {
            cmd.pre_exec(move || {
                for fd in fds {
                    libc::fcntl(fd, libc::F_SETFD, 0);
                }
                Ok(())
            });
        }
    }

    fn channel(&self) -> Channel {
        Channel {
            req: self.req.as_raw_fd(),
            res: self.res.as_raw_fd(),
            err: self.err.as_raw_fd(),
            pgid: self.child.id() as i32,
        }
    }

    /// End it: its process group killed, the process reaped.
    pub fn end(mut self) {
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let _ = self.child.wait();
    }
}

/// A server's descriptors and process group, as this process reaches them.
#[derive(Clone, Copy)]
struct Channel {
    req: i32,
    res: i32,
    err: i32,
    pgid: i32,
}

/// The sweep job's server this `patina run` was lent (`SERVER_VAR`), its descriptors made
/// close-on-exec at once so that nothing this process starts inherits them. Read once.
fn channel() -> Option<Channel> {
    static CH: std::sync::OnceLock<Option<Channel>> = std::sync::OnceLock::new();
    *CH.get_or_init(|| {
        let v = std::env::var(SERVER_VAR).ok()?;
        let n: Vec<i32> = v.split(',').filter_map(|x| x.parse().ok()).collect();
        let [req, res, err, pgid] = n[..] else {
            return None;
        };
        for fd in [req, res, err] {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        Some(Channel {
            req,
            res,
            err,
            pgid,
        })
    })
}

/// Take a lent server's descriptors before anything is started (`main`).
pub fn adopt_server() {
    let _ = channel();
}

fn serve_one(
    c: &Check,
    rundir: &Path,
    seed: u64,
    exit: Option<i64>,
    own: Option<Channel>,
) -> Res<Verdict> {
    let rundir = std::path::absolute(rundir).unwrap_or_else(|_| rundir.to_path_buf());
    let path = rundir.join(OUTPUT);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut env = serde_json::Map::new();
    env.insert("PATINA_SEED".into(), seed.to_string().into());
    env.insert(
        "PATINA_EXIT".into(),
        exit.map(|x| x.to_string()).unwrap_or_default().into(),
    );
    if let Some(k) = &c.case {
        env.insert(CASE_VAR.into(), k.text.clone().into());
        env.insert(CASE_NAME_VAR.into(), k.name.clone().into());
        if let Some(id) = &k.id {
            env.insert(CASE_ID_VAR.into(), id.clone().into());
        }
    }
    let line = serde_json::json!({"rundir": rundir, "env": env}).to_string();
    let (mut v, said, stderr) = match own.or_else(channel).map(|ch| (ch, idle(ch))) {
        Some((ch, Idle::Yes)) => ask(ch, &line, c.timeout),
        Some((ch, Idle::Wrote)) => {
            unsafe { libc::kill(-ch.pgid, libc::SIGKILL) };
            (
                Verdict::error(
                    "the checker server wrote to its stdout between requests: one line answers one request".into(),
                ),
                String::new(),
                vec![],
            )
        }
        // A run of its own (`patina run`, a replay), or the sweep job's server has ended
        // since its last answer: a server for this one run.
        _ => {
            let s = Server::start(c)?;
            let r = ask(s.channel(), &line, c.timeout);
            s.end();
            r
        }
    };
    out.write_all(said.as_bytes())
        .and_then(|_| out.write_all(&stderr))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if v.verdict == Kind::Fail {
        // As for a checker's first line: the run directory's own path is RUNDIR.
        v.detail = v
            .detail
            .map(|d| d.replace(&rundir.display().to_string(), "RUNDIR"));
    }
    Ok(v)
}

enum Idle {
    Yes,
    /// It wrote between requests: that would be taken as the next run's answer.
    Wrote,
    Ended,
}

/// Whether a lent server waits for a request, wrote out of turn, or has ended.
fn idle(ch: Channel) -> Idle {
    if !crate::sys::readable(ch.res, 0) {
        return Idle::Yes;
    }
    let mut b = [0u8; 1];
    match unsafe { libc::read(ch.res, b.as_mut_ptr().cast(), 1) } {
        0 => Idle::Ended,
        _ => Idle::Wrote,
    }
}

/// One request and its answer: the verdict, the answer as received (for `check.out`), and what
/// the server wrote to stderr meanwhile. A server that answers out of turn, not at all or
/// with anything but a verdict line is killed: it cannot be trusted with the next run.
fn ask(ch: Channel, line: &str, timeout: u64) -> (Verdict, String, Vec<u8>) {
    let kill = || unsafe {
        libc::kill(-ch.pgid, libc::SIGKILL);
    };
    let size = |fd: i32| -> u64 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(fd, &mut st) };
        st.st_size as u64
    };
    let from = size(ch.err);
    let stderr = || -> Vec<u8> {
        let to = size(ch.err);
        let mut b = vec![0u8; to.saturating_sub(from) as usize];
        let n = unsafe { libc::pread(ch.err, b.as_mut_ptr().cast(), b.len(), from as i64) };
        b.truncate(n.max(0) as usize);
        // Read once: its pages go (the size stays, so offsets do), or a server that logs
        // would hold a sweep job's whole log in memory.
        unsafe {
            libc::fallocate(
                ch.err,
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                0,
                to as i64,
            )
        };
        b
    };
    let fail = |m: String, said: Vec<u8>| {
        kill();
        (
            Verdict::error(m),
            String::from_utf8_lossy(&said).into_owned(),
            stderr(),
        )
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    // Written without blocking: a server that does not read is held to the same deadline.
    unsafe {
        let fl = libc::fcntl(ch.req, libc::F_GETFL);
        libc::fcntl(ch.req, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let req = format!("{line}\n");
    let mut at = 0;
    while at < req.len() {
        let n = unsafe { libc::write(ch.req, req[at..].as_ptr().cast(), req.len() - at) };
        if n > 0 {
            at += n as usize;
            continue;
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EAGAIN) => match crate::sys::wait_fd_out(ch.req, deadline) {
                crate::sys::Waited::Ready => {}
                crate::sys::Waited::Timeout => {
                    return fail(
                        format!("the checker server did not read its request within --check-timeout ({timeout} s)"),
                        vec![],
                    )
                }
                crate::sys::Waited::Terminated => {
                    kill();
                    crate::sys::exit_terminated();
                }
            },
            Some(libc::EINTR) => {}
            _ => {
                return fail(
                    format!("the checker server does not take requests: {e}"),
                    vec![],
                )
            }
        }
    }
    let mut got: Vec<u8> = vec![];
    loop {
        match crate::sys::wait_fd(ch.res, deadline) {
            crate::sys::Waited::Ready => {}
            crate::sys::Waited::Timeout => {
                return fail(
                    format!(
                        "the checker server did not answer within --check-timeout ({timeout} s)"
                    ),
                    got,
                )
            }
            crate::sys::Waited::Terminated => {
                kill();
                crate::sys::exit_terminated();
            }
        }
        let mut b = [0u8; 4096];
        let n = unsafe { libc::read(ch.res, b.as_mut_ptr().cast(), b.len()) };
        if n <= 0 {
            return fail("the checker server ended without answering".into(), got);
        }
        got.extend_from_slice(&b[..n as usize]);
        if let Some(i) = got.iter().position(|&x| x == b'\n') {
            if i + 1 != got.len() {
                return fail(
                    "the checker server answered with more than one line".into(),
                    got,
                );
            }
            let said = String::from_utf8_lossy(&got).into_owned();
            let v = verdict_line(said.trim_end_matches('\n'));
            if v.verdict == Kind::Error {
                kill();
            }
            return (v, said, stderr());
        }
    }
}

/// A server's answer: `pass`, `fail LABEL: detail`, `skip REASON`; anything else is `error`.
fn verdict_line(l: &str) -> Verdict {
    let (word, rest) = l.split_once(' ').unwrap_or((l, ""));
    let rest = rest.trim();
    match word {
        "pass" if rest.is_empty() => Verdict::new(Kind::Pass),
        "fail" if !rest.is_empty() => {
            let (label, detail) = finding(rest);
            Verdict {
                label: Some(label),
                detail: Some(detail),
                ..Verdict::new(Kind::Fail)
            }
        }
        "skip" => Verdict {
            detail: Some(rest.to_string()),
            ..Verdict::new(Kind::NotJudged)
        },
        _ => Verdict::error(format!(
            "the checker server answered {l:?}, not pass, fail LABEL: detail, or skip CLASS: detail"
        )),
    }
}

fn run_inner(c: &Check, rundir: &Path, seed: u64, exit: Option<i64>, timeout: u64) -> Res<Verdict> {
    let rundir = std::path::absolute(rundir).unwrap_or_else(|_| rundir.to_path_buf());
    let path = rundir.join(OUTPUT);
    let mut out = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // Stderr apart, appended after stdout: the first line of stdout names a finding.
    let name = c"patina-check-stderr";
    let err = crate::sys::cvt_i(unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) })
        .map_err(|e| format!("memfd: {e}"))?;
    let mut err = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(err) });
    let mut cmd = command(c);
    cmd.arg(&rundir)
        .stdin(Stdio::null())
        .stdout(out.try_clone().map_err(|e| e.to_string())?)
        .stderr(err.try_clone().map_err(|e| e.to_string())?)
        .env("PATINA_SEED", seed.to_string())
        .env(
            "PATINA_EXIT",
            exit.map(|x| x.to_string()).unwrap_or_default(),
        );
    let started = std::time::Instant::now();
    let mut child = match cmd.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            return Ok(Verdict::error(format!(
                "the checker {} could not be started: {e}",
                c.program.display()
            )))
        }
    };
    let pid = child.id() as i32;
    let pidfd = match crate::sys::pidfd_open(pid) {
        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
        Err(e) => {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = child.wait();
            return Err(format!("pidfd_open: {e}"));
        }
    };
    let deadline = started + std::time::Duration::from_secs(timeout);
    // Readable once the checker has exited; it stays a zombie (its pid and group not reused)
    // until the wait below, so the group can be ended safely first.
    let waited = crate::sys::wait_fd(pidfd.as_raw_fd(), deadline);
    let timed_out = waited == crate::sys::Waited::Timeout;
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let status = child
        .wait()
        .map_err(|e| format!("wait for the checker: {e}"))?;
    if waited == crate::sys::Waited::Terminated {
        // Stopped: the checker's group is ended; `result.json` stays `pending`.
        crate::sys::exit_terminated();
    }
    let mut raw = vec![];
    out.rewind().map_err(|e| e.to_string())?;
    (&out)
        .read_to_end(&mut raw)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let stdout = String::from_utf8_lossy(&raw).into_owned();
    let mut stderr = vec![];
    err.rewind().map_err(|e| e.to_string())?;
    err.read_to_end(&mut stderr).map_err(|e| e.to_string())?;
    out.write_all(&stderr)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let all = format!("{stdout}{}", String::from_utf8_lossy(&stderr));
    let last = all
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(|l| format!(": {l}"))
        .unwrap_or_default();
    if timed_out {
        return Ok(Verdict::error(format!(
            "the checker ran longer than --check-timeout ({timeout} s){last}"
        )));
    }
    // The run directory differs between a run, its replay and minimize's tries: a path in it
    // is named RUNDIR, so one finding has one name.
    let first = first_line(&stdout).replace(&rundir.display().to_string(), "RUNDIR");
    let mut v = match (status.code(), status.signal()) {
        (Some(0), _) => Verdict::new(Kind::Pass),
        (Some(1), _) => {
            let (label, detail) = finding(&first);
            Verdict {
                label: Some(label),
                detail: Some(detail),
                ..Verdict::new(Kind::Fail)
            }
        }
        (Some(NOT_JUDGED), _) => Verdict {
            detail: Some(first),
            ..Verdict::new(Kind::NotJudged)
        },
        (Some(x), _) => Verdict::error(format!(
            "the checker exited with status {x} (0 pass, 1 finding, 77 not judged){last}"
        )),
        (None, Some(sig)) => Verdict::error(format!(
            "the checker was killed by {}{last}",
            crate::outcome::signal_name(sig as i64)
        )),
        (None, None) => Verdict::error(format!("the checker ended with {status}{last}")),
    };
    v.exit = status.code();
    v.signal = status.signal();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finding_line_may_carry_its_grouping_key() {
        let f = |l: &str| {
            let (a, b) = finding(l);
            (a, b)
        };
        let s = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(f("wrong-exit: exit 3"), s("wrong-exit", "exit 3"));
        assert_eq!(f("wrong-exit"), s("wrong-exit", ""));
        assert_eq!(
            f("wrong-output [echo -e]: got 0x0"),
            s("wrong-output [echo -e]", "got 0x0")
        );
        // A key may hold `: ` and `]`; it ends at a `]` before `: ` or the end.
        assert_eq!(f("diff [a: b] c]: x: y"), s("diff [a: b] c]", "x: y"));
        assert_eq!(f("diff [k]"), s("diff [k]", ""));
        // Not a key: a label with a space, or a bracket that does not close before `: `.
        assert_eq!(f("two words [k]: d"), s("two words [k]", "d"));
        assert_eq!(f("x [open: d"), s("x [open", "d"));
    }

    #[test]
    fn words_round_trip_through_one_argument() {
        for spec in [
            "./same-tree ref",
            "sh -c 'exit 1'",
            r#"a "b c" d\ e"#,
            "x ''",
        ] {
            let w = crate::sweep::words(spec).unwrap();
            assert_eq!(crate::sweep::words(&join(&w)).unwrap(), w, "{spec}");
        }
    }
}
