//! `--check 'CMD ARGS'`: a checker outside the simulation. After a run that ended `ok`, and
//! after `result.json` is written, `CMD ARGS RUNDIR` runs on the host as the user, outside the
//! sandbox and without network or other restrictions of Patina's: it is the user's own program.
//! Its working directory is the directory patina was started in (recorded), so paths in
//! `ARGS` are relative to it. It gets `PATINA_SEED`, `PATINA_EXIT` (the program's exit
//! status) and, for a sweep's `--cases` run, `PATINA_CASE` (the line) and `PATINA_CASE_NAME`
//! (the case's directory, `K-NAME`). Its stdout, then its stderr, go to `RUNDIR/check.out`.
//!
//! The words are split as a `--cases` line is (quotes, no expansion; no shell runs unless the
//! user names one). The program is resolved (a path against the recorded directory, a bare
//! name on `PATH`) and recorded with its SHA-256 in `run.json`, so `replay`, `minimize` and
//! `verify` run the same checker, and refuse a changed one.
//!
//! Exit 0 passes; 1 is a finding, named by the first non-empty line of stdout, `LABEL:
//! detail` (`signature::violation`); 77 is "not judged" (the run stays `ok`); anything else,
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
    /// The case of a sweep's `--cases` run (set by the sweep for its runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<Case>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// The line as written.
    pub text: String,
    /// Its directory under `seed-N`: `K-NAME`.
    pub name: String,
}

/// The variables a sweep passes a case in to its runs (and the checker gets).
pub const CASE_VAR: &str = "PATINA_CASE";
pub const CASE_NAME_VAR: &str = "PATINA_CASE_NAME";

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
            case: None,
        })
    }

    /// Refuse a checker changed since it was recorded (a replay repeats the recorded one).
    pub fn unchanged(&self) -> Res<()> {
        let now = crate::config::sha256_file(&self.program)
            .map_err(|e| format!("checker {} is gone: {e}", self.program.display()))?;
        if now != self.sha256 {
            return Err(format!(
                "checker {} changed since the run (sha256 {} recorded, {} now)",
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

/// Run `c` on the run directory `rundir`: its seed, the program's exit status, at most
/// `timeout` seconds.
pub fn run(c: &Check, rundir: &Path, seed: u64, exit: Option<i64>, timeout: u64) -> Verdict {
    match run_inner(c, rundir, seed, exit, timeout) {
        Ok(v) => v,
        Err(e) => Verdict::error(e),
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
    let mut cmd = Command::new(&c.program);
    cmd.arg0(&c.words[0])
        .args(&c.words[1..])
        .arg(&rundir)
        .current_dir(&c.dir)
        .stdin(Stdio::null())
        .stdout(out.try_clone().map_err(|e| e.to_string())?)
        .stderr(err.try_clone().map_err(|e| e.to_string())?)
        .env("PATINA_SEED", seed.to_string())
        .env(
            "PATINA_EXIT",
            exit.map(|x| x.to_string()).unwrap_or_default(),
        )
        // Its own process group: what it leaves running is ended with it.
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
    let mut timed_out = true;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        if crate::sys::readable(pidfd.as_raw_fd(), ms) {
            timed_out = false;
            break;
        }
    }
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let status = child
        .wait()
        .map_err(|e| format!("wait for the checker: {e}"))?;
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
            "the checker ran longer than --timeout ({timeout} s){last}"
        )));
    }
    // The run directory differs between a run, its replay and minimize's tries: a path in it
    // is named RUNDIR, so one finding has one name.
    let first = first_line(&stdout).replace(&rundir.display().to_string(), "RUNDIR");
    let mut v = match (status.code(), status.signal()) {
        (Some(0), _) => Verdict::new(Kind::Pass),
        (Some(1), _) => {
            let (label, detail) = match first.split_once(": ") {
                Some((l, d)) => (l.to_string(), d.to_string()),
                None => (first.clone(), String::new()),
            };
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
