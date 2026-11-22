//! `patina report --recheck DIR...`: judge kept runs again with a checker, without running the program
//! again, then report. Only the check is rewritten: `result.json`'s `check` and what follows
//! from it (`outcome`, `stop`, `message`, `exit`, `signature`), the checker `run.json` records
//! (`config.check`, so that a replay repeats this checker), and `check.out`. The run's own
//! outcome, its logs, digest and every other field stay as they are.
//!
//! The checker reads the run's logs, which a sweep removes from the runs it does not keep
//! (`--keep fail`: every run that ended ok). Such a run that ended ok cannot be judged again:
//! it is left as it was and named (`Rejudged::Pruned`); a run that did not end ok is a finding
//! without a checker either way (`not-run`). A sweep that resumes with an edited checker uses
//! the same step on the runs it kept (`sweep.rs`), and runs again those it cannot judge.

use crate::check::{Check, Kind, Server, Verdict};
use crate::cli::{Args, Res};
use crate::outcome::{Classified, Outcome};
use crate::result::{read_json, write_json};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

/// What judging a run again did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejudged {
    /// The checker ran (or, for a run that did not end ok, was recorded as not run).
    Judged(Kind),
    /// The run ended ok and its logs are gone: nothing to judge; left as it was.
    Pruned,
    /// Patina refused the run (no `run.json`): no program ran; left as it was.
    Unmade,
}

/// The run's own outcome, before a checker judged it: a run its checker ran on ended ok.
fn own(r: &Value) -> Classified {
    let judged = r["check"]["verdict"]
        .as_str()
        .is_some_and(|v| v != "not-run");
    if judged {
        return crate::outcome::ok_end(r["guest"]["exit"].as_i64().unwrap_or(0));
    }
    let name = r["outcome"].as_str().unwrap_or("");
    Classified::new(
        Outcome::ALL
            .into_iter()
            .find(|o| o.name() == name)
            .unwrap_or(Outcome::Internal),
        r["stop"].as_str().unwrap_or(""),
        r["message"].as_str().unwrap_or(""),
    )
}

/// The case a sweep's case run belongs to, as its checker gets it: the line after its
/// settings (its `case` file), its directory, its id (`run.json`).
pub fn case_of(dir: &Path, run: &Value) -> Option<crate::check::Case> {
    let line = std::fs::read_to_string(dir.join(crate::sweep::CASE_FILE)).ok()?;
    Some(crate::check::Case {
        text: crate::sweep::case_shown(line.trim_end_matches('\n')),
        name: dir.file_name()?.to_string_lossy().into_owned(),
        id: run["config"]["case"]["id"].as_str().map(str::to_string),
    })
}

/// Whether a checker reads the run: it ended ok on its own (a checker judged it, or would).
pub fn checkable(r: &Value) -> bool {
    own(r).outcome == Outcome::Ok
}

/// Whether the run ended ok on its own and its logs are gone: a checker has nothing to read.
pub fn pruned(dir: &Path, r: &Value) -> bool {
    own(r).outcome == Outcome::Ok && !dir.join("boot-1").is_dir()
}

/// Judge the run in `dir` again with `check` (none: the run gets no check), through `server`
/// when the checker serves. The verdict is written `pending` first, so that a recheck stopped
/// midway leaves an error, never the old verdict recorded as the new checker's.
pub fn rejudge(dir: &Path, check: Option<&Check>, server: Option<&Server>) -> Res<Rejudged> {
    let rpath = dir.join("result.json");
    let jpath = dir.join("run.json");
    let mut r = read_json(&rpath)?;
    // A run patina refused has no run.json: no program ran, there is nothing to judge.
    let Ok(mut run) = read_json(&jpath) else {
        return Ok(Rejudged::Unmade);
    };
    if check.is_some() && pruned(dir, &r) {
        return Ok(Rejudged::Pruned);
    }
    let own = own(&r);
    let ok = own.outcome == Outcome::Ok;
    let check = check.map(|c| Check {
        case: case_of(dir, &run),
        ..c.clone()
    });
    let set_check = |run: &mut Value| match &check {
        Some(c) => run["config"]["check"] = serde_json::to_value(c).unwrap(),
        None => {
            run["config"].as_object_mut().map(|o| o.remove("check"));
        }
    };
    let rp = dir.join("replay.json");
    // A `--crash-points` child that missed its crash point is nondeterministic whatever its checker
    // says, a finding already: its result stays, and the new checker is not run on it, as on
    // any run that did not end ok. The result first: stopped before run.json, it is stale.
    if r["crash_point_missed"].is_object() {
        match &check {
            Some(_) => r["check"] = serde_json::to_value(Verdict::not_run()).unwrap(),
            None => {
                r.as_object_mut().map(|o| o.remove("check"));
            }
        }
        let _ = std::fs::remove_file(dir.join(crate::check::OUTPUT));
        write_json(&rpath, &r)?;
        set_check(&mut run);
        write_json(&jpath, &run)?;
        return Ok(Rejudged::Judged(Kind::NotRun));
    }
    let write = |r: &mut Value, v: Option<&Verdict>| -> Res<()> {
        let c = crate::result::with_check(own.clone(), v);
        r["outcome"] = c.outcome.name().into();
        r["stop"] = c.stop.into();
        r["message"] = c.message.into();
        r["exit"] = crate::result::run_exit(c.outcome, r).into();
        match v {
            Some(v) => r["check"] = serde_json::to_value(v).unwrap(),
            None => {
                r.as_object_mut().map(|o| o.remove("check"));
            }
        }
        // Only an ok run's signature follows from its verdict; another's reads its logs,
        // which a sweep may have pruned: it stays as the sweep wrote it.
        if ok {
            r["signature"] = crate::signature::of(r, dir);
        }
        write_json(&rpath, r)
    };
    let before = r["check"].clone();
    let changed = !same_checker(&run["config"]["check"], &run_check(&check));
    // A recheck stopped midway must leave the run stale for the next one: with a checker,
    // `pending` first; without one, the result (no verdict) before run.json (no checker).
    if ok && check.is_some() {
        write(&mut r, Some(&Verdict::pending()))?;
    }
    if check.is_some() {
        set_check(&mut run);
        write_json(&jpath, &run)?;
    }
    let v = match (&check, ok) {
        (Some(c), true) => Some(crate::check::run_on(
            c,
            dir,
            r["seed"].as_u64().unwrap_or(0),
            r["guest"]["exit"].as_i64(),
            server,
        )),
        (Some(_), false) => Some(Verdict::not_run()),
        (None, _) => None,
    };
    if !ok || check.is_none() {
        let _ = std::fs::remove_file(dir.join(crate::check::OUTPUT));
    }
    // A replay made under another checker or verdict says nothing of this one's: removed
    // before the result is written, so a stop in between cannot keep it.
    let now = v
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap())
        .unwrap_or_default();
    if changed || before != now || read_json(&rp).is_ok_and(|x| x["result"] == "check-unstable") {
        let _ = std::fs::remove_file(&rp);
    }
    write(&mut r, v.as_ref())?;
    if check.is_none() {
        set_check(&mut run);
        write_json(&jpath, &run)?;
    }
    Ok(Rejudged::Judged(
        v.map(|v| v.verdict).unwrap_or(Kind::NotRun),
    ))
}

/// Judge every run in `dirs` again, `width` at a time, each with the checker `check_of` gives
/// it. A serving checker gets one server per worker, started again after one that failed.
pub fn rejudge_all(
    dirs: &[PathBuf],
    check_of: &(dyn Fn(&Path) -> Res<Option<Check>> + Sync),
    width: usize,
) -> Vec<(PathBuf, Res<Rejudged>)> {
    let queue = Mutex::new(dirs.iter().cloned().enumerate().collect::<Vec<_>>());
    let done: Mutex<Vec<(usize, PathBuf, Res<Rejudged>)>> = Mutex::new(vec![]);
    std::thread::scope(|sc| {
        for _ in 0..width.max(1) {
            sc.spawn(|| {
                // The server and the checker it serves (the whole record: words, directory,
                // program and its SHA-256).
                let mut server: Option<(Value, Server)> = None;
                loop {
                    let Some((i, dir)) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let res = check_of(&dir).and_then(|c| {
                        let serve = c.as_ref().filter(|c| c.serve);
                        if let Some(c) = serve {
                            let k = serde_json::to_value(c).unwrap();
                            let fresh = server.as_mut().is_none_or(|(w, s)| *w != k || !s.alive());
                            if fresh {
                                if let Some((_, s)) = server.take() {
                                    s.end();
                                }
                                server = Server::start(c).ok().map(|s| (k, s));
                            }
                        }
                        let r = rejudge(&dir, c.as_ref(), server.as_ref().map(|s| &s.1));
                        if matches!(r, Ok(Rejudged::Judged(Kind::Error | Kind::Pending))) {
                            // Killed for its answer, or never answered: not trusted again.
                            if let Some((_, s)) = server.take() {
                                s.end();
                            }
                        }
                        r
                    });
                    done.lock().unwrap().push((i, dir, res));
                }
                if let Some((_, s)) = server {
                    s.end();
                }
            });
        }
    });
    let mut out = done.into_inner().unwrap();
    out.sort_by_key(|x| x.0);
    out.into_iter().map(|(_, d, r)| (d, r)).collect()
}

/// Runs whose logs were pruned, named at most this many at a time; the count names all.
const PRUNED_SHOWN: usize = 10;

pub fn main(a: &Args) -> Result<ExitCode, crate::Fail> {
    let err = crate::error;
    if a.positional.is_empty() {
        return Err(err(
            "usage: patina report --recheck [--check 'CMD ARGS'] DIR...".into(),
        ));
    }
    let dirs: Vec<PathBuf> = a.positional.iter().map(PathBuf::from).collect();
    let runs = crate::report::collect(&dirs).map_err(err)?;
    // A checker given here, or each run's own (its words again: an edited file is read anew).
    let fixed = match a.last("--check") {
        Some(k) => Some(Check::resolve(k, &crate::config::logical(".")).map_err(err)?),
        None => None,
    };
    // Recorded checkers, each resolved once.
    let mut recorded: Vec<(Value, Check)> = vec![];
    if fixed.is_none() {
        for r in &runs {
            let k = &r.run["config"]["check"];
            if k.is_null() || recorded.iter().any(|(v, _)| same_checker(v, k)) {
                continue;
            }
            let c: Check = serde_json::from_value(k.clone())
                .map_err(|e| err(format!("{}: run.json check: {e}", r.dir.display())))?;
            let again = c.again().map_err(err)?;
            recorded.push((k.clone(), again));
        }
        if recorded.is_empty() {
            return Err(err(
                "no run here was made with a checker: give one with --check".into(),
            ));
        }
    }
    let check_of = |dir: &Path| -> Res<Option<Check>> {
        if let Some(c) = &fixed {
            return Ok(Some(c.clone()));
        }
        let Ok(run) = read_json(&dir.join("run.json")) else {
            return Ok(None);
        };
        Ok(recorded
            .iter()
            .find(|(v, _)| same_checker(v, &run["config"]["check"]))
            .map(|(_, c)| c.clone()))
    };
    let width = match a.num::<usize>("--jobs").map_err(err)? {
        Some(0) => return Err(err("--jobs is at least 1".into())),
        Some(n) => n,
        None => crate::sweep::default_jobs(),
    };
    let list: Vec<PathBuf> = runs.iter().map(|r| r.dir.clone()).collect();
    let t0 = std::time::Instant::now();
    let results = rejudge_all(&list, &check_of, width);
    let mut pruned = vec![];
    let mut judged = 0;
    for (d, r) in &results {
        match r {
            Ok(Rejudged::Judged(_)) => judged += 1,
            Ok(Rejudged::Pruned) => pruned.push(d),
            Ok(Rejudged::Unmade) => {}
            Err(e) => return Err(err(format!("{}: {e}", d.display()))),
        }
    }
    let rel = |d: &Path| -> String {
        dirs.iter()
            .find_map(|top| {
                let top = std::path::absolute(top).ok()?;
                d.strip_prefix(&top).ok().map(|p| p.display().to_string())
            })
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| d.display().to_string())
    };
    for d in pruned.iter().take(PRUNED_SHOWN) {
        eprintln!(
            "recheck: {}: its logs were pruned (a sweep without a checker prunes them): not judged again; its verdict is the earlier checker's",
            rel(d)
        );
    }
    if pruned.len() > PRUNED_SHOWN {
        eprintln!(
            "recheck: and {} more whose logs were pruned",
            pruned.len() - PRUNED_SHOWN
        );
    }
    eprintln!(
        "recheck: judged {} again in {:.1}s{}",
        crate::report::count(judged, "run"),
        t0.elapsed().as_secs_f64(),
        if pruned.is_empty() {
            String::new()
        } else {
            format!(
                "; {} pruned, left as they were (a sweep with a checker keeps what it reads)",
                pruned.len()
            )
        }
    );
    // The report over the runs as they are now.
    let runs = crate::report::collect(&dirs).map_err(err)?;
    let known = crate::report::known_flag(a).map_err(err)?;
    let mut again = "patina report --group N".to_string();
    if let Some(k) = a.last("--known") {
        again.push_str(&format!(" --known {}", crate::report::quote(k)));
    }
    for d in &a.positional {
        again.push_str(&format!(" {}", crate::report::quote(d)));
    }
    let (v, text) =
        crate::report::build(&runs, a.all("--allow-unmet"), known.as_ref(), None, &again);
    // A sweep directory's own report.json, when it is the one directory reported.
    for d in dirs.iter().filter(|_| dirs.len() == 1) {
        if d.join(crate::sweep::SWEEP_FILE).is_file() {
            let mut v = v.clone();
            if let Ok(old) = read_json(&d.join("report.json")) {
                v["sweep"] = old["sweep"].clone();
            }
            write_json(&d.join("report.json"), &v).map_err(err)?;
        }
    }
    if a.json() {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        print!("{text}");
    }
    Ok(ExitCode::from(v["exit"].as_u64().unwrap_or(2) as u8))
}

/// A checker as `run.json` records it (`null`: none).
fn run_check(c: &Option<Check>) -> Value {
    c.as_ref()
        .map(|c| serde_json::to_value(c).unwrap())
        .unwrap_or_default()
}

/// Whether two recorded checkers (`run.json`'s `config.check`) are one: the same words from
/// the same directory, the same program and serving mode (the case differs by run).
pub fn same_checker(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("case");
        }
        v
    };
    strip(a) == strip(b)
}
