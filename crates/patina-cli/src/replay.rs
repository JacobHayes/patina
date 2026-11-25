//! `patina replay RUNDIR`: run again from `run.json` and compare the logs record by record.
//! A re-execution checked against the log; the log is not fed back as input. The replay is
//! written to `RUNDIR/replay` unless `--out` says otherwise.

use crate::cli::{Args, Res};
use crate::config::{sha256_file, Config, Program};
use crate::launch::{default_cpu, run_one, PERTURB_DRAWS};
use crate::outcome::{Classified, Outcome};
use crate::result::{read_json, result_json, same_build, write_json};
use std::path::{Path, PathBuf};

/// What a replay concluded, and the replay's directory.
pub struct Replayed {
    pub classified: Classified,
    /// How the replayed run itself ended, before it was compared with the run.
    pub own: Classified,
    pub result: serde_json::Value,
    pub dir: PathBuf,
}

/// Remove an earlier run in `dir` (a directory holding `run.json` or `boot-1`); refuse any
/// other non-empty directory.
pub fn clear_out(dir: &Path) -> Res<()> {
    let Ok(mut rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    if rd.next().is_none() {
        return Ok(());
    }
    if ["run.json", "boot-1", "run-0"]
        .iter()
        .any(|f| dir.join(f).exists())
    {
        return std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()));
    }
    Err(format!(
        "{}: exists and is not a run directory; give another --out",
        dir.display()
    ))
}

pub fn replay(args: &Args) -> Res<Replayed> {
    let [rundir] = args.positional.as_slice() else {
        return Err("usage: patina replay RUNDIR [--out DIR]".into());
    };
    let rundir = PathBuf::from(rundir);
    let (mut cfg, program) = load(&rundir)?;
    if let Some(n) = crate::config::parse_profile_cpu(args)? {
        cfg.profile_cpu_interval = n;
    }
    if args.has("--coverage") {
        cfg.coverage = true;
    }
    let recorded = read_json(&rundir.join("result.json"))?;
    let out = match args.last("--out") {
        Some(o) => PathBuf::from(o),
        // Inside the run it replays: a report or sweep over the run's parent never counts it
        // (a run directory's subdirectories are not walked).
        None => rundir.join("replay"),
    };
    replay_into(&rundir, &out, cfg, program, &recorded)
}

/// The configuration and program a run directory's `run.json` records, after checking that
/// this is the patina build that made it and the program is unchanged.
pub fn load(rundir: &Path) -> Res<(Config, Program)> {
    let run_path = rundir.join("run.json");
    if !run_path.is_file() {
        return Err(format!(
            "{}: not a run directory (no run.json)",
            rundir.display()
        ));
    }
    let run = read_json(&run_path)?;
    same_build(&run, &run_path)?;
    let cfg: Config = serde_json::from_value(run["config"].clone())
        .map_err(|e| format!("{}: config: {e}", run_path.display()))?;
    let program: Program = serde_json::from_value(run["program"].clone())
        .map_err(|e| format!("{}: program: {e}", run_path.display()))?;
    let machines: Vec<Program> = match run.get("machine_programs") {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| format!("{}: machine_programs: {e}", run_path.display()))?,
        None => vec![],
    };
    for p in std::iter::once(&program).chain(&machines) {
        let now = sha256_file(&p.host)
            .map_err(|e| format!("program {} is gone: {e}", p.host.display()))?;
        if now != p.sha256 {
            return Err(format!(
                "program {} changed since the run (sha256 {} recorded, {} now)",
                p.host.display(),
                p.sha256,
                now
            ));
        }
    }
    if let Some(c) = &cfg.check {
        c.unchanged()?;
    }
    Ok((cfg, program))
}

pub fn replay_into(
    rundir: &Path,
    out: &Path,
    cfg: Config,
    program: Program,
    recorded: &serde_json::Value,
) -> Res<Replayed> {
    let out = out.to_path_buf();
    let o = cfg.opts_with(program)?;
    crate::launch::preflight(&o)?;
    clear_out(&out)?;
    if std::env::var_os("PATINA_TEST_REPLAY_PERTURB").is_some() {
        PERTURB_DRAWS.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let cpu = default_cpu();
    let (end, mut result) = run_one(&o, &out, cpu, false)?;
    let mine = crate::result::classified(&end);
    // The run's own outcome, before a checker judged it: a run the checker judged was ok.
    let own = |r: &serde_json::Value| -> serde_json::Value {
        let judged = r["check"]["verdict"]
            .as_str()
            .is_some_and(|v| v != "not-run");
        if judged {
            "ok".into()
        } else {
            r["outcome"].clone()
        }
    };
    // A run a sweep pruned kept no logs: its digest, the hash of every record, is the
    // comparison.
    let pruned = crate::durability::check::boots(rundir).is_empty();
    let first = match pruned {
        true => None,
        false => crate::log::first_run_difference(rundir, &out)?,
    };
    let diverged = match first {
        Some(d) => Some(d),
        None if own(recorded) != own(&result) || recorded["digest"] != result["digest"] => {
            Some(format!(
                "logs equal, but the outcome differs: recorded {} {}, replayed {} {}",
                own(recorded),
                recorded["digest"],
                own(&result),
                result["digest"]
            ))
        }
        // The self-check reads the exported disks, which the logs do not hold (a run
        // recorded without one has nothing to compare).
        None if !recorded["self_check"].is_null()
            && recorded["self_check"]["verdict"] != result["self_check"]["verdict"] =>
        {
            Some(format!(
                "logs equal, but the operation log's self-check differs: recorded {}, replayed {}",
                recorded["self_check"]["verdict"], result["self_check"]["verdict"]
            ))
        }
        None => None,
    };
    let key = |r: &serde_json::Value| crate::signature::check_key(&r["check"]);
    // A difference after a mounted source changed is the program reading other inputs.
    let changed = match &diverged {
        Some(_) => read_json(&rundir.join("run.json"))
            .map(|run| crate::inputs::changed(&run, &cfg))
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let classified = match diverged {
        Some(d) if !changed.is_empty() => Some(Classified::new(
            Outcome::Error,
            "inputs-changed",
            format!(
                "the mounted {} changed since the run (an entry added, removed or modified): the replay read other inputs, so a difference is expected, not a Patina bug; first difference: {d}",
                changed.join(", ")
            ),
        )),
        Some(d) => Some(Classified::new(Outcome::Nondeterministic, "divergence", d)),
        // The same run, judged otherwise: the checker reads something besides the run
        // directory. Not a Patina divergence.
        None if key(recorded) != key(&result) => Some(Classified::new(
            Outcome::Error,
            "check-unstable",
            format!(
                "the logs are identical and the checker answered differently ({}, now {}): it depends on something outside the run directory",
                verdict_text(&recorded["check"]),
                verdict_text(&result["check"])
            ),
        )),
        None => None,
    };
    let own = mine.clone();
    let classified = match classified {
        Some(c) => {
            result = result_json(&end, &c);
            result["signature"] = crate::signature::of(&result, &out);
            write_json(&out.join("result.json"), &result)?;
            c
        }
        None => mine,
    };
    Ok(Replayed {
        classified,
        own,
        result,
        dir: out,
    })
}

/// A checker's verdict in a sentence's words: `fail (LABEL: detail)`, `pass`.
fn verdict_text(c: &serde_json::Value) -> String {
    let v = c["verdict"].as_str().unwrap_or("none");
    let label = c["label"].as_str().unwrap_or("");
    let detail = c["detail"].as_str().unwrap_or("");
    match (label, detail) {
        ("", "") => v.to_string(),
        ("", d) => format!("{v}: {d}"),
        (l, "") => format!("{v}: {l}"),
        (l, d) => format!("{v}: {l}: {d}"),
    }
}
