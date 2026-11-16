//! `patina replay RUNDIR`: run again from `run.json` and compare the logs record by record.
//! A re-execution checked against the log; the log is not fed back as input.

use crate::cli::{Args, Res};
use crate::config::{sha256_file, Config, Program};
use crate::launch::{default_cpu, run_one, PERTURB_DRAWS};
use crate::outcome::{Classified, Outcome};
use crate::result::{read_json, result_json, write_json, RUN_SCHEMA};
use std::path::{Path, PathBuf};

/// What a replay concluded, and the replay's directory.
pub struct Replayed {
    pub classified: Classified,
    pub result: serde_json::Value,
    pub dir: PathBuf,
}

/// Remove an earlier run in `dir` (a directory holding `run.json` or `inc-0`); refuse any
/// other non-empty directory.
pub fn clear_out(dir: &Path) -> Res<()> {
    let Ok(mut rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    if rd.next().is_none() {
        return Ok(());
    }
    if ["run.json", "inc-0", "run-0"]
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
    let (cfg, program) = load(&rundir)?;
    let recorded = read_json(&rundir.join("result.json"))?;
    let out = match args.last("--out") {
        Some(o) => PathBuf::from(o),
        None => {
            let mut s = rundir.as_os_str().to_owned();
            s.push("-replay");
            PathBuf::from(s)
        }
    };
    let run = read_json(&rundir.join("run.json"))?;
    replay_into(&rundir, &out, cfg, program, &recorded, &run)
}

/// The configuration and program a run directory's `run.json` records, after checking that
/// the program is unchanged.
pub fn load(rundir: &Path) -> Res<(Config, Program)> {
    let run_path = rundir.join("run.json");
    if !run_path.is_file() {
        return Err(format!(
            "{}: not a run directory (no run.json)",
            rundir.display()
        ));
    }
    let run = read_json(&run_path)?;
    if run["schema"] != RUN_SCHEMA {
        return Err(format!(
            "{}: schema {} (this patina reads {RUN_SCHEMA})",
            run_path.display(),
            run["schema"]
        ));
    }
    let cfg: Config = serde_json::from_value(run["config"].clone())
        .map_err(|e| format!("{}: config: {e}", run_path.display()))?;
    let program: Program = serde_json::from_value(run["program"].clone())
        .map_err(|e| format!("{}: program: {e}", run_path.display()))?;
    let now = sha256_file(&program.host)
        .map_err(|e| format!("program {} is gone: {e}", program.host.display()))?;
    if now != program.sha256 {
        return Err(format!(
            "program {} changed since the run (sha256 {} recorded, {} now)",
            program.host.display(),
            program.sha256,
            now
        ));
    }
    Ok((cfg, program))
}

fn replay_into(
    rundir: &Path,
    out: &Path,
    cfg: Config,
    program: Program,
    recorded: &serde_json::Value,
    run: &serde_json::Value,
) -> Res<Replayed> {
    let out = out.to_path_buf();
    let o = cfg.opts_with(program)?;
    crate::launch::preflight(&o)?;
    clear_out(&out)?;
    if run["faults"] != o.plan.json() {
        return Err(format!(
            "the fault plan resolves to {} now, {} in the run",
            o.plan.json(),
            run["faults"]
        ));
    }
    if std::env::var_os("PATINA_TEST_REPLAY_PERTURB").is_some() {
        PERTURB_DRAWS.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let cpu = cfg.host_cpu.unwrap_or_else(default_cpu);
    let (end, mut result) = run_one(&o, &out, cpu, false)?;
    let mine = crate::result::classified(&end);
    let diverged = match crate::log::first_run_difference(rundir, &out)? {
        Some(d) => Some(d),
        None if recorded["outcome"] != result["outcome"]
            || recorded["digest"] != result["digest"] =>
        {
            Some(format!(
                "logs equal, but the outcome differs: recorded {} {}, replayed {} {}",
                recorded["outcome"], recorded["digest"], result["outcome"], result["digest"]
            ))
        }
        None => None,
    };
    let classified = match diverged {
        Some(d) => {
            let c = Classified::new(Outcome::Nondeterministic, "divergence", d);
            result = result_json(&end, &c);
            result["signature"] = crate::signature::of(&result, &out);
            write_json(&out.join("result.json"), &result)?;
            c
        }
        None => mine,
    };
    Ok(Replayed {
        classified,
        result,
        dir: out,
    })
}
