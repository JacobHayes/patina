//! `patina minimize RUNDIR`: rerun a failing run with less fault injection while it keeps its
//! signature. First each fault setting (each `--fault` key, `--crash`, `--buggify`) is dropped
//! in turn, keeping a removal when the signature is unchanged; then each remaining rate is
//! halved for as long as that holds. The seed and every scheduling setting stay as they were.
//! At most `MAX_RUNS` runs, one at a time; the smallest run found is written to `--out`.

use crate::cli::Args;
use crate::config::{Config, Program};
use crate::launch::{default_cpu, run_one};
use crate::outcome::Outcome;
use crate::replay::{clear_out, load};
use crate::result::read_json;
use crate::{error, internal, Fail};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The most runs one minimisation makes.
pub const MAX_RUNS: usize = 30;

/// A rate halved: `K=N` or `K=A..B` for a `-permille` key, `KIND:N` for a crash rate.
fn halve(v: &str) -> Option<String> {
    let h = |x: &str| x.parse::<u64>().ok().filter(|n| *n > 1).map(|n| n / 2);
    if let Some((k, val)) = v.split_once('=') {
        if !k.ends_with("-permille") {
            return None;
        }
        return match val.split_once("..") {
            Some((a, b)) => {
                let b2 = h(b)?;
                let a2 = a.parse::<u64>().ok()? / 2;
                Some(format!("{k}={}..{b2}", a2.min(b2)))
            }
            None => Some(format!("{k}={}", h(val)?)),
        };
    }
    let (kind, n) = v.split_once(':')?;
    matches!(kind, "machine" | "process").then_some(())?;
    Some(format!("{kind}:{}", h(n)?))
}

struct Search<'a> {
    program: &'a Program,
    signature: Value,
    tries: PathBuf,
    runs: usize,
}

impl Search<'_> {
    /// Run `cfg`; its directory if it fails with the target signature.
    fn attempt(&mut self, cfg: &Config) -> Result<Option<PathBuf>, Fail> {
        if self.runs >= MAX_RUNS {
            return Ok(None);
        }
        self.runs += 1;
        let dir = self.tries.join(format!("try-{}", self.runs));
        let o = cfg.opts_with(self.program.clone()).map_err(error)?;
        let cpu = cfg.host_cpu.unwrap_or_else(default_cpu);
        let (_, r) = run_one(&o, &dir, cpu, false).map_err(internal)?;
        let same = r["signature"] == self.signature;
        eprintln!(
            "minimize: run {}: {} {}",
            self.runs,
            if same { "keeps" } else { "loses" },
            describe(cfg)
        );
        if same {
            Ok(Some(dir))
        } else {
            let _ = std::fs::remove_dir_all(&dir);
            Ok(None)
        }
    }
}

/// The fault settings of a configuration, one per word.
fn describe(cfg: &Config) -> String {
    let mut v: Vec<String> = cfg.faults.clone();
    if let Some(c) = &cfg.crash {
        v.push(format!("crash {c}"));
    }
    if cfg.buggify {
        v.push("buggify".into());
    }
    if v.is_empty() {
        "no faults".into()
    } else {
        v.join(" ")
    }
}

pub fn main(a: &Args) -> Result<ExitCode, Fail> {
    let [rundir] = a.positional.as_slice() else {
        return Err(error("usage: patina minimize RUNDIR [--out DIR]".into()));
    };
    let rundir = PathBuf::from(rundir);
    let (cfg, program) = load(&rundir).map_err(error)?;
    let recorded = read_json(&rundir.join("result.json")).map_err(error)?;
    let outcome = recorded["outcome"].as_str().unwrap_or("");
    if !Outcome::ALL
        .iter()
        .any(|o| o.name() == outcome && o.exit() == 1)
    {
        return Err(error(format!(
            "{}: {outcome} is not a finding; minimize takes a failing run",
            rundir.display()
        )));
    }
    let signature = match &recorded["signature"] {
        Value::Null => crate::signature::of(&recorded, &rundir),
        s => s.clone(),
    };
    let out = crate::absolute(match a.last("--out") {
        Some(o) => PathBuf::from(o),
        None => {
            let mut s = rundir.as_os_str().to_owned();
            s.push("-min");
            PathBuf::from(s)
        }
    });
    clear_out(&out).map_err(error)?;
    let mut tries = out.as_os_str().to_owned();
    tries.push(".tries");
    let tries = PathBuf::from(tries);
    let _ = std::fs::remove_dir_all(&tries);
    let mut s = Search {
        program: &program,
        signature,
        tries: tries.clone(),
        runs: 0,
    };
    crate::launch::pmu_event(&cfg.opts_with(program.clone()).map_err(error)?).map_err(error)?;
    // A preset is its keys: settings given beside it replace its keys of the same name, and
    // each key resolves from the seed alone, so the expanded run is the same run.
    let mut cfg = cfg;
    let mut expanded: Vec<String> = vec![];
    for p in cfg.faults_preset.iter().flat_map(|p| p.split(',')) {
        let (_, kv) = crate::faults::PRESETS
            .iter()
            .find(|x| x.0 == p)
            .ok_or_else(|| error(format!("--faults: unknown preset {p}")))?;
        for (k, v) in kv.iter() {
            let given = |x: &String| x.split_once('=').is_some_and(|(xk, _)| xk == *k);
            if !cfg.faults.iter().any(given) && !expanded.iter().any(given) {
                expanded.push(format!("{k}={v}"));
            }
        }
    }
    expanded.append(&mut cfg.faults);
    cfg.faults = expanded;
    cfg.faults_preset.clear();
    let mut cur = cfg.clone();
    let mut best: Option<PathBuf> = None;
    let mut keep = |s: &mut Search, cand: Config, cur: &mut Config| -> Result<bool, Fail> {
        match s.attempt(&cand)? {
            Some(d) => {
                if let Some(old) = best.replace(d) {
                    let _ = std::fs::remove_dir_all(old);
                }
                *cur = cand;
                Ok(true)
            }
            None => Ok(false),
        }
    };
    // Drop each setting in turn.
    for f in cfg.faults.clone() {
        let mut c = cur.clone();
        c.faults.retain(|x| *x != f);
        keep(&mut s, c, &mut cur)?;
    }
    if cur.crash.is_some() {
        let mut c = cur.clone();
        c.crash = None;
        keep(&mut s, c, &mut cur)?;
    }
    if cur.buggify {
        let mut c = cur.clone();
        c.buggify = false;
        keep(&mut s, c, &mut cur)?;
    }
    // Halve what is left.
    for i in 0..cur.faults.len() {
        while let Some(h) = halve(&cur.faults[i]) {
            let mut c = cur.clone();
            c.faults[i] = h;
            if !keep(&mut s, c, &mut cur)? {
                break;
            }
        }
    }
    while let Some(h) = cur.crash.as_deref().and_then(halve) {
        let mut c = cur.clone();
        c.crash = Some(h);
        if !keep(&mut s, c, &mut cur)? {
            break;
        }
    }
    let budget_spent = s.runs >= MAX_RUNS;
    let result = match best {
        Some(d) => {
            std::fs::rename(&d, &out).map_err(|e| internal(format!("{}: {e}", out.display())))?;
            Ok(())
        }
        // Nothing could go: the original run is already minimal.
        None => Err(()),
    };
    let _ = std::fs::remove_dir_all(&tries);
    finish(
        a,
        &rundir,
        &out,
        result.is_ok(),
        &cfg,
        &cur,
        s.runs,
        budget_spent,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    a: &Args,
    rundir: &Path,
    out: &Path,
    reduced: bool,
    from: &Config,
    to: &Config,
    runs: usize,
    budget_spent: bool,
) -> Result<ExitCode, Fail> {
    let dir = if reduced { out } else { rundir };
    let run = read_json(&dir.join("run.json")).map_err(error)?;
    let rerun = crate::report::rerun_command(&run, to.seed);
    if a.json() {
        let v = serde_json::json!({
            "runs": runs,
            "max_runs": MAX_RUNS,
            "reduced": reduced,
            "from": describe(from),
            "to": describe(to),
            "dir": dir,
            "rerun": rerun,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!(
            "minimize: {runs} runs{}",
            if budget_spent {
                " (the limit; there may be more to remove)"
            } else {
                ""
            }
        );
        println!("from: {}", describe(from));
        println!("to:   {}", describe(to));
        if reduced {
            println!("run directory: {}", out.display());
        } else {
            println!("nothing could be removed; the run is already minimal");
        }
        println!("rerun: {rerun}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::halve;

    #[test]
    fn rates_halve_and_other_settings_do_not() {
        assert_eq!(
            halve("fs-error-permille=8").as_deref(),
            Some("fs-error-permille=4")
        );
        assert_eq!(
            halve("fs-error-permille=0..5").as_deref(),
            Some("fs-error-permille=0..2")
        );
        assert_eq!(halve("fs-error-permille=1"), None);
        assert_eq!(halve("machine:3").as_deref(), Some("machine:1"));
        assert_eq!(halve("machine-at:300"), None);
        assert_eq!(halve("fs-error-at=write:3"), None);
        assert_eq!(halve("net-delay-ms=0..50"), None);
    }
}
