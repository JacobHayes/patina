//! `patina minimize RUNDIR`: rerun a failing run with less fault injection while it keeps its
//! signature. Its classes are first expanded into their keys; then each fault setting (each
//! `--fault` key, each node's scoped one `KEY=V@NODE` as its own, each class without keys:
//! `buggify`, `crash`, `kill`) is dropped in turn, keeping a removal when the signature is
//! unchanged. With nodes, a crash at crash points that is kept then becomes one node's crash
//! alone (`crash-at=N@NODE`): each node's first crash, then its later ones at
//! their places in a first boot (`single_points`), and the settings left are dropped once
//! more; failing that it is
//! narrowed to fewer nodes, one dropped at a time. Then each remaining rate is halved (a gap
//! between partitions or node crashes doubled) for as long as that holds. The seed and every
//! scheduling setting stay as they were. At most `MAX_RUNS` runs, one at a time; the smallest
//! run found is written to `--out`.

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

/// A crash at one crash point (`crash-at=N`): nothing in it to narrow.
fn c_at(c: &Config) -> bool {
    c.faults.iter().any(|x| x.starts_with("crash-at="))
}

/// Whether a class entry (`CLASS[@NODE,...]`) is a crash's.
fn crash_class(x: &str) -> bool {
    matches!(crate::faults::split_scope(x).0, "crash" | "kill")
}

/// A rate halved: `K=N` or `K=A..B` for a `-permille` key, and the gap between partitions or between a node's crashes
/// (`partition-gap-ms`, `crash-gap-ms`) doubled, up to an hour; a node scope (`@NODE,...`)
/// stays.
fn halve(v: &str) -> Option<String> {
    let (v, scope) = crate::faults::split_scope(v);
    let at = scope.map(|s| format!("@{s}")).unwrap_or_default();
    halve_unscoped(v).map(|h| format!("{h}{at}"))
}

fn halve_unscoped(v: &str) -> Option<String> {
    let h = |x: &str| x.parse::<u64>().ok().filter(|n| *n > 1).map(|n| n / 2);
    for key in ["partition-gap-ms", "crash-gap-ms"] {
        if let Some(val) = v.strip_prefix(key).and_then(|x| x.strip_prefix('=')) {
            let d = |x: &str| x.parse::<u64>().ok().map(|n| n.max(1) * 2);
            let (a, b) = val.split_once("..").unwrap_or((val, val));
            let (a2, b2) = (d(a)?, d(b)?);
            // Always a range: the keys take nothing else.
            return (b2 <= 3_600_000).then(|| format!("{key}={a2}..{b2}"));
        }
    }
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

/// The most single crashes tried for one node (`single_points`).
const SINGLE_TRIES: usize = 6;

/// Where to try a node's one crash (`machine-at:P@NODE`, a point of its first boot) in place of
/// its crashes at points of a failing run, `points` being the point each boot crashed at. First
/// the first crash's own point, which is the same place in a run without the later crashes.
/// Then each later crash, the most recent first (the failure followed it): with no crash
/// before it, the node's first boot runs on through the work of the boots that crashed, so the
/// place is about the points of the boots before it plus its own, give or take the work a crash
/// undid and the next boot did again (the points either side). Last, the points either side of
/// the first crash's. At most `SINGLE_TRIES`: each is
/// a run of minimize's `MAX_RUNS`, which the settings dropped and halved after it share.
fn single_points(points: &[u64]) -> Vec<u64> {
    let mut out: Vec<u64> = points.first().copied().into_iter().collect();
    let mut before = 0;
    let at: Vec<u64> = points
        .iter()
        .map(|p| {
            before += p;
            before
        })
        .collect();
    // Last, the points either side of the first crash's.
    for &c in at.iter().skip(1).rev().chain(at.first()) {
        for p in [c, c - 1, c + 1] {
            if p > 0 && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.truncate(SINGLE_TRIES);
    out
}

struct Search<'a> {
    program: &'a Program,
    signature: Value,
    tries: PathBuf,
    runs: usize,
    /// What each run tried and whether it still failed the same way.
    log: Vec<(String, bool)>,
    /// Print each try on standard error (JSON output) rather than standard output.
    quiet: bool,
}

impl Search<'_> {
    /// Run `cfg` (`change` says what it changed); its directory if it fails with the target
    /// signature.
    fn attempt(&mut self, cfg: &Config, change: String) -> Result<Option<PathBuf>, Fail> {
        if self.runs >= MAX_RUNS {
            return Ok(None);
        }
        self.runs += 1;
        let dir = self.tries.join(format!("try-{}", self.runs));
        let o = cfg.opts_with(self.program.clone()).map_err(error)?;
        let cpu = default_cpu();
        let (_, r) = run_one(&o, &dir, cpu, false).map_err(internal)?;
        let same = r["signature"] == self.signature;
        let line = format!(
            "{change}: {}",
            if same {
                "still fails"
            } else {
                "no longer fails"
            }
        );
        if self.quiet {
            eprintln!("minimize: {line}");
        } else {
            println!("{line}");
        }
        self.log.push((change, same));
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
    let mut v: Vec<String> = cfg.fault_classes.clone();
    v.extend(cfg.faults.iter().cloned());
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
        // Inside the run it reduces, so that a report over the run's parent does not count it.
        None => rundir.join("minimized"),
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
        log: vec![],
        quiet: a.json(),
    };
    crate::launch::preflight(&cfg.opts_with(program.clone()).map_err(error)?).map_err(error)?;
    // A class is its keys: settings given beside it replace its keys of the same name, and
    // each key resolves from the seed alone, so the expanded run is the same run. The classes
    // without keys stay, one entry each.
    let mut cfg = cfg;
    let mut expanded: Vec<String> = vec![];
    let mut classes: Vec<String> = vec![];
    let faultable = crate::faults::faultable_nodes(cfg.nodes.len(), &cfg.faults).map_err(error)?;
    // A class's scope (`disk@a`) goes with each of its keys.
    for e in &cfg.fault_classes {
        let (names, scope) = crate::faults::split_scope(e);
        let at = scope.map(|s| format!("@{s}")).unwrap_or_default();
        for c in crate::faults::classes(names, cfg.nodes.len(), faultable).map_err(error)? {
            if scope.is_some() && !crate::faults::node_class(c) {
                continue;
            }
            let kv = crate::faults::class_settings(c).map_err(error)?;
            if kv.is_empty() {
                classes.push(format!("{c}{at}"));
            }
            for (k, v) in kv {
                let given = |x: &String| {
                    let (x, xs) = crate::faults::split_scope(x);
                    xs == scope && x.split_once('=').is_some_and(|(xk, _)| xk == k)
                };
                if !cfg.faults.iter().any(given) && !expanded.iter().any(given) {
                    expanded.push(format!("{k}={v}{at}"));
                }
            }
        }
    }
    // One machine's crash at its default rate: the rate, to halve.
    let keyed = cfg
        .faults
        .iter()
        .any(|x| x.starts_with("crash-permille=") || x.starts_with("crash-at="));
    if cfg.nodes.is_empty() && !keyed && classes.iter().any(|c| crash_class(c)) {
        expanded.push(format!(
            "crash-permille={}",
            crate::faults::CRASH_DEFAULT_PERMILLE
        ));
    }
    expanded.append(&mut cfg.faults);
    cfg.faults = expanded;
    cfg.fault_classes = classes;
    let mut cur = cfg.clone();
    let best: std::cell::RefCell<Option<PathBuf>> = Default::default();
    let keep =
        |s: &mut Search, cand: Config, cur: &mut Config, change: String| -> Result<bool, Fail> {
            match s.attempt(&cand, change)? {
                Some(d) => {
                    if let Some(old) = best.borrow_mut().replace(d) {
                        let _ = std::fs::remove_dir_all(old);
                    }
                    *cur = cand;
                    Ok(true)
                }
                None => Ok(false),
            }
        };
    // Drop each setting in turn. On one machine a crash key and the class saying its kind
    // (`kill`) go together: the class alone would crash at the default rate, the key alone
    // would crash the machine.
    let one = cfg.nodes.is_empty();
    let crash_key = |x: &String| x.starts_with("crash-permille=") || x.starts_with("crash-at=");
    for f in cfg.faults.clone() {
        let mut c = cur.clone();
        c.faults.retain(|x| *x != f);
        if one && crash_key(&f) && !c.faults.iter().any(crash_key) {
            c.fault_classes.retain(|x| !crash_class(x));
        }
        keep(&mut s, c, &mut cur, format!("without {f}"))?;
    }
    for f in cfg.fault_classes.clone() {
        if !cur.fault_classes.contains(&f)
            || one && crash_class(&f) && cur.faults.iter().any(crash_key)
        {
            continue;
        }
        let mut c = cur.clone();
        c.fault_classes.retain(|x| *x != f);
        keep(&mut s, c, &mut cur, format!("without --faults {f}"))?;
    }
    // With nodes, a crash at crash points (`crash-permille`) becomes one node's first crash
    // alone (`crash-at=N@NODE`, N its point in the run that last kept the signature), tried
    // node by node: a node's crash points count its own oplog records and syncs, so its crash
    // lands at the same place in its work when other nodes no longer crash.
    let rate = cur
        .faults
        .iter()
        .find(|x| x.starts_with("crash-permille="))
        .cloned();
    if let Some(cr) = rate.filter(|_| !cur.nodes.is_empty()) {
        let (_, scope) = crate::faults::split_scope(&cr);
        let d = best.borrow().clone().unwrap_or_else(|| rundir.clone());
        let r = read_json(&d.join("result.json")).unwrap_or_default();
        let names: Vec<String> = match scope {
            Some(s) => s.split(',').map(str::to_string).collect(),
            None => cur
                .nodes
                .iter()
                .filter(|n| !n.no_faults)
                .map(|n| n.name.clone())
                .collect(),
        };
        // The points the node crashed at, boot by boot (its downs at a crash point).
        let points = |n: &str| -> Vec<u64> {
            let node = r["nodes"]["list"]
                .as_array()
                .and_then(|l| l.iter().find(|x| x["name"] == n));
            node.and_then(|x| x["downs"].as_array())
                .into_iter()
                .flatten()
                .map_while(|d| d["point"].as_u64().filter(|p| *p > 0))
                .collect()
        };
        {
            // Each node's first try, then each node's second, and so on: a node's first crash
            // alone, the likeliest, is tried for every node before a later crash of any.
            let tries: Vec<(String, Vec<u64>)> = names
                .into_iter()
                .map(|n| {
                    let p = single_points(&points(&n));
                    (n, p)
                })
                .collect();
            'ranks: for k in 0..SINGLE_TRIES {
                for (n, ps) in &tries {
                    let Some(p) = ps.get(k) else { continue };
                    let at = format!("crash-at={p}@{n}");
                    let mut c = cur.clone();
                    c.faults.retain(|x| !x.starts_with("crash-permille="));
                    c.faults.push(at.clone());
                    if keep(&mut s, c, &mut cur, format!("{cr} -> {at}"))? {
                        // Other settings may have been needed only for the other crashes.
                        for f in cur.faults.clone() {
                            let mut c = cur.clone();
                            c.faults.retain(|x| *x != f);
                            keep(&mut s, c, &mut cur, format!("without {f}"))?;
                        }
                        break 'ranks;
                    }
                }
            }
        }
    }
    // With nodes: the crash on fewer nodes, one dropped at a time while more than one is left.
    let crash = cur.fault_classes.iter().find(|x| crash_class(x)).cloned();
    if let Some(cr) = crash.filter(|_| !cur.nodes.is_empty() && !c_at(&cur)) {
        let (kind, scope) = crate::faults::split_scope(&cr);
        let mut on: Vec<String> = match scope {
            Some(s) => s.split(',').map(str::to_string).collect(),
            None => cur
                .nodes
                .iter()
                .filter(|n| !n.no_faults)
                .map(|n| n.name.clone())
                .collect(),
        };
        for n in on.clone() {
            if on.len() < 2 {
                break;
            }
            let rest: Vec<String> = on.iter().filter(|x| **x != n).cloned().collect();
            let mut c = cur.clone();
            c.fault_classes.retain(|x| *x != cr);
            c.fault_classes.push(format!("{kind}@{}", rest.join(",")));
            if keep(
                &mut s,
                c,
                &mut cur,
                format!("--faults {kind} without node {n}"),
            )? {
                on = rest;
            }
        }
    }
    // Halve what is left.
    for i in 0..cur.faults.len() {
        while let Some(h) = halve(&cur.faults[i]) {
            let mut c = cur.clone();
            let change = format!("{} -> {h}", c.faults[i]);
            c.faults[i] = h;
            if !keep(&mut s, c, &mut cur, change)? {
                break;
            }
        }
    }
    let budget_spent = s.runs >= MAX_RUNS;
    let result = match best.into_inner() {
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
        &s.log,
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
    log: &[(String, bool)],
    budget_spent: bool,
) -> Result<ExitCode, Fail> {
    let dir = if reduced { out } else { rundir };
    let run = read_json(&dir.join("run.json")).map_err(error)?;
    let rerun = crate::report::rerun_command(&run, to.seed, dir);
    if a.json() {
        let v = serde_json::json!({
            "runs": log.len(),
            "max_runs": MAX_RUNS,
            "tries": log.iter().map(|(c, f)| serde_json::json!({"change": c, "still_fails": f})).collect::<Vec<_>>(),
            "reduced": reduced,
            "from": describe(from),
            "to": describe(to),
            "dir": dir,
            "rerun": rerun,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        if budget_spent {
            println!("stopped at {MAX_RUNS} runs, the limit; more may go");
        }
        if reduced {
            println!(
                "reduced: {} (from {}); run directory {}",
                describe(to),
                describe(from),
                out.display()
            );
        } else {
            println!("nothing could go: the run is already minimal");
        }
        println!("{rerun}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::{halve, single_points};

    #[test]
    fn a_later_crash_is_tried_where_a_first_boot_would_reach_it() {
        // The first crash's point, then each later crash at its place over the boots, most
        // recent first, with the points either side, then either side of the first's.
        assert_eq!(single_points(&[4, 7]), vec![4, 11, 10, 12, 3, 5]);
        assert_eq!(single_points(&[9]), vec![9, 8, 10]);
        assert_eq!(single_points(&[1]), vec![1, 2]);
        assert_eq!(single_points(&[6, 2, 7]), vec![6, 15, 14, 16, 8, 7]);
        assert!(single_points(&[]).is_empty());
    }

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
        assert_eq!(
            halve("partition-gap-ms=5000..60000").as_deref(),
            Some("partition-gap-ms=10000..120000")
        );
        assert_eq!(halve("partition-gap-ms=3000000"), None);
        assert_eq!(
            halve("partition-gap-ms=4000..4000").as_deref(),
            Some("partition-gap-ms=8000..8000")
        );
        // A node scope stays; a node's crash gap doubles.
        assert_eq!(
            halve("fs-error-permille=8@a,b").as_deref(),
            Some("fs-error-permille=4@a,b")
        );
        assert_eq!(halve("machine:10@b").as_deref(), Some("machine:5@b"));
        assert_eq!(halve("machine-at:3@b"), None);
        assert_eq!(
            halve("crash-gap-ms=1000..4000").as_deref(),
            Some("crash-gap-ms=2000..8000")
        );
    }
}
