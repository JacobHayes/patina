//! `patina report DIR...`: one report over any set of run directories (a sweep's, or runs
//! made by `patina run --out`). Runs are grouped by their `result.json` signature (and case);
//! each group gets its count, first seed, replay result, the rerun and replay commands and
//! the fault attribution line. The SDK and fault-count folds are the vacuity check.
//! `report.json` (`patina.report/v1`) is the same in JSON.

use crate::cli::{Args, Res};
use crate::config::Config;
use crate::outcome::Outcome;
use crate::result::read_json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub const REPORT_SCHEMA: &str = "patina.report/v1";
/// Labels of each unmet kind the text names; the JSON has all of them.
const LABELS_SHOWN: usize = 5;
/// Seeds the text lists with their crash points tried, when a branch sweep stopped early.
const SEEDS_SHOWN: usize = 8;

/// One finished run found under the report's directories.
pub struct Run {
    pub dir: PathBuf,
    pub seed: u64,
    pub case: Option<String>,
    pub result: Value,
    pub run: Value,
    /// `replay.json`, written by a sweep that replayed this run.
    pub replay: Option<Value>,
    /// In a `--branch` sweep: 0 for a base (`seed-N`), P for the child crashing at point P
    /// (`seed-N@P`).
    pub point: Option<u64>,
}

/// How a run is named: `seed 3`, or `seed 3@120` for a branch child.
pub fn run_name(seed: u64, point: Option<u64>) -> String {
    match point {
        Some(p) if p > 0 => format!("{seed}@{p}"),
        _ => seed.to_string(),
    }
}

/// What a sweep adds to the head of its report.
pub struct SweepHead {
    pub seconds: f64,
    pub jobs: usize,
    /// The width after a host limit lowered it.
    pub lowered_to: Option<usize>,
    pub stopped: Option<String>,
}

pub fn main(a: &Args) -> Res<ExitCode> {
    if a.positional.is_empty() {
        return Err("usage: patina report DIR...".into());
    }
    let dirs: Vec<PathBuf> = a.positional.iter().map(PathBuf::from).collect();
    let runs = collect(&dirs)?;
    let (v, text) = build(&runs, a.all("--allow-unmet"), None);
    if a.json() {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        print!("{text}");
    }
    Ok(ExitCode::from(v["exit"].as_u64().unwrap_or(2) as u8))
}

/// Every run directory (one holding `result.json`) at or under `dirs`, in path order.
/// Directories whose names start with `.` (a sweep's replays) are skipped.
pub fn collect(dirs: &[PathBuf]) -> Res<Vec<Run>> {
    let mut found = vec![];
    for d in dirs {
        if !d.is_dir() {
            return Err(format!("{}: not a directory", d.display()));
        }
        let mut here = vec![];
        walk(d, &mut here);
        // A branch sweep's directory says so in its sweep.json.
        let branch = read_json(&d.join("sweep.json")).is_ok_and(|v| v["branch"] == true);
        found.extend(here.into_iter().map(|r| (r, branch)));
    }
    found.sort();
    found.dedup_by(|a, b| a.0 == b.0);
    let mut runs = vec![];
    for (dir, branch) in found {
        let result = read_json(&dir.join("result.json"))?;
        let run = read_json(&dir.join("run.json")).unwrap_or(Value::Null);
        let seed = result["seed"]
            .as_u64()
            .or(run["seed"].as_u64())
            .unwrap_or(0);
        // A sweep's case runs live in OUT/seed-N/K-NAME, with the case's text in a file;
        // other runs in such a layout are named by their directory.
        let written = std::fs::read_to_string(dir.join(crate::sweep::CASE_FILE))
            .ok()
            .map(|c| c.trim_end_matches('\n').to_string());
        // A branch child lives in OUT/seed-N@P[/K-NAME].
        let name = |d: &Path| d.file_name().and_then(|n| n.to_str()).map(str::to_string);
        let parent = dir.parent().and_then(name);
        let seed_dir = |n: &str| {
            n == format!("seed-{seed}")
                || n.strip_prefix(&format!("seed-{seed}@"))
                    .is_some_and(|p| p.parse::<u64>().is_ok())
        };
        let case = match (&parent, name(&dir)) {
            (Some(p), Some(n)) if seed_dir(p) => written.or(Some(n)),
            _ => None,
        };
        let own = if case.is_some() { parent } else { name(&dir) };
        let point = own
            .as_deref()
            .and_then(|n| n.strip_prefix(&format!("seed-{seed}@")))
            .and_then(|p| p.parse::<u64>().ok())
            .or((branch && own.as_deref() == Some(format!("seed-{seed}").as_str())).then_some(0));
        let replay = read_json(&dir.join("replay.json")).ok();
        runs.push(Run {
            dir,
            seed,
            case,
            result,
            run,
            replay,
            point,
        });
    }
    Ok(runs)
}

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    if d.join("result.json").is_file() {
        out.push(std::path::absolute(d).unwrap_or_else(|_| d.to_path_buf()));
        return;
    }
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name.starts_with("inc-") {
            continue;
        }
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&e.path(), out);
        }
    }
}

/// A size in bytes, in the largest binary unit it fills (`1.0 GiB`, `512 KiB`, `96 B`).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = "B";
    for u in UNITS {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    if unit == "B" {
        format!("{n} B")
    } else {
        format!("{v:.1} {unit}")
    }
}

/// `1 finding`, `2 findings`.
pub fn count(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

fn outcome_of(name: &str) -> Outcome {
    Outcome::ALL
        .into_iter()
        .find(|o| o.name() == name)
        .unwrap_or(Outcome::Internal)
}

/// Fault classes a run was configured with (`faults.counts`), those that fired, and how many
/// operations each could have acted on. (configured, injected, eligible).
fn fault_classes(r: &Value) -> (BTreeSet<String>, BTreeSet<String>, BTreeMap<String, u64>) {
    let (mut conf, mut inj, mut elig) = (BTreeSet::new(), BTreeSet::new(), BTreeMap::new());
    for (k, v) in r["faults"]["counts"].as_object().into_iter().flatten() {
        conf.insert(k.clone());
        elig.insert(k.clone(), v["eligible"].as_u64().unwrap_or(0));
        if v["injected"].as_u64().unwrap_or(0) > 0 {
            inj.insert(k.clone());
        }
    }
    (conf, inj, elig)
}

fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./=:,+-@%".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// One runnable `patina run` command that reproduces a run from its `run.json` (in `dir`):
/// the seed and flags, or, when the run has settings only a configuration file carries, the
/// seed and `--config DIR/run.json`, which carries all of them.
pub fn rerun_command(run: &Value, seed: u64, dir: &Path) -> String {
    let Ok(cfg) = serde_json::from_value::<Config>(run["config"].clone()) else {
        return format!(
            "patina run --seed {seed} --config {}",
            quote(&dir.join("run.json").display().to_string())
        );
    };
    let d = Config::default();
    let mut a = vec![
        "patina".to_string(),
        "run".into(),
        "--seed".into(),
        seed.to_string(),
    ];
    // Settings no flag carries: config keys (other than those the flags below set) that
    // differ from the defaults. Allow-unmet and the host CPU do not change the run.
    let mut rest = cfg.clone();
    rest.pmu.on = d.pmu.on;
    let (have, def) = (
        serde_json::to_value(&rest).unwrap(),
        serde_json::to_value(&d).unwrap(),
    );
    let flagged = [
        "seed",
        "cmd",
        "env",
        "mounts",
        "work",
        "stdin",
        "cpus",
        "faults-preset",
        "faults",
        "crash",
        "time-limit",
        "timeout",
        "log-limit",
        "buggify",
        "allow-unmet",
        "host-cpu",
    ];
    let config_only = have
        .as_object()
        .unwrap()
        .iter()
        .any(|(k, v)| !flagged.contains(&k.as_str()) && def.get(k.as_str()) != Some(v));
    if config_only {
        a.push("--config".into());
        a.push(quote(&dir.join("run.json").display().to_string()));
    } else {
        let mut flag = |n: &str, v: String| {
            a.push(n.into());
            a.push(quote(&v));
        };
        for e in &cfg.env {
            flag("--env", e.clone());
        }
        for m in &cfg.mounts {
            let c = if m.copy { ":copy" } else { "" };
            flag("--mount", format!("{}:{}{c}", m.src.display(), m.dst));
        }
        if cfg.work.is_some() || cfg.work_at.is_some() {
            let dir = cfg
                .work
                .as_ref()
                .map(|w| w.display().to_string())
                .unwrap_or_default();
            match &cfg.work_at {
                Some(g) => flag("--work", format!("{dir}:{g}")),
                None => flag("--work", dir),
            }
        }
        if let Some(s) = &cfg.stdin {
            flag("--stdin", s.display().to_string());
        }
        if cfg.cpus != d.cpus {
            flag("--cpus", cfg.cpus.to_string());
        }
        if !cfg.faults_preset.is_empty() {
            flag("--faults", cfg.faults_preset.join(","));
        }
        for f in &cfg.faults {
            flag("--fault", f.clone());
        }
        if let Some(c) = &cfg.crash {
            flag("--crash", c.clone());
        }
        if cfg.time_limit != d.time_limit {
            flag("--time-limit", cfg.time_limit.to_string());
        }
        if cfg.timeout != d.timeout {
            flag("--timeout", cfg.timeout.to_string());
        }
        if cfg.log_limit != d.log_limit {
            flag("--log-limit", cfg.log_limit.to_string());
        }
        if cfg.pmu.on {
            flag("--preempt", "branches".into());
        }
        if cfg.buggify {
            a.push("--buggify".into());
        }
    }
    a.push("--".into());
    // The command as given (a relative program path was made absolute by name when the run
    // was configured).
    for c in &cfg.cmd {
        a.push(quote(c));
    }
    a.join(" ")
}

/// The host limit a run ended on, named, if it ended on one: the supervisor reports a host
/// errno as `internal` with "host limit" and the call.
pub fn host_limit(r: &Value) -> Option<String> {
    let m = r["message"].as_str()?;
    if r["outcome"] != "internal" || !m.starts_with("host limit") {
        return None;
    }
    Some(if m.contains("pipe") || m.contains("fcntl") {
        "the per-user pipe limit (fs.pipe-user-pages-soft)".to_string()
    } else {
        format!("a host limit ({m})")
    })
}

struct Group<'a> {
    signature: String,
    case: Option<String>,
    runs: Vec<&'a Run>,
}

/// The report over `runs`: its JSON (with `exit`) and its text.
pub fn build(runs: &[Run], allow: &[String], head: Option<SweepHead>) -> (Value, String) {
    let free = crate::signature::checkout_free;
    let mut allow: BTreeSet<String> = allow.iter().map(|l| free(l)).collect();
    for r in runs {
        for l in r.run["config"]["allow-unmet"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(l) = l.as_str() {
                allow.insert(free(l));
            }
        }
    }
    // Outcomes by class.
    let mut by_class: BTreeMap<Outcome, usize> = BTreeMap::new();
    for r in runs {
        *by_class
            .entry(outcome_of(r.result["outcome"].as_str().unwrap_or("")))
            .or_default() += 1;
    }
    // Groups: every run that is not ok, by (signature, case).
    let mut groups: Vec<Group> = vec![];
    for r in runs {
        if r.result["outcome"] == "ok" {
            continue;
        }
        let signature = r.result["signature"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "{} {}",
                    r.result["outcome"].as_str().unwrap_or("?"),
                    r.result["stop"].as_str().unwrap_or("?")
                )
            });
        match groups
            .iter_mut()
            .find(|g| g.signature == signature && g.case == r.case)
        {
            Some(g) => g.runs.push(r),
            None => groups.push(Group {
                signature,
                case: r.case.clone(),
                runs: vec![r],
            }),
        }
    }
    for g in &mut groups {
        g.runs.sort_by_key(|r| (r.seed, r.point, r.dir.clone()));
    }
    // Faults: configured classes over the whole set, eligible counts.
    let mut configured = BTreeSet::new();
    let mut eligible: BTreeMap<String, u64> = BTreeMap::new();
    for r in runs {
        let (c, _, e) = fault_classes(&r.result);
        configured.extend(c);
        for (k, v) in e {
            *eligible.entry(k).or_default() += v;
        }
    }
    let idle: Vec<String> = eligible
        .iter()
        .filter(|(k, v)| **v == 0 && !allow.contains(*k))
        .map(|(k, _)| k.clone())
        .collect();
    // The SDK fold, by checkout-free label. Fault points count only in runs that let them
    // fire (`--buggify`).
    let mut sites: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    for r in runs {
        let buggify = r.run["config"]["buggify"] == true;
        for s in r.result["sdk"]["sites"].as_array().into_iter().flatten() {
            let kind = s["kind"].as_str().unwrap_or("");
            if kind == "buggify" && !buggify {
                continue;
            }
            let k = (kind.to_string(), free(s["label"].as_str().unwrap_or("")));
            let e = sites.entry(k).or_default();
            e.0 += s["evaluated"].as_u64().unwrap_or(0);
            e.1 += s["held"].as_u64().unwrap_or(0);
        }
    }
    let unmet = |kind: &str, f: &dyn Fn(u64, u64) -> bool| -> Vec<String> {
        sites
            .iter()
            .filter(|((k, l), (e, h))| k == kind && f(*e, *h) && !allow.contains(l))
            .map(|((_, l), _)| l.clone())
            .collect()
    };
    let never_held = unmet("sometimes", &|_, h| h == 0);
    let never_hit = unmet("reachable", &|_, h| h == 0);
    let never_fired = unmet("buggify", &|_, h| h == 0);
    let never_evaluated = unmet("always", &|e, _| e == 0);
    // Paths the sandbox lacks, by hint, with the runs that met them.
    let mut missing: BTreeMap<String, usize> = BTreeMap::new();
    for r in runs {
        for m in r.result["missing"].as_array().into_iter().flatten() {
            *missing.entry(crate::result::missing_line(m)).or_default() += 1;
        }
    }
    let stalls = runs
        .iter()
        .filter(|r| r.result["stop"] == "compute-stall")
        .count();
    // Compute points: every image any run listed (kinds joined), and the runs with any.
    let mut images: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut with_points = 0;
    for r in runs {
        let Some(l) = r.result["compute"]["images"].as_array() else {
            continue;
        };
        with_points += 1;
        for i in l {
            let k = images
                .entry(i["path"].as_str().unwrap_or("").to_string())
                .or_default();
            for x in i["kinds"].as_array().into_iter().flatten() {
                if let Some(x) = x.as_str().filter(|x| !k.iter().any(|y| y == x)) {
                    k.push(x.to_string());
                }
            }
            k.sort_by_key(|x| crate::result::kind_rank(x));
        }
    }
    let mut limits: BTreeMap<String, usize> = BTreeMap::new();
    for r in runs {
        if let Some(l) = host_limit(&r.result) {
            *limits.entry(l).or_default() += 1;
        }
    }
    // A branch sweep: each base's crash points and the children run of them.
    let mut bases: BTreeMap<(u64, Option<String>), (u64, u64)> = BTreeMap::new();
    for r in runs {
        match r.point {
            Some(0) => {
                bases.entry((r.seed, r.case.clone())).or_default().0 = r.result["faults"]["counts"]
                    ["crash"]["eligible"]
                    .as_u64()
                    .unwrap_or(0)
            }
            Some(_) => bases.entry((r.seed, r.case.clone())).or_default().1 += 1,
            None => {}
        }
    }
    let branch = (!bases.is_empty()).then(|| {
        json!({
            "points": bases.values().map(|b| b.0).sum::<u64>(),
            "tried": bases.values().map(|b| b.1).sum::<u64>(),
            "seeds": bases.iter().map(|((s, c), (p, t))| json!({"seed": s, "case": c, "points": p, "tried": t})).collect::<Vec<_>>(),
        })
    });
    let no_points = branch.as_ref().is_some_and(|b| b["points"] == 0);
    let vacuous = runs.is_empty()
        || no_points
        || !never_held.is_empty()
        || !never_hit.is_empty()
        || !never_fired.is_empty()
        || !idle.is_empty();

    // Each group's JSON, findings first, then by size.
    let mut gj: Vec<Value> = groups
        .iter()
        .map(|g| {
            let first = g.runs[0];
            let outcome = first.result["outcome"].as_str().unwrap_or("").to_string();
            let replay = g.runs.iter().find_map(|r| {
                r.replay.as_ref().map(|v| {
                    json!({"seed": r.seed, "result": v["result"], "message": v["message"]})
                })
            });
            let effective = match &replay {
                Some(v) if v["result"] == "nondeterministic" => "nondeterministic".to_string(),
                _ => outcome.clone(),
            };
            let classes: Vec<_> = g.runs.iter().map(|r| fault_classes(&r.result).1).collect();
            let every: BTreeSet<String> = classes
                .iter()
                .skip(1)
                .fold(classes[0].clone(), |a, b| &a & b);
            let any: BTreeSet<String> = classes.iter().flatten().cloned().collect();
            let none: Vec<&String> = configured.difference(&any).collect();
            json!({
                "signature": g.signature,
                "outcome": effective,
                "run_outcome": outcome,
                "stop": first.result["stop"],
                "case": g.case,
                "count": g.runs.len(),
                "seeds": g.runs.iter().map(|r| r.seed).collect::<Vec<_>>(),
                "first": {"seed": first.seed, "point": first.point.filter(|p| *p > 0), "dir": first.dir},
                "replay": replay,
                "faults": {"every": every, "none": none},
                "rerun": rerun_command(&first.run, first.seed, &first.dir),
                "replay_command": format!("patina replay {}", quote(&first.dir.display().to_string())),
            })
        })
        .collect();
    gj.sort_by_key(|g| {
        let o = outcome_of(g["outcome"].as_str().unwrap_or(""));
        (
            o.exit() != 1,
            o,
            std::cmp::Reverse(g["count"].as_u64().unwrap_or(0)),
            g["first"]["seed"].as_u64().unwrap_or(0),
            g["first"]["point"].as_u64().unwrap_or(0),
        )
    });
    let finding = gj
        .iter()
        .any(|g| outcome_of(g["outcome"].as_str().unwrap_or("")).exit() == 1);
    let not_ok = runs.iter().any(|r| r.result["outcome"] != "ok")
        || gj.iter().any(|g| g["outcome"] == "nondeterministic");
    let exit = if finding {
        1
    } else if not_ok || vacuous {
        2
    } else {
        0
    };
    let findings = runs
        .iter()
        .filter(|r| outcome_of(r.result["outcome"].as_str().unwrap_or("")).exit() == 1)
        .count();
    let finding_groups = gj
        .iter()
        .filter(|g| outcome_of(g["run_outcome"].as_str().unwrap_or("")).exit() == 1)
        .count();
    let mut v = json!({
        "schema": REPORT_SCHEMA,
        "runs": runs.len(),
        "seeds": runs.iter().map(|r| r.seed).collect::<BTreeSet<_>>().len(),
        "findings": findings,
        "outcomes": by_class.iter().map(|(o, n)| (o.name().to_string(), json!(n))).collect::<serde_json::Map<_, _>>(),
        "groups": gj,
        "sdk": {
            "sometimes_never_held": never_held,
            "reachable_never_hit": never_hit,
            "buggify_never_fired": never_fired,
            "always_never_evaluated": never_evaluated,
        },
        "faults": {"configured": configured, "eligible_zero": idle},
        "compute_stall": stalls,
        "missing": missing,
        "host_limits": limits,
        "allow_unmet": allow,
        "vacuous": vacuous,
        "exit": exit,
    });
    if let Some(b) = branch {
        v["branch"] = b;
    }
    if with_points > 0 {
        v["compute"] = json!({
            "images": images.iter().map(|(p, k)| json!({"path": p, "kinds": k})).collect::<Vec<_>>(),
            "runs_with_points": with_points,
        });
    }
    if let Some(h) = &head {
        v["sweep"] = json!({"seconds": h.seconds, "jobs": h.jobs, "lowered_to": h.lowered_to, "stopped": h.stopped});
    }
    let text = render(&v, finding_groups, head.as_ref());
    (v, text)
}

fn render(v: &Value, finding_groups: usize, head: Option<&SweepHead>) -> String {
    let n = |k: &str| v[k].as_u64().unwrap_or(0);
    let ok = v["outcomes"]["ok"].as_u64().unwrap_or(0);
    let what = format!(
        "{}, {} in {}, {} ok",
        count(n("runs") as usize, "run"),
        count(n("findings") as usize, "finding"),
        count(finding_groups, "group"),
        ok
    );
    let mut s = match head {
        Some(h) => format!(
            "patina sweep: {what}   ({:.1}s, {}{})\n",
            h.seconds,
            count(h.jobs, "job"),
            h.lowered_to
                .map(|w| format!(", lowered to {w} by a host limit"))
                .unwrap_or_default()
        ),
        None => format!("patina report: {what}\n"),
    };
    if let Some(stop) = head.and_then(|h| h.stopped.as_ref()) {
        s.push_str(&format!("stopped early: {stop}\n"));
    }
    let classes: Vec<String> = v["outcomes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, n)| format!("{k} {n}"))
        .collect();
    s.push_str(&format!("outcomes: {}\n", classes.join(", ")));
    if let Some(b) = v.get("branch") {
        let (p, t) = (
            b["points"].as_u64().unwrap_or(0),
            b["tried"].as_u64().unwrap_or(0),
        );
        s.push_str(&format!("crash points: {t} of {p} tried\n"));
        if t < p {
            let seeds = b["seeds"].as_array().unwrap();
            let mut l: Vec<String> = seeds
                .iter()
                .take(SEEDS_SHOWN)
                .map(|x| {
                    let c = x["case"]
                        .as_str()
                        .map(|c| format!(" [{c}]"))
                        .unwrap_or_default();
                    format!("seed {}{c}: {} of {}", x["seed"], x["tried"], x["points"])
                })
                .collect();
            if seeds.len() > SEEDS_SHOWN {
                l.push(format!(
                    "and {} more (report.json)",
                    seeds.len() - SEEDS_SHOWN
                ));
            }
            s.push_str(&format!("  {}\n", l.join("   ")));
        }
    }
    if let Some(c) = v.get("compute") {
        let with = c["runs_with_points"].as_u64().unwrap_or(0);
        s.push_str(&format!(
            "compute points: {}{}\n",
            crate::result::compute_images(
                &c["images"],
                if head.is_some() {
                    "report.json"
                } else {
                    "--format json"
                }
            ),
            if with < n("runs") {
                format!(" (in {with} of {} runs)", n("runs"))
            } else {
                String::new()
            }
        ));
    }
    for g in v["groups"].as_array().unwrap() {
        let st = |k: &str| g[k].as_str().unwrap_or("").to_string();
        s.push('\n');
        let mut name = st("signature");
        if let Some(c) = g["case"].as_str() {
            name = format!("[{c}] {name}");
        }
        if g["outcome"] != g["run_outcome"] {
            name = format!("{}: {name}", st("outcome"));
        }
        s.push_str(&format!("{name}\n"));
        let replay = match &g["replay"] {
            Value::Null => "not replayed".to_string(),
            r => {
                let res = r["result"].as_str().unwrap_or("");
                match r["message"].as_str().filter(|m| !m.is_empty()) {
                    Some(m) if res != "identical" => format!("replayed: {res}: {m}"),
                    _ => format!("replayed: {res}"),
                }
            }
        };
        s.push_str(&format!(
            "  {} of {} runs   first: seed {}   {replay}\n",
            g["count"],
            n("runs"),
            run_name(
                g["first"]["seed"].as_u64().unwrap_or(0),
                g["first"]["point"].as_u64()
            )
        ));
        let list = |k: &str| {
            let v: Vec<&str> = g["faults"][k]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|x| x.as_str())
                .collect();
            if v.is_empty() {
                "-".to_string()
            } else {
                v.join(", ")
            }
        };
        if !v["faults"]["configured"].as_array().unwrap().is_empty() {
            s.push_str(&format!(
                "  faults in every failing run: {}      in none: {}\n",
                list("every"),
                list("none")
            ));
        }
        s.push_str(&format!("  rerun:  {}\n", st("rerun")));
        s.push_str(&format!("  replay: {}\n", st("replay_command")));
    }
    let names = |a: &Value| -> Vec<String> {
        a.as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect()
    };
    let mut tail = vec![];
    // A count and the first few labels of each kind; the full lists are in the JSON.
    let full = if head.is_some() {
        "report.json"
    } else {
        "--format json"
    };
    for (k, what) in [
        ("sometimes_never_held", "`sometimes` never held"),
        ("reachable_never_hit", "`reachable` never hit"),
        ("buggify_never_fired", "`buggify` never fired"),
        ("always_never_evaluated", "`always` never evaluated"),
    ] {
        let l = names(&v["sdk"][k]);
        if l.is_empty() {
            continue;
        }
        let more = l.len().saturating_sub(LABELS_SHOWN);
        let mut line = format!(
            "sdk: {what}: {}: {}",
            l.len(),
            l[..l.len().min(LABELS_SHOWN)].join(", ")
        );
        if more > 0 {
            line.push_str(&format!(", and {more} more ({full})"));
        }
        tail.push(line);
    }
    for c in names(&v["faults"]["eligible_zero"]) {
        tail.push(format!("faults: {c} eligible 0 times: nothing to act on"));
    }
    let miss = v["missing"].as_object().unwrap();
    for (l, k) in miss.iter().take(LABELS_SHOWN) {
        tail.push(format!(
            "{l} ({})",
            count(k.as_u64().unwrap_or(0) as usize, "run")
        ));
    }
    if miss.len() > LABELS_SHOWN {
        tail.push(format!(
            "not in the sandbox: {} more paths ({full})",
            miss.len() - LABELS_SHOWN
        ));
    }
    for (l, k) in v["host_limits"].as_object().unwrap() {
        tail.push(format!(
            "host: {} ended internal on {l}; run fewer at once (-j) or raise the limit",
            count(k.as_u64().unwrap_or(0) as usize, "run")
        ));
    }
    if n("compute_stall") > 0 {
        tail.push(format!(
            "compute-stall: {} of {} runs",
            n("compute_stall"),
            n("runs")
        ));
    }
    if v["vacuous"] == true {
        tail.push(if n("runs") == 0 {
            "vacuous: no runs".to_string()
        } else if v["branch"]["points"] == 0 {
            "vacuous: no base has a crash point: nothing under the work tree changed, nothing to branch at".to_string()
        } else {
            "vacuous: see above (allow a label with --allow-unmet or [sdk] allow-unmet)".to_string()
        });
    }
    if !tail.is_empty() {
        s.push('\n');
        for t in tail {
            s.push_str(&t);
            s.push('\n');
        }
    }
    s
}
