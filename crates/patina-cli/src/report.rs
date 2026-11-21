//! `patina report DIR...`: one report over any set of run directories (a sweep's, or runs
//! made by `patina run --out`). Runs are grouped by their `result.json` signature, and by case
//! unless the signature names its bug (`group_case`); each group gets its count, first seed,
//! replay result, the rerun and replay commands and the fault attribution line. A `--known`
//! file labels findings already known: they are counted and listed, and do not fail the
//! report. The SDK, fault-count and check folds, and the known file's `!` entries, are the
//! vacuity check.
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
/// Reasons the `check:` line names for runs the checker did not judge; the JSON has all.
const REASONS_SHOWN: usize = 3;
/// Seeds the text lists with their crash points tried, when a branch sweep stopped early.
const SEEDS_SHOWN: usize = 8;

/// One finished run found under the report's directories.
pub struct Run {
    pub dir: PathBuf,
    pub seed: u64,
    pub case: Option<String>,
    /// A sweep case's id (`run.json`'s `case.id`): its `--name`, or its line number.
    pub case_id: Option<String>,
    /// A sweep case's position in its cases file (its directory's `K-`), which orders a
    /// group's runs of one seed.
    pub case_pos: Option<usize>,
    pub result: Value,
    pub run: Value,
    /// `replay.json`, written by a sweep that replayed this run.
    pub replay: Option<Value>,
    /// In a `--crash-points` sweep: where it crashes (`Point`).
    pub point: Option<Point>,
}

impl Run {
    /// Where the run is, as `report.json` names a run: its seed, branch point, case (and
    /// `case_id` with `id`) and directory.
    fn at(&self, id: bool) -> Value {
        let mut v = json!({"seed": self.seed, "case": self.case, "dir": self.dir});
        if id {
            v["case_id"] = json!(self.case_id);
        }
        Point::json(self.point.as_ref(), &mut v);
        v
    }
}

/// A run's place in a `--crash-points` sweep: a base (`n` 0, `seed-N`), or the child crashing at
/// crash point `n` (`seed-N@P`), of node `node`'s first boot in a run with nodes
/// (`seed-N@NODE.P`; `node` empty: the one machine); under `[sweep] crash-pairs`, a pair's child
/// crashes node `node2` at its point `n2` after that (`seed-N@A.I+B.J`). Ordered by point, then
/// node. A label is a portable file name: no `:` (GitHub's artifact upload refuses one, as
/// Windows does).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Point {
    pub n: u64,
    pub node: String,
    pub n2: u64,
    pub node2: String,
}

impl Point {
    pub fn child(n: u64, node: &str) -> Point {
        Point {
            n,
            node: node.to_string(),
            ..Default::default()
        }
    }

    /// The pair's child: `self`'s crash, then node `node`'s at its point `n`.
    pub fn then(&self, n: u64, node: &str) -> Point {
        Point {
            n2: n,
            node2: node.to_string(),
            ..self.clone()
        }
    }

    /// Its first crash alone (the child of the first level a pair branched from).
    pub fn first(&self) -> Point {
        Point::child(self.n, &self.node)
    }

    /// `P`, `NODE.P` or `A.I+B.J`, as a directory name and a run's name have it after `@` (a
    /// node's name has no `.` or `+`).
    pub fn label(&self) -> String {
        let one = |n: u64, node: &str| {
            if node.is_empty() {
                n.to_string()
            } else {
                format!("{node}.{n}")
            }
        };
        let mut l = one(self.n, &self.node);
        if self.n2 > 0 {
            l = format!("{l}+{}", one(self.n2, &self.node2));
        }
        l
    }

    /// A label read back (`P`, `NODE.P`, `A.I+B.J`, each point > 0).
    pub fn parse(s: &str) -> Option<Point> {
        let one = |s: &str| -> Option<(u64, String)> {
            let (node, n) = s.rsplit_once('.').unwrap_or(("", s));
            let n = n.parse::<u64>().ok().filter(|n| *n > 0)?;
            (node.is_empty() || proto::node::valid_name(node.as_bytes()))
                .then(|| (n, node.to_string()))
        };
        match s.split_once('+') {
            None => one(s).map(|(n, node)| Point::child(n, &node)),
            Some((a, b)) => {
                let ((n, node), (n2, node2)) = (one(a)?, one(b)?);
                (!node.is_empty() && !node2.is_empty() && node != node2)
                    .then(|| Point::child(n, &node).then(n2, &node2))
            }
        }
    }

    /// A child's fields in `report.json`: its `point`, its `node` when it has one, and a
    /// pair's `point2` and `node2`.
    fn json(p: Option<&Point>, v: &mut Value) {
        if let Some(p) = p.filter(|p| p.n > 0) {
            v["point"] = json!(p.n);
            if !p.node.is_empty() {
                v["node"] = json!(p.node);
            }
            if p.n2 > 0 {
                v["point2"] = json!(p.n2);
                v["node2"] = json!(p.node2);
            }
        } else {
            v["point"] = Value::Null;
        }
    }

    /// The child a `report.json` entry names (`Point::json`).
    pub fn of(v: &Value) -> Option<Point> {
        let n = v["point"].as_u64().filter(|n| *n > 0)?;
        let p = Point::child(n, v["node"].as_str().unwrap_or(""));
        Some(match v["point2"].as_u64() {
            Some(n2) => p.then(n2, v["node2"].as_str().unwrap_or("")),
            None => p,
        })
    }
}

/// The crash points a `--crash-points` base counted: with nodes, each node's whose crashes were
/// at its crash points (`nodes.list[].crash_points`, its first boot's), by name; otherwise
/// the one machine's (`""`, the `crash` class's eligible calls).
pub fn base_points(r: &Value, run: &Value) -> Vec<(String, u64)> {
    // A run with nodes counts no points of the one machine, even when it ended before its
    // result had a node table.
    let nodes = run["config"]["nodes"]
        .as_array()
        .is_some_and(|n| !n.is_empty());
    match r["nodes"]["list"].as_array() {
        None if nodes => vec![],
        Some(l) => l
            .iter()
            .filter_map(|n| {
                let p = n["crash_points"].get(0)?.as_u64()?;
                Some((n["name"].as_str()?.to_string(), p))
            })
            .collect(),
        None => vec![(
            String::new(),
            r["faults"]["counts"]["crash"]["eligible"]
                .as_u64()
                .unwrap_or(0),
        )],
    }
}

/// How a run is named: `seed 3`, or `seed 3@120` (`3@b.120` on node b) for a branch child.
pub fn run_name(seed: u64, point: Option<&Point>) -> String {
    match point {
        Some(p) if p.n > 0 => format!("{seed}@{}", p.label()),
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
    let known = known_flag(a)?;
    let mut again = "patina report --group N".to_string();
    if let Some(k) = a.last("--known") {
        again.push_str(&format!(" --known {}", quote(k)));
    }
    for d in &a.positional {
        again.push_str(&format!(" {}", quote(d)));
    }
    let (v, text) = build(&runs, a.all("--allow-unmet"), known.as_ref(), None, &again);
    if let Some(n) = a.num::<usize>("--group")? {
        print!("{}", group(&v, n, a.json())?);
    } else if a.json() {
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
        let branch = read_json(&d.join("sweep.json")).is_ok_and(|v| v["crash_points"] == true);
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
            .map(|c| crate::sweep::case_shown(c.trim_end_matches('\n')));
        // A branch child lives in OUT/seed-N@P[/K-NAME].
        let name = |d: &Path| d.file_name().and_then(|n| n.to_str()).map(str::to_string);
        let parent = dir.parent().and_then(name);
        let seed_dir = |n: &str| {
            n == format!("seed-{seed}")
                || n.strip_prefix(&format!("seed-{seed}@"))
                    .is_some_and(|p| Point::parse(p).is_some())
        };
        let case = match (&parent, name(&dir)) {
            (Some(p), Some(n)) if seed_dir(p) => written.or(Some(n)),
            _ => None,
        };
        let own = if case.is_some() { parent } else { name(&dir) };
        let point = own
            .as_deref()
            .and_then(|n| n.strip_prefix(&format!("seed-{seed}@")))
            .and_then(Point::parse)
            .or(
                (branch && own.as_deref() == Some(format!("seed-{seed}").as_str()))
                    .then(Point::default),
            );
        let replay = read_json(&dir.join("replay.json")).ok();
        let case_pos = case
            .as_ref()
            .and_then(|_| name(&dir)?.split_once('-')?.0.parse::<usize>().ok());
        let case_id = case
            .as_ref()
            .and_then(|_| run["config"]["case"]["id"].as_str().map(str::to_string));
        runs.push(Run {
            dir,
            seed,
            case,
            case_id,
            case_pos,
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

/// The fault classes a setting of their own named in some run (`--fault`, a `[faults]` key),
/// and the count classes of each `--faults` class the runs named (`run.json`).
fn fault_sources(runs: &[Run]) -> (BTreeSet<String>, BTreeMap<String, BTreeSet<String>>) {
    use crate::launcher::attribution::class_of_key;
    let (mut named, mut by_class) = (BTreeSet::new(), BTreeMap::<String, BTreeSet<String>>::new());
    for r in runs {
        let c = &r.run["config"];
        for f in strs(&c["faults"]) {
            let (kv, _) = crate::faults::split_scope(&f);
            if let Some(k) = class_of_key(kv.split_once('=').map_or(kv, |x| x.0)) {
                named.insert(k.to_string());
            }
        }
        let nodes = c["nodes"].as_array().map_or(0, |n| n.len());
        for e in strs(&c["fault-classes"]) {
            let names = crate::faults::split_scope(&e).0;
            // Every class that may apply: `all` over a run with nodes enough for each.
            for class in crate::faults::classes(names, nodes.max(2), 2).unwrap_or_default() {
                let e = by_class.entry(class.to_string()).or_default();
                match class {
                    "crash" | "kill" => {
                        e.insert("crash".to_string());
                    }
                    _ => e.extend(
                        crate::faults::class_keys(class)
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|(k, _)| class_of_key(k))
                            .map(str::to_string),
                    ),
                }
            }
        }
    }
    (named, by_class)
}

/// A JSON array's strings.
fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// Whether every process of the run could fire its fault points: one machine with the class,
/// or the class on the driver and on every node (else a point that only an unfaulted node or
/// the driver reaches never fires, and that says nothing).
fn buggify_everywhere(run: &Value) -> bool {
    let plan = &run["faults"];
    let nodes = strs_of(&run["config"]["nodes"], "name");
    if nodes.is_empty() {
        return plan.get("buggify").is_some();
    }
    std::iter::once("driver".to_string())
        .chain(nodes)
        .all(|n| plan.get(format!("buggify@{n}")).is_some())
}

fn strs_of(v: &Value, k: &str) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x[k].as_str().map(str::to_string))
        .collect()
}

/// The rate `buggify:LABEL` sets in a resolved plan, on any node.
fn own_rate(plan: &Value, label: &str) -> Option<u64> {
    let free = crate::signature::checkout_free;
    plan.as_object().into_iter().flatten().find_map(|(k, v)| {
        k.strip_prefix("buggify:")
            .map(|l| crate::faults::split_scope(l).0)
            .filter(|l| free(l) == label)
            .and_then(|_| v.as_u64())
    })
}

pub fn quote(s: &str) -> String {
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
    let rest = cfg.clone();
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
        "fault-classes",
        "faults",
        // Held faults are what the run comes to by itself (`launch::run_one`).
        "faults-held",
        "fs-model",
        "timeout",
        "allow-unmet",
        "host-cpu",
        "check",
        "ok-exit",
    ];
    // A case's checker gets its case, and a checker its timeout, only from run.json.
    let config_only = have
        .as_object()
        .unwrap()
        .iter()
        .any(|(k, v)| !flagged.contains(&k.as_str()) && def.get(k.as_str()) != Some(v))
        || cfg
            .check
            .as_ref()
            .is_some_and(|k| k.case.is_some() || k.timeout != crate::check::DEFAULT_TIMEOUT);
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
        for c in &cfg.fault_classes {
            flag("--faults", c.clone());
        }
        for f in &cfg.faults {
            flag("--fault", f.clone());
        }
        if cfg.fs_model != d.fs_model {
            flag("--fault", format!("fs-model={}", cfg.fs_model));
        }
        if cfg.timeout != d.timeout {
            flag("--timeout", cfg.timeout.to_string());
        }

        if let Some(k) = &cfg.check {
            flag("--check", crate::check::join(&k.words));
        }
        if cfg.ok_exit == crate::config::ok_exit_any() {
            flag("--ok-exit", "any".into());
        } else if !cfg.ok_exit.is_empty() {
            // Unconditional first (`config::normal`): the list reads back as written.
            let l: Vec<String> = cfg.ok_exit.iter().map(|x| x.to_string()).collect();
            flag("--ok-exit", l.join(","));
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

/// `*` matches any text (also none); every other character itself; the whole of `s` must match.
pub fn glob(pat: &str, s: &str) -> bool {
    let mut parts = pat.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = s.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// A finding as the report prints it, and as a known file's patterns see it: `[CASE] SIGNATURE`,
/// or `SIGNATURE` for a run without a case.
pub fn subject(case: Option<&str>, signature: &str) -> String {
    match case {
        Some(c) => format!("[{c}] {signature}"),
        None => signature.to_string(),
    }
}

/// What a known pattern is matched against: the signature, after `[CASE] ` when the pattern
/// starts with `[`, then ` {faults: F}` when it holds `{faults:`.
fn matched_text(pattern: &str, case: Option<&str>, signature: &str, fired: &[String]) -> String {
    let mut t = if pattern.starts_with('[') {
        subject(case, signature)
    } else {
        signature.to_string()
    };
    if pattern.contains("{faults:") {
        let f = if fired.is_empty() {
            "-".to_string()
        } else {
            fired.join(",")
        };
        t.push_str(&format!(" {{faults: {f}}}"));
    }
    t
}

/// The faults that fired in a run, sorted: each fault class that injected (`faults.counts`),
/// and `buggify:LABEL` for each SDK fault point that fired (`--faults buggify`).
pub fn fired(result: &Value) -> Vec<String> {
    let mut out: Vec<String> = fault_classes(result).1.into_iter().collect();
    for s in result["sdk"]["sites"].as_array().into_iter().flatten() {
        if s["kind"] == "buggify" && s["held"].as_u64().unwrap_or(0) > 0 {
            out.push(format!(
                "buggify:{}",
                crate::signature::checkout_free(s["label"].as_str().unwrap_or(""))
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The case a run's group is keyed by: none for a finding that names its bug
/// (`signature::names_its_bug`), which is one group over every case it appears in.
pub fn group_case(signature: &str, case: Option<&str>) -> Option<String> {
    if crate::signature::names_its_bug(signature) {
        None
    } else {
        case.map(str::to_string)
    }
}

/// A `--known` file: findings already known, each `ID PATTERN` on its own line (`#` starts a
/// comment line). `!ID` marks one that must appear.
pub struct Known {
    pub file: PathBuf,
    entries: Vec<KnownEntry>,
}

struct KnownEntry {
    id: String,
    required: bool,
    pattern: String,
}

impl Known {
    pub fn read(file: &Path) -> Res<Known> {
        let t = std::fs::read_to_string(file)
            .map_err(|e| format!("--known {}: {e}", file.display()))?;
        let mut entries = vec![];
        for (n, line) in t.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, pattern) = line
                .split_once(char::is_whitespace)
                .map(|(i, p)| (i, p.trim()))
                .unwrap_or((line, ""));
            let (id, required) = match id.strip_prefix('!') {
                Some(i) => (i, true),
                None => (id, false),
            };
            if id.is_empty() || pattern.is_empty() {
                return Err(format!(
                    "--known {} line {}: expected ID PATTERN, not {line:?}",
                    file.display(),
                    n + 1
                ));
            }
            entries.push(KnownEntry {
                id: id.to_string(),
                required,
                pattern: pattern.to_string(),
            });
        }
        Ok(Known {
            file: std::path::absolute(file).unwrap_or_else(|_| file.to_path_buf()),
            entries,
        })
    }

    /// The ID of the first entry whose pattern matches the finding of `result` (a run's
    /// `result.json`), if one does. A pattern is matched against the signature; one that
    /// starts with `[` against `[CASE] SIGNATURE`; one holding `{faults:` with ` {faults: F}`
    /// after that, F the fault classes that fired in the run (`fired`).
    pub fn id_of(&self, case: Option<&str>, result: &Value) -> Option<&str> {
        let signature = signature_of(result);
        let fired = fired(result);
        self.entries
            .iter()
            .find(|e| {
                glob(
                    &e.pattern,
                    &matched_text(&e.pattern, case, &signature, &fired),
                )
            })
            .map(|e| e.id.as_str())
    }

    /// For an ID that matched no run: a run's text (`matched_text`) one of its patterns would
    /// match with its numbers written the other way, digits for `N` or `N` for digits. A status
    /// is kept as digits (`exit 5`) and other numbers become `N`, so a pattern can be wrong
    /// either way.
    fn near_miss(&self, id: &str, runs: &[Run]) -> Option<String> {
        // Each run of digits as one `N`.
        let n = |t: &str| {
            let (mut out, mut digit) = (String::new(), false);
            for c in t.chars() {
                if !c.is_ascii_digit() {
                    out.push(c);
                } else if !digit {
                    out.push('N');
                }
                digit = c.is_ascii_digit();
            }
            out
        };
        for e in self.entries.iter().filter(|e| e.id == id) {
            for r in runs
                .iter()
                .filter(|r| is_finding(r.result["outcome"].as_str().unwrap_or("")))
            {
                let t = matched_text(
                    &e.pattern,
                    r.case.as_deref(),
                    &signature_of(&r.result),
                    &fired(&r.result),
                );
                if glob(&e.pattern, &n(&t)) || glob(&n(&e.pattern), &t) {
                    return Some(t);
                }
            }
        }
        None
    }

    /// Every ID once, in file order, with whether it must appear (any of its lines has `!`).
    fn ids(&self) -> Vec<(&str, bool)> {
        let mut out: Vec<(&str, bool)> = vec![];
        for e in &self.entries {
            match out.iter_mut().find(|(i, _)| *i == e.id) {
                Some(x) => x.1 |= e.required,
                None => out.push((&e.id, e.required)),
            }
        }
        out
    }
}

/// `--known FILE`, read, if given.
pub fn known_flag(a: &Args) -> Res<Option<Known>> {
    a.last("--known")
        .map(|f| Known::read(Path::new(f)))
        .transpose()
}

/// Whether `label` is allowed to stay unmet: a pattern with `*` matches by `glob`, one
/// without matches exactly.
fn allowed(allow: &BTreeSet<String>, label: &str) -> bool {
    allow.iter().any(|p| glob(p, label))
}

/// A run's signature, or `OUTCOME STOP` for a result that has none.
pub fn signature_of(result: &Value) -> String {
    result["signature"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "{} {}",
                result["outcome"].as_str().unwrap_or("?"),
                result["stop"].as_str().unwrap_or("?")
            )
        })
}

/// The class a reason for not judging a run is counted under: its text before `: `, as the
/// checker wrote it (`CLASS: detail`), or else the whole reason with its numbers as `N`.
pub fn skip_class(why: &str) -> String {
    match why.split_once(": ") {
        Some((c, _)) if !c.trim().is_empty() => c.trim().to_string(),
        _ => crate::signature::normalise(why),
    }
}

/// The prefix most of `labels` share, up to and including the first `-`, `_`, `:`, `/` or `.`
/// of a label, and how many share it, when at least two do.
fn shared_prefix(labels: &[String]) -> Option<(String, usize)> {
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for l in labels {
        if let Some(i) = l.find(['-', '_', ':', '/', '.']).filter(|i| *i > 0) {
            *by.entry(&l[..=i]).or_default() += 1;
        }
    }
    by.into_iter()
        .filter(|(_, n)| *n >= 2)
        .max_by_key(|(p, n)| (*n, std::cmp::Reverse(*p)))
        .map(|(p, n)| (p.to_string(), n))
}

/// A `--faults buggify` sweep smaller than this is a smoke run: a fault point no run reached is noted,
/// not vacuous.
const SMOKE_RUNS: usize = 20;
/// A fault point that never fired is vacuous when the chance of that at its rates was below this.
const MISS_CHANCE: f64 = 0.001;

/// The natural log of the chance that the fault point `label` fired at none of `evaluated`
/// evaluations in one run with the resolved plan `plan`: active in `ACTIVATION_PERMILLE` of runs
/// and then firing at `FIRE_PERMILLE`, or always active at its own `buggify:LABEL` rate.
fn miss_ln(plan: &Value, label: &str, evaluated: u64) -> f64 {
    use proto::sdk::{ACTIVATION_PERMILLE, FIRE_PERMILLE};
    let (active, rate) = match own_rate(plan, label) {
        Some(p) => (1.0, p as f64 / 1000.0),
        None => (
            ACTIVATION_PERMILLE as f64 / 1000.0,
            FIRE_PERMILLE as f64 / 1000.0,
        ),
    };
    let rate = rate.min(1.0);
    ((1.0 - active) + active * (1.0 - rate).powf(evaluated as f64)).ln()
}

/// Characters of a finding's example the report shows.
const EXAMPLE_MAX: usize = 240;

/// One finding of a violation group as its run wrote it, before the signature normalised it
/// (`0x0`, an exit status) or left the detail out (a checker's keyed label), or why a checker
/// failed: `null` when the signature already says the same.
fn example(signature: &str, result: &Value, dir: &Path) -> Value {
    // The stderr line the signature quotes (a panic or assertion, else the last line): as
    // the guest wrote it, when the signature changed it.
    if matches!(result["outcome"].as_str(), Some("failure" | "crash")) {
        let inc = result["incarnations"].as_u64().unwrap_or(1).max(1) - 1;
        let stderr =
            std::fs::read(dir.join(format!("inc-{inc}")).join("stderr")).unwrap_or_default();
        let stderr = String::from_utf8_lossy(&stderr);
        let line = crate::signature::guest_line_raw(&stderr).or_else(|| {
            let m = result["message"].as_str().unwrap_or("");
            (!m.starts_with("INVARIANT ")).then(|| crate::signature::last_line_raw(&stderr))?
        });
        return match line {
            Some(l) if !signature.contains(&l) => {
                Value::String(l.trim().chars().take(EXAMPLE_MAX).collect())
            }
            _ => Value::Null,
        };
    }
    let checker_error = result["outcome"] == "error" && result["stop"] == "check";
    if result["outcome"] != "violation" && !checker_error {
        return Value::Null;
    }
    let m = result["message"].as_str().unwrap_or("").trim();
    let primary = signature.split_once(": ").map_or("", |p| p.1);
    if m.is_empty() || m == primary {
        return Value::Null;
    }
    Value::String(m.chars().take(EXAMPLE_MAX).collect())
}

/// Whether an outcome name is a finding (exit status 1).
pub fn is_finding(outcome: &str) -> bool {
    outcome_of(outcome).exit() == 1
}

struct Group<'a> {
    signature: String,
    /// The case in its key: `None` for a finding that names its bug, which may span cases.
    case: Option<String>,
    /// The known file's ID its runs matched.
    known: Option<String>,
    runs: Vec<&'a Run>,
}

/// The report over `runs`: its JSON (with `exit`) and its text. `again` is the command that
/// prints one group in full (`patina report --group N ...`).
pub fn build(
    runs: &[Run],
    allow: &[String],
    known: Option<&Known>,
    head: Option<SweepHead>,
    again: &str,
) -> (Value, String) {
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
    // Groups: every run that is not ok, by signature, and by case unless the signature names
    // its bug. A finding a known entry matches is grouped by that entry and its signature.
    let mut groups: Vec<Group> = vec![];
    for r in runs {
        let outcome = r.result["outcome"].as_str().unwrap_or("");
        if outcome == "ok" {
            continue;
        }
        let signature = signature_of(&r.result);
        let known = known
            .filter(|_| is_finding(outcome))
            .and_then(|k| k.id_of(r.case.as_deref(), &r.result))
            .map(str::to_string);
        let case = match known {
            Some(_) => None,
            None => group_case(&signature, r.case.as_deref()),
        };
        match groups
            .iter_mut()
            .find(|g| g.signature == signature && g.case == case && g.known == known)
        {
            Some(g) => g.runs.push(r),
            None => groups.push(Group {
                signature,
                case,
                known,
                runs: vec![r],
            }),
        }
    }
    for g in &mut groups {
        g.runs
            .sort_by_key(|r| (r.seed, r.point.clone(), r.case_pos, r.dir.clone()));
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
    // A fault only a class turned on may have had nothing to act on: `--faults net` on a
    // program with no datagram socket. Never eligible, it is not applicable, not vacuous, if its
    // class acted on something; one a setting of its own named (`--fault`, a `[faults]` key)
    // in any run, or one whose classes applied nowhere, stays vacuous.
    let (named, of_class) = fault_sources(runs);
    let applied =
        |cs: &BTreeSet<String>| cs.iter().any(|c| eligible.get(c).is_some_and(|n| *n > 0));
    let lenient =
        |c: &str| !named.contains(c) && of_class.values().any(|cs| cs.contains(c) && applied(cs));
    let (not_applicable, idle): (Vec<String>, Vec<String>) = eligible
        .iter()
        .filter(|(k, v)| **v == 0 && !allow.contains(*k))
        .map(|(k, _)| k.clone())
        .partition(|k| lenient(k));
    // The SDK fold, by checkout-free label. Fault points count only in runs that let them
    // fire (`--faults buggify`).
    let mut sites: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    // Per site, in how many runs it was evaluated and held (hit, fired), and every label any
    // run declared.
    let mut site_runs: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    // Per fault point: the natural log of the chance that it fired at none of its evaluations,
    // at its rates (`miss_ln`).
    let mut miss: BTreeMap<String, f64> = BTreeMap::new();
    let mut buggify_runs = 0;
    for r in runs {
        let buggify = buggify_everywhere(&r.run);
        buggify_runs += buggify as usize;
        for s in r.result["sdk"]["sites"].as_array().into_iter().flatten() {
            let kind = s["kind"].as_str().unwrap_or("");
            declared.insert(free(s["label"].as_str().unwrap_or("")));
            // A point counts in a run that let it fire wherever it is reached: the class
            // everywhere, or its own `buggify:LABEL` rate.
            if kind == "buggify"
                && !buggify
                && own_rate(&r.run["faults"], &free(s["label"].as_str().unwrap_or(""))).is_none()
            {
                continue;
            }
            let label = free(s["label"].as_str().unwrap_or(""));
            let evaluated = s["evaluated"].as_u64().unwrap_or(0);
            let held = s["held"].as_u64().unwrap_or(0);
            let e = site_runs
                .entry((kind.to_string(), label.clone()))
                .or_default();
            e.0 += (evaluated > 0) as u64;
            e.1 += (held > 0) as u64;
            if kind == "buggify" {
                *miss.entry(label.clone()).or_default() +=
                    miss_ln(&r.run["faults"], &label, evaluated);
            }
            let e = sites.entry((kind.to_string(), label)).or_default();
            e.0 += evaluated;
            e.1 += s["held"].as_u64().unwrap_or(0);
        }
    }
    // Unmet labels a pattern allows do not make the result vacuous; they are listed apart.
    let mut allowed_unmet: BTreeSet<String> = BTreeSet::new();
    let mut unmet = |kind: &str, f: &dyn Fn(u64, u64) -> bool| -> Vec<String> {
        let mut out = vec![];
        for ((k, l), (e, h)) in &sites {
            if k == kind && f(*e, *h) {
                if allowed(&allow, l) {
                    allowed_unmet.insert(l.clone());
                } else {
                    out.push(l.clone());
                }
            }
        }
        out
    };
    let never_held = unmet("sometimes", &|_, h| h == 0);
    let never_hit = unmet("reachable", &|_, h| h == 0);
    // A fault point that never fired is chance, not vacuity, unless firing was all but
    // certain: no run reached it in a sweep of `SMOKE_RUNS` or more, or it missed at every
    // evaluation where the chance of that was below `MISS_CHANCE`. The rest are noted.
    let mut noted_unfired: Vec<Value> = vec![];
    let never_fired: Vec<String> = unmet("buggify", &|_, h| h == 0)
        .into_iter()
        .filter(|l| {
            let evaluated = sites[&("buggify".to_string(), l.clone())].0;
            let chance = miss.get(l).copied().unwrap_or(0.0).exp();
            let certain = match evaluated {
                0 => buggify_runs >= SMOKE_RUNS,
                _ => chance < MISS_CHANCE,
            };
            if !certain {
                noted_unfired.push(json!({"label": l, "evaluated": evaluated, "chance": chance}));
            }
            certain
        })
        .collect();
    let never_evaluated = unmet("always", &|e, _| e == 0);
    // An --allow-unmet pattern that names nothing the runs have: no label, no fault class
    // configured, not `check` (a shell's expansion of an unquoted `*` is the usual cause).
    let unmatched_allow: Vec<&String> = allow
        .iter()
        .filter(|p| {
            *p != "check"
                && !declared.iter().any(|l| glob(p, l))
                && !configured.iter().chain(eligible.keys()).any(|c| glob(p, c))
        })
        .collect();
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
        // A run under load-time points has the section for its plans' cell alone.
        if l.is_empty() && r.result["rewrite"].is_object() {
            continue;
        }
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
    // Load-time points (load-time points): the points taken, and each file a run asked a plan
    // for, with whether it had one.
    let mut planned: BTreeMap<String, bool> = BTreeMap::new();
    let (mut with_plans, mut taken) = (0, 0);
    for r in runs {
        let w = &r.result["rewrite"];
        let Some(l) = w["images"].as_array() else {
            continue;
        };
        with_plans += 1;
        taken += w["points"].as_u64().unwrap_or(0);
        // A file of data alone holds no code to rewrite: not counted among the files.
        for i in l.iter().filter(|i| i["status"] != "data") {
            *planned
                .entry(i["path"].as_str().unwrap_or("").to_string())
                .or_default() |= i["status"] == "planned";
        }
    }
    let mut limits: BTreeMap<String, usize> = BTreeMap::new();
    for r in runs {
        if let Some(l) = host_limit(&r.result) {
            *limits.entry(l).or_default() += 1;
        }
    }
    // A branch sweep: each base's crash points and the children run of them; with nodes, each
    // node's too; under [sweep] crash-pairs, the pairs after the first crashes (each first crash's
    // `points.json`) and those run.
    #[derive(Default, Clone, Copy)]
    struct Tally {
        points: u64,
        tried: u64,
    }
    let mut bases: BTreeMap<(u64, Option<String>), Tally> = BTreeMap::new();
    // In the order the nodes are configured (the bases' node tables), not by name.
    let mut per_node: Vec<(String, Tally)> = vec![];
    fn node(per_node: &mut Vec<(String, Tally)>, n: &str) -> usize {
        match per_node.iter().position(|x| x.0 == n) {
            Some(i) => i,
            None => {
                per_node.push((n.to_string(), Tally::default()));
                per_node.len() - 1
            }
        }
    }
    let (mut pairs, mut pairs_tried) = (0u64, 0u64);
    let file = |r: &Run| read_json(&r.dir.join(crate::branch::FILE)).unwrap_or_default();
    for r in runs {
        match &r.point {
            Some(p) if p.n == 0 => {
                let pts = base_points(&r.result, &r.run);
                bases.entry((r.seed, r.case.clone())).or_default().points =
                    pts.iter().map(|x| x.1).sum();
                for (n, k) in pts.into_iter().filter(|x| !x.0.is_empty()) {
                    let i = node(&mut per_node, &n);
                    per_node[i].1.points += k;
                }
            }
            Some(p) if p.n2 > 0 => pairs_tried += 1,
            Some(p) => {
                bases.entry((r.seed, r.case.clone())).or_default().tried += 1;
                if !p.node.is_empty() {
                    let i = node(&mut per_node, &p.node);
                    per_node[i].1.tried += 1;
                }
                let f = file(r);
                pairs += f["after"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|x| x.1.as_array().map_or(0, |a| a.len()) as u64)
                    .sum::<u64>();
            }
            None => {}
        }
    }
    let branch = (!bases.is_empty()).then(|| {
        let sum = |f: fn(&Tally) -> u64| bases.values().map(f).sum::<u64>();
        let mut b = json!({
            "points": sum(|t| t.points),
            "tried": sum(|t| t.tried),
            "seeds": bases.iter().map(|((s, c), t)| json!({"seed": s, "case": c, "points": t.points, "tried": t.tried})).collect::<Vec<_>>(),
        });
        if !per_node.is_empty() {
            b["nodes"] = per_node
                .iter()
                .map(|(n, t)| json!({"node": n, "points": t.points, "tried": t.tried}))
                .collect();
        }
        if pairs > 0 || pairs_tried > 0 {
            b["pairs"] = json!({"pairs": pairs, "tried": pairs_tried});
        }
        b
    });
    let no_points = branch.as_ref().is_some_and(|b| b["points"] == 0);
    // The check: what the checker said of each run it ran after (`check.verdict`).
    let mut check = (0u64, 0u64, 0u64, 0u64); // passed, failed, not judged, errors
    let mut not_judged: BTreeMap<String, u64> = BTreeMap::new();
    let mut checked = false;
    for r in runs {
        checked |= !r.run["config"]["check"].is_null();
        let c = &r.result["check"];
        match c["verdict"].as_str() {
            Some("pass") => check.0 += 1,
            Some("fail") => check.1 += 1,
            Some("not-judged") => {
                check.2 += 1;
                *not_judged
                    .entry(skip_class(c["detail"].as_str().unwrap_or("")))
                    .or_default() += 1;
            }
            Some("error" | "pending") => check.3 += 1,
            _ => {}
        }
    }
    let judged_none = checked && check.0 + check.1 == 0 && !allow.contains("check");
    // The checkers that judged these runs (`run.json`), each with its runs: more than one, and
    // the verdicts are not one checker's (a recheck that could not judge pruned runs).
    let mut checkers: Vec<(Value, usize)> = vec![];
    for r in runs {
        let k = &r.run["config"]["check"];
        if k.is_null() || r.result["check"].is_null() {
            continue;
        }
        match checkers
            .iter_mut()
            .find(|(c, _)| crate::recheck::same_checker(c, k))
        {
            Some(c) => c.1 += 1,
            None => checkers.push((k.clone(), 1)),
        }
    }
    // Known entries: the runs each ID labels; one that must appear and did not.
    let mut known_counts: Vec<(String, bool, usize)> = vec![];
    if let Some(k) = known {
        for (id, required) in k.ids() {
            let n = groups
                .iter()
                .filter(|g| g.known.as_deref() == Some(id))
                .map(|g| g.runs.len())
                .sum();
            known_counts.push((id.to_string(), required, n));
        }
    }
    let missing_required: Vec<&str> = known_counts
        .iter()
        .filter(|(_, req, n)| *req && *n == 0)
        .map(|(id, _, _)| id.as_str())
        .collect();
    let vacuous = runs.is_empty()
        || no_points
        || !never_held.is_empty()
        || !never_hit.is_empty()
        || !never_fired.is_empty()
        || !idle.is_empty()
        || judged_none
        || !missing_required.is_empty();

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
                // A finding its checker does not repeat is not evidence about the program.
                Some(v) if v["result"] == "check-unstable" => "error".to_string(),
                // Nor is one whose mounted inputs changed before its replay.
                Some(v) if v["result"] == "inputs-changed" => "error".to_string(),
                _ => outcome.clone(),
            };
            let classes: Vec<_> = g.runs.iter().map(|r| fault_classes(&r.result).1).collect();
            let every: BTreeSet<String> = classes
                .iter()
                .skip(1)
                .fold(classes[0].clone(), |a, b| &a & b);
            let any: BTreeSet<String> = classes.iter().flatten().cloned().collect();
            let none: Vec<&String> = configured.difference(&any).collect();
            let mut cases: Vec<&String> = g.runs.iter().filter_map(|r| r.case.as_ref()).collect();
            cases.sort();
            cases.dedup();
            json!({
                "signature": g.signature,
                "outcome": effective,
                "run_outcome": outcome,
                "stop": first.result["stop"],
                "known": g.known,
                // The group's case when it has one; `null` for a group over several (`cases`).
                "case": (cases.len() == 1).then(|| cases[0]),
                "cases": cases,
                "count": g.runs.len(),
                "seeds": g.runs.iter().map(|r| r.seed).collect::<Vec<_>>(),
                "runs": g.runs.iter().map(|r| r.at(true)).collect::<Vec<_>>(),
                "first": first.at(true),
                "example": example(&g.signature, &first.result, &first.dir),
                "replay": replay,
                "faults": {"every": every, "none": none},
                "nodes": node_causes(&g.runs),
                "rerun": rerun_command(&first.run, first.seed, &first.dir),
                "replay_command": format!("patina replay {}", quote(&first.dir.display().to_string())),
            })
        })
        .collect();
    gj.sort_by_key(|g| {
        let o = outcome_of(g["outcome"].as_str().unwrap_or(""));
        (
            !g["known"].is_null(),
            o.exit() != 1,
            o,
            std::cmp::Reverse(g["count"].as_u64().unwrap_or(0)),
            g["first"]["seed"].as_u64().unwrap_or(0),
            g["first"]["point"].as_u64().unwrap_or(0),
        )
    });
    // A new finding fails; a known one does not. What is neither ok nor a finding (and a
    // finding whose replay differed) is exit 2, known or not.
    let finding = gj.iter().any(|g| {
        g["known"].is_null() && outcome_of(g["outcome"].as_str().unwrap_or("")).exit() == 1
    });
    let not_ok = gj
        .iter()
        .any(|g| outcome_of(g["outcome"].as_str().unwrap_or("")).exit() == 2);
    // Runs whose operation-log self-check failed: a Patina defect, reported beside the
    // outcomes (each stays its program's own) and never passed as clean.
    let mut defects: Vec<&Run> = runs
        .iter()
        .filter(|r| crate::result::self_check_failed(&r.result))
        .collect();
    defects.sort_by_key(|r| (r.seed, r.point.clone(), r.case_pos, r.dir.clone()));
    let exit = if finding {
        1
    } else if not_ok || vacuous || !defects.is_empty() {
        2
    } else {
        0
    };
    let findings = runs
        .iter()
        .filter(|r| outcome_of(r.result["outcome"].as_str().unwrap_or("")).exit() == 1)
        .count();
    // The summary's findings are what fails: a known finding is counted apart.
    let finding_groups = gj
        .iter()
        .filter(|g| {
            g["known"].is_null() && outcome_of(g["run_outcome"].as_str().unwrap_or("")).exit() == 1
        })
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
            "buggify_unfired_noted": noted_unfired,
            "always_never_evaluated": never_evaluated,
            // Every site: in how many runs it was evaluated, and held (a `reachable` hit, a
            // point fired).
            "sites": site_runs.iter().map(|((k, l), (e, h))| json!({"kind": k, "label": l, "runs_evaluated": e, "runs_held": h})).collect::<Vec<_>>(),
        },
        "faults": {"configured": configured, "eligible_zero": idle, "not_applicable": not_applicable},
        "compute_stall": stalls,
        "missing": missing,
        "host_limits": limits,
        "allow_unmet": allow,
        "allowed_unmet": allowed_unmet,
        "allow_unmet_unmatched": unmatched_allow,
        "vacuous": vacuous,
        "exit": exit,
    });
    if let Some(b) = branch {
        v["crash_points"] = b;
    }
    if let Some(first) = defects.first() {
        v["self_check_failed"] = json!({
            "runs": defects.len(),
            "first": first.at(false),
            "detail": first.result["self_check"]["detail"],
            "replay_command": format!("patina replay {}", quote(&first.dir.display().to_string())),
        });
    }
    if checked {
        // Nothing shows that the check can fail: it judged runs, passed every one, and no
        // `!ID` entry requires a finding. Said, not failed: `!ID` is how to make it a failure.
        let required = known.is_some_and(|k| k.ids().iter().any(|(_, r)| *r));
        v["check"] = json!({
            "judged": check.0 + check.1,
            "passed": check.0,
            "failed": check.1,
            "not_judged": not_judged,
            "errors": check.3,
            "checkers": checkers.iter().map(|(k, n)| json!({"words": k["words"], "program": k["program"], "sha256": k["sha256"], "runs": n})).collect::<Vec<_>>(),
            "vacuous": judged_none,
            "unproven": check.0 > 0 && check.1 == 0 && !required,
        });
    }
    if let Some(k) = known {
        let matched: usize = known_counts.iter().map(|e| e.2).sum();
        v["known"] = json!({
            "file": k.file,
            "findings": matched,
            "new": findings - matched,
            "entries": known_counts.iter().map(|(id, req, n)| {
                let mut e = json!({"id": id, "required": req, "count": n});
                if *n == 0 {
                    if let Some(near) = k.near_miss(id, runs) {
                        e["near"] = near.into();
                    }
                }
                e
            }).collect::<Vec<_>>(),
            "required_unseen": missing_required,
        });
    }
    // The ok runs that are clean failures (`--ok-exit`), counted apart from the passes: a
    // sweep where every run failed cleanly says so.
    let ok_exit = runs
        .iter()
        .filter(|r| r.result["outcome"] == "ok" && r.result["stop"] == "ok-exit")
        .count();
    if ok_exit > 0 {
        v["ok_exit"] = ok_exit.into();
    }
    if with_plans > 0 {
        v["rewrite"] = json!({
            "runs": with_plans,
            "points": taken,
            "images": planned.iter().map(|(p, k)| json!({"path": p, "planned": k})).collect::<Vec<_>>(),
        });
    }
    // Runs with nodes: their names, and what the scripted network did over them.
    let with_nodes: Vec<&Value> = runs
        .iter()
        .map(|r| &r.result["nodes"])
        .filter(|n| n.is_object())
        .collect();
    if !with_nodes.is_empty() {
        let mut names: Vec<String> = vec![];
        for n in &with_nodes {
            for m in n["list"].as_array().into_iter().flatten() {
                if let Some(x) = m["name"].as_str().filter(|x| !names.iter().any(|y| y == x)) {
                    names.push(x.to_string());
                }
            }
        }
        let sum = |k: &str| -> u64 {
            with_nodes
                .iter()
                .map(|n| n["net"][k].as_u64().unwrap_or(0))
                .sum()
        };
        // The seed's partitions: drawn, those that acted on traffic, and the shapes drawn.
        let mut shapes = serde_json::Map::new();
        let (mut drawn, mut acted) = (0u64, 0u64);
        for n in &with_nodes {
            drawn += n["partitions_drawn"].as_u64().unwrap_or(0);
            acted += n["partitions_acted"].as_u64().unwrap_or(0);
            for p in n["partitions"].as_array().into_iter().flatten() {
                let k = p["shape"].as_str().unwrap_or("?").to_string();
                let c = shapes.get(&k).and_then(|c| c.as_u64()).unwrap_or(0);
                shapes.insert(k, json!(c + 1));
            }
        }
        v["nodes"] = json!({
            "runs": with_nodes.len(),
            "names": names,
            "cuts": sum("cuts"),
            "heals": sum("heals"),
            "held": sum("held"),
        });
        if drawn > 0 {
            v["nodes"]["partitions"] = json!({"drawn": drawn, "acted": acted, "shapes": shapes});
        }
        // Each time a node went down, by how (`result.json`'s `downs`), and its restarts.
        let mut downs = serde_json::Map::new();
        let mut restarts = 0u64;
        for n in &with_nodes {
            for m in n["list"].as_array().into_iter().flatten() {
                restarts += m["incarnations"].as_u64().unwrap_or(1).saturating_sub(1);
                for d in m["downs"].as_array().into_iter().flatten() {
                    let k = d["how"].as_str().unwrap_or("?").to_string();
                    let c = downs.get(&k).and_then(|c| c.as_u64()).unwrap_or(0);
                    downs.insert(k, json!(c + 1));
                }
            }
        }
        if !downs.is_empty() {
            v["nodes"]["downs"] = json!(downs);
            v["nodes"]["restarts"] = json!(restarts);
        }
        // Pauses (by who made them) and the virtual time paused; clock steps, and the largest
        // offset a node's clock had at the end.
        let (mut pauses, mut paused_ms) = (serde_json::Map::new(), 0u64);
        let (mut steps, mut skew_max) = (0u64, None::<i64>);
        for n in &with_nodes {
            for m in n["list"].as_array().into_iter().flatten() {
                for p in m["pause"].as_array().into_iter().flatten() {
                    let k = p["by"].as_str().unwrap_or("?").to_string();
                    let c = pauses.get(&k).and_then(|c| c.as_u64()).unwrap_or(0);
                    pauses.insert(k, json!(c + 1));
                }
                paused_ms += m["paused_ms"].as_u64().unwrap_or(0);
                steps += m["clock"]["steps"].as_u64().unwrap_or(0);
                for s in m["clock"]["skew_ms"].as_array().into_iter().flatten() {
                    let s = s.as_i64().unwrap_or(0).abs();
                    skew_max = Some(skew_max.map_or(s, |m| m.max(s)));
                }
            }
        }
        if !pauses.is_empty() {
            v["nodes"]["pauses"] = json!({"by": pauses, "paused_ms": paused_ms});
        }
        if steps > 0 || skew_max.is_some() {
            v["nodes"]["clock"] = json!({"steps": steps, "skew_max_ms": skew_max});
        }
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
    let text = render(&v, finding_groups, head.as_ref(), again);
    (v, text)
}

/// With nodes: what happened to each node in a group's runs: in how many it went down, in how
/// many a crash of its machine lost something on its disk (`downs[].lost`), and the crash
/// points it crashed at (a `--crash-points` sweep's children and `machine:P` runs); and in how many a
/// partition was in force at the end. `null` without nodes.
fn node_causes(runs: &[&Run]) -> Value {
    let Some(list) = runs[0].result["nodes"]["list"].as_array() else {
        return Value::Null;
    };
    let nodes: Vec<Value> = list
        .iter()
        .filter_map(|n| n["name"].as_str())
        .filter(|n| *n != "driver")
        .map(|name| {
            let (mut down, mut lost, mut points) = (0, 0, BTreeSet::new());
            for r in runs {
                let Some(n) = r.result["nodes"]["list"]
                    .as_array()
                    .and_then(|l| l.iter().find(|x| x["name"] == name))
                else {
                    continue;
                };
                let downs = n["downs"].as_array().map(Vec::as_slice).unwrap_or(&[]);
                down += usize::from(!downs.is_empty());
                lost += usize::from(downs.iter().any(|d| {
                    d["lost"]["missing"].as_u64().unwrap_or(0)
                        + d["lost"]["changed"].as_u64().unwrap_or(0)
                        > 0
                }));
                points.extend(downs.iter().filter_map(|d| d["point"].as_u64()));
            }
            json!({"node": name, "down": down, "lost": lost, "points": points})
        })
        .collect();
    let partitioned = runs
        .iter()
        .filter(|r| {
            r.result["nodes"]["partitions"]
                .as_array()
                .and_then(|p| p.last())
                .is_some_and(|p| p["to_ms"].is_null())
        })
        .count();
    json!({"list": nodes, "partitioned_at_end": partitioned})
}

/// `nodes: b down in 10 (lost on its disk in 10; crash points 1, 2), a down in 0`, and the
/// runs that ended partitioned; `None` when no node went down and none did.
fn node_causes_line(g: &Value) -> Option<String> {
    let n = &g["nodes"];
    let list = n["list"].as_array()?;
    let part = n["partitioned_at_end"].as_u64().unwrap_or(0);
    if part == 0 && list.iter().all(|x| x["down"] == 0) {
        return None;
    }
    let mut each: Vec<String> = list
        .iter()
        .map(|x| {
            let mut why = vec![];
            if x["lost"].as_u64().unwrap_or(0) > 0 {
                why.push(format!("lost on its disk in {}", x["lost"]));
            }
            let pts: Vec<String> = x["points"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| p.to_string())
                .collect();
            if !pts.is_empty() {
                why.push(format!("crash points {}", pts.join(", ")));
            }
            let why = if why.is_empty() {
                String::new()
            } else {
                format!(" ({})", why.join("; "))
            };
            format!(
                "{} down in {}{why}",
                x["node"].as_str().unwrap_or(""),
                x["down"]
            )
        })
        .collect();
    if part > 0 {
        each.push(format!("partitioned at the end in {part}"));
    }
    Some(format!("  nodes: {}\n", each.join(", ")))
}

/// Groups a report prints in full; the others get one line (`patina report --group N`).
const GROUPS_SHOWN: usize = 3;

/// A group's name: `[CASE] SIGNATURE` for a group of one case, after the effective outcome
/// when its replay changed it.
fn group_name(g: &Value) -> String {
    let st = |k: &str| g[k].as_str().unwrap_or("").to_string();
    let mut name = st("signature");
    if let Some(c) = g["case"].as_str() {
        name = format!("[{c}] {name}");
    }
    if g["outcome"] != g["run_outcome"] {
        name = format!("{}: {name}", st("outcome"));
    }
    name
}

/// `K of R runs, C cases   first: seed S [CASE]   replayed: RESULT`.
fn group_runs(g: &Value, runs: u64) -> String {
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
    let cases = g["cases"].as_array().map_or(0, |c| c.len());
    let id = g["first"]["case_id"]
        .as_str()
        .map(|i| format!(", case {i}"))
        .unwrap_or_default();
    let (of_cases, first_case) = match (cases, g["first"]["case"].as_str()) {
        (k, Some(c)) if k > 1 => (format!(", {k} cases"), format!("{id} [{c}]")),
        _ => (String::new(), id),
    };
    format!(
        "{} of {runs} runs{of_cases}   first: seed {}{first_case}   {replay}",
        g["count"],
        run_name(
            g["first"]["seed"].as_u64().unwrap_or(0),
            Point::of(&g["first"]).as_ref()
        )
    )
}

/// A group in full: its name, runs, the faults in its runs, the rerun and replay commands.
fn group_text(g: &Value, runs: u64, faulted: bool) -> String {
    let st = |k: &str| g[k].as_str().unwrap_or("").to_string();
    let mut s = format!("{}\n  {}\n", group_name(g), group_runs(g, runs));
    if let Some(e) = g["example"].as_str() {
        s.push_str(&format!("  example: {e}\n"));
    }
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
    if faulted {
        s.push_str(&format!(
            "  faults in every failing run: {}      in none: {}\n",
            list("every"),
            list("none")
        ));
    }
    if let Some(l) = node_causes_line(g) {
        s.push_str(&l);
    }
    s.push_str(&format!("  rerun:  {}\n", st("rerun")));
    s.push_str(&format!("  replay: {}\n", st("replay_command")));
    s.push_str(&format!(
        "  explain: patina explain {}\n",
        quote(g["first"]["dir"].as_str().unwrap_or(""))
    ));
    s
}

/// `patina report --group N`: group N of a report (its position in `report.json`'s `groups`,
/// from 1) in full, or as JSON.
pub fn group(v: &Value, n: usize, json: bool) -> Res<String> {
    let groups = v["groups"].as_array().unwrap();
    let g = n
        .checked_sub(1)
        .and_then(|i| groups.get(i))
        .ok_or_else(|| {
            format!(
                "--group {n}: the report has {}",
                count(groups.len(), "group")
            )
        })?;
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(g).unwrap()));
    }
    let faulted = !v["faults"]["configured"].as_array().unwrap().is_empty();
    let mut s = group_text(g, v["runs"].as_u64().unwrap_or(0), faulted);
    if let Some(id) = g["known"].as_str() {
        s = format!("known {id}: {s}");
    }
    Ok(s)
}

fn render(v: &Value, finding_groups: usize, head: Option<&SweepHead>, again: &str) -> String {
    let n = |k: &str| v[k].as_u64().unwrap_or(0);
    let ok = v["outcomes"]["ok"].as_u64().unwrap_or(0);
    let ok_exit = match n("ok_exit") {
        0 => String::new(),
        k => format!(" ({k} by --ok-exit)"),
    };
    let known = v["known"]["findings"].as_u64().unwrap_or(0);
    let what = format!(
        "{}, {} in {}{}, {} ok{ok_exit}",
        count(n("runs") as usize, "run"),
        count((n("findings") - known) as usize, "finding"),
        count(finding_groups, "group"),
        if known > 0 {
            format!(", {known} known")
        } else {
            String::new()
        },
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
    if let Some(d) = v.get("self_check_failed") {
        let f = &d["first"];
        let at = run_name(f["seed"].as_u64().unwrap_or(0), Point::of(f).as_ref());
        s.push_str(&format!(
            "self-check failed in {} (a Patina defect; the outcomes are the programs' own): first seed {at}: {}\n  replay: {}\n",
            count(d["runs"].as_u64().unwrap_or(0) as usize, "run"),
            d["detail"].as_str().unwrap_or(""),
            d["replay_command"].as_str().unwrap_or("")
        ));
    }
    if let Some(c) = v.get("check") {
        let judged = c["judged"].as_u64().unwrap_or(0);
        let mut line = format!(
            "check: judged {judged} of {}: {} passed, {} failed",
            count(n("runs") as usize, "run"),
            c["passed"],
            c["failed"]
        );
        let nj = c["not_judged"].as_object().unwrap();
        if !nj.is_empty() {
            let mut why: Vec<(&String, u64)> = nj
                .iter()
                .map(|(k, n)| (k, n.as_u64().unwrap_or(0)))
                .collect();
            why.sort_by_key(|(k, n)| (std::cmp::Reverse(*n), (*k).clone()));
            let total: u64 = why.iter().map(|w| w.1).sum();
            let mut shown: Vec<String> = why
                .iter()
                .take(REASONS_SHOWN)
                .map(|(k, n)| format!("{} {n}", if k.is_empty() { "no reason given" } else { k }))
                .collect();
            if why.len() > REASONS_SHOWN {
                let rest = &why[REASONS_SHOWN..];
                shown.push(format!(
                    "{} more in {} {}",
                    rest.iter().map(|w| w.1).sum::<u64>(),
                    rest.len(),
                    if rest.len() == 1 { "class" } else { "classes" }
                ));
            }
            line.push_str(&format!("; {total} not judged ({})", shown.join(", ")));
        }
        if c["errors"].as_u64().unwrap_or(0) > 0 {
            line.push_str(&format!("; {} errors", c["errors"]));
        }
        s.push_str(&format!("{line}\n"));
        let checkers = c["checkers"].as_array().map_or(0, |k| k.len());
        if checkers > 1 {
            s.push_str(&format!(
                "check: these verdicts are of {checkers} checkers (check.checkers in {}): patina report --recheck judges them again with one\n",
                if head.is_some() { "report.json" } else { "--format json" }
            ));
        }
        if c["unproven"] == true {
            s.push_str("check: every judged run passed and no --known !ID entry shows that this check can fail\n");
        }
    }
    if let Some(k) = v.get("known") {
        let matched = k["findings"].as_u64().unwrap_or(0);
        let by_id: Vec<String> = k["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["count"].as_u64().unwrap_or(0) > 0)
            .map(|e| format!("{} {}", e["id"].as_str().unwrap_or(""), e["count"]))
            .collect();
        let new_groups = v["groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|g| g["known"].is_null() && is_finding(g["run_outcome"].as_str().unwrap_or("")))
            .count();
        s.push_str(&format!(
            "known: {}{}; {}\n",
            count(matched as usize, "run"),
            if by_id.is_empty() {
                String::new()
            } else {
                format!(" ({})", by_id.join(", "))
            },
            match new_groups {
                0 => "none new".to_string(),
                g => format!(
                    "{} new, in {}",
                    k["new"].as_u64().unwrap_or(0),
                    count(g, "group")
                ),
            }
        ));
    }
    if let Some(b) = v.get("crash_points") {
        let (p, t) = (
            b["points"].as_u64().unwrap_or(0),
            b["tried"].as_u64().unwrap_or(0),
        );
        // With nodes: each node's points and children (`b 120 of 120`).
        let nodes: Vec<String> = b["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|n| {
                format!(
                    "{} {} of {}",
                    n["node"].as_str().unwrap_or(""),
                    n["tried"],
                    n["points"]
                )
            })
            .collect();
        s.push_str(&format!(
            "crash points: {t} of {p} tried{}\n",
            if nodes.is_empty() {
                String::new()
            } else {
                format!(" ({})", nodes.join(", "))
            }
        ));
        if let Some(x) = b.get("pairs") {
            s.push_str(&format!(
                "crash pairs: {} of {} tried (a second node's crash after a first)\n",
                x["tried"], x["pairs"]
            ));
        }
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
    // Load-time points are the default: their line only when a file went without a plan.
    if let Some(w) = v.get("rewrite").filter(|w| {
        w["images"]
            .as_array()
            .is_some_and(|a| a.iter().any(|i| i["planned"] != true))
    }) {
        let images = w["images"].as_array().map_or(&[][..], |a| &a[..]);
        let planned = images.iter().filter(|i| i["planned"] == true).count();
        s.push_str(&format!(
            "load-time points: {} taken in {} runs; {} of {} files rewritten",
            w["points"],
            w["runs"],
            planned,
            images.len()
        ));
        let none: Vec<&str> = images
            .iter()
            .filter(|i| i["planned"] != true)
            .filter_map(|i| i["path"].as_str())
            .map(|p| p.rsplit('/').next().unwrap_or(p))
            .take(crate::result::IMAGES_SHOWN)
            .collect();
        if !none.is_empty() {
            s.push_str(&format!(
                " (without a plan, so switching only at system calls: {}{})",
                none.join(", "),
                if images.len() - planned > none.len() {
                    ", ..."
                } else {
                    ""
                }
            ));
        }
        s.push('\n');
    }
    if let Some(w) = v.get("nodes") {
        let names: Vec<&str> = w["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str())
            .collect();
        s.push_str(&format!(
            "nodes: {} in {} runs; net: {} cuts, {} heals, {} held over them\n",
            names.join(", "),
            w["runs"],
            w["cuts"],
            w["heals"],
            w["held"]
        ));
        let p = &w["partitions"];
        if p.is_object() {
            let shapes: Vec<String> = p["shapes"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, n)| format!("{n} {k}"))
                .collect();
            s.push_str(&format!(
                "partitions: {} drawn ({}), {} acted on traffic\n",
                p["drawn"],
                shapes.join(", "),
                p["acted"]
            ));
        }
        if let Some(d) = w["downs"].as_object() {
            let hows: Vec<String> = d.iter().map(|(k, n)| format!("{n} {k}")).collect();
            s.push_str(&format!(
                "node downs: {}; {} restarts\n",
                hows.join(", "),
                w["restarts"]
            ));
        }
        if let Some(p) = w["pauses"]["by"].as_object() {
            let by: Vec<String> = p.iter().map(|(k, n)| format!("{n} by {k}")).collect();
            s.push_str(&format!(
                "node pauses: {}; {} ms paused\n",
                by.join(", "),
                w["pauses"]["paused_ms"]
            ));
        }
        if w["clock"].is_object() {
            let c = &w["clock"];
            let skew = c["skew_max_ms"]
                .as_i64()
                .map(|m| format!("skews up to {m} ms"))
                .unwrap_or_else(|| "no skew".into());
            s.push_str(&format!("node clocks: {skew}; {} steps\n", c["steps"]));
        }
    }
    let groups = v["groups"].as_array().unwrap();
    let faulted = !v["faults"]["configured"].as_array().unwrap().is_empty();
    // The first few groups in full; the others one line each, numbered for `--group N`.
    let new: Vec<(usize, &Value)> = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g["known"].is_null())
        .collect();
    for (_, g) in new.iter().take(GROUPS_SHOWN) {
        s.push('\n');
        s.push_str(&group_text(g, n("runs"), faulted));
    }
    if new.len() > GROUPS_SHOWN {
        s.push('\n');
        for (i, g) in &new[GROUPS_SHOWN..] {
            s.push_str(&format!(
                "#{} {}   {}\n",
                i + 1,
                group_name(g),
                group_runs(g, n("runs"))
            ));
        }
        s.push_str(&format!("(a group in full: {again})\n"));
    }
    // Known groups: one line each, after the new ones.
    let known: Vec<&Value> = groups.iter().filter(|g| !g["known"].is_null()).collect();
    if !known.is_empty() {
        s.push('\n');
    }
    for g in known {
        let cases = g["cases"].as_array().map_or(0, |c| c.len());
        s.push_str(&format!(
            "known {}: {}   ({}{})\n",
            g["known"].as_str().unwrap_or(""),
            g["signature"].as_str().unwrap_or(""),
            count(g["count"].as_u64().unwrap_or(0) as usize, "run"),
            if cases > 1 {
                format!(", {cases} cases")
            } else {
                String::new()
            }
        ));
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
    let noted = v["sdk"]["buggify_unfired_noted"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !noted.is_empty() {
        let l: Vec<String> = noted
            .iter()
            .take(LABELS_SHOWN)
            .map(|x| {
                let label = x["label"].as_str().unwrap_or("");
                match x["evaluated"].as_u64().unwrap_or(0) {
                    0 => format!("{label} (not reached)"),
                    e => format!(
                        "{label} ({}, {:.0}% chance to miss)",
                        count(e as usize, "evaluation"),
                        x["chance"].as_f64().unwrap_or(1.0) * 100.0
                    ),
                }
            })
            .collect();
        let more = noted.len().saturating_sub(LABELS_SHOWN);
        tail.push(format!(
            "sdk: `buggify` never fired, too few runs to tell from chance: {}{}",
            l.join(", "),
            if more > 0 {
                format!(", and {more} more ({full})")
            } else {
                String::new()
            }
        ));
    }
    // Unmet sites a pattern allowed: one line, by the pattern that allowed them, so that a
    // pattern as wide as '*' is seen hiding what it hides.
    let allowed_unmet = names(&v["allowed_unmet"]);
    if !allowed_unmet.is_empty() {
        let pats = names(&v["allow_unmet"]);
        let mut by: Vec<(String, usize)> = vec![];
        for l in &allowed_unmet {
            if let Some(p) = pats.iter().find(|p| glob(p, l)) {
                match by.iter_mut().find(|(q, _)| q == p) {
                    Some(x) => x.1 += 1,
                    None => by.push((p.clone(), 1)),
                }
            }
        }
        by.sort_by_key(|(p, n)| (std::cmp::Reverse(*n), p.clone()));
        // An exact label allows itself only: its count says nothing.
        let by: Vec<String> = by
            .iter()
            .map(|(p, n)| match p.contains('*') {
                true => format!("{} {n}", quote(p)),
                false => quote(p),
            })
            .collect();
        tail.push(format!(
            "sdk: {} unmet, allowed by --allow-unmet ({}; {full}: allowed_unmet)",
            count(allowed_unmet.len(), "site"),
            by.join(", ")
        ));
    }
    for p in names(&v["allow_unmet_unmatched"]) {
        tail.push(format!(
            "allow-unmet: {} matches no SDK label, fault class or check of these runs (an unquoted * the shell expanded?)",
            quote(&p)
        ));
    }
    for c in names(&v["faults"]["eligible_zero"]) {
        tail.push(format!("faults: {c} eligible 0 times: nothing to act on"));
    }
    let na = names(&v["faults"]["not_applicable"]);
    if !na.is_empty() {
        tail.push(format!(
            "faults: not applicable (a class's, nothing to act on in any run): {}",
            na.join(", ")
        ));
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
    if let Some(k) = v.get("known") {
        let mut unmatched = 0;
        for e in k["entries"].as_array().unwrap() {
            if e["count"] != 0 {
                continue;
            }
            let id = e["id"].as_str().unwrap_or("");
            if let Some(near) = e["near"].as_str() {
                tail.push(format!(
                    "known: {id} matched no run; with its numbers written as the signature writes them it matches {near:?} (an exit status keeps its digits, other numbers are N)"
                ));
            }
            if e["required"] == true {
                tail.push(format!(
                    "vacuous: known !{id} matched no run: the check may be unable to fail"
                ));
            } else if e["near"].is_null() {
                unmatched += 1;
            }
        }
        if unmatched > 0 {
            tail.push(format!(
                "known: {unmatched} {} matched no run ({full}: known.entries)",
                if unmatched == 1 { "entry" } else { "entries" }
            ));
        }
    }
    if v["check"]["vacuous"] == true {
        tail.push(
            "vacuous: the check judged no run (allow it with --allow-unmet check)".to_string(),
        );
    }
    let unmet = [
        "sometimes_never_held",
        "reachable_never_hit",
        "buggify_never_fired",
    ]
    .iter()
    .any(|k| !names(&v["sdk"][*k]).is_empty())
        || !names(&v["faults"]["eligible_zero"]).is_empty();
    if v["vacuous"] == true {
        if n("runs") == 0 {
            tail.push("vacuous: no runs".to_string());
        } else if v["crash_points"]["points"] == 0 {
            tail.push("vacuous: no base has a crash point: nothing under the work tree changed, nothing to branch at".to_string());
        } else if unmet {
            let labels: Vec<String> = [
                "sometimes_never_held",
                "reachable_never_hit",
                "buggify_never_fired",
            ]
            .iter()
            .flat_map(|k| names(&v["sdk"][*k]))
            .collect();
            let hint = match shared_prefix(&labels) {
                Some((p, n)) => format!(
                    "; {n} of these labels start {p:?}, a library's perhaps: allow them once in patina.toml, [sweep] allow-unmet = [\"{p}*\"]"
                ),
                None => String::new(),
            };
            tail.push(format!(
                "vacuous: see above (allow a label with --allow-unmet or [sweep] allow-unmet{hint})"
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_label_is_a_portable_name_and_reads_back() {
        // What GitHub's artifact upload refuses in a path, and what Windows file systems do.
        let bad = |s: &str| s.contains(['"', ':', '<', '>', '|', '*', '?', '\\', '\r', '\n']);
        for p in [
            Point::child(12, ""),
            Point::child(12, "b"),
            Point::child(3, "db-1"),
            Point::child(3, "a").then(40, "db-1"),
        ] {
            let l = p.label();
            assert!(!bad(&l), "{l}");
            assert_eq!(Point::parse(&l), Some(p));
        }
        assert_eq!(Point::parse("0"), None);
        assert_eq!(Point::parse("b.x"), None);
        assert_eq!(Point::parse("a.3+a.4"), None);
        assert_eq!(Point::parse("3+b.4"), None);
    }

    #[test]
    fn a_star_matches_any_text_and_the_rest_matches_whole() {
        assert!(glob("abc", "abc") && !glob("abc", "abcd") && !glob("abc", "xabc"));
        assert!(glob("*", "") && glob("*", "anything"));
        assert!(glob("lib-*", "lib-a") && !glob("lib-*", "app-lib-a"));
        assert!(glob("*-x-*", "a-x-b") && !glob("*-x-*", "a-x"));
        assert!(glob("a*b*c", "abc") && glob("a*b*c", "a1b2c") && !glob("a*b*c", "acb"));
        // A literal end is not matched twice.
        assert!(!glob("a*a", "a") && glob("a*a", "aa"));
    }

    fn known(text: &str) -> Known {
        let f = std::env::temp_dir().join(format!(
            "patina-known-{}-{}",
            std::process::id(),
            text.len()
        ));
        std::fs::write(&f, text).unwrap();
        let k = Known::read(&f);
        std::fs::remove_file(&f).unwrap();
        k.unwrap()
    }

    /// A finding's result: its signature and the fault classes that fired.
    fn res(signature: &str, fired: &[&str]) -> Value {
        let counts: serde_json::Map<String, Value> = ["fs-error", "crash"]
            .iter()
            .map(|c| {
                (
                    c.to_string(),
                    json!({"eligible": 9, "injected": fired.contains(c) as u64}),
                )
            })
            .collect();
        json!({"outcome": "violation", "signature": signature, "faults": {"counts": counts}})
    }

    #[test]
    fn the_first_matching_line_names_a_finding() {
        let sub = res("violation check: wrong-sub: N", &[]);
        let k = known("# known\nwide violation check: *\nnarrow violation check: wrong-sub*\n");
        assert_eq!(k.id_of(None, &sub), Some("wide"));
        let k = known("narrow violation check: wrong-sub*\nwide violation check: *\n");
        assert_eq!(k.id_of(None, &sub), Some("narrow"));
        assert_eq!(k.id_of(None, &res("failure exit: exit N", &[])), None);
    }

    #[test]
    fn a_bracketed_pattern_selects_by_case() {
        let x = res("violation check: x", &[]);
        let k = known("p [*planted*] violation *\nany violation *\n");
        assert_eq!(k.id_of(Some("t planted 2"), &x), Some("p"));
        assert_eq!(k.id_of(Some("t add 2"), &x), Some("any"));
        // Without a bracket the signature alone is matched, with or without a case.
        assert_eq!(k.id_of(None, &x), Some("any"));
    }

    #[test]
    fn a_pattern_with_faults_selects_by_what_fired() {
        let k = known(
            "err violation check: SILENT: * {faults: *fs-error*}\n\
             calm [*vmstat*] violation check: SILENT: * {faults: -}\n\
             any violation check: SILENT: *\n",
        );
        let silent = |f: &[&str]| res("violation check: SILENT: wrote nothing", f);
        assert_eq!(k.id_of(None, &silent(&["crash", "fs-error"])), Some("err"));
        assert_eq!(k.id_of(Some("x vmstat"), &silent(&[])), Some("calm"));
        assert_eq!(k.id_of(Some("x vmstat"), &silent(&["crash"])), Some("any"));
        assert_eq!(k.id_of(Some("x ls"), &silent(&[])), Some("any"));
        let mut r = silent(&[]);
        r["sdk"] = json!({"sites": [{"kind": "buggify", "label": "drop", "held": 2}]});
        assert_eq!(fired(&r), vec!["buggify:drop".to_string()]);
    }

    #[test]
    fn reasons_count_by_class_and_findings_show_as_written() {
        assert_eq!(skip_class("no-ref: case 17 has none"), "no-ref");
        assert_eq!(
            skip_class("no-ref: case 17 has none"),
            skip_class("no-ref: case 3 has none")
        );
        // No class: the reason, its numbers collapsed, as before.
        assert_eq!(
            skip_class("no crash in run 3"),
            skip_class("no crash in run 4")
        );
        let v = |m: &str| json!({"outcome": "violation", "stop": "check", "message": m});
        assert_eq!(
            example(
                "violation check: w [k]",
                &v("w [k]: got 0x0"),
                Path::new("/")
            ),
            json!("w [k]: got 0x0")
        );
        assert_eq!(
            example("violation check: w: x", &v("w: x"), Path::new("/")),
            Value::Null
        );
        assert_eq!(
            example(
                "failure exit: exit 1",
                &json!({"outcome": "failure", "message": "m"}),
                Path::new("/nonexistent")
            ),
            Value::Null
        );
        let l = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            shared_prefix(&l(&["lib-a", "lib-b", "app-c"])),
            Some(("lib-".into(), 2))
        );
        assert_eq!(shared_prefix(&l(&["lib-a", "app-c"])), None);
    }

    /// An ok run with its `run.json` config and `result.json` fields.
    fn run(seed: u64, config: Value, result: Value) -> Run {
        let mut r = json!({"outcome": "ok", "seed": seed});
        r.as_object_mut()
            .unwrap()
            .extend(result.as_object().unwrap().clone());
        Run {
            dir: PathBuf::from(format!("/nonexistent/seed-{seed}")),
            seed,
            case: None,
            case_id: None,
            case_pos: None,
            result: r,
            run: json!({"config": config, "faults": {}}),
            replay: None,
            point: None,
        }
    }

    #[test]
    fn a_failed_self_check_is_reported_beside_the_outcomes() {
        let failed = json!({"self_check": {"verdict": "fail", "detail": "d"}});
        let report = |r: &[Run]| build(r, &[], None, None, "").0;
        // An ok run whose self-check failed stays ok, and the report is not clean.
        let v = report(&[
            run(1, Value::Null, json!({})),
            run(2, Value::Null, failed.clone()),
        ]);
        assert_eq!(v["outcomes"], json!({"ok": 2}));
        assert_eq!(v["self_check_failed"]["runs"], json!(1));
        assert_eq!(v["self_check_failed"]["first"]["seed"], json!(2));
        assert_eq!(v["exit"], json!(2));
        // A violation keeps its group and its signature; a new finding still exits 1.
        let mut viol = failed.clone();
        viol["outcome"] = json!("violation");
        viol["signature"] = json!("violation always: label");
        let v = report(&[run(3, Value::Null, viol)]);
        assert_eq!(
            v["groups"][0]["signature"],
            json!("violation always: label")
        );
        assert_eq!(v["groups"][0]["outcome"], json!("violation"));
        assert_eq!(v["self_check_failed"]["runs"], json!(1));
        assert_eq!(v["exit"], json!(1));
        // Without a failed self-check nothing is said.
        let v = report(&[run(
            4,
            Value::Null,
            json!({"self_check": {"verdict": "pass"}}),
        )]);
        assert!(v.get("self_check_failed").is_none());
        assert_eq!(v["exit"], json!(0));
    }

    #[test]
    fn a_class_only_a_fault_class_turned_on_may_have_nothing_to_act_on() {
        let counts = |drop: u64, chunk: u64| {
            json!({"faults": {"counts": {
                "net-drop": {"eligible": drop, "injected": 0},
                "net-chunk": {"eligible": chunk, "injected": 0},
            }}})
        };
        let faults = |r: &[Run]| build(r, &[], None, None, "").0;
        let class = json!({"fault-classes": ["net"], "faults": []});
        // TCP only: the datagram class is not applicable, and the sweep is not vacuous.
        let v = faults(&[run(1, class.clone(), counts(0, 9))]);
        assert_eq!(v["faults"]["not_applicable"], json!(["net-drop"]));
        assert_eq!(
            (v["faults"]["eligible_zero"].clone(), v["exit"].clone()),
            (json!([]), json!(0))
        );
        // Named on its own (any run), the class stays strict.
        let named = json!({"fault-classes": ["net"], "faults": ["net-drop-permille=5"]});
        let v = faults(&[
            run(1, class.clone(), counts(0, 9)),
            run(2, named, counts(0, 9)),
        ]);
        assert_eq!(
            (v["faults"]["eligible_zero"].clone(), v["exit"].clone()),
            (json!(["net-drop"]), json!(2))
        );
        // A class that applied to nothing is vacuous, every fault of it named.
        let v = faults(&[run(1, class.clone(), counts(0, 0))]);
        assert_eq!(
            v["faults"]["eligible_zero"],
            json!(["net-chunk", "net-drop"])
        );
        assert_eq!(v["exit"], json!(2));
        // A run without run.json is strict.
        let v = faults(&[run(1, Value::Null, counts(0, 9))]);
        assert_eq!(v["faults"]["eligible_zero"], json!(["net-drop"]));
    }

    #[test]
    fn a_fault_point_that_never_fired_is_vacuous_only_when_that_is_not_chance() {
        let site = |evaluated: u64| json!({"sdk": {"sites": [{"kind": "buggify", "label": "p", "evaluated": evaluated, "held": 0}]}});
        let sweep = |n: u64, evaluated: u64, plan: Value| {
            let runs: Vec<Run> = (1..=n)
                .map(|s| {
                    let mut r = run(s, json!({"fault-classes": ["buggify"]}), site(evaluated));
                    r.run["faults"] = plan.clone();
                    r.run["faults"]["buggify"] = json!("all");
                    r
                })
                .collect();
            let v = build(&runs, &[], None, None, "").0;
            (
                v["exit"].clone(),
                v["sdk"]["buggify_unfired_noted"].as_array().unwrap().len(),
            )
        };
        // Never reached: a smoke run notes it; a sweep of SMOKE_RUNS does not.
        assert_eq!(sweep(4, 0, json!({})), (json!(0), 1));
        assert_eq!(sweep(SMOKE_RUNS as u64, 0, json!({})), (json!(2), 0));
        // Reached and missed: chance in a few runs, all but impossible at a rate of 1000.
        assert_eq!(sweep(4, 3, json!({})), (json!(0), 1));
        assert_eq!(sweep(2, 1, json!({"buggify:p": 1000})), (json!(2), 0));
        // Forced off (rate 0): never firing is what was asked.
        assert_eq!(sweep(40, 50, json!({"buggify:p": 0})), (json!(0), 1));
        // With nodes, a point no run reached says nothing unless the driver and every node had
        // fault points on: the driver may be the only one that reaches it.
        let nodes = |plan: Value| {
            let runs: Vec<Run> = (1..=SMOKE_RUNS as u64)
                .map(|s| {
                    let c = json!({"fault-classes": ["buggify"], "nodes": [{"name": "a"}]});
                    let mut r = run(s, c, site(0));
                    r.run["faults"] = plan.clone();
                    r
                })
                .collect();
            build(&runs, &[], None, None, "").0["exit"].clone()
        };
        assert_eq!(nodes(json!({"buggify@a": "all"})), json!(0));
        assert_eq!(
            nodes(json!({"buggify@a": "all", "buggify@driver": "all"})),
            json!(2)
        );
        // The chance at the default rates: a quarter active, a quarter of evaluations firing.
        let one = miss_ln(&json!({}), "p", 1).exp();
        assert!((one - (0.75 + 0.25 * 0.75)).abs() < 1e-9, "{one}");
    }

    #[test]
    fn sites_count_the_runs_that_met_them_and_an_allow_pattern_naming_nothing_is_named() {
        let site = |held: u64| {
            json!({"outcome": "ok", "sdk": {"sites": [
                {"kind": "sometimes", "label": "transfer-done", "evaluated": 1, "held": held},
                {"kind": "reachable", "label": "resume", "evaluated": 0, "held": 0}]}})
        };
        let runs: Vec<Run> = (1..=5)
            .map(|s| run(s, json!({}), site((s % 2 == 1) as u64)))
            .collect();
        let allow = ["resume", "transfer-*", "Cargo.toml", "check"].map(String::from);
        let v = build(&runs, &allow, None, None, "").0;
        let met: Vec<(String, u64, u64)> = v["sdk"]["sites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                (
                    x["label"].as_str().unwrap().to_string(),
                    x["runs_evaluated"].as_u64().unwrap(),
                    x["runs_held"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            met,
            [("resume".into(), 0, 0), ("transfer-done".into(), 5, 3)]
        );
        assert_eq!(v["allow_unmet_unmatched"], json!(["Cargo.toml"]));
    }

    #[test]
    fn a_known_entry_that_matched_nothing_names_what_it_nearly_matched() {
        let r = |sig: &str| {
            let mut x = run(1, json!({}), json!({}));
            x.result = json!({"outcome": "failure", "signature": sig});
            x
        };
        let runs = [
            r("failure exit: exit 5"),
            r("violation always: lost: entry N of N"),
        ];
        let k =
            known("a failure exit: exit N\nb violation always: lost: entry 3 of 9\nc crash *\n");
        assert_eq!(
            k.near_miss("a", &runs).as_deref(),
            Some("failure exit: exit 5")
        );
        assert_eq!(
            k.near_miss("b", &runs).as_deref(),
            Some("violation always: lost: entry N of N")
        );
        assert_eq!(k.near_miss("c", &runs), None);
        // The summary counts a known finding apart from the findings.
        let v = build(
            &runs,
            &[],
            Some(&known("x failure exit: exit 5\n")),
            None,
            "",
        )
        .0;
        assert_eq!(
            (
                v["findings"].clone(),
                v["known"]["new"].clone(),
                v["exit"].clone()
            ),
            (json!(2), json!(1), json!(1))
        );
    }

    #[test]
    fn a_required_entry_and_a_malformed_line() {
        let k = known("!p violation *\nq failure *\np crash *\n");
        assert_eq!(k.ids(), vec![("p", true), ("q", false)]);
        let f = std::env::temp_dir().join(format!("patina-known-bad-{}", std::process::id()));
        std::fs::write(&f, "lonely\n").unwrap();
        assert!(Known::read(&f).is_err());
        std::fs::remove_file(&f).unwrap();
    }
}
