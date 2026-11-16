//! The run directory's two documents: `run.json` (the request) and `result.json` (the
//! answer, schema `patina.result/v3`), and the human summary of a result.

use crate::config::{Config, Program};
use crate::outcome::{classify, Classified, Outcome, Verdict};
use serde_json::{json, Value};
use std::path::Path;

pub const RESULT_SCHEMA: &str = "patina.result/v3";
pub const RUN_SCHEMA: &str = "patina.run/v1";

/// What a chain of incarnations produced.
#[derive(Clone, Debug)]
pub struct RunEnd {
    pub verdict: Verdict,
    pub seed: u64,
    pub incarnations: u64,
    pub digest: String,
    pub traps: u64,
    pub switches: u64,
    pub refused: Vec<String>,
    /// Paths the guest tried to run or open that the sandbox lacks and the host has
    /// (`launch::not_in_sandbox`).
    pub missing: Vec<Value>,
    pub wall_ms: u64,
    /// Blocking I/O counters: parks, re-attempts, spurious re-attempts, blocking calls
    /// completed, of which parked at least once.
    pub io: [u64; 5],
    /// One object per crash.
    pub crashes: Vec<Value>,
    /// What was done to the program (`attribution::faults_json`): the resolved plan, eligible
    /// and injected calls per class, the total and the last injected events.
    pub faults: Value,
    /// Instruction channels.
    pub insn: InsnCounts,
    /// Network wire counters, `NET_NAMES` order, summed over incarnations
    /// (`peak_queued` and `sup_hwm_kb` are maxima).
    pub net: [u64; NET_FIELDS],
    /// AF_UNIX sockets sent in SCM_RIGHTS, summed over incarnations.
    pub unix_sockets: u64,
    /// With `--preempt branches`, the counters in `proto::ctl::PMU_NAMES` order (summed;
    /// `max_skid` is a maximum).
    pub pmu: Option<[u64; proto::ctl::PMU_FIELDS]>,
    /// The SDK's site table, folded over incarnations.
    pub sdk: SdkReport,
    /// Pause points and spin probes.
    pub sched: SchedCounts,
    /// Compute points.
    pub compute: ComputeCounts,
}

/// Compute points (`proto::ctl::ComputeStats`), summed over incarnations, and the run's mean gap.
#[derive(Clone, Debug, Default)]
pub struct ComputeCounts {
    pub hellos: u64,
    pub events: u64,
    pub switches: u64,
    pub deadline_stops: u64,
    pub gap: u64,
    /// The image table (`proto::ctl::ComputeTab`), folded over incarnations.
    pub images: ComputeImages,
}

/// The images that said `COMPUTE_HELLO`, in the order they first did, and the starts of
/// images the table had no room for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComputeImages {
    pub images: Vec<ComputeImage>,
    pub dropped: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeImage {
    /// The guest path (its end, after `...`, when longer than the table keeps).
    pub path: String,
    /// The table's key: a hash of the whole path (two cut paths may print alike).
    pub key: u64,
    pub kinds: u64,
    pub starts: u64,
}

/// `proto::sdk::COMPUTE_*` bits by name.
const COMPUTE_KIND_NAMES: [(u64, &str); 3] = [
    (proto::sdk::COMPUTE_EDGE, "edge"),
    (proto::sdk::COMPUTE_ACCESS, "access"),
    (proto::sdk::COMPUTE_COMPARE, "compare"),
];

impl ComputeImages {
    pub fn read(t: &proto::ctl::ComputeTab) -> ComputeImages {
        ComputeImages {
            images: t
                .used()
                .iter()
                .map(|e| ComputeImage {
                    path: format!(
                        "{}{}",
                        if e.cut() { "..." } else { "" },
                        String::from_utf8_lossy(e.tail())
                    ),
                    key: e.key,
                    kinds: e.kinds,
                    starts: e.starts,
                })
                .collect(),
            dropped: t.dropped,
        }
    }

    /// Fold a later incarnation in: starts add, kinds join.
    pub fn add(&mut self, b: ComputeImages) {
        for x in b.images {
            match self
                .images
                .iter_mut()
                .find(|y| y.key == x.key && y.path == x.path)
            {
                Some(y) => {
                    y.kinds |= x.kinds;
                    y.starts += x.starts;
                }
                None => self.images.push(x),
            }
        }
        self.dropped += b.dropped;
    }
}

impl ComputeImage {
    fn json(&self) -> Value {
        json!({"path": self.path, "kinds": kind_names(self.kinds), "starts": self.starts})
    }
}

/// A kind name's place in `COMPUTE_KIND_NAMES` (unknown names last).
pub fn kind_rank(name: &str) -> usize {
    COMPUTE_KIND_NAMES
        .iter()
        .position(|(_, n)| *n == name)
        .unwrap_or(usize::MAX)
}

fn kind_names(kinds: u64) -> Vec<&'static str> {
    COMPUTE_KIND_NAMES
        .iter()
        .filter(|(b, _)| kinds & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

impl ComputeCounts {
    /// `result.json`'s `compute`: only when an image said hello or events were counted, so a
    /// run of stock programs has the same `result.json` as before compute points existed.
    fn json(&self, counters: bool) -> Option<Value> {
        if self.hellos == 0 && self.events == 0 {
            return None;
        }
        let mut v = json!({
            "images": self.images.images.iter().map(ComputeImage::json).collect::<Vec<_>>(),
            "images_dropped": self.images.dropped,
            "events": self.events,
            "switches": self.switches,
            "deadline_stops": self.deadline_stops,
            "gap": self.gap,
            "charge_ns": proto::compute::CHARGE_NS,
        });
        if counters {
            v["mode"] = json!("counters");
        }
        Some(v)
    }
}

/// The scheduling points beyond traps: `pause` sites patched, and the counters of
/// `proto::ctl::SCHED_NAMES`, summed over incarnations.
#[derive(Clone, Debug, Default)]
pub struct SchedCounts {
    pub pause_sites: u64,
    pub stats: [u64; proto::ctl::SCHED_FIELDS],
}

impl SchedCounts {
    pub fn get(&self, name: &str) -> u64 {
        proto::ctl::SCHED_NAMES
            .iter()
            .position(|n| *n == name)
            .map(|i| self.stats[i])
            .unwrap_or(0)
    }
}

pub const NET_FIELDS: usize = 13;
pub const NET_NAMES: [&str; NET_FIELDS] = [
    "connections",
    "bytes",
    "chunks",
    "resets",
    "partitioned",
    "refused",
    "timeouts",
    "unknown_opts",
    "peak_queued",
    "sup_hwm_kb",
    "steps",
    "fins",
    "sends",
];

pub fn net_read(c: &proto::wire::NetCounters) -> [u64; NET_FIELDS] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        c.connections.load(Relaxed),
        c.bytes.load(Relaxed),
        c.chunks.load(Relaxed),
        c.resets.load(Relaxed),
        c.partitioned.load(Relaxed),
        c.refused.load(Relaxed),
        c.timeouts.load(Relaxed),
        c.unknown_opts.load(Relaxed),
        c.peak_queued.load(Relaxed),
        c.sup_hwm_kb.load(Relaxed),
        c.steps.load(Relaxed),
        c.fins.load(Relaxed),
        c.sends.load(Relaxed),
    ]
}

pub fn net_add(a: &mut [u64; NET_FIELDS], b: &[u64; NET_FIELDS]) {
    for (i, (x, y)) in a.iter_mut().zip(b).enumerate() {
        if NET_NAMES[i] == "peak_queued" || NET_NAMES[i] == "sup_hwm_kb" {
            *x = (*x).max(*y);
        } else {
            *x += y;
        }
    }
}

/// Instruction-channel counters, as in `proto::ctl::InsnCtl`, summed over incarnations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InsnCounts {
    /// By `proto::insn::SiteKind`: [unused, rdrand, rdseed, rdpid, pause].
    pub patched: [u64; 5],
    /// By `proto::ctl::INSN_*`.
    pub emulated: [u64; 5],
    pub unscanned_exec_mappings: u64,
    pub rejected_sites: u64,
    pub rdpid_sites: u64,
    pub scanned_mappings: u64,
    pub scanned_bytes: u64,
    pub table_full: u64,
}

impl InsnCounts {
    pub fn read(c: &proto::ctl::InsnCtl) -> InsnCounts {
        use std::sync::atomic::Ordering::Relaxed;
        let mut o = InsnCounts::default();
        for (a, b) in o.patched.iter_mut().zip(&c.patched) {
            *a = b.load(Relaxed);
        }
        for (a, b) in o.emulated.iter_mut().zip(&c.emulated) {
            *a = b.load(Relaxed);
        }
        o.unscanned_exec_mappings = c.unscanned_exec_mappings.load(Relaxed);
        o.rejected_sites = c.rejected_sites.load(Relaxed);
        o.rdpid_sites = c.rdpid_sites.load(Relaxed);
        o.scanned_mappings = c.scanned_mappings.load(Relaxed);
        o.scanned_bytes = c.scanned_bytes.load(Relaxed);
        o.table_full = c.table_full.load(Relaxed);
        o
    }
    pub fn add(&mut self, b: &InsnCounts) {
        for (x, y) in self.patched.iter_mut().zip(b.patched) {
            *x += y;
        }
        for (x, y) in self.emulated.iter_mut().zip(b.emulated) {
            *x += y;
        }
        self.unscanned_exec_mappings += b.unscanned_exec_mappings;
        self.rejected_sites += b.rejected_sites;
        self.rdpid_sites += b.rdpid_sites;
        self.scanned_mappings += b.scanned_mappings;
        self.scanned_bytes += b.scanned_bytes;
        self.table_full += b.table_full;
    }
    fn json(&self) -> Value {
        let em: serde_json::Map<String, Value> = proto::ctl::INSN_NAMES
            .iter()
            .zip(self.emulated)
            .map(|(n, v)| (n.to_string(), json!(v)))
            .collect();
        json!({
            "patched_sites": { "rdrand": self.patched[1], "rdseed": self.patched[2], "pause": self.patched[4] },
            "emulated": em,
            "scan": {
                "mappings": self.scanned_mappings,
                "bytes": self.scanned_bytes,
                "rejected_sites": self.rejected_sites,
                "rdpid_sites": self.rdpid_sites,
                "table_full": self.table_full,
            },
        })
    }
}

fn named<const N: usize>(names: &[&str; N], v: &[u64; N]) -> Value {
    Value::Object(
        names
            .iter()
            .zip(v)
            .map(|(n, x)| (n.to_string(), json!(x)))
            .collect(),
    )
}

/// `result.json` for a finished run, with the outcome given (a replay or verify may
/// override the run's own).
pub fn result_json(e: &RunEnd, c: &Classified) -> Value {
    let v = &e.verdict;
    let preemptions = e.sched.get("spin_yields")
        + e.compute.switches
        + e.pmu.map_or(0, |p| {
            p[proto::ctl::PMU_NAMES
                .iter()
                .position(|n| *n == "preempts")
                .unwrap()]
        });
    let mut counters = json!({
        "io": named(&["parks", "reattempts", "spurious", "blocking_done", "blocking_parked"], &e.io),
        "net": named(&NET_NAMES, &e.net),
        "insn": e.insn.json(),
    });
    counters["sched"] = named(&proto::ctl::SCHED_NAMES, &e.sched.stats);
    if let Some(p) = &e.pmu {
        counters["pmu"] = named(&proto::ctl::PMU_NAMES, p);
    }
    let mut r = json!({
        "schema": RESULT_SCHEMA,
        "outcome": c.outcome.name(),
        "stop": c.stop,
        "message": c.message,
        "exit": c.outcome.exit(),
        "guest": { "exit": v.exit_status, "signal": v.signal },
        "seed": e.seed,
        "digest": e.digest,
        "incarnations": e.incarnations,
        "crashes": e.crashes,
        "faults": e.faults,
        "sdk": e.sdk.json(),
        "refused": e.refused,
        "missing": e.missing,
        "labels": {
            "unscanned_exec_mappings": e.insn.unscanned_exec_mappings,
            "unix_sockets_in_flight": e.unix_sockets,
        },
        "sched": {
            "traps": e.traps,
            "switches": e.switches,
            "mode": if e.pmu.is_some() { "branches" } else { "traps" },
            "pause_sites": e.sched.pause_sites,
            "pause_points": e.sched.get("pause_points"),
            "preemptions": preemptions,
        },
        "counters": counters,
        "signature": null,
        "wall_ms": e.wall_ms,
    });
    if let Some(cp) = e.compute.json(e.pmu.is_some()) {
        r["compute"] = cp;
    }
    r
}

/// A result without a run (a request that could not be carried out).
pub fn error_json(outcome: Outcome, stop: &str, message: &str) -> Value {
    json!({
        "schema": RESULT_SCHEMA,
        "outcome": outcome.name(),
        "stop": stop,
        "message": message,
        "exit": outcome.exit(),
    })
}

pub fn write_json(path: &Path, v: &Value) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    std::fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn read_json(path: &Path) -> Result<Value, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))
}

/// The host facts `run.json` records (not inputs: a replay elsewhere may differ in them).
pub fn host_facts() -> Value {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default();
    json!({ "kernel": kernel, "cpu": cpu, "arch": std::env::consts::ARCH })
}

/// `run.json`: the request, with the fault plan resolved from the seed (`faults`).
pub fn run_json(cfg: &Config, program: &Program, plan: &crate::faults::Plan) -> Value {
    json!({
        "schema": RUN_SCHEMA,
        "version": env!("CARGO_PKG_VERSION"),
        "seed": cfg.seed,
        "config": cfg,
        "faults": plan.json(),
        "program": program,
        "host": host_facts(),
    })
}

/// The run's own outcome.
pub fn classified(e: &RunEnd) -> Classified {
    classify(&e.verdict)
}

/// Lines of the guest's stderr the summary shows at most, and characters of each.
const STDERR_LINES: usize = 12;
const LINE_MAX: usize = 240;

/// The human summary: the outcome line, the guest's exit; when the run is not ok, the tail of
/// the guest's stderr (with its panic or assertion line) and the faults injected; the calls
/// refused (each answered with an errno the guest may have handled silently); the run
/// directory and how to replay it. `--format json` prints `result.json`, which holds all of it
/// but stderr (in `inc-K/stderr`).
pub fn print_human(r: &Value, dir: &Path) {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    println!("{} ({}): {}", s("outcome"), s("stop"), s("message"));
    let g = &r["guest"];
    if let Some(x) = g["exit"].as_i64() {
        match g["signal"].as_i64() {
            Some(sig) => println!("guest: killed by {}", crate::outcome::signal_name(sig)),
            None => println!("guest: exit {x}"),
        }
    }
    if let Some(l) = compute_line(&r["compute"]) {
        println!("{l}");
    }
    let ok = r["outcome"] == "ok";
    if !ok {
        let inc = r["incarnations"].as_u64().unwrap_or(1).max(1) - 1;
        let path = dir.join(format!("inc-{inc}")).join("stderr");
        let text = std::fs::read(&path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        if !lines.is_empty() {
            let from = lines.len().saturating_sub(STDERR_LINES);
            let cut = |l: &str| l.chars().take(LINE_MAX).collect::<String>();
            println!(
                "guest stderr ({}, {}):",
                if from > 0 {
                    format!("last {STDERR_LINES} of {} lines", lines.len())
                } else {
                    format!("{} lines", lines.len())
                },
                path.display()
            );
            // The panic or assertion line, when it scrolled out of the tail.
            if let Some(i) = lines[..from]
                .iter()
                .position(|l| crate::signature::guest_line(l).is_some())
            {
                println!("  {}", cut(lines[i]));
                println!("  ...");
            }
            for l in &lines[from..] {
                println!("  {}", cut(l));
            }
        }
    }
    // The faults done to the program: per class, then the last few under a finding.
    let injected = r["faults"]["injected"].as_u64().unwrap_or(0);
    if injected > 0 {
        let per: Vec<String> = r["faults"]["counts"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(k, v)| {
                let n = v["injected"].as_u64().unwrap_or(0);
                (n > 0).then(|| format!("{k} {n}"))
            })
            .collect();
        println!("faults injected: {injected} ({})", per.join(", "));
        let recent = r["faults"]["recent"].as_array().map_or(&[][..], |v| v);
        if r["exit"] == 1 && !recent.is_empty() {
            println!("last injected:");
            for f in &recent[recent.len().saturating_sub(5)..] {
                println!("  {}", crate::launcher::attribution::line(f));
            }
        }
    }
    if let Some(l) = refused_line(r) {
        println!("{l}");
    }
    for m in r["missing"].as_array().into_iter().flatten() {
        println!("{}", missing_line(m));
    }
    println!("run directory: {}", dir.display());
    println!("replay: patina replay {}", dir.display());
}

/// Images a summary line names; the rest are counted (the JSON has them all).
pub const IMAGES_SHOWN: usize = 4;

/// `path (edges, accesses)` for the first `IMAGES_SHOWN` images of a `compute.images` list
/// (report.json's or result.json's), with `; N starts` when an image started more than once,
/// then `and N more` naming `full`, where the rest are.
pub fn compute_images(images: &Value, full: &str) -> String {
    let all = images.as_array().map_or(&[][..], |v| v);
    let mut l: Vec<String> = all
        .iter()
        .take(IMAGES_SHOWN)
        .map(|i| {
            let kinds: Vec<String> = i["kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|k| k.as_str())
                .map(|k| match k {
                    "access" => "accesses".to_string(),
                    k => format!("{k}s"),
                })
                .collect();
            let starts = match i["starts"].as_u64() {
                Some(n) if n > 1 => format!("; {n} starts"),
                _ => String::new(),
            };
            let what = format!("{}{starts}", kinds.join(", "));
            let what = what.trim_start_matches("; ");
            match what {
                "" => i["path"].as_str().unwrap_or("").to_string(),
                w => format!("{} ({w})", i["path"].as_str().unwrap_or("")),
            }
        })
        .collect();
    if all.len() > IMAGES_SHOWN {
        l.push(format!("and {} more ({full})", all.len() - IMAGES_SHOWN));
    }
    l.join(", ")
}

/// The `patina run` line for result.json's `compute`, or nothing when no image said hello:
/// which images, the events counted, the points that switched or met a deadline, the mean
/// gap in force.
pub fn compute_line(c: &Value) -> Option<String> {
    let images = c["images"].as_array()?;
    let n = |k: &str| c[k].as_u64().unwrap_or(0);
    let mut s = format!(
        "compute points: {}",
        compute_images(&c["images"], "result.json")
    );
    if images.is_empty() {
        s.push_str("(none listed)");
    }
    if n("images_dropped") > 0 {
        s.push_str(&format!(
            ", and {} not listed (the table holds {} images)",
            plural(n("images_dropped"), "more start"),
            proto::ctl::IMAGES_MAX
        ));
    }
    if c["mode"] == "counters" {
        s.push_str("; idle: branch counters schedule this run");
        return Some(s);
    }
    s.push_str(&format!("; {} events", big(n("events"))));
    match n("gap") {
        0 => s.push_str(", switches off (compute-gap=0)"),
        g => s.push_str(&format!(
            ", {}, mean gap {}",
            plural(n("switches"), "switch"),
            commas(g)
        )),
    }
    if n("deadline_stops") > 0 {
        s.push_str(&format!(
            ", {}",
            plural(n("deadline_stops"), "deadline stop")
        ));
    }
    Some(s)
}

fn plural(n: u64, word: &str) -> String {
    let es = if word.ends_with("ch") { "es" } else { "s" };
    format!("{} {word}{}", commas(n), if n == 1 { "" } else { es })
}

/// 1,234,567
fn commas(n: u64) -> String {
    let d = n.to_string();
    let mut s = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            s.push(',');
        }
        s.push(c);
    }
    s
}

/// Below a million with commas, else 48.2 M or 3.1 G.
fn big(n: u64) -> String {
    match n {
        0..=999_999 => commas(n),
        1_000_000..=999_949_999 => format!("{:.1} M", n as f64 / 1e6),
        _ => format!("{:.1} G", n as f64 / 1e9),
    }
}

/// The hint for one path the guest could not find in the sandbox (`launch::not_in_sandbox`).
pub fn missing_line(m: &Value) -> String {
    let s = |k: &str| m[k].as_str().unwrap_or("");
    if s("name").is_empty() {
        format!(
            "not in the sandbox: {} (the host has it): add --mount {d}:{d}",
            s("path"),
            d = s("mount")
        )
    } else {
        format!(
            "not in the sandbox: {}, run by name (the host's is {}, outside the guest's PATH): add --mount {d}:{d} and run {}",
            s("name"),
            s("host"),
            s("host"),
            d = s("mount")
        )
    }
}

/// One line naming what the run refused, or nothing. Calls the table answers `ENOSYS` (a
/// kernel without them; libraries probe for them and fall back) are left out; `result.json`'s
/// `refused` has them all.
pub fn refused_line(r: &Value) -> Option<String> {
    let probe = |n: &str| {
        proto::table::known().any(|row| row.name == n && row.class == proto::table::Class::Deny(38))
    };
    let names: Vec<&str> = r["refused"]
        .as_array()?
        .iter()
        .filter_map(|x| x.as_str())
        .filter(|n| !probe(n))
        .collect();
    (!names.is_empty()).then(|| {
        format!(
            "refused: {} (unsupported; the guest got an error code)",
            names.join(", ")
        )
    })
}

/// The SDK's site table and violation (`proto::sdk::SdkTab`), folded over incarnations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SdkReport {
    /// Sorted by label, then kind.
    pub sites: Vec<SdkSite>,
    pub dropped: u64,
    pub setup_complete: bool,
    /// The failed `always`: (label, detail).
    pub violation: Option<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkSite {
    pub kind: u8,
    pub label: String,
    pub location: String,
    pub evaluated: u64,
    pub held: u64,
    pub value: i64,
}

impl SdkReport {
    /// The table as the runtime left it, with labels and locations made checkout-free
    /// (`signature::checkout_free`): a label built from a source path names the same site in
    /// every checkout.
    pub fn read(t: &proto::sdk::SdkTab) -> SdkReport {
        let s = |b: &[u8]| crate::signature::checkout_free(&String::from_utf8_lossy(b));
        let mut r = SdkReport {
            sites: t
                .used()
                .iter()
                .map(|x| SdkSite {
                    kind: x.kind,
                    label: s(x.label()),
                    location: s(x.loc()),
                    evaluated: x.evaluated,
                    held: x.held,
                    value: x.value,
                })
                .collect(),
            dropped: t.dropped,
            setup_complete: t.setup_seq != 0,
            violation: t
                .violation_parts()
                .map(|(l, d)| (s(l), String::from_utf8_lossy(d).into_owned())),
        };
        r.sites
            .sort_by(|a, b| (&a.label, a.kind).cmp(&(&b.label, b.kind)));
        r
    }

    /// Fold a later incarnation in: counts add, a knob keeps its last value.
    pub fn add(&mut self, b: SdkReport) {
        for x in b.sites {
            match self
                .sites
                .iter_mut()
                .find(|y| y.kind == x.kind && y.label == x.label)
            {
                Some(y) => {
                    y.evaluated += x.evaluated;
                    y.held += x.held;
                    if x.evaluated > 0 {
                        y.value = x.value;
                    }
                    if y.location.is_empty() {
                        y.location = x.location;
                    }
                }
                None => self.sites.push(x),
            }
        }
        self.sites
            .sort_by(|a, b| (&a.label, a.kind).cmp(&(&b.label, b.kind)));
        self.dropped += b.dropped;
        self.setup_complete |= b.setup_complete;
        if b.violation.is_some() {
            self.violation = b.violation;
        }
    }

    /// `{"sites":[{"kind","label","location","evaluated","held"[,"value"]}],"setup_complete",
    /// "violation":{"label","detail"}|null,"dropped"}`. `evaluated` counts reports (an SDK
    /// reports a passing assertion once per process image) or a point's evaluations; `held`
    /// counts reports whose condition held, hits of a `reachable`, firings of a point or delay.
    pub fn json(&self) -> Value {
        let sites: Vec<Value> = self
            .sites
            .iter()
            .map(|x| {
                let mut o = json!({
                    "kind": proto::sdk::kind_name(x.kind),
                    "label": x.label,
                    "location": if x.location.is_empty() { Value::Null } else { x.location.clone().into() },
                    "evaluated": x.evaluated,
                    "held": x.held,
                });
                if x.kind == proto::sdk::KIND_KNOB && x.evaluated > 0 {
                    o["value"] = x.value.into();
                }
                o
            })
            .collect();
        json!({
            "sites": sites,
            "setup_complete": self.setup_complete,
            "violation": self.violation.as_ref().map(|(l, d)| json!({"label": l, "detail": d})),
            "dropped": self.dropped,
        })
    }
}
