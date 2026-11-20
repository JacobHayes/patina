//! The run directory's two documents: `run.json` (the request) and `result.json` (the
//! answer, schema `patina.result/v3`), and the human summary of a result.

use crate::cli::Res;
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
    /// The size of each sandbox tmpfs (`tmpfs-bytes`) and the file calls a full one answered
    /// `ENOSPC`, summed over incarnations.
    pub tmpfs: [u64; 2],
    /// The most bytes the shadow store held (`proto::oplog::Shadows`; the largest over
    /// incarnations): what the operation log holds of the work files mapped shared.
    pub shadow_bytes: u64,
    /// With `--preempt branches`, the counters in `proto::ctl::PMU_NAMES` order (summed;
    /// `max_skid` is a maximum).
    pub pmu: Option<[u64; proto::ctl::PMU_FIELDS]>,
    /// The SDK's site table, folded over incarnations.
    pub sdk: SdkReport,
    /// Pause points and spin probes.
    pub sched: SchedCounts,
    /// Compute points.
    pub compute: ComputeCounts,
    /// With `--check`, what the checker said (`not-run` when the run did not end ok).
    pub check: Option<crate::check::Verdict>,
    /// Exit statuses that end the run `ok` (`--ok-exit`).
    pub ok_exit: Vec<crate::config::OkExit>,
    /// With `--preempt points`: what the plans did.
    pub rewrite: Option<RewriteReport>,
    /// With `--crash`, the operation log's self-check: Err with the first difference when
    /// replaying the log does not give the live tree (a Patina defect, reported next to the
    /// program's own outcome, never instead of it). None when it did not run.
    pub self_check: Option<Result<(), String>>,
    /// A run with nodes: each node and the scripted network (`nodes_json`).
    pub nodes: Option<Value>,
}

/// `result.json`'s `nodes`: each node (the driver first) with its address, its first process and
/// how that ended (`running` when the run ended first), and the scripted network: cuts and heals
/// served, connection directions a cut held, and the links still cut at the end.
pub fn nodes_json(t: &proto::node::NodeTab) -> Value {
    let name = |k: usize| String::from_utf8_lossy(t.name(k)).into_owned();
    let list: Vec<Value> = (0..t.count())
        .map(|k| {
            let mut v = json!({"name": name(k), "address": format!("10.0.0.{}", k + 1)});
            if k > 0 {
                let s = t.status[k];
                v["pid"] = json!(t.first_pid[k]);
                v["end"] = if t.first_pid[k] == 0 {
                    json!("not started")
                } else if s == proto::node::RUNNING {
                    json!("running")
                } else if s & 0x7f == 0 {
                    json!({"exit": (s >> 8) & 0xff})
                } else {
                    json!({"signal": s & 0x7f})
                };
                // Each time it went down (kills, its command's ends) and the restarts.
                let boots = t.boots[k] as usize;
                v["incarnations"] = json!(boots);
                let downs: Vec<Value> = t.boot[k][..boots.min(proto::node::BOOTS_MAX)]
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| b.how != 0)
                    .map(|(i, b)| {
                        let mut d = json!({
                            "incarnation": i,
                            "how": proto::node::down_name(b.how),
                            "at_ms": b.end_ns / 1_000_000,
                            "up_ms": b.end_ns.saturating_sub(b.start_ns) / 1_000_000,
                            "down_ms": if b.down_ns == 0 { Value::Null } else { json!(b.down_ns / 1_000_000) },
                        });
                        if b.point != 0 {
                            d["point"] = json!(b.point);
                        }
                        match b.how {
                            proto::node::DOWN_EXIT | proto::node::DOWN_FAILED => d["exit"] = json!(b.value),
                            proto::node::DOWN_SIGNAL => d["signal"] = json!(b.value),
                            _ => {}
                        }
                        d
                    })
                    .collect();
                if !downs.is_empty() {
                    v["downs"] = json!(downs);
                }
                // With crashes at its crash points: those each boot passed (the first's are
                // what `machine-at:N@NAME` counts, and `--branch` tries).
                let c = &t.faults[k].cfg;
                if c.crash_kind != proto::faults::CRASH_NONE || c.crash_at != 0 {
                    let p: Vec<u64> = t.boot[k][..boots.min(proto::node::BOOTS_MAX)]
                        .iter()
                        .map(|b| b.points)
                        .collect();
                    v["crash_points"] = json!(p);
                }
            }
            v
        })
        .collect();
    let mut cut = vec![];
    for a in 0..t.count() {
        for b in 0..t.count() {
            if t.cut_at_end[a] & (1 << b) != 0 {
                cut.push(json!([name(a), name(b)]));
            }
        }
    }
    let bits = |b: u64| -> Vec<String> {
        (0..t.count())
            .filter(|k| b & (1 << k) != 0)
            .map(name)
            .collect()
    };
    // Virtual time as events and `faults.recent` give it.
    let ms = |ns: u64| ns / 1_000_000;
    let parts: Vec<Value> = t.parts[..(t.parts_n as usize).min(proto::node::PARTS_MAX)]
        .iter()
        .map(|p| {
            let mut v = json!({
                "n": p.n,
                "shape": proto::node::shape_name(p.shape),
                "a": bits(p.a),
                "b": bits(p.b),
                "from_ms": ms(p.from_ns),
                "to_ms": if p.to_ns == 0 { Value::Null } else { json!(ms(p.to_ns)) },
                "acted": p.acted != 0,
            });
            if p.shape == proto::node::SHAPE_BRIDGE {
                let all = (1u64 << t.count()) - 1;
                v["bridge"] = json!(bits(p.bridge & all));
            }
            v
        })
        .collect();
    let mut v = json!({
        "list": list,
        "net": {"cuts": t.cuts, "heals": t.heals, "held": t.held, "cut_at_end": cut},
        // What the link faults had a chance at, on the links they act on (`net-links`).
        "faulted_links": {
            "connections": t.elig[proto::node::ELIG_CONNECTIONS],
            "chunks": t.elig[proto::node::ELIG_CHUNKS],
            "fins": t.elig[proto::node::ELIG_FINS],
            "sends": t.elig[proto::node::ELIG_SENDS],
            "datagrams": t.elig[proto::node::ELIG_DATAGRAMS],
        },
    });
    if t.ended_by > 0 {
        v["ended_by"] = json!(name(t.ended_by as usize - 1));
    }
    if t.parts_n > 0 {
        v["partitions"] = json!(parts);
        v["partitions_drawn"] = json!(t.parts_n);
        v["partitions_acted"] = json!(t.parts_acted);
    }
    v
}

/// The partition a run with nodes ended in, if one was in force (`in force at the end:
/// partition N SHAPE {A} | {B} since t=Tms`), else the last one the run had (`last partition:
/// ... t=T1..T2ms`).
pub fn partition_line(nodes: &Value) -> Option<String> {
    let p = nodes["partitions"].as_array()?.last()?;
    let side = |k: &str| {
        let v: Vec<&str> = p[k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str())
            .collect();
        format!("{{{}}}", v.join(","))
    };
    let arrow = if p["shape"] == "oneway" { "->" } else { "|" };
    let what = format!(
        "partition {} {} {} {arrow} {}",
        p["n"],
        p["shape"].as_str().unwrap_or(""),
        side("a"),
        side("b"),
    );
    Some(if p["to_ms"].is_null() {
        format!("in force at the end: {what} since t={}ms", p["from_ms"])
    } else {
        format!(
            "last partition: {what} at t={}..{}ms",
            p["from_ms"], p["to_ms"]
        )
    })
}

/// `result.json`'s `rewrite`: each file the runtime asked a plan for (`rewrite::cache`), and
/// the runtime's counts (`proto::ctl::PLAN_NAMES`), summed over incarnations.
#[derive(Clone, Debug)]
pub struct RewriteReport {
    pub images: Vec<Value>,
    pub plans: [u64; proto::ctl::PLAN_FIELDS],
    /// The run's longest walk (`compute-walk`, drawn per seed).
    pub walk: u64,
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
const COMPUTE_KIND_NAMES: [(u64, &str); 4] = [
    (proto::sdk::COMPUTE_EDGE, "edge"),
    (proto::sdk::COMPUTE_ACCESS, "access"),
    (proto::sdk::COMPUTE_COMPARE, "compare"),
    (proto::sdk::COMPUTE_LINE, "line"),
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

pub const NET_FIELDS: usize = 16;
pub const NET_NAMES: [&str; NET_FIELDS] = [
    "connections",
    "bytes",
    "chunks",
    "resets",
    "blacked_out",
    "refused",
    "timeouts",
    "unknown_opts",
    "peak_queued",
    "sup_hwm_kb",
    "steps",
    "fins",
    "sends",
    "datagrams",
    "dgram_delivered",
    "dgram_lost",
];

pub fn net_read(c: &proto::wire::NetCounters) -> [u64; NET_FIELDS] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        c.connections.load(Relaxed),
        c.bytes.load(Relaxed),
        c.chunks.load(Relaxed),
        c.resets.load(Relaxed),
        c.blacked_out.load(Relaxed),
        c.refused.load(Relaxed),
        c.timeouts.load(Relaxed),
        c.unknown_opts.load(Relaxed),
        c.peak_queued.load(Relaxed),
        c.sup_hwm_kb.load(Relaxed),
        c.steps.load(Relaxed),
        c.fins.load(Relaxed),
        c.sends.load(Relaxed),
        c.datagrams.load(Relaxed),
        c.dgram_delivered.load(Relaxed),
        c.dgram_lost.load(Relaxed),
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
    /// By `proto::insn::SiteKind`: [unused, rdrand, rdseed, rdpid, pause] on x86_64, [unused,
    /// rndr, rndrrs, pacga, pause] on arm64.
    pub patched: [u64; 6],
    /// By `proto::ctl::INSN_*`.
    pub emulated: [u64; 5],
    pub unscanned_exec_mappings: u64,
    pub rejected_sites: u64,
    /// `rdpid` sites on x86_64, `pacga` sites on arm64: counted, not patched.
    pub counted_sites: u64,
    pub scanned_mappings: u64,
    pub scanned_bytes: u64,
    pub reused_mappings: u64,
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
        o.counted_sites = c.counted_sites.load(Relaxed);
        o.scanned_mappings = c.scanned_mappings.load(Relaxed);
        o.scanned_bytes = c.scanned_bytes.load(Relaxed);
        o.reused_mappings = c.reused_mappings.load(Relaxed);
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
        self.counted_sites += b.counted_sites;
        self.scanned_mappings += b.scanned_mappings;
        self.scanned_bytes += b.scanned_bytes;
        self.reused_mappings += b.reused_mappings;
        self.table_full += b.table_full;
    }
    fn json(&self) -> Value {
        let em: serde_json::Map<String, Value> = proto::ctl::INSN_NAMES
            .iter()
            .zip(self.emulated)
            .map(|(n, v)| (n.to_string(), json!(v)))
            .collect();
        // The names of the patched kinds and of the counted one, per architecture.
        #[cfg(target_arch = "x86_64")]
        let (patched, counted) = (["rdrand", "rdseed"], "rdpid_sites");
        #[cfg(target_arch = "aarch64")]
        let (patched, counted) = (["rndr", "rndrrs"], "pacga_sites");
        let mut sites = json!({ patched[0]: self.patched[1], patched[1]: self.patched[2], "pause": self.patched[4] });
        // arm64 with counter preemption: the exclusive instructions (`proto::insn`).
        if self.patched[5] != 0 {
            sites["exclusive"] = json!(self.patched[5]);
        }
        json!({
            "patched_sites": sites,
            "emulated": em,
            "scan": {
                "mappings": self.scanned_mappings,
                "bytes": self.scanned_bytes,
                "reused_mappings": self.reused_mappings,
                "rejected_sites": self.rejected_sites,
                counted: self.counted_sites,
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
        "guest": if v.class.starts_with("node-") {
            json!({ "exit": null, "signal": null })
        } else {
            json!({ "exit": v.exit_status, "signal": v.signal })
        },
        "seed": e.seed,
        "digest": e.digest,
        "incarnations": e.incarnations,
        "crashes": e.crashes,
        "faults": e.faults,
        "sdk": e.sdk.json(),
        "refused": e.refused,
        "missing": e.missing,
        "tmpfs": { "bytes": e.tmpfs[0], "enospc": e.tmpfs[1] },
        "shadow_bytes": e.shadow_bytes,
        "labels": {
            "unscanned_exec_mappings": e.insn.unscanned_exec_mappings,
            "unix_sockets_in_flight": e.unix_sockets,
        },
        "sched": {
            "traps": e.traps,
            "switches": e.switches,
            "mode": if e.pmu.is_some() { "branches" } else if e.rewrite.is_some() { "points" } else { "traps" },
            "pause_sites": e.sched.pause_sites,
            "pause_points": e.sched.get("pause_points"),
            "preemptions": preemptions,
        },
        "counters": counters,
        "signature": null,
        "wall_ms": e.wall_ms,
    });
    match &e.self_check {
        Some(Ok(())) => r["self_check"] = json!({"verdict": "pass"}),
        Some(Err(d)) => r["self_check"] = json!({"verdict": "fail", "detail": d}),
        None => {}
    }
    r["exit"] = run_exit(c.outcome, &r).into();
    if let Some(cp) = e.compute.json(e.pmu.is_some()) {
        r["compute"] = cp;
    }
    if let Some(w) = &e.rewrite {
        let mut v = named(&proto::ctl::PLAN_NAMES, &w.plans);
        v["walk_max"] = json!(w.walk);
        v["images"] = json!(w.images);
        r["rewrite"] = v;
    }
    if let Some(k) = &e.check {
        r["check"] = serde_json::to_value(k).unwrap();
    }
    if let Some(n) = &e.nodes {
        r["nodes"] = n.clone();
        // A node's own end ended the run: which node, which of its boots, and how.
        if let Some(name) = n["ended_by"]
            .as_str()
            .filter(|_| v.class.starts_with("node-"))
        {
            let boots = n["list"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|x| x["name"] == name)
                .and_then(|x| x["incarnations"].as_u64())
                .unwrap_or(1);
            r["node_end"] = json!({
                "node": name,
                "incarnation": boots.max(1) - 1,
                "exit": v.exit_status,
                "signal": v.signal,
            });
        }
    }
    // `PACGA` reads a key the kernel redraws at every exec and that cannot be turned off: a
    // program that executes it differs run to run, so its sites are a label.
    if cfg!(target_arch = "aarch64") {
        r["labels"]["pacga_sites"] = json!(e.insn.counted_sites);
    }
    r
}

/// Did the run's operation-log self-check fail (`result.json`'s `self_check`)?
pub fn self_check_failed(r: &Value) -> bool {
    r["self_check"]["verdict"] == "fail"
}

/// A run's exit status: its outcome's, and at least 2 when the self-check failed: the outcome
/// stands, and the run still says that Patina found a defect of its own.
pub fn run_exit(outcome: Outcome, r: &Value) -> u8 {
    if self_check_failed(r) {
        outcome.exit().max(2)
    } else {
        outcome.exit()
    }
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
    // x86_64 names the model; arm64 gives the implementer and part numbers.
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |k: &str| {
        info.lines()
            .find(|l| l.split(':').next().is_some_and(|f| f.trim() == k))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    };
    let cpu = field("model name")
        .or_else(|| {
            Some(format!(
                "implementer {} part {}",
                field("CPU implementer")?,
                field("CPU part")?
            ))
        })
        .unwrap_or_default();
    json!({ "kernel": kernel, "cpu": cpu, "arch": std::env::consts::ARCH })
}

/// This patina build: its version and the SHA-256 of its own binary. `run.json` and
/// `sweep.json` record it; a recorded run is re-executed only by the same build. Hashing the
/// binary costs more than a short run, so the hash is kept in `CACHE/build` under the
/// binary's file identity (device, inode, size, change time), which any rewrite changes.
pub fn build() -> Res<&'static str> {
    use std::os::unix::fs::MetadataExt;
    static B: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(b) = B.get() {
        return Ok(b);
    }
    let exe = std::env::current_exe().map_err(|e| format!("patina binary: {e}"))?;
    let m = std::fs::metadata(&exe).map_err(|e| format!("patina binary: {e}"))?;
    let key = format!(
        "{} {} {} {}.{}",
        m.dev(),
        m.ino(),
        m.size(),
        m.ctime(),
        m.ctime_nsec()
    );
    let cache = crate::launch::cache_dir().join("build");
    let cached = std::fs::read_to_string(&cache).ok().and_then(|t| {
        let (k, h) = t.rsplit_once(' ')?;
        (k == key && h.len() == 64).then(|| h.to_string())
    });
    let hash = match cached {
        Some(h) => h,
        None => {
            let h = crate::config::sha256_file(&exe)?;
            // Best effort; a torn read of it fails the length check and hashes again.
            let _ = std::fs::create_dir_all(crate::launch::cache_dir())
                .and_then(|_| std::fs::write(&cache, format!("{key} {h}")));
            h
        }
    };
    let b = format!("{} {hash}", env!("CARGO_PKG_VERSION"));
    Ok(B.get_or_init(|| b))
}

/// Refuse a run (its `run.json`, read from `at`) made by another patina build: a run repeats
/// only under the build that made it.
pub fn same_build(run: &Value, at: &Path) -> Res<()> {
    let this = build()?;
    if run["patina"] == this {
        return Ok(());
    }
    let short = |b: &str| match b.split_once(' ') {
        Some((v, h)) => format!("{v} ({})", h.chars().take(12).collect::<String>()),
        None => b.to_string(),
    };
    // A run.json from before 0.8.0 records only the version.
    let was = run["patina"]
        .as_str()
        .or(run["version"].as_str())
        .unwrap_or("?");
    Err(format!(
        "{}: made by patina {}, this is patina {}; replay it with that build (install.sh --version {}) or run the seed again with this one",
        at.display(),
        short(was),
        short(this),
        was.split(' ').next().unwrap_or("?")
    ))
}

/// `run.json`: the request, with the fault plan resolved from the seed (`faults`).
pub fn run_json(
    cfg: &Config,
    program: &Program,
    nodes: &[Program],
    plan: &crate::faults::Plan,
) -> Res<Value> {
    let mut v = json!({
        "schema": RUN_SCHEMA,
        "patina": build()?,
        "seed": cfg.seed,
        "config": cfg,
        "faults": plan.json(),
        "program": program,
        "host": host_facts(),
        "inputs": crate::inputs::fingerprints(cfg),
    });
    // Each node's program, as `program` (`cfg.nodes` order).
    if !nodes.is_empty() {
        v["node_programs"] = json!(nodes);
    }
    Ok(v)
}

/// The run's outcome: its own, or for a run that ended ok, the checker's finding or error.
/// A conditional `--ok-exit` status counts when one of its fault classes injected in the run.
pub fn classified(e: &RunEnd) -> Classified {
    let fired = crate::report::fired(&json!({"faults": e.faults, "sdk": e.sdk.json()}));
    let met = |o: &&crate::config::OkExit| o.when.iter().any(|c| fired.contains(c));
    let ok: Vec<u8> = e
        .ok_exit
        .iter()
        .filter(|o| o.when.is_empty() || met(o))
        .map(|o| o.status)
        .collect();
    let mut own = classify(&e.verdict, &ok);
    if own.stop == "ok-exit" {
        if let Some(o) = e.ok_exit.iter().filter(met).find(|o| {
            Some(i64::from(o.status)) == e.verdict.exit_status
                && !e
                    .ok_exit
                    .iter()
                    .any(|u| u.when.is_empty() && u.status == o.status)
        }) {
            let why: Vec<&String> = o.when.iter().filter(|c| fired.contains(*c)).collect();
            own.message = format!(
                "the program exited {}, a status --ok-exit allows when {} injected",
                o.status,
                why.iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    with_check(own, e.check.as_ref())
}

/// A run's outcome given its own and its checker's verdict.
pub fn with_check(own: Classified, check: Option<&crate::check::Verdict>) -> Classified {
    use crate::check::Kind;
    match (check, own.outcome) {
        (Some(k), Outcome::Ok) => match k.verdict {
            Kind::Fail => Classified::new(Outcome::Violation, "check", k.line()),
            Kind::Error | Kind::Pending => Classified::new(
                Outcome::Error,
                "check",
                k.message.clone().unwrap_or_default(),
            ),
            Kind::Pass | Kind::NotJudged | Kind::NotRun => own,
        },
        _ => own,
    }
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
    if self_check_failed(r) {
        println!(
            "self-check failed (a Patina defect; the outcome above is the program's own): {}",
            r["self_check"]["detail"].as_str().unwrap_or("")
        );
    }
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
    if let Some(l) = rewrite_line(&r["rewrite"]) {
        println!("{l}");
    }
    if let Some(l) = nodes_line(&r["nodes"]) {
        println!("{l}");
    }
    let ok = r["outcome"] == "ok";
    if let Some(p) = partition_line(&r["nodes"]).filter(|_| !ok) {
        println!("{p}");
    }
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
    if let Some(l) = tmpfs_line(r) {
        println!("{l}");
    }
    let check = &r["check"];
    if check.is_object() && check["verdict"] != "not-run" {
        match check["verdict"].as_str() {
            Some("pass") => println!("check: pass"),
            Some("not-judged") => println!(
                "check: not judged: {}",
                check["detail"].as_str().unwrap_or("")
            ),
            _ => {}
        }
        println!(
            "checker output: {}",
            dir.join(crate::check::OUTPUT).display()
        );
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
    if images.is_empty() && n("images_dropped") > 0 {
        s.push_str("(none listed)");
    } else if images.is_empty() {
        // `--preempt points` alone: no image was built with them.
        s.push_str("none built in");
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

/// The `patina run` line for result.json's `rewrite` (`--preempt points`): points taken, the
/// switches that walked on (`compute-walk`), and per image rewritten the share of its sites patched and of its text left dark.
/// `nodes: primary 10.0.0.2 running, backup 10.0.0.3 exit 1; net: 2 cuts, 2 heals, 1 held,
/// none cut at the end` (a run with nodes; each node's output is in `node/NAME/inc-K/`).
pub fn nodes_line(n: &Value) -> Option<String> {
    let list = n["list"].as_array()?;
    let nodes: Vec<String> = list
        .iter()
        .skip(1)
        .map(|v| {
            let end = &v["end"];
            let downs = v["downs"].as_array().map_or(&[][..], |d| d.as_slice());
            let incs = v["incarnations"].as_u64().unwrap_or(1);
            // Down at the end: its last incarnation ended (a kill, or an `ok-exit` exit).
            let last = downs
                .last()
                .filter(|d| d["incarnation"].as_u64() == Some(incs.saturating_sub(1)));
            let end = if let Some(d) = last.filter(|d| d["exit"].is_null() && d["signal"].is_null())
            {
                format!("down ({})", d["how"].as_str().unwrap_or("?"))
            } else if let Some(x) = end["exit"].as_u64() {
                format!("exit {x}")
            } else if let Some(sig) = end["signal"].as_i64() {
                format!("killed by {}", crate::outcome::signal_name(sig))
            } else {
                end.as_str().unwrap_or("running").to_string()
            };
            let restarts = match downs.len() {
                0 => String::new(),
                n => format!(
                    " after {n} down{}, {incs} incarnation{}",
                    if n == 1 { "" } else { "s" },
                    if incs == 1 { "" } else { "s" }
                ),
            };
            format!(
                "{} {} {end}{restarts}",
                v["name"].as_str().unwrap_or("?"),
                v["address"].as_str().unwrap_or("?")
            )
        })
        .collect();
    let net = &n["net"];
    let cut = net["cut_at_end"].as_array().map_or(0, |a| a.len());
    let parts = match n["partitions_drawn"].as_u64() {
        Some(p) => format!("; {p} partitions drawn"),
        None => String::new(),
    };
    Some(format!(
        "nodes: {}; net: {} cuts, {} heals, {} held, {}{parts}",
        nodes.join(", "),
        net["cuts"],
        net["heals"],
        net["held"],
        if cut == 0 {
            "none cut at the end".to_string()
        } else {
            format!("{cut} links cut at the end")
        }
    ))
}

pub fn rewrite_line(w: &Value) -> Option<String> {
    let images = w["images"].as_array()?;
    let n = |k: &str| w[k].as_u64().unwrap_or(0);
    let planned: Vec<String> = images
        .iter()
        .filter(|i| i["status"] == "planned")
        .take(IMAGES_SHOWN)
        .map(|i| {
            let name = i["path"].as_str().unwrap_or("");
            format!(
                "{} {}% of {} sites, {}% dark",
                name.rsplit('/').next().unwrap_or(name),
                i["covered_pct"],
                commas(i["sites"].as_u64().unwrap_or(0)),
                i["dark_pct"]
            )
        })
        .collect();
    let all = images.iter().filter(|i| i["status"] == "planned").count();
    let mut s = format!("load-time points: {} taken", commas(n("points")));
    if n("walks") > 0 {
        s.push_str(&format!(
            " ({} taken after a walk of {} instructions in all)",
            plural(n("walks"), "switch"),
            commas(n("walk_steps"))
        ));
    }
    s.push_str(&format!("; {} rewritten", plural(all as u64, "image")));
    if !planned.is_empty() {
        s.push_str(&format!(" ({}", planned.join("; ")));
        if all > IMAGES_SHOWN {
            s.push_str(&format!("; and {} more in result.json", all - IMAGES_SHOWN));
        }
        s.push(')');
    }
    let other = images.len() - all;
    if other > 0 {
        s.push_str(&format!(
            "; {} without a plan",
            plural(other as u64, "file")
        ));
    }
    if n("unplanned") > 0 {
        s.push_str(&format!(
            "; {} unpatched (JIT, shared or unplanned memory: no points there)",
            plural(n("unplanned"), "executable mapping")
        ));
    }
    if n("dropped") > 0 {
        s.push_str(&format!(
            "; {} dropped (the program wrote, moved or unmapped its text)",
            plural(n("dropped"), "plan")
        ));
    }
    if n("restored") > 0 {
        s.push_str(&format!(
            "; {} put back part of a plan (the rest keeps its points)",
            plural(n("restored"), "change")
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

/// The hint for a sandbox tmpfs the guest filled, or nothing.
pub fn tmpfs_line(r: &Value) -> Option<String> {
    let n = r["tmpfs"]["enospc"].as_u64().filter(|&n| n > 0)?;
    let b = r["tmpfs"]["bytes"].as_u64().unwrap_or(0);
    Some(format!(
        "sandbox tmpfs full: {n} file call{} answered ENOSPC; /work, /tmp and copied mounts hold {} each (--tmpfs-bytes, [run] tmpfs-bytes)",
        if n == 1 { "" } else { "s" },
        if b.is_multiple_of(1 << 20) {
            format!("{} MiB", b >> 20)
        } else {
            format!("{b} bytes")
        }
    ))
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
