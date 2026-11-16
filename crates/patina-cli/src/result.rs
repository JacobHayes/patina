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
    json!({
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
    })
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

/// The human summary: outcome and stop, message, the guest's exit, the run directory and
/// how to replay it.
pub fn print_human(r: &Value, dir: &Path) {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    println!("{} ({}): {}", s("outcome"), s("stop"), s("message"));
    let g = &r["guest"];
    if let Some(x) = g["exit"].as_i64() {
        match g["signal"].as_i64() {
            Some(sig) => println!("guest: killed by signal {sig}"),
            None => println!("guest: exit {x}"),
        }
    }
    // Under a finding: the last faults done to the program before it.
    let recent = r["faults"]["recent"].as_array().map_or(&[][..], |v| v);
    if r["exit"] == 1 && !recent.is_empty() {
        println!("last injected faults ({} in all):", r["faults"]["injected"]);
        for f in &recent[recent.len().saturating_sub(5)..] {
            println!("  {}", crate::launcher::attribution::line(f));
        }
    }
    println!("run directory: {}", dir.display());
    println!("replay: patina replay {}", dir.display());
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
    pub fn read(t: &proto::sdk::SdkTab) -> SdkReport {
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
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
            violation: t.violation_parts().map(|(l, d)| (s(l), s(d))),
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
