//! What was done to the program: `result.json`'s `faults` object.
//!
//! - `plan`: the resolved settings (`faults::Plan::resolved`).
//! - `counts`: per configured class, the calls it could act on (`eligible`) and the faults
//!   it injected. Eligibility is counted where the class is consulted: in the runtime's
//!   injector (`proto::faults::Kind`), at crash points, and on the wire (reads of sent data
//!   for resets, connections for connect faults, deliveries for delay, chunking and
//!   partitions, FINs for half-close delays). Zero eligible means the class had nothing to act on.
//! - `injected`: the sum of the classes' `injected` (crashes included), all incarnations. The
//!   report of an earlier failed fsync to another descriptor is an event, not a new fault. A
//!   sync failed by `fs-error-permille` counts for `fs-error`, one failed by
//!   `fsync-error-permille` for `fsync-error`.
//! - `recent`: the last `RECENT` events before the run stopped, each with its call, its
//!   object (the `/work` path, or `pipe`, `unix`, `memory`, `tcp:PORT`) and what was
//!   returned; a crash is an event too, with what it did to `/work`.

use crate::faults::Plan;
use crate::launch::IncEnd;
use crate::result::NET_FIELDS;
use proto::faults::*;
use proto::rec::{Rec, RecKind, REC_SIZE};
use proto::wire::{
    INJ_NET_BLACKOUT, INJ_NET_BLACKOUT_DROP, INJ_NET_CHUNK, INJ_NET_CUT, INJ_NET_DROP, INJ_NET_DUP,
    INJ_NET_REFUSE, INJ_NET_REORDER, INJ_NET_RESET, INJ_NET_TIMEOUT,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

/// Events kept in `recent`.
pub const RECENT: usize = 20;

/// The class an `Injected` record counts for (`None`: a consequence, not an injection).
/// `by` is `args[3]`: for a failed sync, the class that failed it.
fn class_of(kind: u64, class: u64, by: u64) -> Option<&'static str> {
    Some(match kind {
        INJ_FSYNC_EIO if by == SYNC_BY_FS_ERROR => "fs-error",
        INJ_ERROR if class == FClass::Mem as u64 => "mem-error",
        INJ_ERROR => "fs-error",
        INJ_SHORT => "fs-short",
        INJ_DELAY => "fs-delay",
        INJ_ENOSPC => "enospc",
        INJ_FSYNC_EIO => "fsync-error",
        INJ_MEM_LIMIT => "mem-limit",
        INJ_PATH_SWAP => "path-swap",
        INJ_NET_RESET => "net-reset",
        INJ_NET_REFUSE => "net-connect-refuse",
        INJ_NET_TIMEOUT => "net-connect-timeout",
        INJ_NET_BLACKOUT => "net-blackout",
        INJ_NET_CHUNK => "net-chunk",
        INJ_NET_DROP => "net-drop",
        INJ_NET_DUP => "net-dup",
        INJ_NET_REORDER => "net-reorder",
        INJ_NET_BLACKOUT_DROP => "net-blackout",
        INJ_NET_CUT => "partition",
        proto::node::INJ_NODE_KILL => "crash",
        proto::node::INJ_NODE_PAUSE => "pause",
        _ => return None,
    })
}

fn errno_name(e: u64) -> String {
    match e {
        4 => "EINTR".into(),
        5 => "EIO".into(),
        11 => "EAGAIN".into(),
        12 => "ENOMEM".into(),
        23 => "ENFILE".into(),
        24 => "EMFILE".into(),
        28 => "ENOSPC".into(),
        122 => "EDQUOT".into(),
        n => format!("errno {n}"),
    }
}

/// Every class `faults.counts` may name.
pub const CLASSES: &[&str] = &[
    "clock",
    "crash",
    "enospc",
    "fs-delay",
    "fs-error",
    "fs-short",
    "fsync-error",
    "mem-error",
    "mem-limit",
    "net-blackout",
    "net-chunk",
    "net-connect-refuse",
    "net-connect-timeout",
    "net-delay",
    "net-drop",
    "net-dup",
    "net-halfclose",
    "net-reorder",
    "net-reset",
    "partition",
    "path-swap",
    "pause",
];

/// The plan class each setting belongs to.
pub fn class_of_key(k: &str) -> Option<&'static str> {
    Some(match k {
        "fs-error-permille" | "fs-error-at" => "fs-error",
        "fs-short-permille" => "fs-short",
        "fs-delay-permille" => "fs-delay",
        "fsync-error-permille" | "fsync-error-at" => "fsync-error",
        "enospc-after-bytes" => "enospc",
        "mem-error-permille" | "mem-error-at" => "mem-error",
        "mem-limit-mb" => "mem-limit",
        "path-swap-permille" | "path-swap-at" => "path-swap",
        "net-delay-ms" => "net-delay",
        "net-chunk-max" => "net-chunk",
        "net-reset-permille" => "net-reset",
        "net-connect-refuse-permille" => "net-connect-refuse",
        "net-connect-timeout-permille" => "net-connect-timeout",
        "net-blackout" => "net-blackout",
        "partition-gap-ms" => "partition",
        "net-halfclose-delay-ms" => "net-halfclose",
        "net-drop-permille" => "net-drop",
        "net-dup-permille" => "net-dup",
        "net-reorder-permille" => "net-reorder",
        "crash" => "crash",
        "pause-gap-ms" => "pause",
        "clock-skew-ms" => "clock",
        _ => return None,
    })
}

/// The faults of a chain of incarnations, folded as they end.
#[derive(Default)]
pub struct Faults {
    recent: VecDeque<Value>,
    by_class: BTreeMap<&'static str, u64>,
    eligible: [u64; NKIND],
    crash_points: u64,
    crashes: u64,
    /// Nodes' machine crashes at a crash point (counted among `crash_points` already).
    point_kills: u64,
    /// A run with nodes: their names (the driver first), and the seed's partitions that acted
    /// on traffic.
    pub nodes: Vec<String>,
    parts_acted: u64,
    /// Realtime reads on nodes with `clock-skew-ms`, and those under an offset (`clock`).
    clock_reads: (u64, u64),
    /// With nodes: the link faults' chances on the links they act on (`faulted_links`), which
    /// replace the run-wide counters as their eligible counts.
    link_elig: Option<[u64; 5]>,
}

impl Faults {
    fn push(&mut self, v: Value) {
        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(v);
    }

    /// Fold incarnation `k`: its counters and the `Injected` records of its boundary log.
    pub fn add_incarnation(&mut self, inc: &Path, k: u64, end: &IncEnd) {
        for (a, b) in self.eligible.iter_mut().zip(end.eligible) {
            *a += b;
        }
        self.crash_points += end.crash_points;
        let b = std::fs::read(inc.join("boundary.log")).unwrap_or_default();
        // Decoded as needed, never all at once: a log can be as large as [run] log-limit.
        let chunks = b.as_chunks::<REC_SIZE>().0;
        let rec = |i: usize| chunks.get(i).map(|c| Rec::from_bytes(c));
        if let Some(n) = end.nodes.as_ref() {
            self.parts_acted += n["partitions_acted"].as_u64().unwrap_or(0);
            self.clock_reads.0 += n["clock_reads"].as_u64().unwrap_or(0);
            self.clock_reads.1 += n["clock_reads_offset"].as_u64().unwrap_or(0);
        }
        if let Some(f) = end.nodes.as_ref().map(|n| &n["faulted_links"]) {
            if f.is_object() {
                let e = self.link_elig.get_or_insert([0; 5]);
                for (i, k) in ["connections", "chunks", "fins", "sends", "datagrams"]
                    .iter()
                    .enumerate()
                {
                    e[i] += f[k].as_u64().unwrap_or(0);
                }
            }
        }
        for (i, c) in chunks.iter().enumerate() {
            let r = &Rec::from_bytes(c);
            if r.kind != RecKind::Injected as u8 {
                continue;
            }
            let (fault, mut e) = injected(r, rec(i + 1), rec(i + 2));
            name_link(&mut e, &self.nodes);
            if r.args[0] == INJ_NET_CUT {
                // The sides by name.
                let names = |bits: u64| -> Value {
                    (0..64)
                        .filter(|b| bits & (1 << b) != 0)
                        .map(|b| self.nodes.get(b).cloned().unwrap_or_else(|| b.to_string()))
                        .collect()
                };
                e["a"] = names(r.args[3]);
                e["b"] = names(r.args[4]);
            }
            if r.args[0] == proto::node::INJ_NODE_KILL || r.args[0] == proto::node::INJ_NODE_PAUSE {
                let k = r.args[1] as usize;
                e["node"] = json!(self.nodes.get(k).cloned().unwrap_or_else(|| k.to_string()));
            }
            if r.args[0] == proto::node::INJ_NODE_KILL {
                self.point_kills += (r.args[4] != 0) as u64;
            }
            if let Some(c) = fault {
                *self.by_class.entry(c).or_default() += 1;
            }
            e["incarnation"] = json!(k);
            e["seq"] = json!(r.seq);
            e["vtime_ms"] = json!(r.vclock_ns / 1_000_000);
            self.push(e);
        }
    }

    /// Crash points the nodes passed (`nodes.list[].crash_points`): the `crash` class's
    /// eligible calls, as a single machine's are.
    pub fn add_points(&mut self, n: u64) {
        self.crash_points += n;
    }

    /// What node `k`'s machine crash at the end of its boot `boot` did to its disk: on the
    /// crash's event, as a single machine's crash has it.
    pub fn node_lost(&mut self, k: usize, boot: u64, lost: Value) {
        let name = self.nodes.get(k).cloned().unwrap_or_default();
        if let Some(e) = self.recent.iter_mut().find(|e| {
            e["node"] == name.as_str() && e["node_incarnation"] == boot && e["kind"] == "machine"
        }) {
            if let Some(p) = lost["paths"].get(0) {
                e["object"] = p.clone();
            }
            e["lost"] = lost;
        }
    }

    /// A crash ended incarnation `k`; `lost` says what it did to `/work` (machine crashes).
    pub fn add_crash(
        &mut self,
        k: u64,
        kind: &str,
        seq: u64,
        point: u64,
        vclock: u64,
        lost: Option<Value>,
    ) {
        self.crashes += 1;
        let mut e = json!({
            "incarnation": k,
            "seq": seq,
            "point": point,
            "vtime_ms": vclock / 1_000_000,
            "fault": "crash",
            "kind": kind,
        });
        if let Some(l) = lost {
            if let Some(p) = l["paths"].get(0) {
                e["object"] = p.clone();
            }
            e["lost"] = l;
        }
        self.push(e);
    }

    /// The `faults` object of `result.json`.
    pub fn json(&self, plan: &Plan, net: &[u64; NET_FIELDS]) -> Value {
        let mut counts = serde_json::Map::new();
        let got = |c: &str| self.by_class.get(c).copied().unwrap_or(0);
        for (k, v) in &plan.resolved {
            // A node's own setting (`KEY@NODE`) counts under its key's class.
            let Some(c) = class_of_key(crate::faults::split_scope(k).0) else {
                continue;
            };
            if *v == "off" || counts.contains_key(c) {
                continue;
            }
            let kind = KIND_NAMES.iter().position(|n| *n == c);
            let (connections, chunks, fins, sends, datagrams) = match self.link_elig {
                Some(e) => (e[0], e[1], e[2], e[3], e[4]),
                None => (net[0], net[2], net[11], net[12], net[13]),
            };
            let (eligible, injected) = match c {
                // Machine crashes at crash points; node kills (by the seed) at drawn times.
                "crash" => (
                    self.crash_points + got(c) - self.point_kills,
                    self.crashes + got(c),
                ),
                // One delay per TCP delivery and per datagram sent.
                "net-delay" => (chunks + datagrams, chunks + datagrams),
                "net-halfclose" => (fins, fins),
                // Drawn for every read of data a guest sent, not once per connection.
                "net-reset" => (sends, got(c)),
                "net-chunk" => (chunks, got(c)),
                "net-blackout" => (chunks + datagrams, got(c)),
                // Partitions drawn, and those that held, lost or kept back something.
                "partition" => (self.parts_acted, got(c)),
                // Every pause the seed made.
                "pause" => (got(c), got(c)),
                // Realtime clock reads on the nodes with a skew, and those it moved.
                "clock" => self.clock_reads,
                // Drawn once for every datagram sent.
                "net-drop" | "net-dup" | "net-reorder" => (datagrams, got(c)),
                _ if c.starts_with("net-") => (connections, got(c)),
                _ => (kind.map_or(0, |i| self.eligible[i]), got(c)),
            };
            counts.insert(
                c.into(),
                json!({ "eligible": eligible, "injected": injected }),
            );
        }
        // The total is the sum of the classes, so the two always agree.
        let injected: u64 = counts
            .values()
            .map(|v| v["injected"].as_u64().unwrap_or(0))
            .sum();
        json!({
            "plan": plan.json(),
            "counts": counts,
            "injected": injected,
            "recent": self.recent,
        })
    }
}

/// What an `Injected` record `r` did, as `recent` shows it apart from where it happened
/// (`incarnation`, `seq`, `vtime_ms`): its class (`None`: a consequence, not an injection) and
/// the event's fields. `n1` and `n2` are the records after it (its `Name` records, if any).
pub fn injected(r: &Rec, n1: Option<Rec>, n2: Option<Rec>) -> (Option<&'static str>, Value) {
    let [kind, class, value, by, port, _] = r.args;
    let fault = class_of(kind, class, by);
    // A wire or datagram fault in a run with nodes: the link, as node numbers (named by the
    // caller, `name_link`).
    let link = (INJ_NET_RESET..INJ_NET_CUT)
        .contains(&kind)
        .then(|| proto::wire::inj_link_of(class))
        .flatten();
    let mut e = json!({
        "fault": fault.unwrap_or(if kind == INJ_FSYNC_REPORT { "fsync-report" } else { "other" }),
    });
    let named = |n: Option<Rec>| n.filter(|n| n.kind == RecKind::Name as u8 && n.seq == r.seq);
    match named(n1) {
        Some(n) => {
            let (bytes, len, cut) = n.name_bytes();
            let s = String::from_utf8_lossy(&bytes[..len]);
            e["object"] = json!(if cut {
                format!("...{s}")
            } else {
                s.into_owned()
            });
            e["pid"] = json!(n.ret);
            e["thread"] = json!(r.slot);
            e["call"] = json!(proto::table::name(r.nr as u64));
        }
        // Datagram faults: the datagram, its source and destination ports.
        None if (INJ_NET_DROP..=INJ_NET_BLACKOUT_DROP).contains(&kind) => {
            e["object"] = json!(format!("udp:{port}"));
            e["datagram"] = json!(by);
            e["from"] = json!(r.args[5]);
            e["to"] = json!(port);
            e["call"] = json!(proto::table::name(r.nr as u64));
        }
        // A partition: its ordinal, shape and length (the sides are named by the caller).
        None if kind == INJ_NET_CUT => {
            e["object"] = json!("net");
            e["partition"] = json!(value);
            e["shape"] = json!(proto::node::shape_name(class));
            e["length_ms"] = json!(r.args[5] / 1_000_000);
        }
        // A node's processes killed or its machine crashed by the seed (named by the caller):
        // the incarnation it ended, and the crash point it came at.
        None if kind == proto::node::INJ_NODE_KILL => {
            e["kind"] = json!(if by == 1 { "machine" } else { "process" });
            e["node_incarnation"] = json!(value);
            if port != 0 {
                e["point"] = json!(port);
            }
        }
        // The wire's records: the connection's server port.
        // A node paused by the seed (named by the caller): its incarnation, the pause's
        // ordinal on the node, and its length.
        None if kind == proto::node::INJ_NODE_PAUSE => {
            e["node_incarnation"] = json!(value);
            e["pause"] = json!(by);
            e["length_ms"] = json!(port / 1_000_000);
        }
        None => e["object"] = json!(format!("tcp:{port}")),
    }
    if kind == INJ_PATH_SWAP {
        let target = named(n2).map(|n| {
            let (bytes, len, _) = n.name_bytes();
            String::from_utf8_lossy(&bytes[..len]).into_owned()
        });
        let (m, _, back) = proto::swap::decode(class);
        e["swap"] = json!(match m {
            proto::swap::MUT_SYMLINK => "symlink",
            proto::swap::MUT_RENAME => "rename",
            _ => "remove",
        });
        e["target"] = json!(target);
        e["after"] = json!(proto::table::name(r.args[4]));
        e["after_seq"] = json!(r.args[5]);
        e["put_back"] = json!(back);
    }
    if let Some((from, to)) = link {
        e["link"] = json!([from, to]);
    }
    match kind {
        INJ_ERROR | INJ_FSYNC_REPORT => e["errno"] = json!(errno_name(value)),
        INJ_FSYNC_EIO => e["errno"] = json!("EIO"),
        INJ_SHORT => e["count"] = json!(value),
        INJ_DELAY => e["delay_ns"] = json!(value),
        INJ_ENOSPC if value == 0 => e["errno"] = json!("ENOSPC"),
        INJ_ENOSPC => e["count"] = json!(value),
        INJ_MEM_LIMIT => {
            e["errno"] = json!("ENOMEM");
            e["bytes"] = json!(value);
        }
        INJ_NET_CHUNK => e["bytes"] = json!(value),
        INJ_NET_DROP | INJ_NET_DUP | INJ_NET_BLACKOUT_DROP => e["bytes"] = json!(value),
        INJ_NET_REORDER => e["delay_ns"] = json!(value),
        _ => {}
    }
    (fault, e)
}

/// An event's `link` (node numbers, `injected`) by the nodes' names.
pub fn name_link(e: &mut Value, nodes: &[String]) {
    if let Some(l) = e["link"].as_array() {
        let n: Vec<Value> = l
            .iter()
            .map(|k| {
                let k = k.as_u64().unwrap_or(0) as usize;
                json!(nodes.get(k).cloned().unwrap_or_else(|| k.to_string()))
            })
            .collect();
        e["link"] = json!(n);
    }
}

/// What a machine crash did to `/work`: the paths whose post-crash state differs from the
/// live tree at the crash (missing, changed, or back from before), the first few named.
pub fn lost(
    live: &crate::durability::tree::Tree,
    post: &crate::durability::tree::Tree,
    work: &str,
) -> Value {
    let (mut missing, mut changed, mut back) = (0, 0, 0);
    let mut paths = vec![];
    let note = |p: &[u8], paths: &mut Vec<String>| {
        if paths.len() < 8 {
            paths.push(format!("{work}/{}", String::from_utf8_lossy(p)));
        }
    };
    for (p, n) in &live.nodes {
        match post.nodes.get(p) {
            None => {
                missing += 1;
                note(p, &mut paths);
            }
            Some(m) if m.kind != n.kind || m.data.first_difference(&n.data).is_some() => {
                changed += 1;
                note(p, &mut paths);
            }
            Some(_) => {}
        }
    }
    for p in post.nodes.keys().filter(|p| !live.nodes.contains_key(*p)) {
        back += 1;
        note(p, &mut paths);
    }
    json!({ "missing": missing, "changed": changed, "back": back, "paths": paths })
}

/// One event as a line of the human summary.
pub fn line(f: &Value) -> String {
    let s = |k: &str| match &f[k] {
        Value::Null => None,
        Value::String(x) => Some(x.clone()),
        x => Some(x.to_string()),
    };
    let mut out = format!(
        "seq {} t={}ms {}",
        s("seq").unwrap_or_default(),
        s("vtime_ms").unwrap_or_default(),
        s("fault").unwrap_or_default()
    );
    if let Some(d) = s("datagram") {
        // A datagram fault reads as what happened to which datagram.
        let what = match s("fault").as_deref() {
            Some("net-drop") => "dropped",
            Some("net-dup") => "duplicated",
            Some("net-reorder") => "held back",
            _ => "lost in a blackout:",
        };
        out = format!(
            "seq {} t={}ms {} {what} datagram {d} from :{} to :{}",
            s("seq").unwrap_or_default(),
            s("vtime_ms").unwrap_or_default(),
            s("fault").unwrap_or_default(),
            s("from").unwrap_or_default(),
            s("to").unwrap_or_default(),
        );
        if let Some(b) = s("bytes") {
            out.push_str(&format!(" ({b} bytes)"));
        }
        if let Some(n) = s("delay_ns") {
            out.push_str(&format!(" by {n} ns"));
        }
        return out;
    }
    if let Some(n) = s("partition") {
        let side = |k: &str| {
            let v: Vec<&str> = f[k]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str())
                .collect();
            format!("{{{}}}", v.join(","))
        };
        let arrow = if f["shape"] == "oneway" { "->" } else { "|" };
        return format!(
            "seq {} t={}ms partition {n} {} {} {arrow} {} for {}ms",
            s("seq").unwrap_or_default(),
            s("vtime_ms").unwrap_or_default(),
            s("shape").unwrap_or_default(),
            side("a"),
            side("b"),
            s("length_ms").unwrap_or_default(),
        );
    }
    if let Some(m) = s("swap") {
        // A path swap reads as what happened to the path between the two calls.
        let (t, call) = (
            s("target").unwrap_or_default(),
            s("call").unwrap_or_default(),
        );
        let what = match m.as_str() {
            "symlink" => format!("became a symlink to {t}"),
            "rename" => format!("was replaced by {t}, renamed into its place"),
            _ => format!("was renamed away to {t}"),
        };
        out.push_str(&format!(
            " {} {what} between {} (seq {}) and {call}{}",
            s("object").unwrap_or_default(),
            s("after").unwrap_or_default(),
            s("after_seq").unwrap_or_default(),
            if f["put_back"] == true {
                ", put back after it where the call allowed"
            } else {
                ""
            }
        ));
        return out;
    }
    for k in [
        "node",
        "kind",
        "point",
        "pause",
        "length_ms",
        "call",
        "object",
        "errno",
        "count",
        "bytes",
        "delay_ns",
    ] {
        if let Some(v) = s(k) {
            out.push_str(&format!(" {k}={v}"));
        }
    }
    if f["lost"].is_object() {
        out.push_str(&format!(
            " lost: {} missing, {} changed, {} back",
            f["lost"]["missing"], f["lost"]["changed"], f["lost"]["back"]
        ));
    }
    out
}
