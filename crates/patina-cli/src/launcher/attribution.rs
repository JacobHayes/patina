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
    INJ_NET_CHUNK, INJ_NET_PARTITION, INJ_NET_REFUSE, INJ_NET_RESET, INJ_NET_TIMEOUT,
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
        INJ_NET_RESET => "net-reset",
        INJ_NET_REFUSE => "net-connect-refuse",
        INJ_NET_TIMEOUT => "net-connect-timeout",
        INJ_NET_PARTITION => "net-partition",
        INJ_NET_CHUNK => "net-chunk",
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

/// The plan class each setting belongs to.
fn class_of_key(k: &str) -> Option<&'static str> {
    Some(match k {
        "fs-error-permille" | "fs-error-at" => "fs-error",
        "fs-short-permille" => "fs-short",
        "fs-delay-permille" => "fs-delay",
        "fsync-error-permille" | "fsync-error-at" => "fsync-error",
        "enospc-after-bytes" => "enospc",
        "mem-error-permille" | "mem-error-at" => "mem-error",
        "mem-limit-mb" => "mem-limit",
        "net-delay-ms" => "net-delay",
        "net-chunk-max" => "net-chunk",
        "net-reset-permille" => "net-reset",
        "net-connect-refuse-permille" => "net-connect-refuse",
        "net-connect-timeout-permille" => "net-connect-timeout",
        "net-partition" => "net-partition",
        "net-halfclose-delay-ms" => "net-halfclose",
        "crash" => "crash",
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
        // Decoded as needed, never all at once: a log can be as large as --log-limit.
        let chunks = b.as_chunks::<REC_SIZE>().0;
        for (i, c) in chunks.iter().enumerate() {
            let r = &Rec::from_bytes(c);
            if r.kind != RecKind::Injected as u8 {
                continue;
            }
            let [kind, class, value, by, port, _] = r.args;
            let fault = class_of(kind, class, by);
            if let Some(c) = fault {
                *self.by_class.entry(c).or_default() += 1;
            }
            let mut e = json!({
                "incarnation": k,
                "seq": r.seq,
                "vtime_ms": r.vclock_ns / 1_000_000,
                "fault": fault.unwrap_or(if kind == INJ_FSYNC_REPORT { "fsync-report" } else { "other" }),
            });
            let name = chunks
                .get(i + 1)
                .map(|c| Rec::from_bytes(c))
                .filter(|n| n.kind == RecKind::Name as u8 && n.seq == r.seq);
            match name {
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
                // The wire's records: the connection's server port.
                None => e["object"] = json!(format!("tcp:{port}")),
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
                _ => {}
            }
            self.push(e);
        }
    }

    /// A crash ended incarnation `k`; `lost` says what it did to `/work` (machine crashes).
    pub fn add_crash(&mut self, k: u64, kind: &str, seq: u64, vclock: u64, lost: Option<Value>) {
        self.crashes += 1;
        let mut e = json!({
            "incarnation": k,
            "seq": seq,
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
            let Some(c) = class_of_key(k) else { continue };
            if *v == "off" || counts.contains_key(c) {
                continue;
            }
            let kind = KIND_NAMES.iter().position(|n| *n == c);
            let (connections, chunks, fins, sends) = (net[0], net[2], net[11], net[12]);
            let (eligible, injected) = match c {
                "crash" => (self.crash_points, self.crashes),
                "net-delay" => (chunks, chunks),
                "net-halfclose" => (fins, fins),
                // Drawn for every read of data a guest sent, not once per connection.
                "net-reset" => (sends, got(c)),
                "net-chunk" | "net-partition" => (chunks, got(c)),
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
    for k in [
        "kind", "call", "object", "errno", "count", "bytes", "delay_ns",
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
