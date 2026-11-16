//! The crash/restart loop:
//!
//! ```text
//! incarnation k: guest runs; a crash point fires -> verdict "crash", all guests killed,
//!                live tree exported to RUN/inc-k/live.tree
//! launcher:      process crash: next /in = the live tree
//!                machine crash: next /in = materialise(oplog of inc-k, seed, model)
//!                written to RUN/inc-k/post-crash/
//! incarnation k+1: fresh sandbox, same command, PATINA_INCARNATION=k+1, the boundary sequence
//!                number continues, virtual time continues plus a seeded reboot gap
//! ```
//!
//! Crashes are drawn only while incarnations remain: the last permitted incarnation runs
//! with crashes off. An `-at` crash fires once. With `faults-in-recovery=0` faults other
//! than crashes stop after the first crash.

use crate::cli::Res;
use crate::config::Opts;
use crate::durability::log::OpLog;
use crate::durability::materialise::{materialise, replay, unlogged_pages};
use crate::durability::tree::Tree;
use crate::launch::{run_incarnation, Start};
use crate::result::RunEnd;
use proto::faults::{CRASH_MACHINE, CRASH_NONE};
use proto::rec::{Rec, RecKind, REC_SIZE};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::time::Instant;

/// The last injected faults listed in `result.json` (the total is always given).
const FAULTS_RECENT: usize = 20;

fn inj_name(k: u64) -> &'static str {
    use proto::faults::*;
    match k {
        INJ_ERROR => "error",
        INJ_SHORT => "short",
        INJ_DELAY => "delay",
        INJ_ENOSPC => "enospc",
        INJ_FSYNC_EIO => "fsync-eio",
        INJ_FSYNC_REPORT => "fsync-report",
        proto::wire::INJ_NET_RESET => "net-reset",
        proto::wire::INJ_NET_REFUSE => "net-connect-refuse",
        proto::wire::INJ_NET_TIMEOUT => "net-connect-timeout",
        proto::wire::INJ_NET_PARTITION => "net-partition",
        proto::wire::INJ_NET_CHUNK => "net-chunk",
        _ => "other",
    }
}

/// The `Injected` boundary records of an incarnation, as JSON objects.
pub fn injected(inc: &Path, k: u64) -> Vec<Value> {
    let b = fs::read(inc.join("boundary.log")).unwrap_or_default();
    let mut out = vec![];
    for c in b.as_chunks::<REC_SIZE>().0 {
        let r = Rec::from_bytes(c);
        if r.kind != RecKind::Injected as u8 {
            continue;
        }
        let [kind, _class, value, _, _, _] = r.args;
        let v = if kind == proto::faults::INJ_DELAY || kind == proto::faults::INJ_SHORT {
            json!(value)
        } else {
            json!(value as i64)
        };
        out.push(json!({
            "incarnation": k,
            "seq": r.seq,
            "call": proto::table::name(r.nr as u64),
            "kind": inj_name(kind),
            "value": v,
        }));
    }
    out
}

/// Parse the crash verdict detail `KIND SEQ VCLOCK SUBPOINT`.
fn crash_detail(d: &str) -> Option<(String, u64, u64)> {
    let mut f = d.split_whitespace();
    let kind = f.next()?.to_string();
    let seq = f.next()?.parse().ok()?;
    let vclock = f.next()?.parse().ok()?;
    Some((kind, seq, vclock))
}

/// The tree the next incarnation starts from.
pub fn next_tree(
    inc: &Path,
    machine: bool,
    seed: u64,
    key: u64,
    model: crate::durability::materialise::Model,
) -> Res<Tree> {
    if !machine {
        return Tree::read_archive(&inc.join("live.tree"));
    }
    let log = OpLog::load(inc)?;
    // Unlogged pages of shared mappings can exist only for inodes with a `MmapShared`
    // record; without one the live tree and a full replay are not needed.
    let extra = if log
        .ops
        .iter()
        .any(|o| o.kind == proto::oplog::OpKind::MmapShared)
    {
        let live = Tree::read_archive(&inc.join("live.tree"))?;
        let replayed = replay(&log)?;
        unlogged_pages(&log, &replayed, &live)
    } else {
        vec![]
    };
    materialise(&log, u64::MAX, seed, key, model, &extra)
}

pub fn run_chain(o: &Opts, out: &Path, cpu: usize, no_personality: bool) -> Res<RunEnd> {
    let t0 = Instant::now();
    if out.join("result.json").exists() || out.join("inc-0").exists() {
        return Err(format!("{} already holds a run", out.display()));
    }
    let deadline = t0 + std::time::Duration::from_secs(o.cfg.timeout);
    let max = o.cfg.max_incarnations.max(1);
    let mut cfg = o.plan.faults;
    let mut seq0 = 0;
    let mut vclock0 = 0;
    let mut crashes = vec![];
    let mut faults: std::collections::VecDeque<Value> = Default::default();
    let mut nfaults = 0usize;
    let mut digests = vec![];
    let (mut traps, mut switches) = (0, 0);
    let mut io = [0u64; 5];
    let mut insn = crate::result::InsnCounts::default();
    let mut net = [0u64; crate::result::NET_FIELDS];
    let mut unix_sockets = 0;
    let mut pmu = [0u64; proto::ctl::PMU_FIELDS];
    let mut sdk = crate::result::SdkReport::default();
    let mut refused: Vec<String> = vec![];
    let mut root = o.cfg.work.clone();
    let mut k = 0;
    loop {
        let inc = out.join(format!("inc-{k}"));
        cfg.incarnation = k;
        cfg.crash_enabled = (cfg.crash_kind != CRASH_NONE && k + 1 < max) as u64;
        let start = Start {
            k,
            root: root.as_deref(),
            seq0,
            vclock0,
            faults: cfg,
            deadline,
        };
        let end = run_incarnation(o, &inc, cpu, no_personality, &start)?;
        digests.push(end.digest);
        traps += end.traps;
        switches += end.switches;
        for (a, b) in io.iter_mut().zip(end.io) {
            *a += b;
        }
        insn.add(&end.insn);
        crate::result::net_add(&mut net, &end.net);
        unix_sockets += end.unix_sockets;
        sdk.add(end.sdk);
        // A `setup-complete` mark holds for the incarnations after it.
        cfg.fault_after_seq = end.fault_after_seq;
        for (i, (a, b)) in pmu.iter_mut().zip(end.pmu).enumerate() {
            *a = if proto::ctl::PMU_NAMES[i] == "max_skid" {
                (*a).max(b)
            } else {
                *a + b
            };
        }
        for r in end.refused {
            if !refused.contains(&r) {
                refused.push(r);
            }
        }
        let inj = injected(&inc, k);
        nfaults += inj.len();
        for f in inj {
            if faults.len() == FAULTS_RECENT {
                faults.pop_front();
            }
            faults.push_back(f);
        }
        if end.verdict.class != "crash" {
            let digest = if digests.len() == 1 {
                format!("{:016x}", digests[0])
            } else {
                let b: Vec<u8> = digests.iter().flat_map(|d| d.to_le_bytes()).collect();
                format!("{:016x}", proto::rec::hash_bytes(0x696e_6361_726e, &b))
            };
            return Ok(RunEnd {
                verdict: end.verdict,
                seed: o.cfg.seed,
                incarnations: k + 1,
                digest,
                traps,
                switches,
                refused,
                wall_ms: t0.elapsed().as_millis() as u64,
                crashes,
                faults_recent: faults.into(),
                faults_count: nfaults,
                io,
                insn,
                net,
                unix_sockets,
                pmu: (crate::launch::pmu_status(o), pmu),
                sdk,
            });
        }
        let (kind, seq, vclock) = crash_detail(&end.verdict.detail)
            .ok_or_else(|| format!("bad crash verdict: {}", end.verdict.detail))?;
        let machine = cfg.crash_kind == CRASH_MACHINE;
        let t_tree = crate::launch::mono_ns();
        let tree = next_tree(&inc, machine, o.cfg.seed, seq, o.fs_model)?;
        let t_written = crate::launch::mono_ns();
        let post = inc.join("post-crash");
        tree.write_dir(&post)
            .map_err(|e| format!("{}: {e}", post.display()))?;
        let t_digest = crate::launch::mono_ns();
        let mut c = json!({
            "incarnation": k,
            "kind": kind,
            "seq": seq,
            "vclock_ns": vclock,
            "tree_digest": tree.digest(),
            "paths": tree.nodes.len(),
        });
        if machine {
            c["model"] = json!(o.fs_model.name());
        }
        crashes.push(c);
        if std::env::var_os("PATINA_TIMING").is_some() {
            // the launcher's crash work: build the next tree, write it, digest it.
            eprintln!(
                "patina-timing crash inc={k} tree={t_tree} written={t_written} digest={t_digest} end={}",
                crate::launch::mono_ns()
            );
        }
        // The next incarnation.
        root = Some(post);
        seq0 = end.seq;
        let gap = 1_000_000_000
            + proto::draw(o.cfg.seed, proto::Stream::Crash, 0x7265_626f_6f74 ^ k) % 60_000_000_000;
        vclock0 = end.vclock_ns.max(vclock) + gap;
        if cfg.crash_at != 0 {
            // An `-at` crash fires once.
            cfg.crash_kind = CRASH_NONE;
            cfg.crash_at = 0;
        }
        if !o.plan.faults_in_recovery {
            cfg.faults_off = 1;
        }
        k += 1;
    }
}
