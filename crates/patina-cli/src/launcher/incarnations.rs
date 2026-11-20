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
//! with crashes off. An `-at` crash fires once. With `faults-in-recovery = false` faults
//! other than crashes stop after the first crash. A run with crashes on ends with the
//! operation log's self-check (`self_check`).

use super::attribution::{lost, Faults};
use crate::cli::Res;
use crate::config::Opts;
use crate::durability::log::OpLog;
use crate::durability::materialise::materialise;
use crate::durability::tree::Tree;
use crate::launch::{run_incarnation, shm_carrier, Start};
use crate::result::RunEnd;
use proto::faults::{CRASH_MACHINE, CRASH_NONE};
use serde_json::json;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Instant;

/// Parse the crash verdict detail `KIND SEQ VCLOCK SUBPOINT`.
fn crash_detail(d: &str) -> Option<(String, u64, u64)> {
    let mut f = d.split_whitespace();
    let kind = f.next()?.to_string();
    let seq = f.next()?.parse().ok()?;
    let vclock = f.next()?.parse().ok()?;
    Some((kind, seq, vclock))
}

/// Replay every disk's operation log (each incarnation's, each node's) and compare it with
/// the live tree it exported (`durability::check`). `PATINA_TEST_OPLOG_CORRUPT=1` inverts the bytes of incarnation
/// 0's logged data first, so a test can show how a mismatch is reported.
fn self_check(run: &Path) -> Res<()> {
    if std::env::var_os("PATINA_TEST_OPLOG_CORRUPT").is_some() {
        let p = run.join("inc-0/oplog.data");
        let b: Vec<u8> = std::fs::read(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?
            .iter()
            .map(|x| !x)
            .collect();
        std::fs::write(&p, b).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    for inc in crate::durability::check::disks(run) {
        crate::durability::check::check_inc(&inc)
            .map_err(|e| format!("operation log self-check: {e}"))?;
    }
    Ok(())
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
    materialise(&log, u64::MAX, seed, key, model)
}

pub fn run_chain(o: &Opts, out: &Path, cpu: usize, no_personality: bool) -> Res<RunEnd> {
    let t0 = Instant::now();
    if out.join("result.json").exists() || out.join("inc-0").exists() {
        return Err(format!("{} already holds a run", out.display()));
    }
    let deadline = t0 + std::time::Duration::from_secs(o.cfg.timeout);
    let max = o.plan.max_incarnations.max(1);
    let mut cfg = o.plan.faults;
    let mut seq0 = 0;
    let mut vclock0 = 0;
    let mut crashes = vec![];
    let mut faults = Faults::default();
    if !o.cfg.nodes.is_empty() {
        faults.nodes = std::iter::once("driver".to_string())
            .chain(o.cfg.nodes.iter().map(|n| n.name.clone()))
            .collect();
    }
    let mut digests = vec![];
    let (mut traps, mut switches) = (0, 0);
    let mut io = [0u64; 5];
    let mut insn = crate::result::InsnCounts::default();
    let mut net = [0u64; crate::result::NET_FIELDS];
    let mut unix_sockets = 0;
    let mut tmpfs_full = 0;
    let mut shadow_bytes = 0;
    let mut pmu = [0u64; proto::ctl::PMU_FIELDS];
    let mut sdk = crate::result::SdkReport::default();
    let mut sched = [0u64; proto::ctl::SCHED_FIELDS];
    let mut compute = [0u64; 5];
    let mut images = crate::result::ComputeImages::default();
    let mut refused: Vec<String> = vec![];
    let mut missing: Vec<(u8, String)> = vec![];
    let mut root = o.cfg.work.clone();
    let mut log_used = 0;
    let mut k = 0;
    let shm = shm_carrier()?;
    let mut plans = [0u64; proto::ctl::PLAN_FIELDS];
    let planner = planner(o)?;
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
            log_used,
            shm: shm.as_raw_fd(),
            planner: planner.clone(),
        };
        let end = run_incarnation(o, &inc, cpu, no_personality, &start)?;
        faults.add_incarnation(&inc, k, &end);
        log_used += end.log_bytes;
        digests.push(end.digest);
        traps += end.traps;
        switches += end.switches;
        for (a, b) in io.iter_mut().zip(end.io) {
            *a += b;
        }
        insn.add(&end.insn);
        crate::result::net_add(&mut net, &end.net);
        unix_sockets += end.unix_sockets;
        tmpfs_full += end.tmpfs_full;
        shadow_bytes = shadow_bytes.max(end.shadow_bytes);
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
        for (a, b) in sched.iter_mut().zip(end.sched) {
            *a += b;
        }
        for (a, b) in plans.iter_mut().zip(end.plans) {
            *a += b;
        }
        images.add(end.compute_images);
        for (i, (a, b)) in compute.iter_mut().zip(end.compute).enumerate() {
            // [1] is the kinds named, a bit set.
            *a = if i == 1 { *a | b } else { *a + b };
        }
        for r in end.refused {
            if !refused.contains(&r) {
                refused.push(r);
            }
        }
        for m in end.missing {
            if !missing.contains(&m) {
                missing.push(m);
            }
        }
        if end.verdict.class != "crash" {
            // With crashes on, the operation log checks itself: replaying it must give the
            // live tree of every incarnation. A difference is a tracker bug, reported next to
            // the run's outcome (`result::run_exit`), which stays the program's own.
            let verdict = end.verdict;
            let self_check = (o.plan.faults.crash_kind != CRASH_NONE || !o.cfg.nodes.is_empty())
                .then(|| self_check(out));
            let digest = if digests.len() == 1 {
                format!("{:016x}", digests[0])
            } else {
                let b: Vec<u8> = digests.iter().flat_map(|d| d.to_le_bytes()).collect();
                format!("{:016x}", proto::rec::hash_bytes(0x696e_6361_726e, &b))
            };
            return Ok(RunEnd {
                verdict,
                seed: o.cfg.seed,
                incarnations: k + 1,
                digest,
                traps,
                switches,
                refused,
                missing: crate::launch::not_in_sandbox(o, &missing),
                wall_ms: t0.elapsed().as_millis() as u64,
                crashes,
                faults: faults.json(&o.plan, &net),
                io,
                insn,
                net,
                unix_sockets,
                tmpfs: [o.cfg.tmpfs_bytes, tmpfs_full],
                shadow_bytes,
                pmu: o.cfg.pmu.on.then_some(pmu),
                sdk,
                sched: crate::result::SchedCounts {
                    pause_sites: insn.patched[proto::insn::SiteKind::Pause as usize],
                    stats: sched,
                },
                compute: crate::result::ComputeCounts {
                    hellos: compute[0],
                    events: compute[2],
                    switches: compute[3],
                    deadline_stops: compute[4],
                    gap: o.plan.compute_gap,
                    images,
                },
                check: None,
                ok_exit: o.cfg.ok_exit.clone(),
                rewrite: planner.as_ref().map(|p| crate::result::RewriteReport {
                    images: p.images(),
                    plans,
                    walk: o.plan.compute_walk,
                }),
                self_check,
                nodes: end.nodes.clone(),
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
            "point": end.crash_points,
            "vclock_ns": vclock,
            "tree_digest": tree.digest(),
            "paths": tree.nodes.len(),
        });
        let mut what = None;
        if machine {
            c["model"] = json!(o.fs_model.name());
            let live = Tree::read_archive(&inc.join("live.tree"))?;
            what = Some(lost(&live, &tree, o.cfg.work_path()));
        }
        crashes.push(c);
        faults.add_crash(k, &kind, seq, end.crash_points, vclock, what);
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
        let (lo, hi) = o.plan.restart_gap_ns;
        let draw = proto::draw(o.cfg.seed, proto::Stream::Crash, 0x7265_626f_6f74 ^ k);
        let gap = lo + if hi > lo { draw % (hi - lo) } else { 0 };
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

/// With `--preempt points`, the run's plans: made for the program and the libraries it names
/// before the sandbox starts (on the CPUs this process may use, at most 8), the rest when the
/// runtime asks (`launcher::plans`).
fn planner(o: &Opts) -> Res<Option<std::sync::Arc<crate::launcher::plans::Planner>>> {
    if !o.cfg.points {
        return Ok(None);
    }
    let p = crate::launcher::plans::Planner::new(
        crate::result::build()?,
        crate::rewrite::default_threads(),
    );
    crate::rewrite::cache::warm_all(&p, &o.program.host);
    Ok(Some(std::sync::Arc::new(p)))
}
