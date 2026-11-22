//! What `sweep --crash-points` knows of a run's crash points besides their count: each point's
//! place, read back from the run's operation log (one disk's, `oplog.meta`), so that a sweep
//! can sample them by machine and kind of operation (`--crash-points=N`) and find a second machine's
//! points after a first crash (`[sweep] crash-pairs`). Written per run as `points.json` before a
//! sweep prunes the run's logs.
//!
//! The runtime offers a crash point after each record it appends to a disk's log and before
//! each sync call (`rt::oplog`, `inject::crash_point`); the supervisor's own records (the base,
//! a killed process's shared mappings, a `Crash`) offer none. So the points of a disk are, in
//! the order of its records (`places`): for each system call (one sequence number) that
//! recorded a sync, one before its records, then one after each record. The places are used
//! only when their number is the count the runtime made (`crash_points`); otherwise the run's
//! points are `placed: false`: sampled by machine alone, and no pair is taken after them.
//!
//! No point is left out as the same as another: a point before a sync right after a write has
//! the disk of the point before it, but a crash there takes the next sequence number, so every
//! draw keyed by it after the crash differs, stores through a shared mapping made between the
//! two calls are logged at one and not the other, and what the crash keeps is drawn with
//! another key (on `ack2.py`, seed 1, the point after b's write loses the put and the point
//! before its fsync does not).

use proto::oplog::{OpKind, OpRec, KIND_MASK, OPREC_SIZE};
use serde_json::{json, Value};
use std::path::Path;

/// The file a run directory holds it in.
pub const FILE: &str = "points.json";

/// One crash point: the sequence number of its system call, the kind of operation at it (the
/// record it follows, or `before-KIND` for the one before a sync), and how many of the
/// runtime's records come before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    pub seq: u64,
    pub kind: String,
    pub records: usize,
}

fn is_sync(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Fsync | OpKind::FsyncDir | OpKind::FsyncFail | OpKind::Sync
    )
}

/// The records of a disk's log the runtime appended, in order: (sequence number, kind).
fn runtime_records(meta: &[u8]) -> Vec<(u64, OpKind)> {
    meta.as_chunks::<OPREC_SIZE>()
        .0
        .iter()
        .map(|c| OpRec::from_bytes(c))
        .filter(|r| r.pid != 0)
        .filter_map(|r| Some((r.seq, OpKind::from_u32(r.kind & KIND_MASK)?)))
        .filter(|(_, k)| *k != OpKind::Crash)
        .collect()
}

/// The crash points of a disk, from its log's records (`runtime_records`).
pub fn places(recs: &[(u64, OpKind)]) -> Vec<Place> {
    let mut out: Vec<Place> = vec![];
    let mut i = 0;
    while i < recs.len() {
        let seq = recs[i].0;
        let n = recs[i..].iter().take_while(|r| r.0 == seq).count();
        let call = &recs[i..i + n];
        if let Some(s) = call.iter().find(|r| is_sync(r.1)) {
            out.push(Place {
                seq,
                kind: format!("before-{}", s.1.name()),
                records: i,
            });
        }
        for (k, r) in call.iter().enumerate() {
            out.push(Place {
                seq,
                kind: r.1.name().to_string(),
                records: i + k + 1,
            });
        }
        i += n;
    }
    out
}

/// The places of the disk whose log is in `dir`, if there are `count` of them (the runtime's
/// count of its points).
pub fn read_places(dir: &Path, count: u64) -> Option<Vec<Place>> {
    let meta = std::fs::read(dir.join("oplog.meta")).ok()?;
    let p = places(&runtime_records(&meta));
    (p.len() as u64 == count).then_some(p)
}

/// The directory of a disk's first boot in a run: the one machine's (`machine` empty) or a
/// machine's.
fn disk(run: &Path, machine: &str) -> std::path::PathBuf {
    if machine.is_empty() {
        run.join("boot-1")
    } else {
        run.join("machine").join(machine).join("boot-1")
    }
}

/// A base's `points.json`: for each machine with points (`""`: the one machine), their number,
/// whether they were placed, and if so each point's kind (in order, from point 1).
pub fn describe(run: &Path, points: &[(String, u64)]) -> Value {
    let mut machines = serde_json::Map::new();
    for (n, k) in points {
        let v = match read_places(&disk(run, n), *k) {
            Some(p) => json!({
                "points": k,
                "placed": true,
                "kinds": p.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(),
            }),
            None => json!({"points": k, "placed": false}),
        };
        machines.insert(n.clone(), v);
    }
    json!({ "machines": machines })
}

/// A first crash's child (machine `a` crashed at a point; `others` counted theirs): for each other
/// machine, its first `k` points after the crash, each with its kind and the runtime's records
/// before it: `{"after": {"b": [[J, KIND, RECORDS], ...]}, "placed": {"b": true}}`. A machine whose points cannot
/// be placed, or a crash whose `Crash` record is not found, gives none.
pub fn window(run: &Path, a: &str, others: &[(String, u64)], k: usize) -> Value {
    let crash = crash_seq(run, a);
    let mut after = serde_json::Map::new();
    let mut placed = serde_json::Map::new();
    for (b, count) in others {
        let p = crash.and_then(|c| Some((c, read_places(&disk(run, b), *count)?)));
        placed.insert(b.clone(), json!(p.is_some()));
        let w: Vec<Value> = p
            .map(|(c, p)| {
                (1u64..)
                    .zip(p)
                    .filter(|(_, x)| x.seq > c)
                    .take(k)
                    .map(|(j, x)| json!([j, x.kind, x.records]))
                    .collect()
            })
            .unwrap_or_default();
        after.insert(b.clone(), Value::Array(w));
    }
    json!({"after": after, "placed": placed})
}

fn crash_seq(run: &Path, machine: &str) -> Option<u64> {
    let meta = std::fs::read(disk(run, machine).join("oplog.meta")).ok()?;
    meta.as_chunks::<OPREC_SIZE>()
        .0
        .iter()
        .map(|c| OpRec::from_bytes(c))
        .find(|r| OpKind::from_u32(r.kind & KIND_MASK) == Some(OpKind::Crash))
        .map(|r| r.seq)
}

/// How many of the runtime's records the disk of `machine`'s first boot in `run` holds before its
/// first `Crash` record, leaving out the shared mappings the crash itself logged just before
/// it (`None`: no crash).
pub fn records_before_crash(run: &Path, machine: &str) -> Option<usize> {
    let meta = std::fs::read(disk(run, machine).join("oplog.meta")).ok()?;
    let recs: Vec<OpRec> = meta
        .as_chunks::<OPREC_SIZE>()
        .0
        .iter()
        .map(|c| OpRec::from_bytes(c))
        .collect();
    let kind = |r: &OpRec| OpKind::from_u32(r.kind & KIND_MASK);
    let c = recs.iter().position(|r| kind(r) == Some(OpKind::Crash))?;
    let mut before: Vec<&OpRec> = recs[..c].iter().filter(|r| r.pid != 0).collect();
    while before
        .last()
        .is_some_and(|r| kind(r) == Some(OpKind::MmapDirty))
    {
        before.pop();
    }
    Some(before.len())
}

/// SplitMix64: the sweep's own seeded order, the same on every host and run.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn hash(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
}

/// A kind of operation and its items.
type Stratum = (String, Vec<usize>);

/// Lists merged into one order: every list gives its first before any gives a second (the
/// lists in a seeded order), and after that each in proportion to its length.
fn interleave(lists: Vec<Vec<usize>>, key: u64) -> Vec<usize> {
    let mut rank: Vec<u64> = (0..lists.len() as u64).map(|i| mix(key ^ mix(i))).collect();
    // The rank of a list among the others: its place in the seeded order.
    let order = {
        let mut o: Vec<usize> = (0..lists.len()).collect();
        o.sort_by_key(|&i| rank[i]);
        o
    };
    for (r, &i) in order.iter().enumerate() {
        rank[i] = r as u64;
    }
    let mut keyed: Vec<(u64, u64, u64, usize)> = vec![];
    for (li, g) in lists.iter().enumerate() {
        let m = g.len() as u128;
        for (j, &i) in g.iter().enumerate() {
            // Round 0 for every list's first; then j/m, compared exactly as j * 2^64 / m.
            let at = if j == 0 {
                (0, 0)
            } else {
                (1, ((j as u128) << 64) / m)
            };
            keyed.push((at.0, at.1 as u64, rank[li], i));
        }
    }
    keyed.sort();
    keyed.into_iter().map(|x| x.3).collect()
}

/// The order a sample of `items` is taken in, stratified twice by `stratum(i)`: `(group,
/// kind)`, a machine (or a pair of machines) and a kind of operation. Within a group each kind is
/// shuffled by `key` and the kinds interleaved (`interleave`), then the groups interleaved:
/// every group gives an item before any gives a second, every kind of a group one before any
/// of its kinds gives a second, and after that each in proportion to its size. Any prefix is a
/// seeded sample so stratified, and a longer prefix holds a shorter one (a sweep run again with
/// a larger limit adds to the runs it has).
pub fn sample_order<T>(
    items: &[T],
    key: u64,
    stratum: impl Fn(&T) -> (String, String),
) -> Vec<usize> {
    let mut groups: Vec<(String, Vec<Stratum>)> = vec![];
    for (i, x) in items.iter().enumerate() {
        let (g, k) = stratum(x);
        let gi = match groups.iter().position(|x| x.0 == g) {
            Some(gi) => gi,
            None => {
                groups.push((g, vec![]));
                groups.len() - 1
            }
        };
        let kinds = &mut groups[gi].1;
        match kinds.iter_mut().find(|x| x.0 == k) {
            Some(s) => s.1.push(i),
            None => kinds.push((k, vec![i])),
        }
    }
    let lists = groups
        .into_iter()
        .map(|(g, kinds)| {
            let gk = key ^ hash(&g);
            let shuffled = kinds
                .into_iter()
                .map(|(k, mut l)| {
                    // Fisher-Yates from the kind's own stream.
                    let mut st = gk ^ hash(&k).rotate_left(17);
                    for i in (1..l.len()).rev() {
                        st = mix(st);
                        l.swap(i, (st % (i as u64 + 1)) as usize);
                    }
                    l
                })
                .collect();
            interleave(shuffled, gk)
        })
        .collect();
    interleave(lists, key)
}

/// The sweep's key for one base's sample: its seed and case.
pub fn sample_key(seed: u64, case: Option<usize>, level: u64) -> u64 {
    mix(seed ^ mix(case.map_or(u64::MAX, |c| c as u64)) ^ level.wrapping_mul(0x5851_f42d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_has_a_point_before_its_records() {
        use OpKind::*;
        // write; fsync; a rename; a sync call that also logs a mapping's pages; a sync first.
        let recs = [
            (5, Fsync),
            (9, Write),
            (10, Fsync),
            (20, Rename),
            (21, MmapDirty),
            (21, Fsync),
        ];
        let p = places(&recs);
        let kinds: Vec<&str> = p.iter().map(|x| x.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "before-Fsync",
                "Fsync",
                "Write",
                "before-Fsync",
                "Fsync",
                "Rename",
                "before-Fsync",
                "MmapDirty",
                "Fsync"
            ]
        );
        let seqs: Vec<u64> = p.iter().map(|x| x.seq).collect();
        assert_eq!(seqs, [5, 5, 9, 10, 10, 20, 21, 21, 21]);
        // The records before each point: a point before a sync comes before its call's.
        let records: Vec<usize> = p.iter().map(|x| x.records).collect();
        assert_eq!(records, [0, 1, 2, 2, 3, 4, 4, 5, 6]);
    }

    #[test]
    fn a_sample_is_stratified_seeded_and_nested() {
        // Machine a: 90 writes, 9 fsyncs, 1 rename; machine b: 10 writes.
        let items: Vec<(&str, &str)> = (0..110)
            .map(|i| match i {
                0 => ("a", "rename"),
                1..=9 => ("a", "fsync"),
                10..=99 => ("a", "write"),
                _ => ("b", "write"),
            })
            .collect();
        let st = |x: &(&str, &str)| (x.0.to_string(), x.1.to_string());
        let o = sample_order(&items, 7, st);
        let mut all = o.clone();
        all.sort();
        assert_eq!(all, (0..110).collect::<Vec<_>>());
        // Both machines in the first two; every kind of a in a's first three.
        let machines: std::collections::BTreeSet<&str> =
            o[..2].iter().map(|&i| items[i].0).collect();
        assert_eq!(machines.len(), 2);
        let a: Vec<usize> = o.iter().copied().filter(|&i| items[i].0 == "a").collect();
        let kinds: std::collections::BTreeSet<&str> = a[..3].iter().map(|&i| items[i].1).collect();
        assert_eq!(kinds.len(), 3);
        // Then about in proportion: of a's first 20, 2 or 3 fsyncs; of the first 22, 2 of b.
        let fsyncs = a[..20].iter().filter(|&&i| items[i].1 == "fsync").count();
        assert!((2..=3).contains(&fsyncs), "{fsyncs}");
        let b = o[..22].iter().filter(|&&i| items[i].0 == "b").count();
        assert!((2..=3).contains(&b), "{b}");
        // Seeded: the same key gives the same order, another key another.
        assert_eq!(o, sample_order(&items, 7, st));
        assert_ne!(o, sample_order(&items, 8, st));
    }
}
