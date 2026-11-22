//! `ext4-ordered` (semantics borrowed from the Patina crash model's module
//! documentation: ext4, `data=ordered`, delayed allocation, `auto_da_alloc`, 5-second
//! commits).
//!
//! State while replaying the log prefix:
//!
//! - `live`: the page cache (every operation fully applied).
//! - `disk`: what the last journal commit made durable (namespace, attributes, and per file
//!   the data image of that commit), plus in-place block writes since.
//! - per file `Data`: `run`, the data image the next commit records (data written back so
//!   far, with the size the running transaction holds); `dirty`, bytes written in the page
//!   cache and not written back; `failed`, bytes whose writeback failed (never durable);
//!   `freed`, blocks released since the last commit (truncate, punch); `trunc_zero` for
//!   `auto_da_alloc` on close.
//! - the running transaction: the inodes it touches and the virtual time of its first
//!   change.
//!
//! Writeback of a file copies its dirty, non-failed bytes into `run`; for blocks that were
//! allocated at the last commit and not freed since, it also writes them in place into
//! `disk` (an overwrite of an allocated block needs no journal). A write that extends the
//! file within its last allocated block raises the running size at once with no data (the
//! "zeros" case). A commit makes `disk` the live namespace and attributes with each file's
//! `run` image.
//!
//! Commit points: `Fsync(I)` (after writing back I) when I is in the transaction;
//! `FsyncDir(D)` when D is; `Sync` (writeback of everything, then commit); a transaction
//! older than 5 virtual seconds, observed at the next record or at the crash; and one
//! seeded spontaneous commit at a drawn cut position among the records after the last
//! forced commit, which writes back everything first (`data=ordered`: a commit carries the
//! data its metadata refers to, and the kernel may have flushed any file by then).
//!
//! At the crash: every dirty block that is written in place (allocated at the last commit, not freed)
//! survives as old or new by one draw per block. Bytes of a failed writeback never reach
//! `disk`.
//!
//! Cost. File images are `Content` (shared 4 KiB blocks), so a commit or a snapshot
//! copies no file data; a commit copies only the inodes and directories changed since the
//! previous one (`Fs::changed`, `Ext4::run_dirty`); writeback and tearing work on runs of
//! bytes, not single bytes. The log is replayed once: the state at a forced commit is kept
//! (a snapshot at most every "state size" records, so snapshots cost O(log) in total), and
//! a drawn spontaneous cut after the last forced commit replays only from that snapshot.

use super::content::Content;
use super::log::Op;
use super::materialise::{crash_time, torn, Fs, BLOCK};
use super::tree::{Kind, Tree};
use proto::oplog::{OpKind, FSYNC_MSYNC, FSYNC_NO_COMMIT};
use std::collections::{BTreeMap, BTreeSet};

pub const COMMIT_NS: u64 = 5_000_000_000;
const RENAME_EXCHANGE: u64 = 2;
const FALLOC_KEEP_SIZE: u64 = 1;
const FALLOC_PUNCH_HOLE: u64 = 2;
const FALLOC_ZERO_RANGE: u64 = 0x10;
/// Draw key for the spontaneous cut (distinct from any inode number used for tears).
const CUT: u64 = u64::MAX;

type Words = [u64; 64];

/// Set bits `[s, e)` (offsets inside one block) of a block's words to `v`.
fn mark_words(w: &mut Words, s: u64, e: u64, v: bool) {
    let mut x = s;
    while x < e {
        let i = (x / 64) as usize;
        let lo = x % 64;
        let hi = (e - (x - lo)).min(64);
        let m = if hi - lo == 64 {
            u64::MAX
        } else {
            ((1u64 << (hi - lo)) - 1) << lo
        };
        if v {
            w[i] |= m;
        } else {
            w[i] &= !m;
        }
        x += hi - lo;
    }
}

/// The runs `[s, e)` of set bits in a block's words, ascending.
fn runs(w: &Words) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = vec![];
    for (i, &word) in w.iter().enumerate() {
        let mut v = word;
        while v != 0 {
            let s = v.trailing_zeros() as u64;
            let len = (!(v >> s)).trailing_zeros() as u64;
            let (a, b) = (i as u64 * 64 + s, i as u64 * 64 + s + len);
            match out.last_mut() {
                Some(r) if r.1 == a => r.1 = b,
                _ => out.push((a, b)),
            }
            v = if s + len >= 64 {
                0
            } else {
                v & !(((1u64 << len) - 1) << s)
            };
        }
    }
    out
}

/// A byte set, one 4096-bit map per block.
#[derive(Clone, Debug, Default)]
pub struct Bits(BTreeMap<u64, Box<Words>>);

impl Bits {
    pub fn set(&mut self, lo: u64, hi: u64) {
        let mut o = lo;
        while o < hi {
            let b = o / BLOCK;
            let e = hi.min((b + 1) * BLOCK);
            let w = self.0.entry(b).or_insert_with(|| Box::new([0; 64]));
            mark_words(w, o - b * BLOCK, e - b * BLOCK, true);
            o = e;
        }
    }
    pub fn clear(&mut self, lo: u64, hi: u64) {
        let blocks: Vec<u64> = self
            .0
            .range(lo / BLOCK..)
            .map(|(b, _)| *b)
            .take_while(|b| b * BLOCK < hi)
            .collect();
        for b in blocks {
            let w = self.0.get_mut(&b).unwrap();
            let (s, e) = (
                lo.max(b * BLOCK) - b * BLOCK,
                hi.min((b + 1) * BLOCK) - b * BLOCK,
            );
            mark_words(w, s, e, false);
            if w.iter().all(|v| *v == 0) {
                self.0.remove(&b);
            }
        }
    }
    pub fn union(&mut self, o: &Bits) {
        for (b, w) in &o.0 {
            let d = self.0.entry(*b).or_insert_with(|| Box::new([0; 64]));
            for i in 0..64 {
                d[i] |= w[i];
            }
        }
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn blocks(&self) -> Vec<u64> {
        self.0.keys().copied().collect()
    }
    /// The byte runs of block `b` that are in `self`, not in `minus`, and below `limit`,
    /// as absolute offsets.
    fn runs_in(&self, b: u64, minus: &Bits, limit: u64) -> Vec<(u64, u64)> {
        let Some(w) = self.0.get(&b) else {
            return vec![];
        };
        let base = b * BLOCK;
        if base >= limit {
            return vec![];
        }
        let mut m: Words = **w;
        if let Some(f) = minus.0.get(&b) {
            for i in 0..64 {
                m[i] &= !f[i];
            }
        }
        if limit < base + BLOCK {
            mark_words(&mut m, limit - base, BLOCK, false);
        }
        runs(&m)
            .into_iter()
            .map(|(s, e)| (base + s, base + e))
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
struct Data {
    run: Content,
    dirty: Bits,
    failed: Bits,
    freed: BTreeSet<u64>,
    trunc_zero: bool,
}

#[derive(Clone, Debug, Default)]
struct Ext4 {
    live: Fs,
    disk: Fs,
    data: BTreeMap<u64, Data>,
    txn: BTreeSet<u64>,
    txn_start: u64,
    /// Files whose `run` changed since the last commit.
    run_dirty: BTreeSet<u64>,
    /// Files that may have dirty bytes (a superset).
    dirty_inos: BTreeSet<u64>,
    /// Files that may have freed blocks (a superset).
    freed_inos: BTreeSet<u64>,
}

fn blocks_of(size: u64) -> u64 {
    size.div_ceil(BLOCK)
}

impl Ext4 {
    fn touch(&mut self, ino: u64, t: u64) {
        if ino == 0 {
            return;
        }
        if self.txn.is_empty() {
            self.txn_start = t;
        }
        self.txn.insert(ino);
    }

    fn is_file(&self, ino: u64) -> bool {
        self.live
            .inodes
            .get(&ino)
            .is_some_and(|i| i.kind == Kind::File)
    }

    fn data(&mut self, ino: u64) -> &mut Data {
        self.data.entry(ino).or_default()
    }

    /// Is block `b` of `ino` written in place (allocated at the last commit, not freed)?
    fn in_place(&self, ino: u64, b: u64) -> bool {
        self.disk.has(ino)
            && b < blocks_of(self.disk.size(ino))
            && !self.data.get(&ino).is_some_and(|d| d.freed.contains(&b))
    }

    fn writeback(&mut self, ino: u64, t: u64) {
        let Some(d) = self.data.get(&ino) else { return };
        if d.dirty.is_empty() {
            return;
        }
        self.dirty_inos.remove(&ino);
        let live = self
            .live
            .inodes
            .get(&ino)
            .map(|i| i.data.clone())
            .unwrap_or_default();
        let dirty = std::mem::take(&mut self.data.get_mut(&ino).unwrap().dirty);
        let disk_size = if self.disk.has(ino) {
            self.disk.size(ino)
        } else {
            0
        };
        let mut grew = false;
        let mut any = false;
        for b in dirty.blocks() {
            let place = self.in_place(ino, b);
            let d = self.data.get_mut(&ino).unwrap();
            for (lo, hi) in dirty.runs_in(b, &d.failed, live.len()) {
                if hi > d.run.len() {
                    d.run.resize(hi);
                    grew = true;
                }
                d.run.copy_from(&live, lo, hi);
                any = true;
                let h = hi.min(disk_size);
                if place && lo < h {
                    self.disk.copy_from(ino, &live, lo, h).unwrap();
                }
            }
        }
        if any {
            self.run_dirty.insert(ino);
        }
        if grew {
            self.touch(ino, t);
        }
    }

    fn writeback_all(&mut self, t: u64) {
        let inos: Vec<u64> = self.dirty_inos.iter().copied().collect();
        for i in inos {
            self.writeback(i, t);
        }
    }

    /// `disk` becomes the live namespace and attributes with each file's `run` image. Only
    /// what changed since the previous commit is copied: every other inode and directory is
    /// already equal in both.
    fn commit(&mut self) {
        let mut changed = std::mem::take(&mut self.live.changed);
        changed.append(&mut std::mem::take(&mut self.run_dirty));
        for ino in changed {
            match self.live.inodes.get(&ino) {
                Some(i) => {
                    let mut n = i.clone();
                    if n.kind == Kind::File {
                        n.data = self
                            .data
                            .get(&ino)
                            .map(|d| d.run.clone())
                            .unwrap_or_default();
                    }
                    self.disk.inodes.insert(ino, n);
                }
                None => {
                    self.disk.inodes.remove(&ino);
                }
            }
            match self.live.dirs.get(&ino) {
                Some(d) => {
                    self.disk.dirs.insert(ino, d.clone());
                }
                None => {
                    self.disk.dirs.remove(&ino);
                }
            }
        }
        self.disk.root = self.live.root;
        self.disk.owner = self.live.owner;
        for ino in std::mem::take(&mut self.freed_inos) {
            if let Some(d) = self.data.get_mut(&ino) {
                d.freed.clear();
            }
        }
        self.txn.clear();
    }

    /// The 5-second rule, observed at time `t`. Returns whether it committed.
    fn timer(&mut self, t: u64) -> bool {
        if !self.txn.is_empty() && t.saturating_sub(self.txn_start) >= COMMIT_NS {
            self.commit();
            return true;
        }
        false
    }

    /// Apply one record. Returns whether it forced a commit.
    fn step(&mut self, op: &Op) -> Result<bool, String> {
        let t = op.vclock_ns;
        let (a, ino) = (op.a, op.ino);
        let mut forced = false;
        if op.kind == OpKind::Rename
            && a[2] != 0
            && a[3] & RENAME_EXCHANGE == 0
            && self.is_file(ino)
        {
            // auto_da_alloc: replacing a name writes back the source's data first.
            self.writeback(ino, t);
        }
        self.live.apply(op)?;
        match op.kind {
            OpKind::Root => {}
            OpKind::Create | OpKind::Mkdir | OpKind::Symlink | OpKind::Link => {
                if op.kind == OpKind::Create && self.is_file(ino) {
                    self.data.entry(ino).or_default();
                }
                self.touch(ino, t);
                self.touch(a[0], t);
            }
            OpKind::Unlink | OpKind::Rmdir => {
                self.touch(ino, t);
                self.touch(a[0], t);
            }
            OpKind::Rename => {
                self.touch(ino, t);
                self.touch(a[0], t);
                self.touch(a[1], t);
                self.touch(a[2], t);
            }
            OpKind::Write | OpKind::MmapDirty => {
                let (off, len) = (a[0], a[1]);
                let end = off + len;
                self.dirty_inos.insert(ino);
                let d = self.data(ino);
                d.dirty.set(off, end);
                d.failed.clear(off, end);
                let rl = d.run.len();
                if rl > 0 && end > rl && end <= blocks_of(rl) * BLOCK {
                    // Extension inside the last allocated block: the size is journalled
                    // now, the data later.
                    d.run.resize(end);
                    self.run_dirty.insert(ino);
                    self.touch(ino, t);
                }
            }
            OpKind::Truncate => {
                let size = a[0];
                let disk_blocks = if self.disk.has(ino) {
                    blocks_of(self.disk.size(ino))
                } else {
                    0
                };
                let d = self.data(ino);
                d.run.resize(size);
                d.dirty.clear(size, u64::MAX);
                d.failed.clear(size, u64::MAX);
                let mut freed = false;
                for b in blocks_of(size)..disk_blocks {
                    d.freed.insert(b);
                    freed = true;
                }
                d.trunc_zero = size == 0;
                self.run_dirty.insert(ino);
                if freed {
                    self.freed_inos.insert(ino);
                }
                self.touch(ino, t);
            }
            OpKind::Fallocate => {
                let (mode, off, len) = (a[0], a[1], a[2]);
                let end = off + len;
                let mut changed = false;
                let mut freed = false;
                let d = self.data(ino);
                if mode & (FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0 {
                    d.run.zero(off, end);
                    let (fb, fe) = (off.div_ceil(BLOCK), end / BLOCK);
                    for b in fb..fe {
                        d.freed.insert(b);
                        freed = true;
                    }
                    // The partial blocks are zeroed through the page cache.
                    d.dirty.set(off, end.min(fb * BLOCK));
                    d.dirty.set((fe * BLOCK).max(off), end);
                    changed = true;
                }
                if mode & (FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE) == 0 && end > d.run.len() {
                    d.run.resize(end);
                    changed = true;
                }
                if freed {
                    self.freed_inos.insert(ino);
                }
                if changed {
                    self.dirty_inos.insert(ino);
                    self.run_dirty.insert(ino);
                    self.touch(ino, t);
                }
            }
            OpKind::SetAttr | OpKind::XattrSet | OpKind::XattrRemove => self.touch(ino, t),
            OpKind::MmapShared | OpKind::Crash => {}
            OpKind::Fsync => {
                self.writeback(ino, t);
                if (a[0] & FSYNC_NO_COMMIT == 0 || a[0] & FSYNC_MSYNC != 0)
                    && self.txn.contains(&ino)
                {
                    self.commit();
                    forced = true;
                }
            }
            OpKind::FsyncDir => {
                if self.txn.contains(&ino) {
                    self.commit();
                    forced = true;
                }
            }
            OpKind::FsyncFail => {
                let inos: Vec<u64> = if ino == 0 {
                    self.dirty_inos.iter().copied().collect()
                } else {
                    vec![ino]
                };
                for i in inos {
                    self.dirty_inos.remove(&i);
                    let d = self.data(i);
                    let dirty = std::mem::take(&mut d.dirty);
                    d.failed.union(&dirty);
                }
            }
            OpKind::Sync => {
                self.writeback_all(t);
                self.commit();
                forced = true;
            }
            OpKind::Close => {
                let d = self.data(ino);
                if std::mem::take(&mut d.trunc_zero) {
                    self.writeback(ino, t);
                }
            }
        }
        Ok(forced)
    }

    /// A rough count of the entries a clone copies.
    fn weight(&self) -> usize {
        self.live.inodes.len() + self.live.dirs.len() + self.data.len() + 16
    }
}

/// The state after the base records (the base is durable: committed at once).
fn init(ops: &[Op]) -> Result<(Ext4, usize), String> {
    let mut m = Ext4::default();
    m.live.track = true;
    let nbase = ops.iter().take_while(|o| o.is_base()).count();
    for op in &ops[..nbase] {
        m.live.apply(op)?;
    }
    for (ino, i) in &m.live.inodes {
        if i.kind == Kind::File {
            m.data.insert(
                *ino,
                Data {
                    run: i.data.clone(),
                    ..Default::default()
                },
            );
        }
    }
    m.commit();
    Ok((m, nbase))
}

/// The newest kept state at a commit boundary: replay can resume there.
struct Snap {
    pos: usize,
    state: Ext4,
}

/// Replay `ops[from..]` onto `m`. With `cut = Some(k)`, a spontaneous commit (writeback of
/// everything, then commit) happens before record `k` (`k == ops.len()`: at the end).
/// Returns the position just after the last forced commit (`from` if none). With `snap`,
/// keeps a copy of the state at forced commits, at most one per `weight()` records.
fn replay_from(
    m: &mut Ext4,
    ops: &[Op],
    from: usize,
    cut: Option<usize>,
    mut snap: Option<&mut Snap>,
) -> Result<usize, String> {
    let mut last = from;
    let keep = |m: &Ext4, pos: usize, snap: &mut Option<&mut Snap>| {
        if let Some(s) = snap.as_deref_mut() {
            if pos - s.pos >= m.weight() {
                s.pos = pos;
                s.state = m.clone();
            }
        }
    };
    for (i, op) in ops.iter().enumerate().skip(from) {
        if m.timer(op.vclock_ns) {
            last = i;
            keep(m, i, &mut snap);
        }
        if cut == Some(i) {
            m.writeback_all(op.vclock_ns);
            m.commit();
        }
        if m.step(op)
            .map_err(|e| format!("record {i} ({} seq {}): {e}", op.kind.name(), op.seq))?
        {
            last = i + 1;
            keep(m, i + 1, &mut snap);
        }
    }
    if cut == Some(ops.len()) {
        m.writeback_all(crash_time(ops));
        m.commit();
    }
    Ok(last)
}

#[cfg(test)]
/// Full replay with a given cut. Returns the state and the position just after the last
/// forced commit.
fn run(ops: &[Op], cut: Option<usize>) -> Result<(Ext4, usize), String> {
    let (mut m, nbase) = init(ops)?;
    let last = replay_from(&mut m, ops, nbase, cut, None)?;
    Ok((m, last))
}

/// The drawn cut, uniform in `[F, n]`, for the last forced commit position F; a cut equal
/// to F adds nothing (no spontaneous commit happened after the last forced one).
fn draw_cut(ops: &[Op], f: usize, seed: u64, key: u64) -> usize {
    // The `Crash` record is not an operation: the last cut position is just before it.
    let n = ops.len() - ops.last().is_some_and(|o| o.kind == OpKind::Crash) as usize;
    let f = f.min(n);
    f + (torn(seed, key, CUT, 0) % (n - f + 1) as u64) as usize
}

#[cfg(test)]
/// The last forced commit position F and the drawn cut (see `draw_cut`), by a full replay.
pub fn cut_for(ops: &[Op], seed: u64, key: u64) -> Result<(usize, usize), String> {
    let (_, f) = run(ops, None)?;
    let n = ops.len() - ops.last().is_some_and(|o| o.kind == OpKind::Crash) as usize;
    Ok((f.min(n), draw_cut(ops, f, seed, key)))
}

pub fn materialise(log: &super::log::OpLog, seed: u64, key: u64) -> Result<Tree, String> {
    let ops = &log.ops;
    // Timed only when asked: the supervisor, which materialises a machine's crash, reads
    // no clock through the vDSO (`rdtsc` faults there).
    let timing = std::env::var_os("PATINA_TEST_TIMING").is_some();
    let now = || timing.then(std::time::Instant::now);
    let t0 = now();
    // One replay without a cut, keeping a state at or before the last forced commit.
    let (mut m, nbase) = init(ops)?;
    let mut snap = Snap {
        pos: nbase,
        state: m.clone(),
    };
    let f = replay_from(&mut m, ops, nbase, None, Some(&mut snap))?;
    let n = ops.len() - ops.last().is_some_and(|o| o.kind == OpKind::Crash) as usize;
    let k = draw_cut(ops, f, seed, key);
    let t1 = now();
    let snap_pos = snap.pos;
    if k != f.min(n) {
        // A spontaneous commit at k >= F: replay the tail from the kept state with it.
        debug_assert!(snap.pos <= k);
        let Snap { pos, mut state } = snap;
        replay_from(&mut state, ops, pos, Some(k), None)?;
        m = state;
    }
    let t2 = now();
    let tree = finish(m, ops, seed, key)?;
    if let (Some(t0), Some(t1), Some(t2)) = (t0, t1, t2) {
        eprintln!(
            "patina-timing materialise records={} base={nbase} last_forced={f} cut={k} resumed_at={} replay_us={} tail_us={} crash_us={}",
            ops.len(),
            if k != f.min(n) { snap_pos } else { ops.len() },
            t1.duration_since(t0).as_micros(),
            t2.duration_since(t1).as_micros(),
            t2.elapsed().as_micros()
        );
    }
    Ok(tree)
}

#[cfg(test)]
/// `materialise` with the spontaneous cut given (None: no spontaneous commit), by a full
/// replay.
pub fn materialise_at(
    log: &super::log::OpLog,
    cut: Option<usize>,
    seed: u64,
    key: u64,
) -> Result<Tree, String> {
    let ops = &log.ops;
    let (m, _) = run(ops, cut)?;
    finish(m, ops, seed, key)
}

/// The crash itself: the 5-second rule at the crash time, tears.
fn finish(mut m: Ext4, ops: &[Op], seed: u64, key: u64) -> Result<Tree, String> {
    m.timer(crash_time(ops));
    // Tear: each dirty block written in place is old or new.
    let inos: Vec<u64> = m.dirty_inos.iter().copied().collect();
    for ino in inos {
        let Some(d) = m.data.get(&ino) else { continue };
        if d.dirty.is_empty() || !m.disk.has(ino) {
            continue;
        }
        let live = m.live.inodes[&ino].data.clone();
        let disk_size = m.disk.size(ino);
        for b in d.dirty.blocks() {
            if !m.in_place(ino, b) || torn(seed, key, ino, b) & 1 == 0 {
                continue;
            }
            let d = &m.data[&ino];
            for (lo, hi) in d.dirty.runs_in(b, &d.failed, disk_size.min(live.len())) {
                m.disk.copy_from(ino, &live, lo, hi)?;
            }
        }
    }
    Ok(m.disk.to_tree())
}
