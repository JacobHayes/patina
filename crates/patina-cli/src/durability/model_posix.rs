//! `posix-strict`: only what POSIX promises, and every other operation kept
//! or dropped independently by draw.
//!
//! An operation is **guaranteed** when:
//! - data (`Write`, `MmapDirty`, `Truncate`, `Fallocate`) on inode I: the first later sync
//!   event for I is a successful `Fsync(I)` (not a writeback-only one) or `Sync`. If that
//!   first event is an `FsyncFail` (of I, or of everything), the operation **failed**: its
//!   bytes never become durable, whatever comes later.
//! - attributes (`SetAttr`, xattrs) of I: a later `Fsync(I)` or `Sync`.
//! - a directory entry (`Create`, `Mkdir`, `Symlink`, `Link`, `Unlink`, `Rmdir`, `Rename`):
//!   a later `FsyncDir` of every parent directory it changes, or `Sync`.
//!
//! The post-crash tree replays, in log order onto the base, every guaranteed operation and
//! every other non-failed operation whose draw keeps it, skipping any that no longer applies
//! (its inode or parent was dropped, its name is taken, the directory is not empty). That is
//! the legal-subset rule with consistency: no entry without an inode, no data in a file that
//! does not exist. A named `Create` that is dropped still creates the inode (without a name)
//! when a later `Fsync` of it is guaranteed, so a later guaranteed `Link` can name it.
//!
//! Cost: the classification is one backward pass over the log (the next sync event
//! per inode is kept as it goes), and an operation is tested for applicability before it is
//! applied instead of being applied to a copy of the whole image.

use super::log::{Op, OpLog};
use super::materialise::{torn, Fs};
use proto::oplog::{OpKind, FSYNC_MSYNC, FSYNC_NO_COMMIT};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    Guaranteed,
    Failed,
    Maybe,
}

fn full_fsync(o: &Op) -> bool {
    o.kind == OpKind::Fsync && (o.a[0] & FSYNC_NO_COMMIT == 0 || o.a[0] & FSYNC_MSYNC != 0)
}

/// The parents whose `FsyncDir` makes a directory-entry operation durable.
fn parents(o: &Op) -> Vec<u64> {
    match o.kind {
        OpKind::Create if o.a[0] == 0 => vec![],
        OpKind::Create
        | OpKind::Mkdir
        | OpKind::Symlink
        | OpKind::Link
        | OpKind::Unlink
        | OpKind::Rmdir => vec![o.a[0]],
        OpKind::Rename => {
            if o.a[0] == o.a[1] {
                vec![o.a[0]]
            } else {
                vec![o.a[0], o.a[1]]
            }
        }
        _ => vec![],
    }
}

/// Classify every record of `ops` (index-aligned). One backward pass: for each record the
/// later sync events it depends on are known from the records after it.
pub fn fates(ops: &[Op]) -> Vec<Fate> {
    let n = ops.len();
    let mut out = vec![Fate::Maybe; n];
    // Nearest later events, as indices.
    let mut next_sync: Option<usize> = None;
    let mut next_fail_all: Option<usize> = None;
    let mut next_fail: BTreeMap<u64, usize> = BTreeMap::new();
    let mut next_fsync: BTreeMap<u64, usize> = BTreeMap::new();
    let mut dir_synced: BTreeSet<u64> = BTreeSet::new();
    for i in (0..n).rev() {
        let o = &ops[i];
        out[i] = if o.is_base() {
            Fate::Guaranteed
        } else {
            match o.kind {
                OpKind::Write | OpKind::MmapDirty | OpKind::Truncate | OpKind::Fallocate => {
                    // The first later event among: Sync, FsyncFail of this inode or of
                    // everything, a full Fsync of this inode.
                    let fail = [next_fail.get(&o.ino).copied(), next_fail_all]
                        .into_iter()
                        .flatten()
                        .min();
                    let ok = [next_sync, next_fsync.get(&o.ino).copied()]
                        .into_iter()
                        .flatten()
                        .min();
                    match (fail, ok) {
                        (Some(f), Some(g)) if f < g => Fate::Failed,
                        (Some(_), None) => Fate::Failed,
                        (_, Some(_)) => Fate::Guaranteed,
                        (None, None) => Fate::Maybe,
                    }
                }
                OpKind::SetAttr | OpKind::XattrSet | OpKind::XattrRemove => {
                    if next_sync.is_some() || next_fsync.contains_key(&o.ino) {
                        Fate::Guaranteed
                    } else {
                        Fate::Maybe
                    }
                }
                OpKind::Create if o.a[0] == 0 => Fate::Guaranteed,
                OpKind::Create
                | OpKind::Mkdir
                | OpKind::Symlink
                | OpKind::Link
                | OpKind::Unlink
                | OpKind::Rmdir
                | OpKind::Rename => {
                    if next_sync.is_some() || parents(o).iter().all(|p| dir_synced.contains(p)) {
                        Fate::Guaranteed
                    } else {
                        Fate::Maybe
                    }
                }
                // Records with no effect on the tree.
                _ => Fate::Guaranteed,
            }
        };
        // Record i as a later event for the records before it.
        match o.kind {
            OpKind::Sync => next_sync = Some(i),
            OpKind::FsyncFail => {
                next_fail.insert(o.ino, i);
                if o.ino == 0 {
                    next_fail_all = Some(i);
                }
            }
            OpKind::FsyncDir => {
                dir_synced.insert(o.ino);
            }
            _ if full_fsync(o) => {
                next_fsync.insert(o.ino, i);
            }
            _ => {}
        }
    }
    out
}

pub fn materialise(
    log: &OpLog,
    seed: u64,
    key: u64,
    extra: &[(u64, u64, Vec<u8>)],
) -> Result<super::tree::Tree, String> {
    let ops = &log.ops;
    let f = fates(ops);
    // For each record: is there a later Sync, or a later full Fsync of its inode (all such
    // records are Guaranteed)? Backward pass.
    let mut synced_later = vec![false; ops.len()];
    {
        let mut sync = false;
        let mut fsynced: BTreeSet<u64> = BTreeSet::new();
        for i in (0..ops.len()).rev() {
            let o = &ops[i];
            synced_later[i] = sync || fsynced.contains(&o.ino);
            if (o.kind == OpKind::Sync || full_fsync(o)) && f[i] == Fate::Guaranteed {
                if o.kind == OpKind::Sync {
                    sync = true;
                } else {
                    fsynced.insert(o.ino);
                }
            }
        }
    }
    let mut fs = Fs::default();
    for (i, o) in ops.iter().enumerate() {
        let keep = match f[i] {
            Fate::Guaranteed => true,
            Fate::Failed => false,
            Fate::Maybe => torn(seed, key, i as u64, 1) & 1 == 1,
        };
        if o.is_base() {
            fs.apply(o).map_err(|e| format!("base record {i}: {e}"))?;
            continue;
        }
        if !keep {
            if o.kind == OpKind::Create && synced_later[i] && !fs.has(o.ino) {
                let mut inode_only = o.clone();
                inode_only.a[0] = 0;
                let _ = fs.apply(&inode_only);
            }
            continue;
        }
        // An inapplicable operation (its inode or parent was dropped) is skipped: the
        // consistency rule. It is tested before anything changes; the rare records for
        // which `would_fail` cannot tell are applied to a copy.
        match fs.would_fail(o) {
            Some(true) => {}
            Some(false) => fs
                .apply(o)
                .map_err(|e| format!("record {i}: applicable but failed: {e}"))?,
            None => {
                let mut trial = fs.clone();
                if trial.apply(o).is_ok() {
                    fs = trial;
                }
            }
        }
    }
    // Unlogged pages of shared mappings: unsynced writes, each kept by draw.
    for (n, (ino, off, bytes)) in extra.iter().enumerate() {
        if fs.has(*ino) && torn(seed, key, u64::MAX - n as u64, 2) & 1 == 1 {
            fs.write(*ino, *off, bytes)?;
        }
    }
    Ok(fs.to_tree())
}
