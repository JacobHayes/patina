//! Crash reconstruction and surviving source-inode selection.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{EffectError, ErrorCode, FsClock, FsEntryKind, FsMetadata, FsNode};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::{FileData, MemFs};

use crate::baseline::{DurableTimes, enumerate};
use crate::namespace::{PendingKind, Reverted, Survivors};
use crate::{CrashFs, TornGranularity};

/// The creation modes crash reconstruction rebuilds entries at before restoring
/// their recorded permission bits. Nothing is judged against them: every
/// surviving entry's real mode is written back from the live image or the
/// durable baseline immediately afterwards.
const RECONSTRUCTION_FILE_MODE: u32 = 0o666;

const RECONSTRUCTION_DIRECTORY_MODE: u32 = 0o777;

/// Whether a kind is a special node: a FIFO, a socket node or a whiteout —
/// an inode-backed name with no bytes of its own.
fn is_special(kind: FsEntryKind) -> bool {
    matches!(
        kind,
        FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice
    )
}

impl CrashFs {
    pub(super) fn recompute_after_crash(&mut self) -> DriverResult<()> {
        let pending = self.pending.clone();
        let mut sets = Survivors {
            dirs: self.durable.dirs.clone(),
            files: self.durable.files.keys().cloned().collect(),
            symlinks: self.durable.symlinks.keys().cloned().collect(),
            specials: self.durable.specials.keys().cloned().collect(),
        };
        let mut reverted = Reverted::default();

        for op in &pending {
            match &op.kind {
                PendingKind::Create { path, kind } => {
                    let survive = self.entry_survives(op.committed);
                    let set = sets.of(*kind);
                    if survive {
                        set.insert(path.clone());
                        reverted.forget(path);
                    } else {
                        set.remove(path);
                    }
                }
                PendingKind::Remove { path, kind } => {
                    // A surviving unlink persists the removal; a lost unlink
                    // resurrects the durable entry.
                    let persist = self.entry_survives(op.committed);
                    let set = sets.of(*kind);
                    if persist {
                        set.remove(path);
                    } else {
                        set.insert(path.clone());
                        reverted.bring_back(path);
                    }
                }
                PendingKind::Rename {
                    from,
                    to,
                    kind,
                    whiteout,
                } => {
                    if self.policy.model_rename_atomicity || *kind == FsEntryKind::Directory {
                        // Atomic (or directory) renames are all-or-nothing and
                        // fully durable only when both governing directories are
                        // committed; otherwise a single seeded decision applies.
                        // A lost one brings both names' durable entries back —
                        // a replaced destination included.
                        if self.entry_survives(op.committed && op.source_committed) {
                            // A directory replaces only an EMPTY one, and a
                            // durable rename frees the replaced node: nothing
                            // still beneath `to` (a removal this crash lost)
                            // was ever the moved node's.
                            if *kind == FsEntryKind::Directory {
                                sets.drop_beneath(to);
                            }
                            sets.rewrite_prefix(from, to);
                            reverted.forget(to);
                            if *whiteout {
                                sets.specials.insert(from.clone());
                                reverted.forget(from);
                            }
                        } else {
                            reverted.bring_back(from);
                            reverted.bring_back(to);
                        }
                    } else {
                        // Non-atomic: the destination link and the source unlink
                        // are governed by their own directories and fail
                        // independently, so a crash can leave both names or
                        // neither. Draw the link side first, then the unlink
                        // side, for a stable decision order.
                        let link_new = self.entry_survives(op.committed);
                        let unlink_old = self.entry_survives(op.source_committed);
                        let set = sets.of(*kind);
                        if unlink_old {
                            set.remove(from);
                            // The whiteout replaces the old name's entry.
                            if *whiteout {
                                sets.specials.insert(from.clone());
                                reverted.forget(from);
                            }
                        }
                        let set = sets.of(*kind);
                        if link_new {
                            set.insert(to.clone());
                            reverted.forget(to);
                        } else {
                            reverted.bring_back(to);
                        }
                    }
                }
                // An exchange has no half-done state to expose: the kernel
                // swaps both names in one step whatever the rename-atomicity
                // model says, so it is all-or-nothing, durable once both
                // parents are committed.
                PendingKind::Exchange { first, second } => {
                    if self.entry_survives(op.committed && op.source_committed) {
                        sets.swap_prefixes(first, second);
                        reverted.forget(first);
                        reverted.forget(second);
                    } else {
                        reverted.bring_back(first);
                        reverted.bring_back(second);
                    }
                }
            }
        }

        // A crash cannot invalidate a descriptor the guest is still holding.
        // An open file description is the PROCESS's object; power loss reaches
        // the disk, not the caller's descriptor table, so no real storage
        // failure turns a valid fd into `EBADF`. A name can only be pinned back
        // into the rebuilt namespace when its full parent chain survived; the
        // crash model must not silently resurrect lost directories to make a
        // child fit.
        let mut resurrected: BTreeSet<String> = BTreeSet::new();
        for (path, kind) in self.live.open_entries() {
            let fresh = sets.of(kind).insert(path.clone());
            if fresh && kind == FsEntryKind::File {
                resurrected.insert(path);
            }
        }
        sets.prune_to_surviving_parents();
        let Survivors {
            dirs,
            files,
            symlinks,
            specials,
        } = sets;

        let mut durable_content_by_inode: BTreeMap<u64, FileData> = BTreeMap::new();
        for file in self.durable.files.values() {
            durable_content_by_inode
                .entry(file.inode)
                .or_insert_with(|| file.contents.clone());
        }

        // The final unsynced write is eligible for a sub-block partial tear
        // under the byte-granularity policy; every other block still tears
        // wholesale. Captured before the merge loop borrows the rng.
        let last_write = self.last_write.clone();
        let final_write = match self.policy.torn_granularity {
            TornGranularity::Byte => last_write.as_ref().and_then(|(path, offset, len)| {
                self.file_source_inode(path, &reverted).map(|inode| {
                    let (offset, len) = (*offset as u64, *len as u64);
                    (inode, offset, offset.saturating_add(len))
                })
            }),
            TornGranularity::Block => None,
        };
        let mut file_contents_by_inode: BTreeMap<u64, FileData> = BTreeMap::new();
        let mut file_paths_by_inode: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for path in &files {
            let source_inode = self.file_source_inode(path, &reverted).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    format!("surviving file has no source inode: {path}"),
                )
            })?;
            let baseline = self
                .staged_content
                .get(&source_inode)
                .or_else(|| durable_content_by_inode.get(&source_inode))
                .cloned()
                .unwrap_or_default();
            let partial_region = match final_write {
                Some((inode, start, end)) if inode == source_inode => Some((start, end)),
                _ => None,
            };
            let content = if resurrected.contains(path) || reverted.covers(path) {
                // Only open-descriptor pinning put this name back: the crash
                // decided its creation did not survive, so nothing it ever held
                // is durable. The name exists for the descriptor's sake; the
                // contents are the durable baseline (empty for a lost create).
                // A name a lost rename or exchange brought back is its durable
                // entry, whatever the live image holds there now.
                baseline
            } else {
                match self.live.file_data(path) {
                    Ok(current) => {
                        let current = current.clone();
                        self.torn_merge(&baseline, &current, partial_region)
                    }
                    Err(_) => baseline,
                }
            };
            file_contents_by_inode
                .entry(source_inode)
                .or_insert(content);
            file_paths_by_inode
                .entry(source_inode)
                .or_default()
                .insert(path.clone());
        }
        // A symlink's target is metadata, not torn data: the live target if the
        // link is still there, else the durable baseline's. Names of one link
        // node come back as one node.
        let mut symlinks_by_inode: BTreeMap<u64, (String, BTreeSet<String>)> = BTreeMap::new();
        for path in &symlinks {
            let (source_inode, target) = self.symlink_source(path, &reverted).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    format!("surviving symlink has no source inode: {path}"),
                )
            })?;
            symlinks_by_inode
                .entry(source_inode)
                .or_insert_with(|| (target, BTreeSet::new()))
                .1
                .insert(path.clone());
        }

        let mut next = MemFs::new();
        for dir in &dirs {
            if dir != "/" && next.metadata(dir).is_err() {
                next.create_directory(FsClock::EPOCH, dir, RECONSTRUCTION_DIRECTORY_MODE)?;
            }
        }
        for (source_inode, paths) in &file_paths_by_inode {
            let first = paths.iter().next().expect("file group is non-empty");
            let contents = file_contents_by_inode
                .get(source_inode)
                .expect("file group has content")
                .clone();
            next = next.with_file_data(first, contents)?;
            for path in paths.iter().skip(1) {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        for (target, paths) in symlinks_by_inode.values() {
            let first = paths.iter().next().expect("symlink group is non-empty");
            next.symlink(FsClock::EPOCH, target, first)?;
            for path in paths.iter().skip(1) {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        // A FIFO's, a socket node's or a whiteout's name is what survives; a
        // FIFO's buffered bytes never were durable. Names that share an inode
        // are ONE node — a hard link to a FIFO is the same pipe — so they are
        // grouped exactly as a file's links are.
        let mut special_paths_by_inode: BTreeMap<u64, (FsEntryKind, BTreeSet<String>)> =
            BTreeMap::new();
        for path in &specials {
            let (source_inode, kind) = self.special_source(path, &reverted).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    format!("surviving special node has no source inode: {path}"),
                )
            })?;
            special_paths_by_inode
                .entry(source_inode)
                .or_insert_with(|| (kind, BTreeSet::new()))
                .1
                .insert(path.clone());
        }
        for (kind, paths) in special_paths_by_inode.values() {
            let first = paths.iter().next().expect("special group is non-empty");
            let node = match kind {
                FsEntryKind::Fifo => FsNode::Fifo,
                FsEntryKind::Socket => FsNode::Socket,
                _ => FsNode::Whiteout,
            };
            next.make_node(FsClock::EPOCH, first, node, RECONSTRUCTION_FILE_MODE)?;
            for path in paths.iter().skip(1) {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        // Restore durable timestamps for the surviving baseline entries so
        // crash reconstruction does not silently reset metadata to zero. All
        // four are written back through the storage layer's own setter: a
        // guest-facing `set_times` would stamp `ctime` with the rebuild instant
        // and could not restore a birth time at all.
        // enumerate includes symlinks, unlike paths_with_modes.
        for path in enumerate(&next).times.keys() {
            let live = self.live_entry(path, &reverted);
            let source_ino = live
                .map(|m| m.ino)
                .or_else(|| self.durable.files.get(path).map(|f| f.inode))
                .or_else(|| self.durable.symlinks.get(path).map(|link| link.inode))
                .or_else(|| self.durable.specials.get(path).map(|(ino, _)| *ino));
            let times = source_ino
                .and_then(|ino| self.staged_times.get(&ino).copied())
                .or_else(|| self.durable.times.get(path).copied())
                .or_else(|| live.map(DurableTimes::from));
            if let Some(times) = times {
                next.restore_times(
                    path,
                    times.atime_nanos,
                    times.mtime_nanos,
                    times.ctime_nanos,
                    times.btime_nanos,
                )?;
            }
            // Extended attributes are metadata like a mode: the live set if the
            // entry is still there, else the durable baseline's.
            let xattrs = if live.is_some() {
                self.live.entry_xattrs(path)
            } else {
                self.durable.xattrs.get(path).cloned().unwrap_or_default()
            };
            next.restore_xattrs(path, xattrs)?;
        }
        // Permission bits last, and deepest name first. A mode is metadata like
        // a symlink's target — the live value if the entry is still there, else
        // the durable baseline — and rebuilding at a per-kind constant would
        // silently revert a `chmod`, or a `0o400` creation mode, that a real
        // crash has no way to undo. Restrictive modes are written from the
        // leaves up so a directory clamped to `0o500` cannot lock the walk out
        // of the names beneath it.
        let mut restored_modes: BTreeMap<String, u32> = BTreeMap::new();
        for path in next.paths_with_modes() {
            let mode = self
                .live_entry(&path, &reverted)
                .map(|metadata| metadata.mode)
                .or_else(|| self.durable.modes.get(&path).copied());
            if let Some(mode) = mode {
                restored_modes.insert(path, mode);
            }
        }
        for (path, mode) in restored_modes.iter().rev() {
            next.restore_mode(path, *mode)?;
        }

        self.durable = enumerate(&next);
        // Descriptors survive the crash (see the pinning comment above), so the
        // handle table and the descriptor-to-path map both move across: a `sync`
        // on an fd opened before the crash must still be attributed to its file.
        next.adopt_handles(&self.live);
        self.live = next;
        self.staged_content.clear();
        self.staged_times.clear();
        self.pending.clear();
        self.dirty.clear();
        self.last_write = None;
        Ok(())
    }

    /// Decide whether an uncommitted namespace change survives a crash. When a
    /// directory fsync committed it, or the directory-durability model is off,
    /// it survives without consuming the decision stream.
    fn entry_survives(&mut self, committed: bool) -> bool {
        if committed || !self.policy.model_directory_durability {
            return true;
        }
        !self.decide(self.policy.directory_loss_probability)
    }

    /// The inode and kind a surviving FIFO, socket-node or whiteout name
    /// belongs to: the live one if the entry is still there, else the durable
    /// baseline's. The mirror of [`CrashFs::file_source_inode`], and for the
    /// same reason — two names of one node must come back as one node.
    fn special_source(&mut self, path: &str, reverted: &Reverted) -> Option<(u64, FsEntryKind)> {
        self.live_entry(path, reverted)
            .filter(|metadata| is_special(metadata.kind))
            .map(|metadata| (metadata.ino, metadata.kind))
            .or_else(|| self.durable.specials.get(path).copied())
    }

    /// The link node and target a surviving symlink name has: the live link
    /// if it is still there, else the durable baseline's.
    fn symlink_source(&mut self, path: &str, reverted: &Reverted) -> Option<(u64, String)> {
        let live = self
            .live_entry(path, reverted)
            .filter(|metadata| metadata.kind == FsEntryKind::Symlink)
            .and_then(|metadata| {
                self.live
                    .symlink_target(path)
                    .map(|target| (metadata.ino, target))
            });
        live.or_else(|| {
            self.durable
                .symlinks
                .get(path)
                .map(|link| (link.inode, link.target.clone()))
        })
    }

    fn file_source_inode(&mut self, path: &str, reverted: &Reverted) -> Option<u64> {
        self.live_entry(path, reverted)
            .filter(|metadata| metadata.kind == FsEntryKind::File)
            .map(|metadata| metadata.ino)
            .or_else(|| self.durable.files.get(path).map(|file| file.inode))
    }

    /// The live entry at a surviving name — unless the crash brought the
    /// name's durable entry back over it, in which case the live node there is
    /// not the one that survived and nothing is read off it.
    fn live_entry(&self, path: &str, reverted: &Reverted) -> Option<FsMetadata> {
        if reverted.covers(path) {
            return None;
        }
        self.live.entry_metadata(path).ok()
    }
}

#[cfg(test)]
mod tests;
