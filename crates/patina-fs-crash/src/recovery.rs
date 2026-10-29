//! Crash reconstruction and surviving source-inode selection.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{EffectError, ErrorCode, FsClock, FsEntryKind, FsMetadata, FsNode};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::{FileData, MemFs};

use crate::CrashFs;
use crate::baseline::{DurableTimes, enumerate};
use crate::namespace::{PendingKind, Reverted, Survivors};

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

/// What reconstruction restores onto one rebuilt name.
struct NodeMetadata {
    mode: Option<u32>,
    xattrs: BTreeMap<String, Vec<u8>>,
    times: Option<DurableTimes>,
}

impl CrashFs {
    /// Rebuild the image a crash leaves. `process_survives` says whether the
    /// process that holds descriptors lives on past it (an in-place
    /// [`FsDriver::crash`]), so its open files keep their names; a restart's
    /// process is gone, and with it every descriptor.
    pub(super) fn recompute_after_crash(&mut self, process_survives: bool) -> DriverResult<()> {
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
                // A lost creation changes nothing: whatever the
                // reconstruction holds at the name (nothing, or a node a lost
                // removal or rename left there) stays.
                PendingKind::Create { path, kind } => {
                    if self.entry_survives(op.committed) {
                        sets.of(*kind).insert(path.clone());
                        reverted.forget(path);
                    }
                }
                PendingKind::Remove { path, removed } => {
                    // A surviving unlink persists the removal. A lost one
                    // changes nothing: a name the reconstruction has keeps the
                    // node the removal took away (the durable entry, when the
                    // baseline holds that node there), and a name it does not
                    // have, a lost creation's, stays gone.
                    // Whatever happens to the name, the record is its node's
                    // last known state.
                    reverted.remember(removed);
                    let persist = self.entry_survives(op.committed);
                    let set = sets.of(removed.kind());
                    if persist {
                        set.remove(path);
                    } else if set.contains(path) && !reverted.covers(path) {
                        if self.durable.inodes.get(path) == Some(&removed.metadata.ino) {
                            reverted.bring_back(path);
                        } else {
                            reverted.keep(path, removed);
                        }
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
        let open = if process_survives {
            self.live.open_entries()
        } else {
            BTreeMap::new()
        };
        for (path, kind) in open {
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

        let mut file_contents_by_inode: BTreeMap<u64, FileData> = BTreeMap::new();
        let mut file_paths_by_inode: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for path in &files {
            // A name only a descriptor pins holds that descriptor's node, even
            // where a lost rename brought back the name's (absent) durable entry.
            let pinned = resurrected
                .contains(path)
                .then(|| self.live.entry_metadata(path).ok())
                .flatten()
                .map(|metadata| metadata.ino);
            let source_inode = self
                .file_source_inode(path, &reverted)
                .or(pinned)
                .ok_or_else(|| {
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
                    // A page a writeback error dropped never reached the
                    // disk, so no tear can have persisted it.
                    Ok(current) => {
                        let current = self.written_back(source_inode, &baseline, current);
                        self.torn_merge(&baseline, &current)
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
        // Restore each rebuilt node's metadata: durable timestamps, extended
        // attributes and permission bits. All are read per NODE (see
        // `node_metadata`), so every name of one node restores the same
        // values. Timestamps go through the storage layer's own setter: a
        // guest-facing `set_times` would stamp `ctime` with the rebuild instant
        // and could not restore a birth time at all. Permission bits go last,
        // deepest name first, so a directory clamped to `0o500` cannot lock the
        // walk out of the names beneath it.
        let durable_times: BTreeMap<u64, DurableTimes> = self
            .durable
            .inodes
            .iter()
            .filter_map(|(path, ino)| Some((*ino, *self.durable.times.get(path)?)))
            .collect();
        let live_nodes: BTreeMap<u64, FsMetadata> = self
            .live
            .inventory()
            .into_iter()
            .map(|(_, metadata)| (metadata.ino, metadata))
            .collect();
        let mut restored_modes: BTreeMap<String, u32> = BTreeMap::new();
        // enumerate includes symlinks, unlike paths_with_modes.
        for (path, metadata) in next.inventory() {
            let node = self.node_metadata(&path, &reverted, &live_nodes, &durable_times);
            if let Some(times) = node.times {
                next.restore_times(
                    &path,
                    times.atime_nanos,
                    times.mtime_nanos,
                    times.ctime_nanos,
                    times.btime_nanos,
                )?;
            }
            next.restore_xattrs(&path, node.xattrs)?;
            // A symlink leaf has no mode of its own.
            if metadata.kind != FsEntryKind::Symlink
                && let Some(mode) = node.mode
            {
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
        // The cache is rebuilt from the disk, and the errors recorded on it
        // go with it.
        self.lost.clear();
        self.file_errors.clear();
        self.filesystem_errors = crate::writeback::ErrSeq::default();
        self.samples.clear();
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
        self.entry_at(path, reverted)
            .filter(|metadata| is_special(metadata.kind))
            .map(|metadata| (metadata.ino, metadata.kind))
            .or_else(|| self.durable.specials.get(path).copied())
    }

    /// The link node and target a surviving symlink name has: the live link
    /// if it is still there, else the durable baseline's.
    fn symlink_source(&mut self, path: &str, reverted: &Reverted) -> Option<(u64, String)> {
        if let Some(kept) = reverted.kept(path) {
            return kept
                .target
                .clone()
                .map(|target| (kept.metadata.ino, target));
        }
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
        self.entry_at(path, reverted)
            .filter(|metadata| metadata.kind == FsEntryKind::File)
            .map(|metadata| metadata.ino)
            .or_else(|| self.durable.files.get(path).map(|file| file.inode))
    }

    /// The metadata a rebuilt name restores, decided by the node it holds,
    /// never by the name alone. Permission bits and extended attributes are
    /// durable the moment they change, so a node still in the live image —
    /// through any name, or only a descriptor — restores its live values; a
    /// node the live image no longer holds restores what was last recorded
    /// for it: its removal's record, else the durable baseline's. Timestamps
    /// roll back: they are the node's last fsynced ones, else the baseline's
    /// for this node (under whichever name the baseline held it), and only a
    /// node neither ever made durable takes that same fallback.
    fn node_metadata(
        &mut self,
        path: &str,
        reverted: &Reverted,
        live_nodes: &BTreeMap<u64, FsMetadata>,
        durable_times: &BTreeMap<u64, DurableTimes>,
    ) -> NodeMetadata {
        let ino = reverted
            .kept(path)
            .map(|kept| kept.metadata.ino)
            .or_else(|| self.live_entry(path, reverted).map(|metadata| metadata.ino))
            .or_else(|| self.durable.inodes.get(path).copied());
        let durable = NodeMetadata {
            mode: self.durable.modes.get(path).copied(),
            xattrs: self.durable.xattrs.get(path).cloned().unwrap_or_default(),
            times: self.durable.times.get(path).copied(),
        };
        let Some(ino) = ino else {
            return durable;
        };
        let live = live_nodes
            .get(&ino)
            .copied()
            .or_else(|| FsDriver::inode_metadata(&mut self.live, ino).ok());
        let mut node = match (live, reverted.record(ino)) {
            (Some(metadata), _) => NodeMetadata {
                mode: Some(metadata.mode),
                xattrs: self.live.inode_xattrs(ino),
                times: Some(DurableTimes::from(metadata)),
            },
            (None, Some(removed)) => NodeMetadata {
                mode: Some(removed.metadata.mode),
                xattrs: removed.xattrs.clone(),
                times: Some(DurableTimes::from(removed.metadata)),
            },
            (None, None) => durable,
        };
        node.times = self
            .staged_times
            .get(&ino)
            .or_else(|| durable_times.get(&ino))
            .copied()
            .or(node.times);
        node
    }

    /// The node a surviving name holds, when it is not the durable
    /// baseline's: the one a lost removal left there, else the live entry.
    fn entry_at(&self, path: &str, reverted: &Reverted) -> Option<FsMetadata> {
        reverted
            .kept(path)
            .map(|kept| kept.metadata)
            .or_else(|| self.live_entry(path, reverted))
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
