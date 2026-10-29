//! Crash reconstruction: the last committed image, with the blocks
//! overwritten in place since torn per the seeded policy.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{FsClock, FsEntryKind, FsNode};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::{BLOCK_SIZE, FileData, MemFs};

use crate::CrashFs;
use crate::baseline::{DurableTimes, enumerate};
use crate::journal::parent_path;

/// The creation modes crash reconstruction rebuilds entries at before restoring
/// their recorded permission bits. Nothing is judged against them: every
/// rebuilt entry's real mode is written back immediately afterwards.
const RECONSTRUCTION_FILE_MODE: u32 = 0o666;

const RECONSTRUCTION_DIRECTORY_MODE: u32 = 0o777;

/// What reconstruction restores onto one rebuilt name.
struct NodeMetadata {
    mode: Option<u32>,
    xattrs: BTreeMap<String, Vec<u8>>,
    times: Option<DurableTimes>,
}

/// Whether every ancestor of `path` is among `dirs`.
fn parent_chain_in(path: &str, dirs: &BTreeSet<String>) -> bool {
    let mut parent = parent_path(path);
    loop {
        if !dirs.contains(parent) {
            return false;
        }
        if parent == "/" {
            return true;
        }
        parent = parent_path(parent);
    }
}

impl CrashFs {
    /// Rebuild the image a crash at `clock` leaves: the last commit (one
    /// falls due now if the running transaction is old enough), with each
    /// block overwritten in place since then torn to its old or new bytes.
    /// `process_survives` says whether the process that holds descriptors
    /// lives on past it (an in-place [`FsDriver::crash`]), so its open files
    /// keep their names; a restart's process is gone, and with it every
    /// descriptor.
    pub(super) fn recompute_after_crash(
        &mut self,
        clock: FsClock,
        process_survives: bool,
    ) -> DriverResult<()> {
        self.tick(clock);
        let committed = self.committed.clone();
        let mut dirs = committed.dirs.clone();
        let mut files: BTreeMap<String, u64> = committed
            .files
            .iter()
            .map(|(path, file)| (path.clone(), file.inode))
            .collect();
        // A crash cannot invalidate a descriptor the guest is still holding:
        // an open file description is the PROCESS's object, and power loss
        // reaches the disk, not the caller's descriptor table. A name an open
        // descriptor holds comes back when its full parent chain did and the
        // commit put nothing else there; lost directories are never
        // resurrected to make a child fit.
        let mut pinned: BTreeMap<String, u64> = BTreeMap::new();
        if process_survives {
            for (path, kind) in self.live.open_entries() {
                if committed.inodes.contains_key(&path) || !parent_chain_in(&path, &dirs) {
                    continue;
                }
                let Ok(metadata) = self.live.entry_metadata(&path) else {
                    continue;
                };
                match kind {
                    FsEntryKind::Directory => {
                        dirs.insert(path.clone());
                    }
                    FsEntryKind::File => {
                        files.insert(path.clone(), metadata.ino);
                    }
                    _ => continue,
                }
                pinned.insert(path, metadata.ino);
            }
        }

        let committed_bytes: BTreeMap<u64, &FileData> = committed
            .files
            .values()
            .map(|file| (file.inode, &file.contents))
            .collect();
        let live_bytes: BTreeMap<u64, FileData> = self
            .live
            .inventory()
            .into_iter()
            .filter(|(_, metadata)| metadata.kind == FsEntryKind::File)
            .filter_map(|(path, metadata)| {
                Some((metadata.ino, self.live.file_data(&path).ok()?.clone()))
            })
            .collect();
        let mut file_paths_by_inode: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for (path, inode) in &files {
            file_paths_by_inode
                .entry(*inode)
                .or_default()
                .insert(path.clone());
        }

        let mut next = MemFs::new();
        for dir in &dirs {
            if dir != "/" && next.metadata(dir).is_err() {
                next.create_directory(FsClock::EPOCH, dir, RECONSTRUCTION_DIRECTORY_MODE)?;
            }
        }
        for (inode, paths) in &file_paths_by_inode {
            // A node only a descriptor pinned back was never committed: none
            // of its bytes are on disk.
            let contents = match committed_bytes.get(inode) {
                Some(base) => match live_bytes.get(inode) {
                    Some(current) => {
                        let current = self.written_back(*inode, base, current);
                        // The block a truncation's end fell in stayed
                        // allocated; every block past it was freed.
                        let limit = self.shrunk.get(inode).map_or(base.len(), |floor| {
                            base.len().min(floor.div_ceil(BLOCK_SIZE) * BLOCK_SIZE)
                        });
                        let freed = self.freed.get(inode).cloned().unwrap_or_default();
                        self.torn_in_place(base, &current, limit, &freed)
                    }
                    None => (*base).clone(),
                },
                None => FileData::default(),
            };
            let first = paths.iter().next().expect("file group is non-empty");
            next = next.with_file_data(first, contents)?;
            for path in paths.iter().skip(1) {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        // A symlink's target is metadata. Names of one link node come back as
        // one node.
        let mut symlinks_by_inode: BTreeMap<u64, (&str, BTreeSet<&str>)> = BTreeMap::new();
        for (path, link) in &committed.symlinks {
            symlinks_by_inode
                .entry(link.inode)
                .or_insert_with(|| (&link.target, BTreeSet::new()))
                .1
                .insert(path);
        }
        for (target, paths) in symlinks_by_inode.values() {
            let mut paths = paths.iter();
            let first = paths.next().expect("symlink group is non-empty");
            next.symlink(FsClock::EPOCH, target, first)?;
            for path in paths {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        // A FIFO's, a socket node's or a whiteout's name is what survives; a
        // FIFO's buffered bytes never were durable. Names that share an inode
        // are ONE node — a hard link to a FIFO is the same pipe — so they are
        // grouped exactly as a file's links are.
        let mut specials_by_inode: BTreeMap<u64, (FsEntryKind, BTreeSet<&str>)> = BTreeMap::new();
        for (path, (inode, kind)) in &committed.specials {
            specials_by_inode
                .entry(*inode)
                .or_insert_with(|| (*kind, BTreeSet::new()))
                .1
                .insert(path);
        }
        for (kind, paths) in specials_by_inode.values() {
            let mut paths = paths.iter();
            let first = paths.next().expect("special group is non-empty");
            let node = match kind {
                FsEntryKind::Fifo => FsNode::Fifo,
                FsEntryKind::Socket => FsNode::Socket,
                _ => FsNode::Whiteout,
            };
            next.make_node(FsClock::EPOCH, first, node, RECONSTRUCTION_FILE_MODE)?;
            for path in paths {
                next.link(FsClock::EPOCH, first, path)?;
            }
        }
        // Restore each rebuilt name's committed metadata: timestamps,
        // extended attributes and permission bits; a pinned name's node was
        // never committed, so it keeps what the live node has. Timestamps go
        // through the storage layer's own setter: a guest-facing `set_times`
        // would stamp `ctime` with the rebuild instant and could not restore a
        // birth time at all. Permission bits go last, deepest name first, so a
        // directory clamped to `0o500` cannot lock the walk out of the names
        // beneath it.
        let mut restored_modes: BTreeMap<String, u32> = BTreeMap::new();
        for (path, metadata) in next.inventory() {
            let node = match pinned.get(&path) {
                Some(ino) => {
                    let live = FsDriver::inode_metadata(&mut self.live, *ino).ok();
                    NodeMetadata {
                        mode: live.map(|metadata| metadata.mode),
                        xattrs: self.live.inode_xattrs(*ino),
                        times: live.map(DurableTimes::from),
                    }
                }
                None => NodeMetadata {
                    mode: committed.modes.get(&path).copied(),
                    xattrs: committed.xattrs.get(&path).cloned().unwrap_or_default(),
                    times: committed.times.get(&path).copied(),
                },
            };
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

        self.committed = enumerate(&next);
        self.committed_data = crate::journal::data_by_inode(&self.committed);
        // Descriptors survive the crash (see the pinning comment above), so the
        // handle table moves across: a `sync` on an fd opened before the crash
        // must still reach its file.
        next.adopt_handles(&self.live);
        self.live = next;
        self.written.clear();
        self.shrunk.clear();
        self.freed.clear();
        self.journaled.clear();
        self.opened = None;
        self.flush_on_close.clear();
        self.dirty.clear();
        // The cache is rebuilt from the disk, and the errors recorded on it
        // go with it.
        self.lost.clear();
        self.file_errors.clear();
        self.filesystem_errors = crate::writeback::ErrSeq::default();
        self.samples.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
