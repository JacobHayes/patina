//! Filesystem driver operations and dirty-page tracking.

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry, FsEntryKind, FsMetadata,
    FsNode, OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::BLOCK_SIZE;

use crate::CrashFs;
use crate::baseline::DurableTimes;
use crate::namespace::{PendingKind, normalize_entry_path, swapped};

/// The page `cachestat` counts dirty pages in: the virtual machine's.
const DIRTY_PAGE: u64 = 4096;

impl FsDriver for CrashFs {
    fn open(&mut self, clock: FsClock, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        let existed = self
            .live
            .metadata(path)
            .map(|metadata| matches!(metadata.kind, FsEntryKind::File))
            .unwrap_or(false);
        let fd = self.live.open(clock, path, flags)?;
        let normalized = normalize_entry_path(path).expect("open normalized the path already");
        if flags.create && !existed {
            self.journal(PendingKind::Create {
                path: normalized.clone(),
                kind: FsEntryKind::File,
            });
        }
        // An `O_TRUNC` open of an existing file drops its pages, dirty ones
        // included (`do_truncate`), as a shortening `set_len` does.
        if flags.truncate && existed {
            let metadata = self.live.fd_metadata(fd)?;
            self.truncated(metadata.ino, metadata.len);
        }
        self.open_paths.insert(fd, normalized);
        Ok(fd)
    }

    fn read(&mut self, clock: FsClock, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        self.live.read(clock, fd, max_len)
    }

    fn write(&mut self, clock: FsClock, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        let written = self.live.write(clock, fd, bytes)?;
        // Capture the actual byte range after the filesystem has applied open
        // mode semantics. In particular, O_APPEND chooses EOF at write time, so
        // the pre-write cursor can be stale after intervening writes or crash
        // reconstruction.
        if let (Ok(end), Some(path)) = (
            self.live.seek(fd, 0, SeekWhence::Current),
            self.open_paths.get(&fd).cloned(),
        ) && let Some(start) = usize::try_from(end)
            .ok()
            .and_then(|end| end.checked_sub(written))
        {
            self.dirtied(fd, start as u64, written);
            self.last_write = Some((path, start, written));
        }
        Ok(written)
    }

    fn write_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        let written = self.live.write_at(clock, fd, offset, bytes)?;
        if let (Ok(start), Some(path)) =
            (usize::try_from(offset), self.open_paths.get(&fd).cloned())
        {
            self.dirtied(fd, offset, written);
            self.last_write = Some((path, start, written));
        }
        Ok(written)
    }

    /// A mapping's write-back is unsynced data like a positional write.
    fn write_back_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        let written = self.live.write_back_at(clock, fd, offset, bytes)?;
        if let (Ok(start), Some(path)) =
            (usize::try_from(offset), self.open_paths.get(&fd).cloned())
        {
            self.dirtied(fd, offset, written);
            self.last_write = Some((path, start, written));
        }
        Ok(written)
    }

    /// An anonymous file has no name for the durable baseline to carry: it is
    /// process state, like the bytes in a pipe, and a restart has nothing
    /// that could reach it.
    fn create_anonymous(
        &mut self,
        clock: FsClock,
        name: &str,
        mode: u32,
        seals: u32,
        huge_page: u64,
    ) -> DriverResult<Fd> {
        self.live
            .create_anonymous(clock, name, mode, seals, huge_page)
    }

    fn seals(&mut self, fd: Fd) -> DriverResult<u32> {
        self.live.seals(fd)
    }

    fn add_seals(&mut self, fd: Fd, seals: u32, writably_mapped: bool) -> DriverResult<()> {
        self.live.add_seals(fd, seals, writably_mapped)
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        let ino = self.live.fd_metadata(fd).ok().map(|metadata| metadata.ino);
        self.live.close(fd)?;
        self.open_paths.remove(&fd);
        self.forget_if_gone(ino);
        Ok(())
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        self.live.seek(fd, offset, whence)
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        let duplicate = self.live.dup(fd)?;
        if let Some(path) = self.open_paths.get(&fd).cloned() {
            self.open_paths.insert(duplicate, path);
        }
        Ok(duplicate)
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        self.live.metadata(path)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        self.live.fd_metadata(fd)
    }

    /// Reading an inode's live metadata touches no crash state: it is the same
    /// query `fd_metadata` is, addressed by node instead of by descriptor.
    fn inode_metadata(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        self.live.inode_metadata(ino)
    }

    /// A mode is durable metadata wherever it is named from; the crash model
    /// reads it back off the live image at reconstruction, exactly as it does
    /// for the path- and descriptor-named spellings.
    fn set_inode_mode(&mut self, clock: FsClock, ino: u64, mode: u32) -> DriverResult<()> {
        self.live.set_inode_mode(clock, ino, mode)
    }

    /// An inode reference is a descriptor's hold on a node, and a descriptor is
    /// the process's object: no crash state is touched by taking or dropping
    /// one. The rebuilt image carries the reference across a restart with the
    /// descriptor itself (see `MemFs::adopt_handles`).
    fn retain_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.live.retain_inode(ino)
    }

    fn release_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.live.release_inode(ino)
    }

    fn create_directory(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        self.live.create_directory(clock, path, mode)?;
        let normalized = normalize_entry_path(path).expect("create normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Directory,
        });
        Ok(())
    }

    fn remove_file(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        // A symlink is removed through this call too, so capture the kind before
        // it disappears to journal the correct survival set.
        let before = self.live.metadata(path).ok();
        let kind = before.map_or(FsEntryKind::File, |metadata| metadata.kind);
        self.live.remove_file(clock, path)?;
        let normalized = normalize_entry_path(path).expect("remove normalized the path already");
        self.journal(PendingKind::Remove {
            path: normalized,
            kind,
        });
        self.forget_if_gone(before.map(|metadata| metadata.ino));
        Ok(())
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.sync(fd)?;
        let metadata = self.live.fd_metadata(fd)?;
        self.staged_times
            .insert(metadata.ino, DurableTimes::from(metadata));
        match metadata.kind {
            FsEntryKind::File => {
                let bytes = self.live.fd_file_data(fd)?.clone();
                self.staged_content.insert(metadata.ino, bytes);
                self.dirty.remove(&metadata.ino);
            }
            FsEntryKind::Directory => {
                if let Some(path) = self.open_paths.get(&fd).cloned() {
                    self.sync_directory(&path)?;
                }
            }
            // Neither a symlink's target nor a FIFO's buffer is file data this
            // model stages, and a socket node or a whiteout holds none: there
            // is nothing to make durable.
            FsEntryKind::Symlink
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice => {}
        }
        Ok(())
    }

    /// A length change is unsynced data like a write: the live image takes it
    /// and the durable baseline keeps the old bytes until a `sync`.
    /// Pages past a shortened end leave the cache, dirty or not.
    fn set_len(&mut self, clock: FsClock, fd: Fd, len: u64) -> DriverResult<()> {
        self.live.set_len(clock, fd, len)?;
        let ino = self.live.fd_metadata(fd)?.ino;
        self.truncated(ino, len);
        Ok(())
    }

    fn set_len_by_path(&mut self, clock: FsClock, path: &str, len: u64) -> DriverResult<()> {
        self.live.set_len_by_path(clock, path, len)?;
        let ino = self.live.metadata(path)?.ino;
        self.truncated(ino, len);
        Ok(())
    }

    fn dirty_pages(&mut self, fd: Fd, first: u64, last: u64) -> DriverResult<u64> {
        let ino = self.live.fd_metadata(fd)?.ino;
        Ok(self.dirty.get(&ino).map_or(0, |pages| {
            pages.range(first..=last.max(first)).count() as u64
        }))
    }

    fn allocate(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        len: u64,
        mode: FsAllocateMode,
        keep_size: bool,
    ) -> DriverResult<()> {
        self.live
            .allocate(clock, fd, offset, len, mode, keep_size)?;
        if mode != FsAllocateMode::Reserve {
            self.zeroed(fd, offset, len)?;
        }
        Ok(())
    }

    fn read_directory(
        &mut self,
        clock: FsClock,
        path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.live.read_directory(clock, path)
    }

    fn read_directory_fd(&mut self, clock: FsClock, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.live.read_directory_fd(clock, fd)
    }

    fn remove_directory(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        self.live.remove_directory(clock, path)?;
        let normalized =
            normalize_entry_path(path).expect("remove_directory normalized the path already");
        self.journal(PendingKind::Remove {
            path: normalized,
            kind: FsEntryKind::Directory,
        });
        Ok(())
    }

    fn rename(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        let replaced = self.live.metadata(to).ok().map(|metadata| metadata.ino);
        self.live.rename(clock, from, to)?;
        self.record_rename(from, to, false)?;
        self.forget_if_gone(replaced);
        Ok(())
    }

    /// One journal entry for the rename and its whiteout, decided together.
    fn rename_whiteout(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.live.rename_whiteout(clock, from, to)?;
        self.record_rename(from, to, true)
    }

    /// An exchange moves the open descriptors' attribution with the names;
    /// staged (fsynced) bytes are the nodes' and need no move.
    fn exchange(&mut self, clock: FsClock, first: &str, second: &str) -> DriverResult<()> {
        self.live.exchange(clock, first, second)?;
        let first = normalize_entry_path(first).expect("exchange normalized the path already");
        let second = normalize_entry_path(second).expect("exchange normalized the path already");
        for path in self.open_paths.values_mut() {
            *path = swapped(path, &first, &second);
        }
        self.journal(PendingKind::Exchange { first, second });
        Ok(())
    }

    fn set_times(
        &mut self,
        clock: FsClock,
        fd: Fd,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.live.set_times(clock, fd, atime_nanos, mtime_nanos)
    }

    fn set_inode_times(
        &mut self,
        clock: FsClock,
        ino: u64,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.live
            .set_inode_times(clock, ino, atime_nanos, mtime_nanos)
    }

    fn set_times_by_path(
        &mut self,
        clock: FsClock,
        path: &str,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.live
            .set_times_by_path(clock, path, atime_nanos, mtime_nanos)
    }

    fn link(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.live.link(clock, from, to)?;
        // The new name is a fresh namespace entry; its kind follows the source
        // (a hard link to a file, or a copied symlink per MemFs semantics).
        let to_norm = normalize_entry_path(to).expect("link normalized the destination already");
        let kind = self
            .live
            .metadata(to)
            .map(|metadata| metadata.kind)
            .unwrap_or(FsEntryKind::File);
        self.journal(PendingKind::Create {
            path: to_norm,
            kind,
        });
        Ok(())
    }

    /// A FIFO creation is a NAME appearing, exactly like a symlink's: the
    /// namespace-durability journal holds it, and a crash before the parent
    /// directory is fsynced can lose it.
    fn make_fifo(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        self.live.make_fifo(clock, path, mode)?;
        let normalized = normalize_entry_path(path).expect("make_fifo normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Fifo,
        });
        Ok(())
    }

    /// A special node (a regular file made by `mknod`, a socket node, a
    /// whiteout) is a NAME appearing, like a FIFO's.
    fn make_node(
        &mut self,
        clock: FsClock,
        path: &str,
        node: FsNode,
        mode: u32,
    ) -> DriverResult<()> {
        self.live.make_node(clock, path, node, mode)?;
        let normalized = normalize_entry_path(path).expect("make_node normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: node.kind().expect("the live image made the node"),
        });
        Ok(())
    }

    /// `sync(2)`/`syncfs(2)`: the whole live image becomes the durable
    /// baseline — every staged file, every namespace change — as one
    /// checkpoint.
    fn sync_all(&mut self) -> DriverResult<()> {
        self.live.sync_all()?;
        self.checkpoint();
        Ok(())
    }

    /// Extended attributes are metadata on an existing node, like a mode: the
    /// live image takes a change, and reconstruction reads them back off it
    /// (or off the durable baseline for a resurrected entry).
    fn get_xattr(&mut self, target: &XattrTarget, name: &str) -> DriverResult<Vec<u8>> {
        self.live.get_xattr(target, name)
    }

    fn list_xattr(&mut self, target: &XattrTarget) -> DriverResult<Vec<String>> {
        self.live.list_xattr(target)
    }

    fn set_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> DriverResult<()> {
        self.live.set_xattr(clock, target, name, value, flags)
    }

    fn remove_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
    ) -> DriverResult<()> {
        self.live.remove_xattr(clock, target, name)
    }

    fn symlink(&mut self, clock: FsClock, target: &str, link_path: &str) -> DriverResult<()> {
        self.live.symlink(clock, target, link_path)?;
        let normalized =
            normalize_entry_path(link_path).expect("symlink normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Symlink,
        });
        Ok(())
    }

    fn read_link(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        self.live.read_link(clock, path)
    }

    /// A mode change is metadata on an existing entry, like `set_times`: the
    /// live image takes it and no name appears or disappears, so there is
    /// nothing for the namespace-durability journal to hold.
    fn set_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        self.live.set_mode(clock, path, mode)
    }

    fn set_fd_mode(&mut self, clock: FsClock, fd: Fd, mode: u32) -> DriverResult<()> {
        self.live.set_fd_mode(clock, fd, mode)
    }

    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        self.live.fd_path(fd)
    }

    fn fd_ino(&mut self, fd: Fd) -> DriverResult<u64> {
        self.live.fd_ino(fd)
    }

    fn metadata_unfaulted(&mut self, path: &str) -> DriverResult<FsMetadata> {
        self.live.metadata_unfaulted(path)
    }

    fn fd_metadata_unfaulted(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        self.live.fd_metadata_unfaulted(fd)
    }

    fn crash(&mut self) -> DriverResult<()> {
        let crashes = self.crashes.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidState,
                "filesystem crash counter exhausted",
            )
        })?;
        self.recompute_after_crash()?;
        self.crashes = crashes;
        Ok(())
    }

    fn crash_and_export_restart_snapshot(&mut self) -> DriverResult<Vec<u8>> {
        Ok(self.crash_and_snapshot()?.encode()?)
    }
}

impl CrashFs {
    /// `written` bytes at `offset` of named file `fd` are dirty pages until
    /// its next durability point.
    fn dirtied(&mut self, fd: Fd, offset: u64, written: usize) {
        if written == 0 {
            return;
        }
        let Ok(metadata) = self.live.fd_metadata(fd) else {
            return;
        };
        let first = offset / DIRTY_PAGE;
        let last = (offset + written as u64 - 1) / DIRTY_PAGE;
        self.dirty
            .entry(metadata.ino)
            .or_default()
            .extend(first..=last);
    }

    /// `ino` is `len` bytes long now: its pages past the end are gone.
    fn truncated(&mut self, ino: u64, len: u64) {
        if let Some(pages) = self.dirty.get_mut(&ino) {
            pages.retain(|page| *page < len.div_ceil(DIRTY_PAGE));
        }
    }

    /// `[offset, offset + len)` of named file `fd` was zeroed or punched out
    /// (`ext4_zero_range`, `ext4_punch_hole`): the range is written back
    /// (`filemap_write_and_wait_range`) and its whole pages dropped, and a
    /// page it covers only in part is zeroed through its block, which dirties
    /// it again, when that page lies within the file and its block holds
    /// written data; over a hole or an unwritten block there is nothing to
    /// zero and the page stays clean (host-checked with `cachestat` on ext4
    /// and XFS).
    fn zeroed(&mut self, fd: Fd, offset: u64, len: u64) -> DriverResult<()> {
        if len == 0 || !self.open_paths.contains_key(&fd) {
            return Ok(());
        }
        let metadata = self.live.fd_metadata(fd)?;
        let written = |page: u64| {
            self.live
                .fd_file_data(fd)
                .is_ok_and(|data| data.is_written(page * DIRTY_PAGE / BLOCK_SIZE))
        };
        let partial = [
            (!offset.is_multiple_of(DIRTY_PAGE)).then_some(offset / DIRTY_PAGE),
            (!offset.saturating_add(len).is_multiple_of(DIRTY_PAGE))
                .then_some((offset.saturating_add(len) - 1) / DIRTY_PAGE),
        ]
        .map(|page| page.filter(|page| written(*page)));
        let end = offset.saturating_add(len);
        let (first, last) = (offset / DIRTY_PAGE, (end - 1) / DIRTY_PAGE);
        let pages = self.dirty.entry(metadata.ino).or_default();
        pages.retain(|page| *page < first || *page > last);
        for page in partial.into_iter().flatten() {
            if page * DIRTY_PAGE < metadata.len {
                pages.insert(page);
            }
        }
        if pages.is_empty() {
            self.dirty.remove(&metadata.ino);
        }
        Ok(())
    }

    /// `ino` may have lost its last name or reference: once it is gone, its
    /// dirty pages go with it.
    fn forget_if_gone(&mut self, ino: Option<u64>) {
        if let Some(ino) = ino.filter(|ino| self.dirty.contains_key(ino))
            && self.live.inode_metadata(ino).is_err()
        {
            self.dirty.remove(&ino);
        }
    }
}

#[cfg(test)]
mod tests;
