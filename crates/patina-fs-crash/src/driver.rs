//! Filesystem driver operations: what each joins the running transaction
//! with, what commits it, and dirty-page tracking.

use patina_dst_abi::{
    CrashKind, EffectError, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry, FsEntryKind,
    FsMetadata, FsNode, OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::BLOCK_SIZE;

use crate::CrashFs;

/// The page `cachestat` counts dirty pages in: the virtual machine's.
pub(crate) const DIRTY_PAGE: u64 = 4096;

impl FsDriver for CrashFs {
    fn open(&mut self, clock: FsClock, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        self.tick(clock);
        let existed = self
            .live
            .metadata(path)
            .map(|metadata| matches!(metadata.kind, FsEntryKind::File))
            .unwrap_or(false);
        let fd = self.live.open(clock, path, flags)?;
        let ino = self.live.fd_metadata(fd)?.ino;
        if flags.create && !existed {
            let inodes = self.entry_and_parent(path);
            self.journal(clock, inodes);
        }
        // An `O_TRUNC` open of an existing file drops its pages, dirty ones
        // included (`do_truncate`), as a shortening `set_len` does.
        if flags.truncate && existed {
            self.truncated(clock, ino, 0);
        }
        self.named.insert(fd);
        self.description_opened(fd);
        Ok(fd)
    }

    fn read(&mut self, clock: FsClock, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        self.tick(clock);
        self.live.read(clock, fd, max_len)
    }

    fn write(&mut self, clock: FsClock, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        self.tick(clock);
        let written = self.live.write(clock, fd, bytes)?;
        // Capture the actual byte range after the filesystem has applied open
        // mode semantics. In particular, O_APPEND chooses EOF at write time, so
        // the pre-write cursor can be stale after intervening writes or crash
        // reconstruction.
        if let Ok(end) = self.live.seek(fd, 0, SeekWhence::Current)
            && let Some(start) = end.checked_sub(written as u64)
        {
            self.dirtied(clock, fd, start, written);
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
        self.tick(clock);
        let written = self.live.write_at(clock, fd, offset, bytes)?;
        self.dirtied(clock, fd, offset, written);
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
        self.tick(clock);
        let written = self.live.write_back_at(clock, fd, offset, bytes)?;
        self.dirtied(clock, fd, offset, written);
        Ok(written)
    }

    /// An anonymous file has no name for the committed image to carry: it is
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
        self.tick(clock);
        let fd = self
            .live
            .create_anonymous(clock, name, mode, seals, huge_page)?;
        self.description_opened(fd);
        Ok(fd)
    }

    fn seals(&mut self, fd: Fd) -> DriverResult<u32> {
        self.live.seals(fd)
    }

    fn add_seals(&mut self, fd: Fd, seals: u32, writably_mapped: bool) -> DriverResult<()> {
        self.live.add_seals(fd, seals, writably_mapped)
    }

    /// Closing a file truncated to zero writes its data back
    /// (`auto_da_alloc`), so the commit that carries the truncation carries
    /// the bytes written since.
    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        let metadata = self.live.fd_metadata(fd).ok();
        let ino = metadata.map(|metadata| metadata.ino);
        if let Some(ino) = ino.filter(|ino| self.flush_on_close.remove(ino))
            && let Ok(current) = self.live.fd_file_data(fd)
        {
            let current = current.clone();
            self.write_back_delayed(ino, &current);
        }
        let description = self.live.description_of(fd).ok();
        self.live.close(fd)?;
        self.named.remove(&fd);
        if let Some(description) = description {
            self.description_closed(description);
        }
        self.forget_if_gone(ino);
        Ok(())
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        self.live.seek(fd, offset, whence)
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        let duplicate = self.live.dup(fd)?;
        if self.named.contains(&fd) {
            self.named.insert(duplicate);
        }
        Ok(duplicate)
    }

    fn set_append(&mut self, fd: Fd, append: bool) -> DriverResult<()> {
        self.live.set_append(fd, append)
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

    fn set_inode_mode(&mut self, clock: FsClock, ino: u64, mode: u32) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_inode_mode(clock, ino, mode)?;
        self.journal(clock, [ino]);
        Ok(())
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
        self.tick(clock);
        self.live.create_directory(clock, path, mode)?;
        let inodes = self.entry_and_parent(path);
        self.journal(clock, inodes);
        Ok(())
    }

    fn remove_file(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        self.tick(clock);
        let inodes = self.entry_and_parent(path);
        self.live.remove_file(clock, path)?;
        self.journal(clock, inodes.iter().copied());
        self.forget_if_gone(inodes.first().copied());
        Ok(())
    }

    /// `fsync`: write the file's dirty pages back, then commit if the inode
    /// has a change in the running transaction. An `fsync` that reports a
    /// writeback error returns before it commits.
    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.sync(fd)?;
        let metadata = self.live.fd_metadata(fd)?;
        if metadata.kind == FsEntryKind::File && self.named.contains(&fd) {
            let current = self.live.fd_file_data(fd)?.clone();
            self.write_back(metadata.ino, &current);
        }
        self.check_file_error(fd)?;
        if self.named.contains(&fd) && self.journaled.contains(&metadata.ino) {
            self.commit();
        }
        Ok(())
    }

    fn fail_writeback(&mut self, fd: Fd, code: ErrorCode) -> DriverResult<()> {
        self.writeback_failed(fd, code)
    }

    fn fail_writeback_all(&mut self, code: ErrorCode) -> DriverResult<()> {
        self.writeback_failed_all(code);
        Ok(())
    }

    fn wait_writeback(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.fd_metadata(fd)?;
        self.check_file_error(fd)
    }

    fn drop_cache(&mut self, fd: Fd, offset: u64, len: u64) -> DriverResult<()> {
        self.cache_dropped(fd, offset, len)
    }

    /// A truncation is journaled metadata: the next commit records the new
    /// size. Pages past a shortened end leave the cache, dirty or not.
    fn set_len(&mut self, clock: FsClock, fd: Fd, len: u64) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_len(clock, fd, len)?;
        let ino = self.live.fd_metadata(fd)?.ino;
        if self.named.contains(&fd) {
            self.truncated(clock, ino, len);
        }
        Ok(())
    }

    fn set_len_by_path(&mut self, clock: FsClock, path: &str, len: u64) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_len_by_path(clock, path, len)?;
        let ino = self.live.metadata(path)?.ino;
        self.truncated(clock, ino, len);
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
        self.tick(clock);
        self.live
            .allocate(clock, fd, offset, len, mode, keep_size)?;
        if !self.named.contains(&fd) {
            return Ok(());
        }
        let metadata = self.live.fd_metadata(fd)?;
        if mode != FsAllocateMode::Reserve {
            self.zeroed(fd, offset, len)?;
            // The range's extents change on disk too: the next commit
            // records them punched or zeroed.
            let current = self.live.fd_file_data(fd)?;
            let end = offset.saturating_add(len).min(current.len());
            let mut disk = self.disk_content(metadata.ino);
            disk.overlay(current, offset, end);
            self.written.insert(metadata.ino, disk);
            self.freed_range(metadata.ino, offset, len);
        }
        self.journal(clock, [metadata.ino]);
        // An allocation that grew the file records the new size itself.
        if metadata.len > self.disk_content(metadata.ino).len() {
            self.resized_on_disk(metadata.ino, metadata.len);
        }
        Ok(())
    }

    fn read_directory(
        &mut self,
        clock: FsClock,
        path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.tick(clock);
        self.live.read_directory(clock, path)
    }

    fn read_directory_fd(&mut self, clock: FsClock, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.tick(clock);
        self.live.read_directory_fd(clock, fd)
    }

    fn remove_directory(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        self.tick(clock);
        let inodes = self.entry_and_parent(path);
        self.live.remove_directory(clock, path)?;
        self.journal(clock, inodes);
        Ok(())
    }

    /// A rename over an existing name writes the source file's data back
    /// first (`auto_da_alloc`), so the commit that carries the rename carries
    /// the bytes it names.
    fn rename(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.tick(clock);
        let mut inodes = self.entry_and_parent(from);
        let destination = self.entry_and_parent(to);
        let replaced = self
            .live
            .entry_metadata(to)
            .ok()
            .map(|metadata| metadata.ino);
        self.live.rename(clock, from, to)?;
        inodes.extend(destination);
        self.journal(clock, inodes);
        if replaced.is_some()
            && let Ok(metadata) = self.live.entry_metadata(to)
            && let Ok(current) = self.live.file_data(to)
        {
            let current = current.clone();
            self.write_back_delayed(metadata.ino, &current);
        }
        self.forget_if_gone(replaced);
        Ok(())
    }

    fn rename_whiteout(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.tick(clock);
        let mut inodes = self.entry_and_parent(from);
        inodes.extend(self.entry_and_parent(to));
        self.live.rename_whiteout(clock, from, to)?;
        inodes.extend(self.entry_and_parent(from));
        self.journal(clock, inodes);
        Ok(())
    }

    fn exchange(&mut self, clock: FsClock, first: &str, second: &str) -> DriverResult<()> {
        self.tick(clock);
        let mut inodes = self.entry_and_parent(first);
        inodes.extend(self.entry_and_parent(second));
        self.live.exchange(clock, first, second)?;
        self.journal(clock, inodes);
        Ok(())
    }

    fn set_times(
        &mut self,
        clock: FsClock,
        fd: Fd,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_times(clock, fd, atime_nanos, mtime_nanos)?;
        let ino = self.live.fd_metadata(fd)?.ino;
        self.journal(clock, [ino]);
        Ok(())
    }

    fn set_inode_times(
        &mut self,
        clock: FsClock,
        ino: u64,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.tick(clock);
        self.live
            .set_inode_times(clock, ino, atime_nanos, mtime_nanos)?;
        self.journal(clock, [ino]);
        Ok(())
    }

    fn set_times_by_path(
        &mut self,
        clock: FsClock,
        path: &str,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        self.tick(clock);
        self.live
            .set_times_by_path(clock, path, atime_nanos, mtime_nanos)?;
        let inodes = self.entry_and_parent(path);
        self.journal(clock, inodes.first().copied());
        Ok(())
    }

    fn link(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.tick(clock);
        self.live.link(clock, from, to)?;
        let inodes = self.entry_and_parent(to);
        self.journal(clock, inodes);
        Ok(())
    }

    fn make_fifo(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        self.tick(clock);
        self.live.make_fifo(clock, path, mode)?;
        let inodes = self.entry_and_parent(path);
        self.journal(clock, inodes);
        Ok(())
    }

    fn make_node(
        &mut self,
        clock: FsClock,
        path: &str,
        node: FsNode,
        mode: u32,
    ) -> DriverResult<()> {
        self.tick(clock);
        self.live.make_node(clock, path, node, mode)?;
        let inodes = self.entry_and_parent(path);
        self.journal(clock, inodes);
        Ok(())
    }

    /// `sync(2)`/`syncfs(2)`: every dirty page is written back and the
    /// running transaction commits.
    fn sync_all(&mut self) -> DriverResult<()> {
        self.live.sync_all()?;
        self.checkpoint();
        Ok(())
    }

    fn sync_filesystem(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.fd_metadata(fd)?;
        self.sync_all()?;
        self.check_filesystem_error(fd)
    }

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
        self.tick(clock);
        self.live.set_xattr(clock, target, name, value, flags)?;
        self.journal_xattr_target(clock, target);
        Ok(())
    }

    fn remove_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
    ) -> DriverResult<()> {
        self.tick(clock);
        self.live.remove_xattr(clock, target, name)?;
        self.journal_xattr_target(clock, target);
        Ok(())
    }

    fn symlink(&mut self, clock: FsClock, target: &str, link_path: &str) -> DriverResult<()> {
        self.tick(clock);
        self.live.symlink(clock, target, link_path)?;
        let inodes = self.entry_and_parent(link_path);
        self.journal(clock, inodes);
        Ok(())
    }

    fn read_link(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        self.tick(clock);
        self.live.read_link(clock, path)
    }

    fn set_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_mode(clock, path, mode)?;
        let ino = self.live.metadata(path)?.ino;
        self.journal(clock, [ino]);
        Ok(())
    }

    fn set_fd_mode(&mut self, clock: FsClock, fd: Fd, mode: u32) -> DriverResult<()> {
        self.tick(clock);
        self.live.set_fd_mode(clock, fd, mode)?;
        let ino = self.live.fd_metadata(fd)?.ino;
        self.journal(clock, [ino]);
        Ok(())
    }

    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        self.live.fd_path(fd)
    }

    fn fd_ino(&mut self, fd: Fd) -> DriverResult<u64> {
        self.live.fd_ino(fd)
    }

    /// A path-only open creates and truncates nothing, so the handle is the
    /// only thing to track.
    fn open_path_unfaulted(&mut self, clock: FsClock, path: &str) -> DriverResult<Fd> {
        self.tick(clock);
        let fd = self.live.open_path_unfaulted(clock, path)?;
        self.named.insert(fd);
        self.description_opened(fd);
        Ok(fd)
    }

    fn metadata_unfaulted(&mut self, path: &str) -> DriverResult<FsMetadata> {
        self.live.metadata_unfaulted(path)
    }

    fn read_link_unfaulted(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        self.tick(clock);
        self.live.read_link_unfaulted(clock, path)
    }

    fn fd_metadata_unfaulted(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        self.live.fd_metadata_unfaulted(fd)
    }

    fn inode_metadata_unfaulted(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        self.live.inode_metadata_unfaulted(ino)
    }

    fn read_at_unfaulted(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> DriverResult<Vec<u8>> {
        self.tick(clock);
        self.live.read_at_unfaulted(clock, fd, offset, max_len)
    }

    fn crash(&mut self, clock: FsClock) -> DriverResult<()> {
        let crashes = self.crashes.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidState,
                "filesystem crash counter exhausted",
            )
        })?;
        self.recompute_after_crash(clock, true)?;
        self.crashes = crashes;
        Ok(())
    }

    fn crash_and_export_restart_snapshot(
        &mut self,
        clock: FsClock,
        kind: CrashKind,
    ) -> DriverResult<Vec<u8>> {
        Ok(self.crash_and_snapshot(clock, kind)?.encode()?)
    }
}

impl CrashFs {
    /// `written` bytes at `offset` of `fd` are dirty pages until its next
    /// writeback, and its inode (its size and `mtime`) has a change in the
    /// running transaction, when it is a named file.
    fn dirtied(&mut self, clock: FsClock, fd: Fd, offset: u64, written: usize) {
        if written == 0 || !self.named.contains(&fd) {
            return;
        }
        let Ok(metadata) = self.live.fd_metadata(fd) else {
            return;
        };
        self.journal(clock, [metadata.ino]);
        self.extended(metadata.ino, metadata.len);
        let first = offset / DIRTY_PAGE;
        let last = (offset + written as u64 - 1) / DIRTY_PAGE;
        self.rewritten(metadata.ino, first, last);
        self.dirty
            .entry(metadata.ino)
            .or_default()
            .extend(first..=last);
    }

    /// `ino` is `len` bytes long now: the next commit records the size,
    /// and its pages past the end are gone. A page a writeback error dropped
    /// that the new end cuts through is zeroed past it through its block
    /// (`ext4_block_truncate_page`), which dirties the page again. A file
    /// truncated to zero writes its data back at close (`auto_da_alloc`).
    fn truncated(&mut self, clock: FsClock, ino: u64, len: u64) {
        self.journal(clock, [ino]);
        self.resized_on_disk(ino, len);
        if len == 0 {
            self.flush_on_close.insert(ino);
        }
        if let Some(pages) = self.dirty.get_mut(&ino) {
            pages.retain(|page| *page < len.div_ceil(DIRTY_PAGE));
        }
        self.rewritten(ino, len.div_ceil(DIRTY_PAGE), u64::MAX);
        let tail = len / DIRTY_PAGE;
        if !len.is_multiple_of(DIRTY_PAGE)
            && self.lost.get(&ino).is_some_and(|lost| lost.contains(&tail))
        {
            self.rewritten(ino, tail, tail);
            self.dirty.entry(ino).or_default().insert(tail);
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
        if len == 0 {
            return Ok(());
        }
        let metadata = self.live.fd_metadata(fd)?;
        // A range at or past the end leaves the file as it was (a punch
        // there returns at once; a zeroing that grew the file ends past it).
        if offset >= metadata.len {
            return Ok(());
        }
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
        self.rewritten(metadata.ino, first, last);
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

    /// The inode an extended-attribute change on `target` journals.
    fn journal_xattr_target(&mut self, clock: FsClock, target: &XattrTarget) {
        let ino = match target {
            XattrTarget::Path(path) => self.live.metadata(path).ok().map(|metadata| metadata.ino),
            XattrTarget::Fd(fd) => self.live.fd_metadata(*fd).ok().map(|metadata| metadata.ino),
            XattrTarget::Inode(ino) => Some(*ino),
        };
        self.journal(clock, ino);
    }

    /// `ino` may have lost its last name or reference: once it is gone, its
    /// dirty pages go with it.
    fn forget_if_gone(&mut self, ino: Option<u64>) {
        if let Some(ino) = ino.filter(|ino| {
            self.dirty.contains_key(ino)
                || self.lost.contains_key(ino)
                || self.file_errors.contains_key(ino)
                || self.flush_on_close.contains(ino)
        }) && self.live.inode_metadata(ino).is_err()
        {
            self.flush_on_close.remove(&ino);
            self.dirty.remove(&ino);
            self.lost.remove(&ino);
            self.file_errors.remove(&ino);
        }
    }
}

#[cfg(test)]
mod tests;
