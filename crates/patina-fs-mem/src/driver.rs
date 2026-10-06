//! Guest-facing filesystem operations through FsDriver.

use crate::descriptors::invalid_fd;
use crate::file_io::{no_such_position, not_sealable, sealed, too_big};
use crate::metadata::{denied, owner_allows};
use crate::namespace::{normalize_entry_path, not_found, parent_path};
use crate::xattrs::{XattrAccess, no_xattr};
use crate::{
    Access, BLOCK_SIZE, FileData, Inode, MODE_MASK, MemFs, READ, SYMLINK_MODE, TimeRange, Times,
    WRITE, XATTR_CREATE, XATTR_REPLACE,
};
use patina_dst_abi::seals::{
    F_ALL_SEALS, F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK,
    F_SEAL_WRITE,
};
use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry, FsEntryKind, FsMetadata,
    FsNode, OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::{DriverResult, FsDriver, XattrNamespace};

impl FsDriver for MemFs {
    fn open(&mut self, clock: FsClock, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if flags.path_only {
            // `O_PATH` names a location. The kernel ignores the access mode and
            // every creating flag under it, so a caller that sets one is asking
            // for two different descriptors at once.
            if flags.read
                || flags.write
                || flags.create
                || flags.truncate
                || flags.append
                || flags.exclusive
            {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    "a path-only open carries no access mode and creates nothing",
                ));
            }
        } else if !flags.read && !flags.write {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "open requires read or write access",
            ));
        }
        if (flags.create || flags.truncate || flags.append || flags.exclusive) && !flags.write {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "create, truncate, append, and exclusive flags require write access",
            ));
        }
        if flags.exclusive && !flags.create {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "exclusive open requires create",
            ));
        }
        if let Some(metadata) = self.directories.get(&path).copied() {
            if flags.write || flags.create || flags.truncate || flags.append || flags.exclusive {
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual filesystem path is a directory: {path}"),
                ));
            }
            // The two directory opens cost different things, which is the whole
            // reason `O_PATH` is in this vocabulary. An `O_PATH` open never
            // opens the entry: Linux charges nothing on it, only the `x` walk of
            // the prefix that `resolve_guard` has already done, and the
            // descriptor can resolve and `fstat` but not iterate. A plain
            // `O_RDONLY|O_DIRECTORY` open DOES open it for reading and costs
            // `r` — charged here, once, so a later `chmod` cannot retroactively
            // break a walk already in progress.
            if !flags.path_only && !owner_allows(metadata.mode, READ) {
                return Err(denied(&path, "list"));
            }
            // A plain directory open is a READ of the directory; a path-only
            // one opens nothing at all.
            let access = if flags.path_only {
                Access::LOCATION
            } else {
                Access {
                    readable: true,
                    writable: false,
                    append: false,
                    path_only: false,
                }
            };
            return self.allocate_handle(metadata.ino, 0, access, FsEntryKind::Directory);
        }
        if let Some(inode) = self.names.get(&path).copied() {
            let (kind, mode) = {
                let node = self.inodes.get(&inode).expect("name references an inode");
                (node.kind, node.mode)
            };
            match kind {
                FsEntryKind::Symlink => {
                    return Err(EffectError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "virtual symlink cannot be opened without host-level follow: {path}"
                        ),
                    ));
                }
                // `O_PATH` is the one open of a FIFO, a socket node or a
                // whiteout that never reaches past the name: it names the entry
                // without opening it, so there is no rendezvous, no permission
                // on the entry to charge, and the descriptor IS a filesystem
                // descriptor — the only kind of handle this filesystem can hold
                // on one.
                FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice => {
                    if flags.path_only {
                        return self.allocate_handle(inode, 0, Access::LOCATION, kind);
                    }
                    // The permission decision belongs HERE — one enforcement
                    // point for every kind — even though no filesystem
                    // descriptor comes back: opening for reading needs `r` and
                    // for writing `w`, exactly as a regular file does.
                    if flags.exclusive {
                        return Err(EffectError::new(
                            ErrorCode::AlreadyExists,
                            format!("virtual filesystem entry already exists: {path}"),
                        ));
                    }
                    if flags.read && !owner_allows(mode, READ) {
                        return Err(denied(&path, "read"));
                    }
                    if flags.write && !owner_allows(mode, WRITE) {
                        return Err(denied(&path, "write"));
                    }
                    // A FIFO carries no filesystem bytes, so there is no
                    // filesystem description to hand back: the caller opens the
                    // pipe the FIFO's openers share. A socket node or a whiteout
                    // has nothing behind it at all, and the caller answers the
                    // `ENXIO` the kernel's open does. The permission and
                    // existence answers above are the part that IS filesystem
                    // state, and they have been given.
                    return Err(EffectError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "virtual {kind:?} node is not opened as a filesystem descriptor: {path}"
                        ),
                    ));
                }
                FsEntryKind::File | FsEntryKind::Directory => {}
            }
        }

        if !self.names.contains_key(&path) {
            // A path-only open creates nothing, so a missing name is missing.
            if flags.create {
                self.check_directory_write(parent_path(&path))?;
                self.insert_parent_directories(clock, &path);
                // The caller's own creation mode — `open`'s third argument, which
                // the kernel reads only on the branch that actually creates the
                // entry, already under the caller's umask.
                let inode =
                    self.allocate_inode(clock, FsEntryKind::File, FileData::default(), flags.mode);
                self.names.insert(path.clone(), inode);
                self.stamp_directory(clock, parent_path(&path));
            } else {
                return Err(not_found(&path));
            }
        } else if flags.exclusive {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        } else if !flags.path_only {
            let mode = self
                .entry_mode(&path)
                .expect("the file was found in this branch");
            if flags.read && !owner_allows(mode, READ) {
                return Err(denied(&path, "read"));
            }
            if flags.write && !owner_allows(mode, WRITE) {
                return Err(denied(&path, "write"));
            }
            if flags.truncate {
                // `O_TRUNC` is a truncation: `mtime`/`ctime` move even when the
                // file was already empty (`handle_truncate` → `do_truncate`).
                let inode = self.file_inode(&path)?;
                let inode = self
                    .inodes
                    .get_mut(&inode)
                    .expect("file path references an inode");
                inode.contents.set_len(0);
                inode.times.data_changed(clock);
            }
        }

        let node = self.file_inode(&path)?;
        let cursor = if flags.append {
            let len = self
                .inodes
                .get(&node)
                .expect("file path references an inode")
                .contents
                .len();
            usize::try_from(len).unwrap_or(usize::MAX)
        } else {
            0
        };
        self.allocate_handle(node, cursor, Access::from_flags(flags), FsEntryKind::File)
    }

    fn read(&mut self, clock: FsClock, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        let description = self.description(fd)?;
        if !description.readable {
            return Err(EffectError::new(
                ErrorCode::NotReadable,
                format!("virtual file handle {} is not readable", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        let start = description.cursor;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        let bytes = inode.contents.read(start as u64, max_len);
        if max_len != 0 {
            inode.times.accessed(clock);
        }
        self.description_mut(fd)?.cursor = start + bytes.len();
        Ok(bytes)
    }

    fn write(&mut self, clock: FsClock, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        let description = self.description(fd)?;
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotWritable,
                format!("virtual file handle {} is not writable", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let cursor = description.cursor;
        let append = description.append;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        let start = if append {
            inode.contents.len()
        } else {
            cursor as u64
        };
        let bytes = &bytes[..inode.write_limit(start, bytes.len())?];
        let end = start + bytes.len() as u64;
        let cursor = usize::try_from(end).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual write end exceeds the addressable range",
            )
        })?;
        inode.check_write_seals(end)?;
        inode.contents.write(start, bytes);
        inode.times.data_changed(clock);
        self.description_mut(fd)?.cursor = cursor;
        Ok(bytes.len())
    }

    fn write_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        self.write_node_at(clock, fd, offset, bytes, true)
    }

    /// The page cache's write-back: what a shared mapping stored. A write
    /// seal does not refuse it — a mapping writable before the seal keeps
    /// writing the file.
    fn write_back_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        self.write_node_at(clock, fd, offset, bytes, false)
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        let id = self.handles.remove(&fd).ok_or_else(|| invalid_fd(fd))?;
        let description = self
            .descriptions
            .get_mut(&id)
            .expect("handle references a description");
        description.fds -= 1;
        if description.fds == 0 {
            // The LAST descriptor on the description drops the description's
            // reference to the node; if its last name went first, this is where
            // the node itself is finally freed.
            let node = description.node;
            self.descriptions.remove(&id);
            if let Some(inode) = self.inodes.get_mut(&node) {
                inode.openers -= 1;
            }
            self.release_if_unreferenced(node);
        }
        Ok(())
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        let duplicate = Fd(self.next_fd);
        // Reserve the descriptor number before touching the refcount so an
        // exhausted `next_fd` fails without leaking a description reference.
        self.next_fd = self.next_fd.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidHandle, "virtual file handles exhausted")
        })?;
        self.descriptions
            .get_mut(&id)
            .expect("handle references a description")
            .fds += 1;
        self.handles.insert(duplicate, id);
        Ok(duplicate)
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        let description = self.description(fd)?;
        if description.kind == FsEntryKind::Directory || description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "virtual handle {} names a location and cannot be seeked",
                    fd.0
                ),
            ));
        }
        let cursor = description.cursor;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get(&inode)
            .expect("open handle references a file");
        let (contents, max) = (&inode.contents, inode.max_bytes());
        let base = match whence {
            SeekWhence::Start => 0,
            SeekWhence::Current => cursor,
            SeekWhence::End => usize::try_from(contents.len()).unwrap_or(usize::MAX),
            // `iomap_seek_data`/`iomap_seek_hole` over the blocks: only a
            // written block is data (an unwritten one reads as a hole), and
            // the end is the last hole.
            SeekWhence::Data | SeekWhence::Hole => {
                let found = u64::try_from(offset).ok().and_then(|offset| {
                    if whence == SeekWhence::Data {
                        contents.seek_data(offset)
                    } else {
                        contents.seek_hole(offset)
                    }
                });
                let position = found.ok_or_else(|| no_such_position(offset))?;
                self.description_mut(fd)?.cursor = position as usize;
                return Ok(position);
            }
        };
        let position = i128::try_from(base).expect("usize fits in i128") + i128::from(offset);
        // `vfs_setpos`: a position before the start, or past the node's
        // size limit, is EINVAL.
        let position = usize::try_from(position)
            .ok()
            .filter(|position| *position as u64 <= max)
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual seek before the start or past the size limit: {position}"),
                )
            })?;
        self.description_mut(fd)?.cursor = position;
        u64::try_from(position).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual seek position does not fit in u64",
            )
        })
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.metadata_for_path(&path)
    }

    /// `fstat`. A descriptor answers from its NODE, so an entry whose last name
    /// was unlinked while it stayed open reports its live mode, size and link
    /// count rather than a copy taken when it was opened.
    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        let description = self.description(fd)?;
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            return self.metadata_for_path(&path);
        }
        self.metadata_for_inode(node)
    }

    /// The LIVE metadata of the entry an inode names — what `fstat` on a FIFO
    /// descriptor reads, since the pipe endpoint holds a node and no filesystem
    /// handle. Any of the node's names answers identically (a mode, a link count
    /// and a timestamp belong to the inode, not to a name), so the first in path
    /// order is taken for determinism. A node with no names left is `NotFound`:
    /// the filesystem has nothing to say about an inode only a descriptor holds.
    fn inode_metadata(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        self.metadata_for_inode(ino)
    }

    /// `fchmod` on a node, for the descriptor class the filesystem holds no
    /// handle for. It reaches an unlinked node exactly as `inode_metadata` does.
    fn set_inode_mode(&mut self, clock: FsClock, ino: u64, mode: u32) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        inode.mode = mode & MODE_MASK;
        inode.times.metadata_changed(clock);
        Ok(())
    }

    /// Take a descriptor's reference on a node the filesystem hands back no
    /// handle for — the FIFO endpoint whose bytes belong to the openers' pipe.
    fn retain_inode(&mut self, ino: u64) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        inode.openers += 1;
        Ok(())
    }

    fn release_inode(&mut self, ino: u64) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        if inode.openers == 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                format!("virtual filesystem node {ino} holds no descriptor reference"),
            ));
        }
        inode.openers -= 1;
        self.release_if_unreferenced(ino);
        Ok(())
    }

    fn create_directory(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if self.path_exists(&path) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        }
        let parent = parent_path(&path);
        if !self.directories.contains_key(parent) {
            return Err(EffectError::new(
                ErrorCode::NotFound,
                format!("virtual parent directory does not exist: {parent}"),
            ));
        }
        // `mkdir`'s mode argument, already under the caller's umask.
        let metadata = self.allocate_entry_metadata(clock, mode);
        self.directories.insert(path.clone(), metadata);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    fn make_fifo(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        // A FIFO is an inode with no bytes: hard links, the link count, the
        // mode and the identity the openers' pipe channel is keyed by all live
        // there, exactly as they do for a regular file.
        self.make_node(clock, path, FsNode::Fifo, mode)
    }

    /// `mknod`: a new name for a fresh node with no bytes, at the mode the
    /// caller asked for (already under its umask). The name and the parent's
    /// `w`+`x` are judged first, then the privilege a device other than the
    /// whiteout needs, which the one modeled identity does not have.
    fn make_node(
        &mut self,
        clock: FsClock,
        path: &str,
        node: FsNode,
        mode: u32,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.check_new_name(&path)?;
        let kind = node.kind().ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotPermitted,
                format!("a device node needs CAP_MKNOD: {path}"),
            )
        })?;
        let inode = self.allocate_inode(clock, kind, FileData::default(), mode);
        self.names.insert(path.clone(), inode);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    /// `renameat2(RENAME_WHITEOUT)`: the rename, then a whiteout (a 0:0
    /// character device, mode 0) at the name it vacated, in one call. A rename
    /// between two names of one node changes nothing, whiteout included.
    fn rename_whiteout(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.rename(clock, from, to)?;
        let from = normalize_entry_path(from)?;
        if self.path_exists(&from) {
            return Ok(());
        }
        let inode = self.allocate_inode(clock, FsEntryKind::CharDevice, FileData::default(), 0);
        self.names.insert(from, inode);
        Ok(())
    }

    fn remove_file(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if self.directories.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual filesystem path is a directory: {path}"),
            ));
        }
        // Unlink removes the NAME, never the node. Whatever still holds the node
        // — another name, or an open descriptor — keeps it alive, and the last
        // reference of either kind is what frees it. A FIFO name goes the same
        // way whatever is open on it: the openers hold the pipe, not the name.
        let inode = self.names.remove(&path).ok_or_else(|| not_found(&path))?;
        self.drop_name(clock, inode);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!(
                    "virtual handle {} names a location and cannot be synced",
                    fd.0
                ),
            ));
        }
        Ok(())
    }

    /// `ftruncate`. The kernel's refusals (`do_sys_ftruncate`): a path-only
    /// descriptor is `EBADF`; a directory, or any descriptor not open for
    /// writing, is `EINVAL` — not `EBADF` (the number is valid) and not
    /// `EISDIR` (that is the by-NAME answer). `mtime`/`ctime` move even when
    /// the length does not.
    fn set_len(&mut self, clock: FsClock, fd: Fd, len: u64) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!(
                    "virtual handle {} names a location and cannot be truncated",
                    fd.0
                ),
            ));
        }
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        let inode = self.handle_inode(fd)?;
        self.inodes
            .get(&inode)
            .expect("open handle references a file")
            .check_resize_seals(len)?;
        Self::truncate_inode(self.inodes.get_mut(&inode), clock, len)
    }

    /// `truncate(2)`: `EISDIR` for a directory, `EINVAL` for any other
    /// non-regular entry (a FIFO, a socket node, a whiteout, or a symlink the
    /// caller declined to follow), `EACCES` without `w`.
    fn set_len_by_path(&mut self, clock: FsClock, path: &str, len: u64) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.directories.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual filesystem path is a directory: {path}"),
            ));
        }
        if self
            .leaf_kind(&path)
            .is_some_and(|kind| kind != FsEntryKind::File)
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual filesystem entry is not a regular file: {path}"),
            ));
        }
        let inode = self.file_inode(&path)?;
        let mode = self
            .inodes
            .get(&inode)
            .expect("file path references an inode")
            .mode;
        if !owner_allows(mode, WRITE) {
            return Err(denied(&path, "write"));
        }
        Self::truncate_inode(self.inodes.get_mut(&inode), clock, len)
    }

    /// `fallocate`: the kernel's refusals in its order (`EBADF` for a
    /// descriptor not open for writing or a path-only one, `EISDIR` for a
    /// directory), then the range change, then `mtime`/`ctime`.
    fn allocate(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        len: u64,
        mode: FsAllocateMode,
        keep_size: bool,
    ) -> DriverResult<()> {
        let zero = mode != FsAllocateMode::Reserve;
        let description = self.description(fd)?;
        if description.path_only || !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotWritable,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual allocation range overflowed",
            )
        })?;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        // `vfs_fallocate`: a range past the size limit, whatever the mode.
        if end > inode.max_bytes() {
            return Err(too_big("virtual allocation past the file size limit"));
        }
        // The kernel refuses an empty range before this (`EINVAL`); here it
        // changes nothing.
        if len == 0 {
            return Ok(());
        }
        // `hugetlbfs_fallocate` with no huge page to allocate: a hole punch has
        // nothing to free, an allocation fails.
        if inode.huge_page != 0 {
            if zero {
                return Ok(());
            }
            return Err(EffectError::new(
                ErrorCode::NoSpace,
                "no huge page is reserved to allocate",
            ));
        }
        // `shmem_fallocate`: punching needs no write seal, growing no grow seal.
        let seals = inode.seals.unwrap_or(0);
        if (zero && seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0)
            || (!keep_size && end > inode.contents.len() && seals & F_SEAL_GROW != 0)
        {
            return Err(sealed());
        }
        let file = &mut inode.contents;
        let size = file.len();
        match mode {
            FsAllocateMode::Reserve => file.reserve(offset, end),
            FsAllocateMode::ZeroRange => file.zero_range(offset, end),
            // tmpfs frees whatever the range covers (`shmem_truncate_range`).
            FsAllocateMode::PunchHole if inode.seals.is_some() => file.punch(offset, end),
            // `ext4_punch_hole`: nothing at or past the size, and a range
            // past it ends with the page that holds the size, so a
            // reservation further out survives.
            FsAllocateMode::PunchHole if offset < size => {
                let past_size = size - size % BLOCK_SIZE + BLOCK_SIZE;
                file.punch(offset, end.min(past_size));
            }
            FsAllocateMode::PunchHole => {}
        }
        if !keep_size && end > size {
            file.set_len(end);
        }
        inode.times.data_changed(clock);
        Ok(())
    }

    fn set_times(
        &mut self,
        clock: FsClock,
        fd: Fd,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual handle {} names a location and has no times", fd.0),
            ));
        }
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            let times = self.times_mut(&path).expect("a named directory has times");
            times.set(clock, atime_nanos, mtime_nanos, TimeRange::Ext4);
            return Ok(());
        }
        let inode = self.inodes.get_mut(&node).ok_or_else(|| invalid_fd(fd))?;
        let range = TimeRange::of(inode);
        inode.times.set(clock, atime_nanos, mtime_nanos, range);
        Ok(())
    }

    fn set_inode_times(
        &mut self,
        clock: FsClock,
        ino: u64,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        let (times, range) = if let Some(inode) = self.inodes.get_mut(&ino) {
            let range = TimeRange::of(inode);
            (&mut inode.times, range)
        } else {
            let entry = self
                .directories
                .values_mut()
                .find(|entry| entry.ino == ino)
                .ok_or_else(|| not_found("<inode>"))?;
            (&mut entry.times, TimeRange::Ext4)
        };
        times.set(clock, atime_nanos, mtime_nanos, range);
        Ok(())
    }

    fn set_times_by_path(
        &mut self,
        clock: FsClock,
        path: &str,
        atime_nanos: Option<i128>,
        mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        // A path names a node on the volume, never an anonymous file.
        let times = self.times_mut(&path).ok_or_else(|| not_found(&path))?;
        times.set(clock, atime_nanos, mtime_nanos, TimeRange::Ext4);
        Ok(())
    }

    fn read_directory(
        &mut self,
        clock: FsClock,
        path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.names.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        let Some(metadata) = self.directories.get(&path).copied() else {
            return Err(not_found(&path));
        };
        // The fused path form is `opendir`+`readdir` in one call, so it charges
        // the `r` the open inside it would have charged. The descriptor form
        // ([`FsDriver::read_directory_fd`]) charges nothing: its `r` was paid
        // when the descriptor was opened.
        if !owner_allows(metadata.mode, READ) {
            return Err(denied(&path, "list"));
        }
        self.directories
            .get_mut(&path)
            .expect("directory was checked")
            .times
            .accessed(clock);
        self.list_directory(&path)
    }

    fn read_directory_fd(&mut self, clock: FsClock, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        let description = self.description(fd)?;
        if description.kind != FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!(
                    "virtual file handle {} does not reference a directory",
                    fd.0
                ),
            ));
        }
        if !description.readable {
            // An `O_PATH` directory descriptor: it names the location and never
            // opened it, so there is nothing to iterate however permissive the
            // directory's own bits are.
            return Err(EffectError::new(
                ErrorCode::NotReadable,
                format!(
                    "virtual directory handle {} was not opened for reading",
                    fd.0
                ),
            ));
        }
        let path = self
            .node_path(description.node, FsEntryKind::Directory)
            .ok_or_else(|| not_found("<removed directory>"))?;
        // Reached through the descriptor, the listing itself is unenforced: the
        // access was charged at open, and a `chmod` afterwards cannot reach back
        // into a walk already under way.
        self.directories
            .get_mut(&path)
            .expect("the node has a name")
            .times
            .accessed(clock);
        let mut listing = self.dot_entries(&path).to_vec();
        listing.extend(self.list_directory(&path)?);
        Ok(listing)
    }

    fn remove_directory(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if path == "/" {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "cannot remove the virtual filesystem root",
            ));
        }
        if self.names.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        if !self.directories.contains_key(&path) {
            return Err(not_found(&path));
        }
        if self.has_children(&path) {
            return Err(EffectError::new(
                ErrorCode::DirectoryNotEmpty,
                format!("virtual directory is not empty: {path}"),
            ));
        }
        self.drop_directory(&path);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    /// `rename`. A name moves onto a free name or replaces what is there: a
    /// non-directory replaces a non-directory (`EISDIR` onto a directory), a
    /// directory replaces an EMPTY directory (`ENOTDIR` onto anything else,
    /// `ENOTEMPTY` onto a directory with entries). Two names for one node (a
    /// file onto its own hard link, a name onto itself) are the kernel's
    /// no-op success. A directory cannot move beneath itself (`EINVAL`).
    fn rename(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        let from = normalize_entry_path(from)?;
        let to = normalize_entry_path(to)?;
        self.resolve_guard(&from)?;
        self.resolve_guard(&to)?;
        self.check_directory_write(parent_path(&from))?;
        self.check_directory_write(parent_path(&to))?;
        if from == "/" || to == "/" || to.starts_with(&format!("{from}/")) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("invalid virtual rename from {from} to {to}"),
            ));
        }
        if !self.directories.contains_key(parent_path(&to)) {
            return Err(not_found(parent_path(&to)));
        }
        if let Some(inode) = self.names.get(&from).copied() {
            if self.directories.contains_key(&to) {
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual rename destination is a directory: {to}"),
                ));
            }
            if self.names.get(&to) == Some(&inode) {
                return Ok(());
            }
            self.names.remove(&from);
            self.unlink_leaf_at(clock, &to);
            self.names.insert(to.clone(), inode);
            // Nothing else to do: a description holds the NODE, so every
            // descriptor on this entry moved with it by construction.
            self.stamp_renamed(clock, &from, &to);
            return Ok(());
        }
        if !self.directories.contains_key(&from) {
            return Err(not_found(&from));
        }
        if from == to {
            return Ok(());
        }
        if self.names.contains_key(&to) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual rename of a directory onto a non-directory: {to}"),
            ));
        }
        if self.directories.contains_key(&to) {
            if self.has_children(&to) {
                return Err(EffectError::new(
                    ErrorCode::DirectoryNotEmpty,
                    format!("virtual rename destination is not empty: {to}"),
                ));
            }
            // An empty directory is replaced: its name now belongs to the
            // moved directory, and the node it named is gone.
            self.drop_directory(&to);
        }
        let moved = self.take_subtree(&from);
        self.place_subtree(moved, &to);
        self.stamp_renamed(clock, &from, &to);
        Ok(())
    }

    /// `renameat2(RENAME_EXCHANGE)`: both names must exist; each takes the
    /// other's entry — a directory's whole subtree with it — whatever the two
    /// kinds are. One cannot hold the other (`EINVAL`); a name exchanged with
    /// itself, or with another name for the same node, changes nothing.
    fn exchange(&mut self, clock: FsClock, first: &str, second: &str) -> DriverResult<()> {
        let first = normalize_entry_path(first)?;
        let second = normalize_entry_path(second)?;
        self.resolve_guard(&first)?;
        self.resolve_guard(&second)?;
        self.check_directory_write(parent_path(&first))?;
        self.check_directory_write(parent_path(&second))?;
        for path in [&first, &second] {
            if !self.path_exists(path) {
                return Err(not_found(path));
            }
        }
        if first == "/"
            || second == "/"
            || second.starts_with(&format!("{first}/"))
            || first.starts_with(&format!("{second}/"))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("invalid virtual exchange of {first} and {second}"),
            ));
        }
        if first == second || self.node_id(&first) == self.node_id(&second) {
            return Ok(());
        }
        let first_tree = self.take_subtree(&first);
        let second_tree = self.take_subtree(&second);
        self.place_subtree(first_tree, &second);
        self.place_subtree(second_tree, &first);
        for path in [&first, &second] {
            if let Some(times) = self.times_mut(path) {
                times.metadata_changed(clock);
            }
        }
        self.stamp_directory(clock, parent_path(&first));
        if parent_path(&second) != parent_path(&first) {
            self.stamp_directory(clock, parent_path(&second));
        }
        Ok(())
    }

    /// `link`: a second name for the node `from` names, whatever its kind but
    /// a directory's (`EPERM`) — a symlink's included: without
    /// `AT_SYMLINK_FOLLOW` the kernel links the link itself.
    fn link(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        let from = normalize_entry_path(from)?;
        let to = normalize_entry_path(to)?;
        self.resolve_guard(&from)?;
        self.resolve_guard(&to)?;
        self.check_directory_write(parent_path(&to))?;
        if self.path_exists(&to) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {to}"),
            ));
        }
        if !self.directories.contains_key(parent_path(&to)) {
            return Err(not_found(parent_path(&to)));
        }
        if self.directories.contains_key(&from) {
            return Err(EffectError::new(
                ErrorCode::NotPermitted,
                format!("virtual hard link to a directory: {from}"),
            ));
        }
        let inode = self
            .names
            .get(&from)
            .copied()
            .ok_or_else(|| not_found(&from))?;
        self.names.insert(to.clone(), inode);
        let entry = self
            .inodes
            .get_mut(&inode)
            .expect("name references an inode");
        entry.links += 1;
        // The link count is inode metadata: `ctime` moves on the node, and the
        // new name is a data change to its directory.
        entry.times.metadata_changed(clock);
        self.stamp_directory(clock, parent_path(&to));
        Ok(())
    }

    fn symlink(&mut self, clock: FsClock, target: &str, link_path: &str) -> DriverResult<()> {
        if target.contains('\0') {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual symlink target contains NUL",
            ));
        }
        let link_path = normalize_entry_path(link_path)?;
        self.check_new_name(&link_path)?;
        let inode = self.allocate_inode(
            clock,
            FsEntryKind::Symlink,
            FileData::from_bytes(target.as_bytes()),
            SYMLINK_MODE,
        );
        self.names.insert(link_path.clone(), inode);
        self.stamp_directory(clock, parent_path(&link_path));
        Ok(())
    }

    fn read_link(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if let Some(ino) = self
            .names
            .get(&path)
            .copied()
            .filter(|ino| self.kind_of(*ino) == Some(FsEntryKind::Symlink))
        {
            let inode = self.inodes.get_mut(&ino).expect("name references an inode");
            // Reading a link is a read of the link: `atime`, under the policy.
            inode.times.accessed(clock);
            return Ok(String::from_utf8_lossy(&inode.contents.to_vec()).into_owned());
        }
        // An entry that exists but is not a symlink is `EINVAL` (readlink(2)),
        // distinguishable from a name that is not there at all.
        if self.path_exists(&path) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual filesystem entry is not a symbolic link: {path}"),
            ));
        }
        Err(not_found(&path))
    }

    /// `chmod` / `fchmodat`. Changing a mode is an OWNER right, not a
    /// permission-bit right, and the single modeled identity owns every entry —
    /// so only REACHING the entry is checked, never the entry's own bits.
    ///
    /// A symlink leaf has no mode of its own here (Linux ignores one too), so
    /// naming a link fails closed rather than silently recording a mode nothing
    /// will ever read. `chmod`'s follow-the-link spelling resolves above this
    /// boundary and arrives naming the target.
    fn set_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.leaf_kind(&path) == Some(FsEntryKind::Symlink) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!("virtual symlink has no mode of its own: {path}"),
            ));
        }
        self.apply_mode(clock, &path, mode)
    }

    /// `fchmod`. The bits belong to the NODE, so this reaches an unlinked entry
    /// through its descriptor exactly as a kernel does — and an `O_PATH`
    /// descriptor, which never opened the file, cannot change them at all.
    fn set_fd_mode(&mut self, clock: FsClock, fd: Fd, mode: u32) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual handle {} names a location and has no mode", fd.0),
            ));
        }
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            return self.apply_mode(clock, &path, mode);
        }
        let inode = self.inodes.get_mut(&node).ok_or_else(|| invalid_fd(fd))?;
        inode.mode = mode & MODE_MASK;
        inode.times.metadata_changed(clock);
        Ok(())
    }

    /// The path this descriptor's NODE currently has — see
    /// [`FsDriver::fd_path`]. A description is bound to the node, and every
    /// rename that moves the node rewrites the descriptions that reference it,
    /// so this answers where the node IS rather than the name it was opened
    /// under.
    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        let description = self.description(fd)?;
        let (node, kind) = (description.node, description.kind);
        self.node_path(node, kind)
            .ok_or_else(|| not_found("<unlinked node>"))
    }

    fn fd_ino(&mut self, fd: Fd) -> DriverResult<u64> {
        Ok(self.description(fd)?.node)
    }

    /// `sync(2)`: nothing to write back — every change is already the image.
    fn sync_all(&mut self) -> DriverResult<()> {
        Ok(())
    }

    fn get_xattr(&mut self, target: &XattrTarget, name: &str) -> DriverResult<Vec<u8>> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Read)?;
        self.xattrs
            .get(&ino)
            .and_then(|attributes| attributes.get(name))
            .cloned()
            .ok_or_else(|| no_xattr(name))
    }

    /// The names a caller may see: every attribute but a `trusted.*` one, which
    /// is listed only to `CAP_SYS_ADMIN`. Listing checks no permission bits.
    fn list_xattr(&mut self, target: &XattrTarget) -> DriverResult<Vec<String>> {
        let (ino, _, _) = self.xattr_node(target)?;
        Ok(self
            .xattrs
            .get(&ino)
            .map(|attributes| {
                attributes
                    .keys()
                    .filter(|name| XattrNamespace::of(name) != XattrNamespace::Trusted)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `XATTR_CREATE` on a name that exists is `EEXIST`, `XATTR_REPLACE` on
    /// one that does not `ENODATA` (with both, whichever applies). The node's
    /// `ctime` moves.
    fn set_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> DriverResult<()> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Write)?;
        let exists = self
            .xattrs
            .get(&ino)
            .is_some_and(|attributes| attributes.contains_key(name));
        if exists && flags & XATTR_CREATE != 0 {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual extended attribute already exists: {name}"),
            ));
        }
        if !exists && flags & XATTR_REPLACE != 0 {
            return Err(no_xattr(name));
        }
        self.xattrs
            .entry(ino)
            .or_default()
            .insert(name.to_owned(), value.to_vec());
        self.stamp_node(clock, ino, kind);
        Ok(())
    }

    fn remove_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
    ) -> DriverResult<()> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Write)?;
        let attributes = self.xattrs.get_mut(&ino).ok_or_else(|| no_xattr(name))?;
        attributes.remove(name).ok_or_else(|| no_xattr(name))?;
        if attributes.is_empty() {
            self.xattrs.remove(&ino);
        }
        self.stamp_node(clock, ino, kind);
        Ok(())
    }

    /// [`FsDriver::create_anonymous`]: a node with no name, alive while a
    /// descriptor holds it, exactly an unlinked file's lifetime.
    fn create_anonymous(
        &mut self,
        clock: FsClock,
        _name: &str,
        mode: u32,
        seals: u32,
        huge_page: u64,
    ) -> DriverResult<Fd> {
        let node = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::NoSpace, "virtual inode numbers exhausted")
        })?;
        self.inodes.insert(
            node,
            Inode {
                kind: FsEntryKind::File,
                contents: FileData::default(),
                links: 0,
                openers: 0,
                times: Times::created(clock),
                mode: mode & MODE_MASK,
                seals: Some(seals & F_ALL_SEALS),
                huge_page,
            },
        );
        let access = Access {
            readable: true,
            writable: true,
            append: false,
            path_only: false,
        };
        match self.allocate_handle(node, 0, access, FsEntryKind::File) {
            Ok(fd) => Ok(fd),
            Err(error) => {
                self.inodes.remove(&node);
                Err(error)
            }
        }
    }

    fn seals(&mut self, fd: Fd) -> DriverResult<u32> {
        let node = self.description(fd)?.node;
        self.inodes
            .get(&node)
            .and_then(|inode| inode.seals)
            .ok_or_else(not_sealable)
    }

    fn add_seals(&mut self, fd: Fd, seals: u32, writably_mapped: bool) -> DriverResult<()> {
        let description = self.description(fd)?;
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotPermitted,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        if seals & !F_ALL_SEALS != 0 {
            return Err(EffectError::new(ErrorCode::InvalidInput, "unknown seal"));
        }
        let node = description.node;
        let inode = self
            .inodes
            .get_mut(&node)
            .filter(|inode| inode.seals.is_some())
            .ok_or_else(not_sealable)?;
        let current = inode.seals.expect("filtered to a sealable node");
        if current & F_SEAL_SEAL != 0 {
            return Err(sealed());
        }
        if seals & F_SEAL_WRITE != 0 && current & F_SEAL_WRITE == 0 && writably_mapped {
            return Err(EffectError::new(
                ErrorCode::Busy,
                "a shared writable mapping of the virtual file is live",
            ));
        }
        // `F_SEAL_EXEC` on an executable file implies every write seal.
        let implied = if seals & F_SEAL_EXEC != 0 && inode.mode & 0o111 != 0 {
            F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE
        } else {
            0
        };
        inode.seals = Some(current | seals | implied);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
