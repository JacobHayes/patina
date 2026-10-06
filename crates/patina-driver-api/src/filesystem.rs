//! Filesystem driver operations and extended-attribute permissions.

use crate::{DriverResult, FsFaultReport};
use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry, FsMetadata, FsNode,
    OpenFlags, SeekWhence, XattrTarget,
};

pub trait FsDriver: Send {
    /// `open(2)`. `clock` stamps a created entry's four timestamps (and its
    /// parent directory's `mtime`/`ctime`) and an `O_TRUNC`'d file's
    /// `mtime`/`ctime`; an open of an existing entry touches no time.
    fn open(&mut self, _clock: FsClock, _path: &str, _flags: OpenFlags) -> DriverResult<Fd> {
        Err(unsupported_filesystem_operation("open"))
    }
    /// A cursor read. Updates `atime` under the clock's [`patina_dst_abi::AtimePolicy`].
    fn read(&mut self, _clock: FsClock, _fd: Fd, _max_len: usize) -> DriverResult<Vec<u8>> {
        Err(unsupported_filesystem_operation("read"))
    }
    /// A cursor write. Stamps `mtime` and `ctime`.
    fn write(&mut self, _clock: FsClock, _fd: Fd, _bytes: &[u8]) -> DriverResult<usize> {
        Err(unsupported_filesystem_operation("write"))
    }
    /// Positional read: read up to `max_len` bytes starting at `offset` WITHOUT
    /// disturbing the shared file cursor (the `pread`/`read_at` contract).
    ///
    /// The default composes `seek`(save)/`seek`(offset)/`read`/`seek`(restore)
    /// and runs entirely inside this one driver call. The runtime never
    /// interleaves a scheduler switch inside a single driver invocation, so the
    /// save/seek/read/restore sequence is atomic with respect to the
    /// deterministic scheduler even when multiple guest threads share the fd --
    /// which is exactly why positional I/O must reach the driver as ONE
    /// operation rather than being emulated with separate seek/read calls on the
    /// caller side. Drivers with native positional reads may override this.
    fn read_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> DriverResult<Vec<u8>> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.read(clock, fd, max_len);
        // Restore the cursor regardless of the read outcome, so a positional
        // read is a no-op on the file offset; the read result takes precedence.
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|bytes| restored.map(|_| bytes))
    }
    /// Positional write: write `bytes` starting at `offset` WITHOUT disturbing
    /// the shared file cursor (the `pwrite`/`write_at` contract). Atomic with
    /// respect to the scheduler for the same reason as [`FsDriver::read_at`];
    /// crash-consistency wrappers see the underlying `write`, so a positional
    /// write is journaled and crash-losable exactly like a cursor write.
    fn write_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.write(clock, fd, bytes);
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|written| restored.map(|_| written))
    }
    fn close(&mut self, _fd: Fd) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("close"))
    }
    /// `lseek`: the cursor moves to `offset` from `whence`, or, for
    /// [`SeekWhence::Data`]/[`SeekWhence::Hole`], to the first data or hole
    /// at or past `offset` as the file's allocation answers.
    fn seek(&mut self, _fd: Fd, _offset: i64, _whence: SeekWhence) -> DriverResult<u64> {
        Err(unsupported_filesystem_operation("seek"))
    }
    fn dup(&mut self, _fd: Fd) -> DriverResult<Fd> {
        Err(unsupported_filesystem_operation("dup"))
    }
    fn metadata(&mut self, _path: &str) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("metadata"))
    }
    fn fd_metadata(&mut self, _fd: Fd) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("descriptor metadata"))
    }
    /// Metadata of the entry a bare INODE names.
    ///
    /// This exists for the one descriptor class the filesystem does not hold: a
    /// FIFO endpoint is a pipe, and the only thing the deterministic filesystem
    /// gave it is the node identity. `fstat` on such a descriptor reads the LIVE
    /// entry through here, so a `chmod` after the open is visible exactly as it
    /// is through a regular file's descriptor. An inode with no name left is
    /// [`patina_dst_abi::ErrorCode::NotFound`]: the filesystem has nothing to say
    /// about a node only a descriptor still holds.
    fn inode_metadata(&mut self, _ino: u64) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("inode metadata"))
    }
    /// `mkdir`. `mode` is the mode the kernel would store (the caller applied
    /// the process umask). The new directory's four timestamps and its parent's
    /// `mtime`/`ctime` are stamped from `clock`.
    fn create_directory(&mut self, _clock: FsClock, _path: &str, _mode: u32) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("create directory"))
    }
    /// `unlink`. The parent's `mtime`/`ctime` and the unlinked node's `ctime`
    /// are stamped from `clock`.
    fn remove_file(&mut self, _clock: FsClock, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove file"))
    }
    fn sync(&mut self, _fd: Fd) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("sync"))
    }
    /// `ftruncate`. Stamps `mtime`/`ctime` even when the length is unchanged,
    /// as `do_truncate` does.
    fn set_len(&mut self, _clock: FsClock, _fd: Fd, _len: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set length"))
    }
    /// `truncate(2)`: [`FsDriver::set_len`] by NAME. The entry must be a
    /// regular file the identity may write ([`patina_dst_abi::ErrorCode::IsDirectory`]
    /// for a directory, `InvalidInput` for any other kind, `Denied` without `w`).
    fn set_len_by_path(&mut self, _clock: FsClock, _path: &str, _len: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set length by path"))
    }
    /// `fallocate(2)` over a writable regular-file descriptor: `mode` says what
    /// becomes of the blocks in `offset..offset+len` ([`FsAllocateMode`]);
    /// without `keep_size` the file grows to `offset + len` when that is past
    /// its end. Stamps `mtime`/`ctime`. A non-writable descriptor is
    /// `NotWritable`, a directory `IsDirectory`, a path-only descriptor
    /// `InvalidHandle`.
    fn allocate(
        &mut self,
        _clock: FsClock,
        _fd: Fd,
        _offset: u64,
        _len: u64,
        _mode: FsAllocateMode,
        _keep_size: bool,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("allocate"))
    }
    /// `utimensat` on a descriptor: `None` leaves a time alone (`UTIME_OMIT`);
    /// the caller resolves `UTIME_NOW` to a value before the call. `ctime` is
    /// stamped from `clock` whenever either time changes.
    fn set_times(
        &mut self,
        _clock: FsClock,
        _fd: Fd,
        _atime_nanos: Option<i128>,
        _mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times"))
    }
    /// Timestamp update through a retained inode (for FIFO endpoints).
    fn set_inode_times(
        &mut self,
        _clock: FsClock,
        _ino: u64,
        _atime_nanos: Option<i128>,
        _mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set inode times"))
    }
    fn set_times_by_path(
        &mut self,
        _clock: FsClock,
        _path: &str,
        _atime_nanos: Option<i128>,
        _mtime_nanos: Option<i128>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times by path"))
    }
    /// A listing by NAME (`opendir`+`readdir` fused). Updates the directory's
    /// `atime` under the clock's policy.
    fn read_directory(
        &mut self,
        _clock: FsClock,
        _path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        Err(unsupported_filesystem_operation("read directory"))
    }
    /// List the directory an open DESCRIPTOR names (`getdents`/`readdir`):
    /// `.` and `..` first, then the children, each with its inode.
    ///
    /// Iteration is a read of the descriptor, not a fresh lookup of a name: the
    /// `r` it costs was charged when the descriptor was opened, so a `chmod`
    /// afterwards cannot retroactively break a walk in progress, and a
    /// descriptor opened `O_PATH` — which charged no access at all — cannot
    /// list at [`patina_dst_abi::ErrorCode::NotReadable`] however permissive the
    /// directory's bits are. The path-taking [`FsDriver::read_directory`] is the
    /// fused `opendir`+`readdir` an in-process guest issues and charges `r`
    /// itself.
    fn read_directory_fd(
        &mut self,
        _clock: FsClock,
        _fd: Fd,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        Err(unsupported_filesystem_operation(
            "read directory descriptor",
        ))
    }
    /// `rmdir`. The parent's `mtime`/`ctime` are stamped from `clock`.
    fn remove_directory(&mut self, _clock: FsClock, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove directory"))
    }
    /// `rename`. Both parents' `mtime`/`ctime` and the moved node's `ctime` are
    /// stamped from `clock`.
    fn rename(&mut self, _clock: FsClock, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("rename"))
    }
    /// `link`. The node's `ctime` and the new parent's `mtime`/`ctime` are
    /// stamped from `clock`.
    fn link(&mut self, _clock: FsClock, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("link"))
    }
    /// `symlink`. The link's four timestamps and its parent's `mtime`/`ctime`
    /// are stamped from `clock`.
    fn symlink(&mut self, _clock: FsClock, _target: &str, _link_path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("symlink"))
    }
    /// `readlink`. Updates the link's `atime` under the clock's policy.
    fn read_link(&mut self, _clock: FsClock, _path: &str) -> DriverResult<String> {
        Err(unsupported_filesystem_operation("read link"))
    }
    /// Create a named pipe (`mkfifo`). Creates only the NAME: a FIFO's bytes are
    /// never filesystem state, so nothing here holds them — the openers share a
    /// pipe channel above this boundary, exactly as they share a kernel pipe.
    /// `mode` is the mode the kernel would store (the caller applied the
    /// process umask). Timestamps as for [`FsDriver::create_directory`].
    fn make_fifo(&mut self, _clock: FsClock, _path: &str, _mode: u32) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("make fifo"))
    }
    /// `mknod`: create `node` at `path`, judged as the kernel's `vfs_mknod`
    /// judges it — the name and the parent's `w`+`x` first, then the
    /// privilege a device other than the whiteout needs (`NotPermitted`: the
    /// modeled identity has no `CAP_MKNOD`). A directory or symlink has its own
    /// call. `mode` is the mode the kernel would store. Timestamps as for
    /// [`FsDriver::create_directory`].
    fn make_node(
        &mut self,
        _clock: FsClock,
        _path: &str,
        _node: FsNode,
        _mode: u32,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("make node"))
    }
    /// `renameat2(RENAME_WHITEOUT)`: [`FsDriver::rename`] that leaves a
    /// whiteout (a 0:0 character device, mode 0) at `from`, as one change —
    /// a crash keeps both halves or neither.
    fn rename_whiteout(&mut self, _clock: FsClock, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("rename whiteout"))
    }
    /// `renameat2(RENAME_EXCHANGE)`: swap the entries at `first` and `second`
    /// (both must exist; any two kinds) atomically. Neither side follows a
    /// trailing symlink. Stamps both parents' `mtime`/`ctime` and both entries'
    /// `ctime`.
    fn exchange(&mut self, _clock: FsClock, _first: &str, _second: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("exchange"))
    }
    /// `sync(2)`/`syncfs(2)`: every change on the volume made durable. A driver
    /// with no durability model has nothing to do.
    fn sync_all(&mut self) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("sync all"))
    }
    /// One extended attribute's value, with the kernel's namespace and
    /// permission rules applied to the node `target` names (a read: `ENODATA`
    /// where a write would be refused outright). The name arrives validated
    /// (`1..=255` bytes).
    fn get_xattr(&mut self, _target: &XattrTarget, _name: &str) -> DriverResult<Vec<u8>> {
        Err(unsupported_filesystem_operation("get xattr"))
    }
    /// The extended attribute names the caller may see, in the order the
    /// filesystem lists them.
    fn list_xattr(&mut self, _target: &XattrTarget) -> DriverResult<Vec<String>> {
        Err(unsupported_filesystem_operation("list xattr"))
    }
    /// Set one extended attribute (`flags`: `XATTR_CREATE` 1, `XATTR_REPLACE`
    /// 2). Stamps `ctime`.
    fn set_xattr(
        &mut self,
        _clock: FsClock,
        _target: &XattrTarget,
        _name: &str,
        _value: &[u8],
        _flags: u32,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set xattr"))
    }
    /// Remove one extended attribute. Stamps `ctime`.
    fn remove_xattr(
        &mut self,
        _clock: FsClock,
        _target: &XattrTarget,
        _name: &str,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove xattr"))
    }
    /// Change the permission bits of the entry `path` names (`chmod` /
    /// `fchmodat`). Like every other path entry point here, this acts on the
    /// entry the caller named: a trailing symlink is resolved by the caller, not
    /// by the driver. Stamps `ctime` from `clock`, even when the bits are
    /// unchanged (`chown` routes through here: the kernel writes the inode
    /// either way).
    fn set_mode(&mut self, _clock: FsClock, _path: &str, _mode: u32) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set mode"))
    }
    /// Change the permission bits of the entry an open descriptor names
    /// (`fchmod`). Stamps `ctime`.
    fn set_fd_mode(&mut self, _clock: FsClock, _fd: Fd, _mode: u32) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set descriptor mode"))
    }
    /// The path the descriptor's filesystem NODE currently has.
    ///
    /// A descriptor names an inode, not a name. `*at` resolution therefore asks
    /// the filesystem where the node is *now* rather than replaying the name the
    /// descriptor was opened under, so a rename moves the descriptor with the
    /// node and a symlink planted at the old name is never followed.
    fn fd_path(&mut self, _fd: Fd) -> DriverResult<String> {
        Err(unsupported_filesystem_operation("descriptor path"))
    }
    /// The inode an open descriptor names (an `O_PATH` one included): the file
    /// identity record and `flock` locks key on.
    fn fd_ino(&mut self, fd: Fd) -> DriverResult<u64> {
        self.fd_metadata(fd).map(|metadata| metadata.ino)
    }
    /// [`FsDriver::metadata`] as bookkeeping the runtime reads without a trace
    /// op (the directory an fs notification is reported to): never faulted,
    /// since no storage access happens that could fail.
    fn metadata_unfaulted(&mut self, path: &str) -> DriverResult<FsMetadata> {
        self.metadata(path)
    }
    /// [`FsDriver::fd_metadata`] as the same never-faulted bookkeeping (the
    /// inode and size of a descriptor's file).
    fn fd_metadata_unfaulted(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        self.fd_metadata(fd)
    }
    /// How many of the 4096-byte pages `first..=last` of `fd`'s file hold
    /// bytes written since they were last made durable (`cachestat`'s dirty
    /// pages): never faulted bookkeeping, as
    /// [`FsDriver::fd_metadata_unfaulted`] is. A driver whose writes are
    /// durable at once has none.
    fn dirty_pages(&mut self, _fd: Fd, _first: u64, _last: u64) -> DriverResult<u64> {
        Ok(0)
    }
    /// Change the permission bits of the entry an INODE names (`fchmod` through
    /// the one descriptor class the filesystem does not hold — a FIFO endpoint).
    /// The mirror of [`FsDriver::inode_metadata`], and it reaches an unlinked
    /// node for the same reason: the bits belong to the node, not to a name.
    /// Stamps `ctime`.
    fn set_inode_mode(&mut self, _clock: FsClock, _ino: u64, _mode: u32) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set inode mode"))
    }
    /// Take a reference on an inode that no filesystem descriptor holds.
    ///
    /// A kernel keeps an inode alive while ANY descriptor references it, and a
    /// FIFO endpoint is a descriptor this filesystem does not itself hold: the
    /// bytes belong to the openers' pipe. Its reference therefore has to be
    /// taken explicitly, or the node would vanish under the endpoint the moment
    /// its last name was unlinked and `fstat` on a perfectly live descriptor
    /// would answer `NotFound`. Paired with [`FsDriver::release_inode`].
    fn retain_inode(&mut self, _ino: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("retain inode"))
    }
    /// Drop a reference taken by [`FsDriver::retain_inode`]. The node is freed
    /// when its last name and its last reference are both gone.
    fn release_inode(&mut self, _ino: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("release inode"))
    }
    /// Store `bytes` a shared mapping of `fd`'s file wrote at `offset`: the
    /// page cache's write-back. Like [`FsDriver::write_at`] except that a
    /// write seal does not refuse it — a mapping writable before
    /// `F_SEAL_FUTURE_WRITE` keeps writing the file. A filesystem without
    /// seals has nothing to tell apart.
    fn write_back_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        self.write_at(clock, fd, offset, bytes)
    }
    /// `memfd_create`: a regular file that no name reaches, on a new
    /// read-write handle, with permission bits `mode` (no umask: the kernel
    /// applies none) and the initial seal set `seals`. It lives while a
    /// descriptor holds it. A nonzero `huge_page` makes it a hugetlbfs file of
    /// that page size on a machine with no huge pages reserved: `write` is
    /// `InvalidInput`, a length that is not a multiple of the page size is
    /// `InvalidInput`, an allocation is `NoSpace`, and every read is a hole.
    fn create_anonymous(
        &mut self,
        _clock: FsClock,
        _name: &str,
        _mode: u32,
        _seals: u32,
        _huge_page: u64,
    ) -> DriverResult<Fd> {
        Err(unsupported_filesystem_operation("anonymous files"))
    }
    /// `F_GET_SEALS`: the seal set of `fd`'s node. A node that cannot be
    /// sealed — every node of a filesystem without anonymous files — is
    /// [`patina_dst_abi::ErrorCode::InvalidInput`], the kernel's `EINVAL`.
    fn seals(&mut self, _fd: Fd) -> DriverResult<u32> {
        Err(not_sealable())
    }
    /// `F_ADD_SEALS`, in `memfd_add_seals`' order: a description not open for
    /// writing is `NotPermitted`, an unknown seal bit `InvalidInput`, a node
    /// that cannot be sealed `InvalidInput`, a node sealed with `F_SEAL_SEAL`
    /// `NotPermitted`, and a new `F_SEAL_WRITE` while `writably_mapped` (a
    /// shared mapping that may write is live) `Busy`.
    fn add_seals(&mut self, _fd: Fd, _seals: u32, _writably_mapped: bool) -> DriverResult<()> {
        Err(not_sealable())
    }
    fn crash(&mut self) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("crash"))
    }

    /// Recover from a modeled storage crash and export the durable filesystem
    /// image for a fresh incarnation. Drivers that cannot produce a canonical
    /// restart snapshot must fail closed; the default deliberately refuses so a
    /// custom filesystem never silently pretends to support crash restart.
    fn crash_and_export_restart_snapshot(&mut self) -> DriverResult<Vec<u8>> {
        Err(unsupported_filesystem_operation(
            "crash restart snapshot export",
        ))
    }

    /// End-of-run filesystem fault-injection summary for the default-on vacuity
    /// diagnostic. A wrapper that models fs faults reports its counts; the
    /// default (a driver with no fault model) reports `None` and is never
    /// diagnosed as vacuous. Wrappers forward it so an inner fault-modeling
    /// driver remains visible.
    fn fault_report(&self) -> Option<FsFaultReport> {
        None
    }
}

/// The extended-attribute namespace a name resolves into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrNamespace {
    User,
    Trusted,
    Security,
    System,
    /// A name outside every namespace: no handler resolves it.
    Unknown,
}

impl XattrNamespace {
    pub fn of(name: &str) -> Self {
        [
            ("user.", Self::User),
            ("trusted.", Self::Trusted),
            ("security.", Self::Security),
            ("system.", Self::System),
        ]
        .into_iter()
        .find_map(|(prefix, namespace)| name.starts_with(prefix).then_some(namespace))
        .unwrap_or(Self::Unknown)
    }
}

/// The kernel's judgment of an extended-attribute access before any
/// filesystem's handler sees it (`fs/xattr.c`: `xattr_permission` and the
/// capability hooks), for the one modeled identity — the owner of every node,
/// with no capabilities. `trusted.*` needs `CAP_SYS_ADMIN`, and so does
/// writing `security.*`; `user.*` exists only on regular files and
/// directories — each refusal `NotPermitted` for a write and `NoData` for a
/// read. `user.*` and a name in no namespace are then charged against the
/// owner's permission bits (`Denied`). One judge for every node, whichever
/// filesystem holds it; the namespace comes back for its handlers.
pub fn xattr_permission(
    file_or_directory: bool,
    mode: u32,
    name: &str,
    write: bool,
) -> Result<XattrNamespace, ErrorCode> {
    let refused = if write {
        ErrorCode::NotPermitted
    } else {
        ErrorCode::NoData
    };
    let namespace = XattrNamespace::of(name);
    match namespace {
        XattrNamespace::Trusted => return Err(refused),
        XattrNamespace::Security if write => return Err(refused),
        XattrNamespace::User if !file_or_directory => return Err(refused),
        XattrNamespace::Security | XattrNamespace::System => return Ok(namespace),
        XattrNamespace::User | XattrNamespace::Unknown => {}
    }
    let want = if write { 0o2 } else { 0o4 };
    if (mode >> 6) & want == 0 {
        return Err(ErrorCode::Denied);
    }
    Ok(namespace)
}

fn not_sealable() -> EffectError {
    EffectError::new(
        patina_dst_abi::ErrorCode::InvalidInput,
        "no node of this filesystem can be sealed",
    )
}

fn unsupported_filesystem_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_dst_abi::ErrorCode::Denied,
        format!("filesystem driver does not support {operation}"),
    )
}

/// Convert an unsigned byte offset to the signed offset `seek` takes, rejecting
/// values past `i64::MAX` (unreachable for the in-memory filesystems but kept
/// sound rather than silently wrapping).
fn checked_offset(offset: u64) -> DriverResult<i64> {
    i64::try_from(offset).map_err(|_| {
        EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            format!("positional offset {offset} exceeds the addressable range"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MinimalFs;

    impl FsDriver for MinimalFs {
        fn open(&mut self, _clock: FsClock, _path: &str, _flags: OpenFlags) -> DriverResult<Fd> {
            Err(EffectError::new(
                patina_dst_abi::ErrorCode::Denied,
                "unused",
            ))
        }

        fn read(&mut self, _clock: FsClock, _fd: Fd, _max_len: usize) -> DriverResult<Vec<u8>> {
            Err(EffectError::new(
                patina_dst_abi::ErrorCode::Denied,
                "unused",
            ))
        }

        fn write(&mut self, _clock: FsClock, _fd: Fd, _bytes: &[u8]) -> DriverResult<usize> {
            Err(EffectError::new(
                patina_dst_abi::ErrorCode::Denied,
                "unused",
            ))
        }

        fn close(&mut self, _fd: Fd) -> DriverResult<()> {
            Err(EffectError::new(
                patina_dst_abi::ErrorCode::Denied,
                "unused",
            ))
        }
    }

    #[test]
    fn restart_snapshot_export_fails_closed_by_default() {
        let mut filesystem = MinimalFs;
        let error = filesystem.crash_and_export_restart_snapshot().unwrap_err();
        assert_eq!(error.code, patina_dst_abi::ErrorCode::Denied);
        assert!(error.message.contains("crash restart snapshot export"));
    }
}
