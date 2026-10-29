//! The context's unrecorded filesystem reads: the kernel's and the
//! embedder's own steps inside a guest call, which record nothing, draw no
//! fault, charge no latency and are no crash point.

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsMetadata, OpenFlags, Operation, Outcome, SeekWhence,
};
use patina_dst_driver_api::FsDriver;

use crate::recording::{
    FilesystemExpected, decode_bytes, decode_handle, decode_metadata, decode_string, decode_u64,
    decode_unit,
};
use crate::{Context, RuntimeError};

impl Context {
    /// The cursor of filesystem handle `fd`, read UNRECORDED: it is a pure
    /// function of the recorded operations the driver executed, and the driver
    /// executes every one of them again on replay, so it reproduces without a
    /// trace op of its own (the native shim's page cache asks where a cursor
    /// write landed). On a host-capture filesystem it is the host's seek,
    /// recorded ([`Self::captured_unrecorded`]).
    pub fn fs_cursor_unrecorded(&mut self, fd: Fd) -> Result<u64, RuntimeError> {
        if self.filesystem_is_capture {
            let whence = SeekWhence::Current;
            return self.captured_unrecorded(
                Operation::FsSeek {
                    fd,
                    offset: 0,
                    whence,
                },
                |fs| fs.seek(fd, 0, whence).map(Outcome::U64),
                decode_u64,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .seek(fd, 0, SeekWhence::Current)?)
    }

    /// The metadata of the entry filesystem handle `fd` is open on, read
    /// UNRECORDED as [`Self::fs_cursor_unrecorded`] is: the driver executes
    /// every operation that shaped it again on replay. It is bookkeeping, not
    /// a guest operation, so it costs no latency and is never faulted
    /// ([`FsDriver::fd_metadata_unfaulted`]): the native shim's page cache asks
    /// which file a handle's bytes belong to, its fs notifications which inode
    /// a handle is on, `cachestat` how many pages a file has, and a call the
    /// kernel answers from the in-memory inode (`FIONREAD`'s size, a
    /// `SEEK_END` lock's base, `fchdir`'s search bit) what that inode holds.
    pub fn fs_fd_metadata_unrecorded(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsFdMetadata { fd },
                |fs| fs.fd_metadata(fd).map(Outcome::Metadata),
                decode_metadata,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .fd_metadata_unfaulted(fd)?)
    }

    /// The metadata of the entry inode `ino` names
    /// ([`Self::fs_inode_metadata`]), read UNRECORDED and never faulted as
    /// [`Self::fs_fd_metadata_unrecorded`] is: the mode `fchown` decides on
    /// for a FIFO endpoint, whose node the filesystem holds no handle to.
    pub fn fs_inode_metadata_unrecorded(&mut self, ino: u64) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsInodeMetadata { ino },
                |fs| fs.inode_metadata(ino).map(Outcome::Metadata),
                decode_metadata,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .inode_metadata_unfaulted(ino)?)
    }

    /// Up to `max_len` bytes of `fd`'s file from `offset`, read UNRECORDED and
    /// never faulted ([`FsDriver::read_at_unfaulted`]), with no latency: the
    /// bytes are a pure function of the recorded operations the driver
    /// executes again on replay, as [`Self::fs_fd_metadata_unrecorded`]'s
    /// answer is, and the caller loads at the same point on replay, so the
    /// `atime` the read stamps reproduces too. The native shim fills a mapped
    /// file's page cache with it, a load no guest read issued. On a
    /// host-capture filesystem it is the host's read, recorded.
    pub fn fs_read_at_unrecorded(
        &mut self,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        let clock = self.fs_clock()?;
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsReadAt {
                    fd,
                    offset,
                    max_len,
                },
                |fs| fs.read_at(clock, fd, offset, max_len).map(Outcome::Bytes),
                decode_bytes,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .read_at_unfaulted(clock, fd, offset, max_len)?)
    }

    /// How many of pages `first..=last` of `fd`'s file are dirty (written
    /// since their last durability point), read UNRECORDED and never faulted
    /// as [`Self::fs_fd_metadata_unrecorded`] is (`cachestat`). A
    /// host-capture replay executes no driver and has no answer.
    pub fn fs_dirty_pages_unrecorded(
        &mut self,
        fd: Fd,
        first: u64,
        last: u64,
    ) -> Result<u64, RuntimeError> {
        if self.filesystem_is_capture {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "a host-capture replay does not model dirty pages",
            )
            .into());
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .dirty_pages(fd, first, last)?)
    }

    /// A path-only handle on canonical `path` the runtime's embedder holds
    /// for itself (the native shim's working directory: the configured one at
    /// install, the root on first use, or the one a `chdir` names), opened
    /// UNRECORDED, never faulted
    /// ([`FsDriver::open_path_unfaulted`]), with no latency, and it is
    /// no crash point. No guest called open: the open happens at the same point
    /// on replay (install reads the trace's working directory; the root and a
    /// `chdir`'s directory open at the same guest call), and a path-only open
    /// changes nothing, so the driver hands back the same handle there. On a
    /// host-capture filesystem it is the host's open, recorded.
    pub fn fs_open_path_unrecorded(&mut self, path: &str) -> Result<Fd, RuntimeError> {
        let clock = self.fs_clock()?;
        if self.filesystem_is_capture {
            let flags = OpenFlags::path_only();
            return self.captured_unrecorded(
                Operation::FsOpen {
                    path: path.into(),
                    flags,
                },
                |fs| fs.open(clock, path, flags).map(Outcome::Handle),
                decode_handle,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .open_path_unfaulted(clock, path)?)
    }

    /// Release a handle [`Self::fs_open_path_unrecorded`] opened, UNRECORDED
    /// and with no crash point: the embedder lets go of its own
    /// handle (the native shim's working directory, replaced by a `chdir`) at
    /// the same guest call on replay, where the driver releases it again. On
    /// a host-capture filesystem it is the host's close, recorded to pair
    /// with the recorded open.
    pub fn fs_close_unrecorded(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsClose { fd },
                |fs| fs.close(fd).map(|()| Outcome::Unit),
                decode_unit,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .close(fd)?)
    }

    /// `F_SETFL`'s `O_APPEND` on filesystem handle `fd`'s description
    /// ([`FsDriver::set_append`]), UNRECORDED and never faulted, with no
    /// latency: the guest's `fcntl` happens at the same point on replay, so
    /// the driver changes the description there again, and every recorded
    /// write after it lands where it did. A host-capture handle is read-only,
    /// so the flag changes no write it can make, and nothing executes there.
    pub fn fs_set_append_unrecorded(&mut self, fd: Fd, append: bool) -> Result<(), RuntimeError> {
        if self.filesystem_is_capture {
            return Ok(());
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .set_append(fd, append)?)
    }

    /// The metadata of the entry at canonical `path`, read UNRECORDED and
    /// never faulted as [`Self::fs_fd_metadata_unrecorded`] is, with no
    /// latency: the native shim's path walk (each lookup the kernel's namei
    /// does inside the call, which only the call's own operation pays for),
    /// and the directory an fs notification is reported to, looked up inside
    /// the call that caused it.
    pub fn fs_metadata_unrecorded(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsMetadata { path: path.into() },
                |fs| fs.metadata(path).map(Outcome::Metadata),
                decode_metadata,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .metadata_unfaulted(path)?)
    }

    /// The target of the symlink at canonical `path` ([`Self::fs_read_link`]),
    /// read UNRECORDED, never faulted and with no latency, as
    /// [`Self::fs_metadata_unrecorded`] is: the native shim's path walk
    /// following a symlink it meets. The read stamps the link's `atime` as
    /// the recorded read does, at the same point on replay. On a host-capture
    /// filesystem it is the host's read, recorded.
    pub fn fs_read_link_unrecorded(&mut self, path: &str) -> Result<String, RuntimeError> {
        let clock = self.fs_clock()?;
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsReadLink { path: path.into() },
                |fs| {
                    fs.read_link(clock, path)
                        .map(|target| Outcome::Bytes(target.into_bytes()))
                },
                decode_string,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .read_link_unfaulted(clock, path)?)
    }

    /// Where filesystem handle `fd`'s node is now ([`Self::fs_fd_path`]),
    /// read UNRECORDED and never faulted as [`Self::fs_fd_metadata_unrecorded`]
    /// is: the base the native shim's path walk starts from (the working
    /// directory, an `*at` call's directory descriptor), and, after an
    /// in-process crash rebuilt the image, the name each descriptor holds for
    /// its fs notifications.
    pub fn fs_fd_path_unrecorded(&mut self, fd: Fd) -> Result<String, RuntimeError> {
        if self.filesystem_is_capture {
            return self.captured_unrecorded(
                Operation::FsFdPath { fd },
                |fs| fs.fd_path(fd).map(|path| Outcome::Bytes(path.into_bytes())),
                decode_string,
            );
        }
        Ok(self
            .filesystem
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?
            .fd_path(fd)?)
    }

    /// An unrecorded read on a host-capture filesystem, whose replay executes
    /// no driver: the host's answer to `read` is recorded as `operation` so
    /// the replay returns it, and nothing else of a guest operation happens.
    /// No latency is drawn, no clock advances and no crash point is drawn, so
    /// the read stays bookkeeping on every filesystem.
    fn captured_unrecorded<T>(
        &mut self,
        operation: Operation,
        read: impl FnOnce(&mut dyn FsDriver) -> Result<Outcome, EffectError>,
        decode: fn(&Operation, Outcome) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode(&operation, outcome),
        };
        let filesystem = self
            .filesystem
            .as_deref_mut()
            .ok_or_else(|| EffectError::missing_driver("filesystem"))?;
        let actual = read(filesystem).unwrap_or_else(Outcome::Error);
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode(&operation, outcome)
    }
}
