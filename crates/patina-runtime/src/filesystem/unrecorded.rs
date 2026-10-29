//! The context's unrecorded filesystem reads: the kernel's and the
//! embedder's own steps inside a guest call, which record nothing, draw no
//! fault, charge no latency and are no crash point.

use patina_dst_abi::{Fd, FsMetadata, SeekWhence};

use crate::{Context, RuntimeError};

impl Context {
    /// The cursor of filesystem handle `fd`, read UNRECORDED: it is a pure
    /// function of the recorded operations the driver executed, and the driver
    /// executes every one of them again on replay, so it reproduces without a
    /// trace op of its own (the native shim's page cache asks where a cursor
    /// write landed).
    pub fn fs_cursor_unrecorded(&mut self, fd: Fd) -> Result<u64, RuntimeError> {
        Ok(self.filesystem.seek(fd, 0, SeekWhence::Current)?)
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
        Ok(self.filesystem.fd_metadata_unfaulted(fd)?)
    }

    /// The metadata of the entry inode `ino` names
    /// ([`Self::fs_inode_metadata`]), read UNRECORDED and never faulted as
    /// [`Self::fs_fd_metadata_unrecorded`] is: the mode `fchown` decides on
    /// for a FIFO endpoint, whose node the filesystem holds no handle to.
    pub fn fs_inode_metadata_unrecorded(&mut self, ino: u64) -> Result<FsMetadata, RuntimeError> {
        Ok(self.filesystem.inode_metadata_unfaulted(ino)?)
    }

    /// Up to `max_len` bytes of `fd`'s file from `offset`, read UNRECORDED and
    /// never faulted ([`FsDriver::read_at_unfaulted`]), with no latency: the
    /// bytes are a pure function of the recorded operations the driver
    /// executes again on replay, as [`Self::fs_fd_metadata_unrecorded`]'s
    /// answer is, and the caller loads at the same point on replay, so the
    /// `atime` the read stamps reproduces too. The native shim fills a mapped
    /// file's page cache with it, a load no guest read issued.
    pub fn fs_read_at_unrecorded(
        &mut self,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        let clock = self.fs_clock()?;
        Ok(self
            .filesystem
            .read_at_unfaulted(clock, fd, offset, max_len)?)
    }

    /// How many of pages `first..=last` of `fd`'s file are dirty (written
    /// since their last durability point), read UNRECORDED and never faulted
    /// as [`Self::fs_fd_metadata_unrecorded`] is (`cachestat`).
    pub fn fs_dirty_pages_unrecorded(
        &mut self,
        fd: Fd,
        first: u64,
        last: u64,
    ) -> Result<u64, RuntimeError> {
        Ok(self.filesystem.dirty_pages(fd, first, last)?)
    }

    /// A path-only handle on canonical `path` the runtime's embedder holds
    /// for itself (the native shim's working directory: the configured one at
    /// install, the root on first use, or the one a `chdir` names), opened
    /// UNRECORDED, never faulted
    /// ([`FsDriver::open_path_unfaulted`]), with no latency, and it is
    /// no crash point. No guest called open: the open happens at the same point
    /// on replay (install reads the trace's working directory; the root and a
    /// `chdir`'s directory open at the same guest call), and a path-only open
    /// changes nothing, so the driver hands back the same handle there.
    pub fn fs_open_path_unrecorded(&mut self, path: &str) -> Result<Fd, RuntimeError> {
        let clock = self.fs_clock()?;
        Ok(self.filesystem.open_path_unfaulted(clock, path)?)
    }

    /// Release a handle [`Self::fs_open_path_unrecorded`] opened, UNRECORDED
    /// and with no crash point: the embedder lets go of its own
    /// handle (the native shim's working directory, replaced by a `chdir`) at
    /// the same guest call on replay, where the driver releases it again.
    pub fn fs_close_unrecorded(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        Ok(self.filesystem.close(fd)?)
    }

    /// `F_SETFL`'s `O_APPEND` on filesystem handle `fd`'s description
    /// ([`FsDriver::set_append`]), UNRECORDED and never faulted, with no
    /// latency: the guest's `fcntl` happens at the same point on replay, so
    /// the driver changes the description there again, and every recorded
    /// write after it lands where it did.
    pub fn fs_set_append_unrecorded(&mut self, fd: Fd, append: bool) -> Result<(), RuntimeError> {
        Ok(self.filesystem.set_append(fd, append)?)
    }

    /// The metadata of the entry at canonical `path`, read UNRECORDED and
    /// never faulted as [`Self::fs_fd_metadata_unrecorded`] is, with no
    /// latency: the native shim's path walk (each lookup the kernel's namei
    /// does inside the call, which only the call's own operation pays for),
    /// and the directory an fs notification is reported to, looked up inside
    /// the call that caused it.
    pub fn fs_metadata_unrecorded(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        Ok(self.filesystem.metadata_unfaulted(path)?)
    }

    /// The target of the symlink at canonical `path` ([`Self::fs_read_link`]),
    /// read UNRECORDED, never faulted and with no latency, as
    /// [`Self::fs_metadata_unrecorded`] is: the native shim's path walk
    /// following a symlink it meets. The read stamps the link's `atime` as
    /// the recorded read does, at the same point on replay.
    pub fn fs_read_link_unrecorded(&mut self, path: &str) -> Result<String, RuntimeError> {
        let clock = self.fs_clock()?;
        Ok(self.filesystem.read_link_unfaulted(clock, path)?)
    }

    /// Where filesystem handle `fd`'s node is now ([`Self::fs_fd_path`]),
    /// read UNRECORDED and never faulted as [`Self::fs_fd_metadata_unrecorded`]
    /// is: the base the native shim's path walk starts from (the working
    /// directory, an `*at` call's directory descriptor), and, after an
    /// in-process crash rebuilt the image, the name each descriptor holds for
    /// its fs notifications.
    pub fn fs_fd_path_unrecorded(&mut self, fd: Fd) -> Result<String, RuntimeError> {
        Ok(self.filesystem.fd_path(fd)?)
    }
}
