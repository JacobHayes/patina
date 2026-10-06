//! File contents, positional writes, size limits and seals.

use crate::namespace::normalize_path;
use crate::{FileData, Inode, MAX_LFS_FILESIZE, MemFs, VOLUME_MAX_BYTES};
use patina_dst_abi::seals::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SHRINK, F_SEAL_WRITE};
use patina_dst_abi::{EffectError, ErrorCode, Fd, FsClock, FsEntryKind};
use patina_dst_driver_api::DriverResult;

impl Inode {
    /// The node's filesystem's `s_maxbytes`: a memfd is on tmpfs or
    /// hugetlbfs, anything else on the ext4 volume.
    pub(super) fn max_bytes(&self) -> u64 {
        if self.seals.is_some() || self.huge_page != 0 {
            MAX_LFS_FILESIZE
        } else {
            VOLUME_MAX_BYTES
        }
    }

    /// How much of a write of `len` bytes at `start` the node takes:
    /// `rw_verify_area` refuses an end past the largest signed offset
    /// (`EINVAL`), and `generic_write_check_limits` a start at or past the
    /// size limit (`EFBIG`) and shortens a write that would cross it.
    pub(super) fn write_limit(&self, start: u64, len: usize) -> DriverResult<usize> {
        if start
            .checked_add(len as u64)
            .is_none_or(|end| end > MAX_LFS_FILESIZE)
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual write range overflows a file offset",
            ));
        }
        let max = self.max_bytes();
        if start >= max {
            return Err(too_big(
                "virtual write starts at or past the file size limit",
            ));
        }
        Ok(usize::try_from(max - start).map_or(len, |room| len.min(room)))
    }

    /// A write reaching `end`: a hugetlbfs file has no write method
    /// (`vfs_write`'s `FMODE_CAN_WRITE`), then the node's seals
    /// (`shmem_write_begin`): a write seal refuses every write, a grow seal one
    /// past the end.
    pub(super) fn check_write_seals(&self, end: u64) -> DriverResult<()> {
        if self.huge_page != 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "a hugetlbfs file has no write method",
            ));
        }
        let seals = self.seals.unwrap_or(0);
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0
            || (seals & F_SEAL_GROW != 0 && end > self.contents.len())
        {
            return Err(sealed());
        }
        Ok(())
    }

    /// A length change to `len`: a hugetlbfs file sizes in whole huge pages
    /// (`hugetlbfs_setattr`), then the node's seals (`shmem_setattr`).
    pub(super) fn check_resize_seals(&self, len: u64) -> DriverResult<()> {
        if self.huge_page != 0 && !len.is_multiple_of(self.huge_page) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "a hugetlbfs file sizes in whole huge pages",
            ));
        }
        let seals = self.seals.unwrap_or(0);
        let current = self.contents.len();
        if (len < current && seals & F_SEAL_SHRINK != 0)
            || (len > current && seals & F_SEAL_GROW != 0)
        {
            return Err(sealed());
        }
        Ok(())
    }
}

/// `EFBIG`: past the node's filesystem's size limit.
pub(super) fn too_big(message: &str) -> EffectError {
    EffectError::new(ErrorCode::FileTooBig, message)
}

pub(super) fn sealed() -> EffectError {
    EffectError::new(
        ErrorCode::NotPermitted,
        "the virtual file is sealed against this change",
    )
}

pub(super) fn not_sealable() -> EffectError {
    EffectError::new(
        ErrorCode::InvalidInput,
        "only an anonymous virtual file can be sealed",
    )
}

/// A `SEEK_DATA`/`SEEK_HOLE` that finds nothing (`ENXIO`): no data at or past
/// the offset, or an offset at or past the end.
pub(super) fn no_such_position(offset: i64) -> EffectError {
    EffectError::new(
        ErrorCode::NoSuchPosition,
        format!("no data or hole at or past offset {offset} before the end of the file"),
    )
}

impl MemFs {
    /// Every byte of the regular file at `path`, its holes read as zeros.
    pub fn contents(&self, path: &str) -> DriverResult<Vec<u8>> {
        Ok(self.file_data(path)?.to_vec())
    }

    /// The stored contents of the regular file at `path`: its written blocks,
    /// holes and reservations.
    pub fn file_data(&self, path: &str) -> DriverResult<&FileData> {
        let path = normalize_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        let inode = self.file_inode(&path)?;
        Ok(&self
            .inodes
            .get(&inode)
            .expect("file path references an inode")
            .contents)
    }

    /// The stored contents of the regular file `fd` is open on, whatever
    /// names it has now (none, once unlinked).
    pub fn fd_file_data(&self, fd: Fd) -> DriverResult<&FileData> {
        let node = self.description(fd)?.node;
        self.inodes
            .get(&node)
            .filter(|inode| inode.kind == FsEntryKind::File)
            .map(|inode| &inode.contents)
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual descriptor is not open on a regular file: {fd:?}"),
                )
            })
    }

    /// A positional write through `fd`, judged against the node's write seals
    /// when `sealed`.
    pub(super) fn write_node_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
        sealed: bool,
    ) -> DriverResult<usize> {
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
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        let bytes = &bytes[..inode.write_limit(offset, bytes.len())?];
        if sealed {
            inode.check_write_seals(offset + bytes.len() as u64)?;
        }
        inode.contents.write(offset, bytes);
        inode.times.data_changed(clock);
        Ok(bytes.len())
    }

    /// Set a file's length and stamp `mtime`/`ctime` — `do_truncate` moves
    /// them even when the length is unchanged. Growing past the size limit
    /// is `EFBIG` (`inode_newsize_ok`).
    pub(super) fn truncate_inode(
        inode: Option<&mut Inode>,
        clock: FsClock,
        len: u64,
    ) -> DriverResult<()> {
        let inode = inode.expect("a checked handle or name references an inode");
        if len > inode.contents.len() && len > inode.max_bytes() {
            return Err(too_big("virtual truncate past the file size limit"));
        }
        inode.contents.set_len(len);
        inode.times.data_changed(clock);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
