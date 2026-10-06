//! Open descriptions, descriptor allocation and inode reference lifetime.

use crate::{Access, Description, InodeId, MemFs};
use patina_dst_abi::{EffectError, ErrorCode, Fd, FsClock, FsEntryKind};
use patina_dst_driver_api::DriverResult;

pub(super) fn invalid_fd(fd: Fd) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidHandle,
        format!("virtual file handle {} is not open", fd.0),
    )
}

impl MemFs {
    pub(super) fn description_mut(&mut self, fd: Fd) -> DriverResult<&mut Description> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        Ok(self
            .descriptions
            .get_mut(&id)
            .expect("handle references a description"))
    }

    pub(super) fn description(&self, fd: Fd) -> DriverResult<&Description> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        Ok(self
            .descriptions
            .get(&id)
            .expect("handle references a description"))
    }

    /// Mint a descriptor on `node`, taking the node's open reference with it.
    pub(super) fn allocate_handle(
        &mut self,
        node: InodeId,
        cursor: usize,
        access: Access,
        kind: FsEntryKind,
    ) -> DriverResult<Fd> {
        let fd = Fd(self.next_fd);
        self.next_fd = self.next_fd.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidHandle, "virtual file handles exhausted")
        })?;
        let description = self.next_description;
        self.next_description = self.next_description.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "virtual file descriptions exhausted",
            )
        })?;
        self.descriptions.insert(
            description,
            Description {
                node,
                cursor,
                readable: access.readable,
                writable: access.writable,
                append: access.append,
                path_only: access.path_only,
                kind,
                fds: 1,
            },
        );
        self.handles.insert(fd, description);
        // A descriptor is a reference on the node (a directory's metadata is not
        // in the inode table, so it has none to take).
        if let Some(inode) = self.inodes.get_mut(&node) {
            inode.openers += 1;
        }
        Ok(fd)
    }

    /// The node an open descriptor holds. A directory description names an ino
    /// the inode table does not hold, so it is refused here rather than read as
    /// a file.
    pub(super) fn handle_inode(&self, fd: Fd) -> DriverResult<InodeId> {
        let description = self.description(fd)?;
        if !self.inodes.contains_key(&description.node) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        Ok(description.node)
    }

    /// Drop one NAME's reference to a node, releasing it if that was its last
    /// reference of either kind.
    pub(super) fn drop_name(&mut self, clock: FsClock, inode: InodeId) {
        let entry = self.inodes.get_mut(&inode).expect("inode was checked");
        entry.links -= 1;
        // The link count is inode metadata: `ctime` moves, on a node that may
        // live on behind a descriptor.
        entry.times.metadata_changed(clock);
        self.release_if_unreferenced(inode);
    }

    /// Free a node once NOTHING references it — no name and no descriptor. This
    /// is the whole of inode lifetime: a kernel drops the on-disk inode when
    /// `i_nlink` and `i_count` both reach zero, and until then an unlinked entry
    /// stays fully alive behind every descriptor that holds it. Its attributes
    /// go with it.
    pub(super) fn release_if_unreferenced(&mut self, inode: InodeId) {
        let Some(entry) = self.inodes.get(&inode) else {
            return;
        };
        if entry.links == 0 && entry.openers == 0 {
            self.inodes.remove(&inode);
            self.xattrs.remove(&inode);
        }
    }
}

#[cfg(test)]
mod tests;
