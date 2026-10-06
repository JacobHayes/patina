//! Persistent state inspection, restoration and descriptor adoption.

use crate::namespace::{normalize_entry_path, not_found};
use crate::{DescriptionId, FsSnapshot, InodeId, MODE_MASK, MemFs, Times};
use patina_dst_abi::{FsEntryKind, FsMetadata};
use patina_dst_driver_api::DriverResult;
use std::collections::{BTreeMap, BTreeSet};

impl MemFs {
    /// Clone persistent filesystem state without carrying open handles across
    /// a modeled process restart.
    pub fn persistent_snapshot(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.forget_open_state();
        snapshot
    }

    /// Export a canonical, versioned restart snapshot. Open descriptors and
    /// descriptions are deliberately omitted; inode identity, timestamps, names,
    /// contents, extended attributes, and future inode allocation state are
    /// preserved.
    pub fn export_snapshot(&self) -> FsSnapshot {
        FsSnapshot::from_memfs(self)
    }

    /// Import a restart snapshot as a fresh filesystem image with no descriptors.
    pub fn import_snapshot(snapshot: &FsSnapshot) -> Self {
        snapshot.into_memfs()
    }

    /// The paths a live descriptor currently names, with the entry kind each was
    /// opened as, deduplicated and in path order.
    ///
    /// A crash model reads this to keep the guest's descriptors meaningful
    /// across a rebuilt image: see [`MemFs::adopt_handles`].
    /// A node whose last name is already gone contributes nothing: there is no
    /// name to pin back into a rebuilt namespace, and the node itself crosses
    /// with the descriptor through [`MemFs::adopt_handles`].
    pub fn open_entries(&self) -> BTreeMap<String, FsEntryKind> {
        self.handles
            .values()
            .filter_map(|id| self.descriptions.get(id))
            .filter_map(|description| {
                self.node_path(description.node, description.kind)
                    .map(|path| (path, description.kind))
            })
            .collect()
    }

    /// Every entry in the image with its metadata, in path order, WITHOUT
    /// permission enforcement.
    ///
    /// A crash model is the storage layer, not the guest. Permission bits gate a
    /// PROCESS's access; a power cut does not consult them, and neither does the
    /// journal that decides what survived one. Walking the enforced
    /// `read_directory`/`metadata` here would make a `0o000` directory look
    /// EMPTY and silently drop every child beneath it on the next crash — a
    /// mode change quietly deleting data.
    pub fn inventory(&self) -> Vec<(String, FsMetadata)> {
        let mut paths: BTreeSet<&String> = self.directories.keys().collect();
        paths.extend(self.names.keys());
        paths
            .into_iter()
            .map(|path| {
                let metadata = self
                    .metadata_for_path(path)
                    .expect("an enumerated path has metadata");
                (path.clone(), metadata)
            })
            .collect()
    }

    /// The metadata of one entry WITHOUT permission enforcement — the storage
    /// layer's own view, for the same reason [`MemFs::inventory`] has one.
    pub fn entry_metadata(&self, path: &str) -> DriverResult<FsMetadata> {
        let path = normalize_entry_path(path)?;
        self.metadata_for_path(&path)
    }

    /// A symlink's stored target WITHOUT permission enforcement.
    pub fn symlink_target(&self, path: &str) -> Option<String> {
        let path = normalize_entry_path(path).ok()?;
        let inode = self
            .leaf(&path)
            .filter(|inode| inode.kind == FsEntryKind::Symlink)?;
        String::from_utf8(inode.contents.to_vec()).ok()
    }

    /// The extended attributes of the entry at `path` WITHOUT permission
    /// enforcement — the storage layer's own view, for a crash model carrying
    /// them onto a rebuilt image.
    pub fn entry_xattrs(&self, path: &str) -> BTreeMap<String, Vec<u8>> {
        normalize_entry_path(path)
            .ok()
            .and_then(|path| self.node_id(&path))
            .and_then(|ino| self.xattrs.get(&ino).cloned())
            .unwrap_or_default()
    }

    /// Write the extended attributes of the entry at `path` back verbatim —
    /// the storage layer's own setter, the mirror of [`MemFs::entry_xattrs`]
    /// for a rebuild. It stamps nothing.
    pub fn restore_xattrs(
        &mut self,
        path: &str,
        xattrs: BTreeMap<String, Vec<u8>>,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let ino = self.node_id(&path).ok_or_else(|| not_found(&path))?;
        if xattrs.is_empty() {
            self.xattrs.remove(&ino);
        } else {
            self.xattrs.insert(ino, xattrs);
        }
        Ok(())
    }

    /// Write all four timestamps of the entry at `path` back verbatim — the
    /// storage layer's own setter, for a crash model rebuilding an image from
    /// its durable baseline. Unlike the guest-facing `set_times` it stamps
    /// nothing (a rebuild is not an inode change) and it restores the birth
    /// time, which no guest-facing call can set.
    pub fn restore_times(
        &mut self,
        path: &str,
        atime_nanos: i128,
        mtime_nanos: i128,
        ctime_nanos: i128,
        btime_nanos: i128,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let times = self.times_mut(&path).ok_or_else(|| not_found(&path))?;
        *times = Times {
            atime_nanos,
            mtime_nanos,
            ctime_nanos,
            btime_nanos,
        };
        Ok(())
    }

    /// Write permission bits back onto the entry at `path` WITHOUT stamping
    /// `ctime` or enforcing the search path: the storage-layer mirror of
    /// [`MemFs::restore_times`], for the same rebuild.
    pub fn restore_mode(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let mode = mode & MODE_MASK;
        if let Some(inode) = self.names.get(&path).copied() {
            self.inodes
                .get_mut(&inode)
                .expect("name references an inode")
                .mode = mode;
            return Ok(());
        }
        if let Some(metadata) = self.directories.get_mut(&path) {
            metadata.mode = mode;
            return Ok(());
        }
        Err(not_found(&path))
    }

    /// Every path that OWNS a mode — every entry but a symlink — in path
    /// order. A symlink leaf is excluded: Linux ignores a link's own mode and
    /// this filesystem has none to set.
    ///
    /// A crash model reads this to write permission bits back onto a
    /// reconstructed image without inventing a per-kind constant.
    pub fn paths_with_modes(&self) -> Vec<String> {
        let mut paths: BTreeSet<&String> = self.directories.keys().collect();
        paths.extend(
            self.names
                .iter()
                .filter(|(_, ino)| self.kind_of(**ino) != Some(FsEntryKind::Symlink))
                .map(|(path, _)| path),
        );
        paths.into_iter().cloned().collect()
    }

    /// Carry `previous`'s open descriptor table onto this image.
    ///
    /// A crash model rebuilds the post-crash filesystem as a fresh [`MemFs`];
    /// without this the guest's still-open descriptors would all become
    /// unknown handles, and every later read/write/close on one would fail
    /// `InvalidHandle` — `EBADF` at the POSIX boundary. No real storage failure
    /// does that: a descriptor is the process's own object, and power loss
    /// cannot reach into a running process and close its files. Injecting
    /// `EBADF` would test the guest against an impossible world, so the table
    /// moves across intact.
    ///
    /// Descriptor and description IDs advance past the previous image's, so a
    /// post-crash `open` can never hand back a number the guest still believes
    /// is live.
    /// A description names a NODE, and this image minted its own inode numbers,
    /// so every description is re-bound to the node its name has HERE. A
    /// description whose name did not come back — an entry unlinked while open,
    /// whose node no crash can reach because the journal enumerates names — is
    /// re-bound to a fresh node carrying the bytes the descriptor last saw: the
    /// descriptor is the process's object either way, and a number reused by an
    /// unrelated entry would be far worse than an anonymous one.
    pub fn adopt_handles(&mut self, previous: &Self) {
        self.handles.clone_from(&previous.handles);
        self.descriptions.clone_from(&previous.descriptions);
        self.next_fd = self.next_fd.max(previous.next_fd);
        self.next_description = self.next_description.max(previous.next_description);
        let mut rebound: BTreeMap<InodeId, InodeId> = BTreeMap::new();
        // Per DESCRIPTION, not per descriptor: a `dup`ed pair is two fds on one
        // description, which is one reference on the node.
        let descriptions: BTreeSet<DescriptionId> = self.handles.values().copied().collect();
        for id in descriptions {
            let description = self
                .descriptions
                .get(&id)
                .expect("handle references a description");
            let (node, kind) = (description.node, description.kind);
            let carried = match rebound.get(&node).copied() {
                Some(carried) => carried,
                None => {
                    let carried = previous
                        .node_path(node, kind)
                        .and_then(|path| self.node_at(&path, kind))
                        .unwrap_or_else(|| self.carry_anonymous_node(previous, node, kind));
                    rebound.insert(node, carried);
                    carried
                }
            };
            self.descriptions
                .get_mut(&id)
                .expect("handle references a description")
                .node = carried;
            if let Some(inode) = self.inodes.get_mut(&carried) {
                inode.openers += 1;
            }
        }
    }

    /// The node the entry at `path` has in THIS image, if it has one of `kind`.
    fn node_at(&self, path: &str, kind: FsEntryKind) -> Option<InodeId> {
        match kind {
            FsEntryKind::Directory => self.directories.get(path).map(|metadata| metadata.ino),
            _ => self
                .names
                .get(path)
                .copied()
                .filter(|ino| self.kind_of(*ino) == Some(kind)),
        }
    }

    /// Mint a nameless node for a descriptor whose entry this image does not
    /// have, carrying the previous image's contents and metadata. A directory
    /// has no inode-table entry to carry, so it gets a fresh unused id that
    /// names nothing — which is the point: a stale descriptor must never be
    /// captured by an unrelated entry that happens to reuse the number.
    fn carry_anonymous_node(
        &mut self,
        previous: &Self,
        node: InodeId,
        kind: FsEntryKind,
    ) -> InodeId {
        let fresh = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        if kind != FsEntryKind::Directory
            && let Some(inode) = previous.inodes.get(&node)
        {
            let mut carried = inode.clone();
            carried.links = 0;
            carried.openers = 0;
            self.inodes.insert(fresh, carried);
        }
        fresh
    }

    /// Drop every descriptor and every node only a descriptor was holding — the
    /// image as a fresh incarnation inherits it. An anonymous node is exactly
    /// what a restart cannot carry: nothing names it.
    pub(super) fn forget_open_state(&mut self) {
        self.handles.clear();
        self.descriptions.clear();
        self.next_fd = 3;
        self.next_description = 1;
        for inode in self.inodes.values_mut() {
            inode.openers = 0;
        }
        self.inodes.retain(|_, inode| inode.links > 0);
        let directories: BTreeSet<InodeId> = self
            .directories
            .values()
            .map(|metadata| metadata.ino)
            .collect();
        let inodes = &self.inodes;
        self.xattrs
            .retain(|ino, _| inodes.contains_key(ino) || directories.contains(ino));
    }
}

#[cfg(test)]
mod tests;
