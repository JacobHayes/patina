//! Path resolution, directory enumeration and namespace moves.

use crate::{DIRECTORY_MODE, EntryMetadata, Inode, InodeId, MemFs};
use patina_dst_abi::{EffectError, ErrorCode, FsClock, FsDirectoryEntry, FsEntryKind};
use patina_dst_driver_api::DriverResult;
use std::collections::BTreeMap;

/// The entries at and beneath one path, detached for a move: each keyed by its
/// suffix relative to that path (`""` for the entry itself).
pub(super) struct Subtree {
    directories: Vec<(String, EntryMetadata)>,
    names: Vec<(String, InodeId)>,
}

pub(super) fn normalize_path(path: &str) -> DriverResult<String> {
    if !path.starts_with('/') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            format!("virtual filesystem path must be absolute: {path:?}"),
        ));
    }
    if path.contains('\0') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "virtual filesystem path contains NUL",
        ));
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("parent traversal is not supported: {path:?}"),
                ));
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "the virtual filesystem root is not a file",
        ));
    }
    Ok(format!("/{}", components.join("/")))
}

pub(super) fn normalize_entry_path(path: &str) -> DriverResult<String> {
    if path == "/" || path.chars().all(|character| character == '/') {
        return Ok("/".into());
    }
    normalize_path(path)
}

pub(super) fn parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

pub(super) fn not_found(path: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NotFound,
        format!("virtual file does not exist: {path}"),
    )
}

impl MemFs {
    /// The node a non-directory name refers to.
    pub(super) fn leaf(&self, path: &str) -> Option<&Inode> {
        self.names.get(path).and_then(|ino| self.inodes.get(ino))
    }

    pub(super) fn kind_of(&self, ino: InodeId) -> Option<FsEntryKind> {
        self.inodes.get(&ino).map(|inode| inode.kind)
    }

    /// The kind of the non-directory entry at `path`.
    pub(super) fn leaf_kind(&self, path: &str) -> Option<FsEntryKind> {
        self.leaf(path).map(|inode| inode.kind)
    }

    /// The node id of the entry at `path`, whatever its kind (a directory's
    /// `ino` included).
    pub(super) fn node_id(&self, path: &str) -> Option<InodeId> {
        self.names
            .get(path)
            .copied()
            .or_else(|| self.directories.get(path).map(|metadata| metadata.ino))
    }

    /// The guard every path-taking entry point runs first: no symlink in the
    /// interior, then `x` on every directory above the final component.
    pub(super) fn resolve_guard(&self, path: &str) -> DriverResult<()> {
        self.ensure_no_intermediate_symlink(path)?;
        self.check_search_path(path)
    }

    /// The node a regular-file name refers to; any other entry, or none, is
    /// `NotFound` to a caller that asked for a file.
    pub(super) fn file_inode(&self, path: &str) -> DriverResult<InodeId> {
        self.names
            .get(path)
            .copied()
            .filter(|ino| self.kind_of(*ino) == Some(FsEntryKind::File))
            .ok_or_else(|| not_found(path))
    }

    /// Remove the directory at `path` (which the caller checked is empty),
    /// its attributes with it.
    pub(super) fn drop_directory(&mut self, path: &str) {
        if let Some(metadata) = self.directories.remove(path) {
            self.xattrs.remove(&metadata.ino);
        }
    }

    /// The path a live node currently has, or `None` when its last name is gone.
    /// A node with several names (hard links) answers the first in path order,
    /// deterministically; every name of one node reports identical metadata.
    pub(super) fn node_path(&self, node: InodeId, kind: FsEntryKind) -> Option<String> {
        if kind == FsEntryKind::Directory {
            return self
                .directories
                .iter()
                .find_map(|(path, metadata)| (metadata.ino == node).then(|| path.clone()));
        }
        self.names
            .iter()
            .find_map(|(path, inode)| (*inode == node).then(|| path.clone()))
    }

    /// Does directory `path` hold any entry?
    pub(super) fn has_children(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        let under = |candidate: &String| candidate.starts_with(&prefix);
        self.directories.keys().any(under) || self.names.keys().any(under)
    }

    pub(super) fn path_exists(&self, path: &str) -> bool {
        self.directories.contains_key(path) || self.names.contains_key(path)
    }

    pub(super) fn ensure_no_intermediate_symlink(&self, path: &str) -> DriverResult<()> {
        let mut current = String::new();
        for component in path
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
        {
            current.push('/');
            current.push_str(component);
            if current != path && self.leaf_kind(&current) == Some(FsEntryKind::Symlink) {
                return Err(EffectError::new(
                    ErrorCode::Denied,
                    format!(
                        "virtual symlink cannot be traversed as an intermediate component: {current}"
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn insert_parent_directories(&mut self, clock: FsClock, path: &str) {
        let mut parents = Vec::new();
        let mut parent = parent_path(path);
        while parent != "/" {
            if !self.directories.contains_key(parent) {
                parents.push(parent.to_owned());
            }
            parent = parent_path(parent);
        }
        for parent in parents.into_iter().rev() {
            let metadata = self.allocate_entry_metadata(clock, DIRECTORY_MODE);
            self.directories.insert(parent, metadata);
        }
        if !self.directories.contains_key("/") {
            let metadata = self.allocate_entry_metadata(clock, DIRECTORY_MODE);
            self.directories.insert("/".into(), metadata);
        }
    }

    /// The checks every creating call runs on the NAME: resolvable, the parent
    /// writable, the name free, the parent a directory.
    pub(super) fn check_new_name(&self, path: &str) -> DriverResult<()> {
        self.resolve_guard(path)?;
        self.check_directory_write(parent_path(path))?;
        if self.path_exists(path) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        }
        let parent = parent_path(path);
        if !self.directories.contains_key(parent) {
            return Err(EffectError::new(
                ErrorCode::NotFound,
                format!("virtual parent directory does not exist: {parent}"),
            ));
        }
        Ok(())
    }

    /// Enumerate one directory's immediate children, in path order and without
    /// enforcement. Both listing entry points share it: the access decision is
    /// theirs, the enumeration is one implementation.
    pub(super) fn list_directory(&self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let child = |candidate: &String| {
            candidate
                .strip_prefix(&prefix)
                .filter(|relative| !relative.is_empty() && !relative.contains('/'))
                .map(str::to_owned)
        };
        let mut entries = BTreeMap::new();
        for (directory, metadata) in &self.directories {
            if let Some(name) = child(directory) {
                entries.insert(name, (FsEntryKind::Directory, metadata.ino));
            }
        }
        for (name, ino) in &self.names {
            if let Some(name) = child(name) {
                let kind = self.kind_of(*ino).expect("name references an inode");
                entries.insert(name, (kind, *ino));
            }
        }
        Ok(entries
            .into_iter()
            .map(|(name, (kind, ino))| FsDirectoryEntry { name, kind, ino })
            .collect())
    }

    /// The `.` and `..` a descriptor listing starts with: the directory's own
    /// inode and its parent's (the root is its own parent), as `getdents`
    /// reports them.
    pub(super) fn dot_entries(&self, path: &str) -> [FsDirectoryEntry; 2] {
        let parent = match path.rfind('/') {
            Some(0) | None => "/",
            Some(slash) => &path[..slash],
        };
        [(".", path), ("..", parent)].map(|(name, directory)| FsDirectoryEntry {
            name: name.into(),
            kind: FsEntryKind::Directory,
            ino: self.directories[directory].ino,
        })
    }

    /// Drop whatever non-directory NAME sits at `path`, releasing its node
    /// reference. The one place a rename's destination is overwritten, so no
    /// kind can be dropped without its link count following.
    pub(super) fn unlink_leaf_at(&mut self, clock: FsClock, path: &str) {
        if let Some(replaced) = self.names.remove(path) {
            self.drop_name(clock, replaced);
        }
    }

    /// Detach every entry at or beneath `root` — the entry itself and, for a
    /// directory, its whole subtree — as `(relative suffix, entry)` pairs.
    pub(super) fn take_subtree(&mut self, root: &str) -> Subtree {
        let prefix = format!("{root}/");
        let within = |path: &String| *path == root || path.starts_with(&prefix);
        let directory_paths: Vec<String> = self
            .directories
            .keys()
            .filter(|path| within(path))
            .cloned()
            .collect();
        let name_paths: Vec<String> = self
            .names
            .keys()
            .filter(|path| within(path))
            .cloned()
            .collect();
        Subtree {
            directories: directory_paths
                .into_iter()
                .map(|path| {
                    let metadata = self.directories.remove(&path).expect("path was listed");
                    (path[root.len()..].to_owned(), metadata)
                })
                .collect(),
            names: name_paths
                .into_iter()
                .map(|path| {
                    let ino = self.names.remove(&path).expect("path was listed");
                    (path[root.len()..].to_owned(), ino)
                })
                .collect(),
        }
    }

    /// Re-attach a detached subtree under `root`. Nodes keep their identity, so
    /// every descriptor on one moves with it by construction.
    pub(super) fn place_subtree(&mut self, subtree: Subtree, root: &str) {
        for (suffix, metadata) in subtree.directories {
            self.directories.insert(format!("{root}{suffix}"), metadata);
        }
        for (suffix, ino) in subtree.names {
            self.names.insert(format!("{root}{suffix}"), ino);
        }
    }
}

#[cfg(test)]
mod tests;
