//! Namespace journaling, directory durability, and survivor paths.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{EffectError, ErrorCode, FsEntryKind, FsMetadata};
use patina_dst_driver_api::{DriverResult, FsDriver};

use crate::CrashFs;
use crate::baseline::DurableTimes;

/// A namespace mutation observed since the last durable baseline. Every entry
/// carries its kind so files, directories, and symlinks are tracked in the same
/// journal and none is silently dropped across a crash.
#[derive(Clone, Debug)]
pub(super) enum PendingKind {
    Create {
        path: String,
        kind: FsEntryKind,
    },
    Remove {
        path: String,
        removed: Box<Removed>,
    },
    Rename {
        from: String,
        to: String,
        kind: FsEntryKind,
        /// `RENAME_WHITEOUT`: a whiteout takes `from` in the same change.
        whiteout: bool,
    },
    /// `renameat2(RENAME_EXCHANGE)`: two names swap their entries in one
    /// all-or-nothing step, governed by both parents.
    Exchange {
        first: String,
        second: String,
    },
}

/// The node a name held when it was removed. A crash that loses the removal
/// leaves the name holding this node, which the live image no longer has, so
/// reconstruction reads the node off this record.
#[derive(Clone, Debug)]
pub(super) struct Removed {
    pub(super) metadata: FsMetadata,
    pub(super) xattrs: BTreeMap<String, Vec<u8>>,
    /// A symlink's target; `None` for every other kind.
    pub(super) target: Option<String>,
}

impl Removed {
    pub(super) fn kind(&self) -> FsEntryKind {
        self.metadata.kind
    }
}

#[derive(Clone, Debug)]
pub(super) struct PendingOp {
    pub(super) kind: PendingKind,
    /// Whether the governing directory of the create (or a rename's link) side
    /// has been made durable by a `sync_directory`.
    pub(super) committed: bool,
    /// Whether the source parent directory of a rename has been made durable.
    /// Only meaningful for [`PendingKind::Rename`]; a rename is fully durable
    /// only when both its link and unlink sides are committed.
    pub(super) source_committed: bool,
}

/// The names a crash reconstruction keeps, by the table each kind belongs to,
/// so files, directories, symlinks, and special nodes each apply their
/// namespace decisions to the right set.
pub(super) struct Survivors {
    pub(super) dirs: BTreeSet<String>,
    pub(super) files: BTreeSet<String>,
    pub(super) symlinks: BTreeSet<String>,
    pub(super) specials: BTreeSet<String>,
}

impl Survivors {
    pub(super) fn of(&mut self, kind: FsEntryKind) -> &mut BTreeSet<String> {
        match kind {
            FsEntryKind::Directory => &mut self.dirs,
            FsEntryKind::File => &mut self.files,
            FsEntryKind::Symlink => &mut self.symlinks,
            FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice => &mut self.specials,
        }
    }

    fn all(&mut self) -> [&mut BTreeSet<String>; 4] {
        [
            &mut self.dirs,
            &mut self.files,
            &mut self.symlinks,
            &mut self.specials,
        ]
    }

    /// Drop every entry strictly beneath `root`.
    pub(super) fn drop_beneath(&mut self, root: &str) {
        for set in self.all() {
            set.retain(|path| path == root || !within(path, root));
        }
    }

    /// Move every entry rooted at `from` to be rooted at `to`.
    pub(super) fn rewrite_prefix(&mut self, from: &str, to: &str) {
        for set in self.all() {
            let moved: Vec<String> = set
                .iter()
                .filter(|path| within(path, from))
                .cloned()
                .collect();
            for path in moved {
                set.remove(&path);
                set.insert(format!("{to}{}", &path[from.len()..]));
            }
        }
    }

    /// Swap the entries rooted at `first` with those rooted at `second`.
    pub(super) fn swap_prefixes(&mut self, first: &str, second: &str) {
        for set in self.all() {
            let moved: Vec<String> = set
                .iter()
                .filter(|path| within(path, first) || within(path, second))
                .cloned()
                .collect();
            for path in &moved {
                set.remove(path);
            }
            for path in moved {
                set.insert(swapped(&path, first, second));
            }
        }
    }

    /// Remove entries whose parent directories did not survive the crash. A
    /// child name is not independently meaningful without its full parent
    /// chain, and reconstruction must not create implicit ancestor directories
    /// just to make a selected child fit.
    pub(super) fn prune_to_surviving_parents(&mut self) {
        let selected_dirs = self.dirs.clone();
        self.dirs
            .retain(|path| path == "/" || full_parent_chain_survives(path, &selected_dirs));
        let dirs = self.dirs.clone();
        for set in [&mut self.files, &mut self.symlinks, &mut self.specials] {
            set.retain(|path| full_parent_chain_survives(path, &dirs));
        }
    }
}

/// Names whose live entry a crash overruled. A lost rename, exchange or
/// removal brings back a name's DURABLE entry: the live image may hold a
/// different node at such a name (the moved one, a replacement), so
/// reconstruction reads the entry off the durable baseline. A lost removal of
/// a node the baseline does not hold at that name keeps the node it took
/// away. Either holds until a later surviving change puts a live entry there
/// again.
#[derive(Default)]
pub(super) struct Reverted {
    durable: BTreeSet<String>,
    /// The node a lost removal left at each name, by inode.
    kept: BTreeMap<String, u64>,
    /// The last [`Removed`] record of each removed node: what the node was
    /// when its last name went, for a node the live image no longer holds.
    records: BTreeMap<u64, Removed>,
}

impl Reverted {
    pub(super) fn bring_back(&mut self, root: &str) {
        self.durable.insert(root.to_owned());
    }

    /// A lost removal left `path` holding the node it took away, which the
    /// durable baseline does not hold there.
    pub(super) fn keep(&mut self, path: &str, removed: &Removed) {
        self.kept.insert(path.to_owned(), removed.metadata.ino);
        self.remember(removed);
    }

    /// A removal took `removed`'s node, whether or not the removal or the
    /// name survives the crash: its record is the node's last known state,
    /// for whichever name brings back a node the live image no longer holds.
    pub(super) fn remember(&mut self, removed: &Removed) {
        self.records.insert(removed.metadata.ino, removed.clone());
    }

    /// A surviving change put a live entry at `root`: nothing at or beneath it
    /// is the durable or a kept entry any more.
    pub(super) fn forget(&mut self, root: &str) {
        self.durable.retain(|path| !within(path, root));
        self.kept.retain(|path, _| !within(path, root));
    }

    /// Whether the live entry at `path` is not the one that survived.
    pub(super) fn covers(&self, path: &str) -> bool {
        self.kept.contains_key(path) || self.durable.iter().any(|root| within(path, root))
    }

    /// The node a lost removal left at `path`.
    pub(super) fn kept(&self, path: &str) -> Option<&Removed> {
        self.kept.get(path).and_then(|ino| self.records.get(ino))
    }

    /// What node `ino` was when a removal last took it.
    pub(super) fn record(&self, ino: u64) -> Option<&Removed> {
        self.records.get(&ino)
    }
}

/// Whether `path` is `root` or lies beneath it.
fn within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path` with an exchange of `first` and `second` applied: a name at or
/// beneath one now lies at or beneath the other.
pub(super) fn swapped(path: &str, first: &str, second: &str) -> String {
    if within(path, first) {
        format!("{second}{}", &path[first.len()..])
    } else if within(path, second) {
        format!("{first}{}", &path[second.len()..])
    } else {
        path.to_owned()
    }
}

fn full_parent_chain_survives(path: &str, dirs: &BTreeSet<String>) -> bool {
    let mut parent = parent_path(path);
    while parent != "/" {
        if !dirs.contains(parent) {
            return false;
        }
        parent = parent_path(parent);
    }
    dirs.contains("/")
}

fn parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

fn normalize_path(path: &str) -> DriverResult<String> {
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

impl CrashFs {
    /// Commit the namespace operations of one directory, modeling a directory
    /// fsync. After this, the directory's creations, unlinks, and renames
    /// survive a crash even under the directory-durability model.
    pub fn sync_directory(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let metadata = self.live.metadata(&path)?;
        if !matches!(metadata.kind, FsEntryKind::Directory) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        self.staged_times
            .insert(metadata.ino, DurableTimes::from(metadata));
        // Committing a directory makes durable exactly the namespace changes it
        // governs. A rename has two governing directories: the destination
        // parent (its link side, tracked by `committed`) and the source parent
        // (its unlink side, tracked by `source_committed`). Only fsyncing both
        // makes the whole rename durable.
        for op in &mut self.pending {
            match &op.kind {
                PendingKind::Create { path: entry, .. }
                | PendingKind::Remove { path: entry, .. } => {
                    if parent_path(entry) == path {
                        op.committed = true;
                    }
                }
                PendingKind::Rename { from, to, .. } => {
                    if parent_path(to) == path {
                        op.committed = true;
                    }
                    if parent_path(from) == path {
                        op.source_committed = true;
                    }
                }
                PendingKind::Exchange { first, second } => {
                    if parent_path(second) == path {
                        op.committed = true;
                    }
                    if parent_path(first) == path {
                        op.source_committed = true;
                    }
                }
            }
        }
        Ok(())
    }

    /// Journal a rename the live image took, moving the open descriptors'
    /// attribution with it. Durable and staged bytes are the node's, keyed by
    /// inode, so they need no move.
    pub(super) fn record_rename(
        &mut self,
        from: &str,
        to: &str,
        whiteout: bool,
    ) -> DriverResult<()> {
        let from = normalize_entry_path(from).expect("rename normalized the source already");
        let to = normalize_entry_path(to).expect("rename normalized the destination already");
        let kind = self.live.metadata(&to)?.kind;
        let prefix = format!("{from}/");
        for path in self.open_paths.values_mut() {
            if *path == from {
                path.clone_from(&to);
            } else if path.starts_with(&prefix) {
                *path = format!("{to}{}", &path[from.len()..]);
            }
        }
        self.journal(PendingKind::Rename {
            from,
            to,
            kind,
            whiteout,
        });
        Ok(())
    }

    /// Record a namespace mutation in the pending journal, initially uncommitted
    /// on both governing-directory sides.
    pub(super) fn journal(&mut self, kind: PendingKind) {
        self.pending.push(PendingOp {
            kind,
            committed: false,
            source_committed: false,
        });
    }
}

#[cfg(test)]
mod tests;
