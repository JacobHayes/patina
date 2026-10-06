//! Durable entry records and filesystem inventory capture.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{FsEntryKind, FsMetadata};
use patina_dst_fs_mem::{FileData, MemFs};

/// A file name captured in the durable baseline.
#[derive(Clone, Debug)]
pub(super) struct BaselineFile {
    pub(super) inode: u64,
    /// Shares its blocks with the image it was taken from: a durability
    /// point costs the file's block map, never a copy of its bytes.
    pub(super) contents: FileData,
}

/// A symlink name captured in the durable baseline: the node it names (two
/// names of one link node come back as one) and the target.
#[derive(Clone, Debug)]
pub(super) struct BaselineSymlink {
    pub(super) inode: u64,
    pub(super) target: String,
}

/// The four timestamps of one durable entry, restored verbatim onto a
/// reconstructed image (the storage layer's own values, not stamps of the
/// crash instant).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DurableTimes {
    pub(super) atime_nanos: i128,
    pub(super) mtime_nanos: i128,
    pub(super) ctime_nanos: i128,
    pub(super) btime_nanos: i128,
}

impl From<FsMetadata> for DurableTimes {
    fn from(m: FsMetadata) -> Self {
        Self {
            atime_nanos: m.atime_nanos,
            mtime_nanos: m.mtime_nanos,
            ctime_nanos: m.ctime_nanos,
            btime_nanos: m.btime_nanos,
        }
    }
}

/// A durable filesystem baseline captured at a durability point: the directory
/// set, file contents, file inode identity, symlink targets, and per-entry
/// timestamps.
#[derive(Clone, Default)]
pub(super) struct Baseline {
    pub(super) dirs: BTreeSet<String>,
    pub(super) files: BTreeMap<String, BaselineFile>,
    pub(super) symlinks: BTreeMap<String, BaselineSymlink>,
    /// Named pipes, socket nodes and whiteouts, by path, with their inode
    /// identity and kind. Their NAME is durable namespace state like any other,
    /// and the INODE is what a second hard link names, so the two names come
    /// back as one node; a FIFO's bytes in flight are process state, so nothing
    /// here holds them and a crash simply drops them, exactly as a real one
    /// does.
    pub(super) specials: BTreeMap<String, (u64, FsEntryKind)>,
    /// All four timestamps, by path. A crash cannot reset a surviving entry's
    /// change or birth time any more than its modification time.
    pub(super) times: BTreeMap<String, DurableTimes>,
    /// Permission bits, by path, for every entry that owns a mode (files,
    /// directories and FIFOs; a symlink leaf has none). A mode is durable
    /// metadata like a symlink's target — a crash reverts a lost entry, never a
    /// surviving entry's bits to a per-kind constant.
    pub(super) modes: BTreeMap<String, u32>,
    /// Extended attributes, by path, for every entry that has any. Metadata
    /// like a mode: a surviving entry keeps its live attributes, a resurrected
    /// one the durable baseline's.
    pub(super) xattrs: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

/// Snapshot a filesystem into a durable baseline: directories, file contents,
/// symlink targets, special nodes, permission bits, extended attributes, and
/// per-entry timestamps. Every entry kind is captured so none is silently lost
/// across a crash.
///
/// The image is read through [`MemFs::inventory`], the storage layer's own
/// unenforced view. A crash journal is not a process: it must see a `0o000`
/// directory's children, or a mode change would quietly delete data on the next
/// crash.
pub(super) fn enumerate(fs: &MemFs) -> Baseline {
    let mut baseline = Baseline::default();
    baseline.dirs.insert("/".to_owned());
    for (path, metadata) in fs.inventory() {
        baseline.times.insert(
            path.clone(),
            DurableTimes {
                atime_nanos: metadata.atime_nanos,
                mtime_nanos: metadata.mtime_nanos,
                ctime_nanos: metadata.ctime_nanos,
                btime_nanos: metadata.btime_nanos,
            },
        );
        // A symlink leaf has no mode of its own; every other kind does.
        if metadata.kind != FsEntryKind::Symlink {
            baseline.modes.insert(path.clone(), metadata.mode);
        }
        let xattrs = fs.entry_xattrs(&path);
        if !xattrs.is_empty() {
            baseline.xattrs.insert(path.clone(), xattrs);
        }
        match metadata.kind {
            FsEntryKind::Directory => {
                baseline.dirs.insert(path);
            }
            FsEntryKind::File => {
                let contents = fs.file_data(&path).cloned().unwrap_or_default();
                baseline.files.insert(
                    path,
                    BaselineFile {
                        inode: metadata.ino,
                        contents,
                    },
                );
            }
            FsEntryKind::Symlink => {
                let target = fs.symlink_target(&path).unwrap_or_default().to_owned();
                baseline.symlinks.insert(
                    path,
                    BaselineSymlink {
                        inode: metadata.ino,
                        target,
                    },
                );
            }
            FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice => {
                baseline
                    .specials
                    .insert(path, (metadata.ino, metadata.kind));
            }
        }
    }
    baseline
}

#[cfg(test)]
mod tests;
