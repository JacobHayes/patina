//! Timestamps, metadata assembly and permission checks.

use crate::namespace::{not_found, parent_path};
use crate::{
    BLOCK_SIZE, FAST_SYMLINK_MAX, Inode, InodeId, MODE_MASK, MemFs, RELATIME_REFRESH_NANOS, SEARCH,
    TimeRange, Times, WRITE,
};
use patina_dst_abi::{AtimePolicy, EffectError, ErrorCode, FsClock, FsEntryKind, FsMetadata};
use patina_dst_driver_api::DriverResult;

impl Times {
    /// A freshly created entry: all four at `now`.
    pub(super) fn created(clock: FsClock) -> Self {
        let now = i128::from(clock.now_nanos);
        Self {
            atime_nanos: now,
            mtime_nanos: now,
            ctime_nanos: now,
            btime_nanos: now,
        }
    }

    /// The entry's DATA changed (a write, a truncation, an allocation; for a
    /// directory, a name appeared or disappeared): `mtime` and `ctime`.
    pub(super) fn data_changed(&mut self, clock: FsClock) {
        self.mtime_nanos = i128::from(clock.now_nanos);
        self.ctime_nanos = i128::from(clock.now_nanos);
    }

    /// The entry's METADATA changed (mode, link count, name, explicit times):
    /// `ctime` only.
    pub(super) fn metadata_changed(&mut self, clock: FsClock) {
        self.ctime_nanos = i128::from(clock.now_nanos);
    }

    /// The entry was READ: `atime`, under the clock's policy. `relatime` is
    /// Linux's `relatime_need_update` — an access time not newer than `mtime`
    /// or `ctime`, or at least a day old, is refreshed; otherwise a read leaves
    /// it alone — and no policy rewrites an access time that already reads
    /// `now`.
    pub(super) fn accessed(&mut self, clock: FsClock) {
        let now = i128::from(clock.now_nanos);
        let due = match clock.atime {
            AtimePolicy::NoAtime => false,
            AtimePolicy::Strict => true,
            AtimePolicy::Relatime => {
                self.mtime_nanos >= self.atime_nanos
                    || self.ctime_nanos >= self.atime_nanos
                    || now - self.atime_nanos >= i128::from(RELATIME_REFRESH_NANOS)
            }
        };
        if due && self.atime_nanos != now {
            self.atime_nanos = now;
        }
    }

    /// `utimensat`: `None` leaves a time alone, and a set one is truncated to
    /// the filesystem's range. Any change stamps `ctime`.
    pub(super) fn set(
        &mut self,
        clock: FsClock,
        atime: Option<i128>,
        mtime: Option<i128>,
        range: TimeRange,
    ) {
        if atime.is_none() && mtime.is_none() {
            return;
        }
        if let Some(value) = atime {
            self.atime_nanos = range.truncate(value);
        }
        if let Some(value) = mtime {
            self.mtime_nanos = range.truncate(value);
        }
        self.metadata_changed(clock);
    }
}

impl TimeRange {
    pub(super) fn of(inode: &Inode) -> Self {
        if inode.seals.is_some() {
            TimeRange::Tmpfs
        } else {
            TimeRange::Ext4
        }
    }

    /// The kernel's `timestamp_truncate`: the seconds clamped to the range,
    /// the nanoseconds dropped at either bound (both filesystems keep whole
    /// nanoseconds). A time is never refused and never wraps.
    fn truncate(self, nanos: i128) -> i128 {
        const NANOS_PER_SECOND: i128 = 1_000_000_000;
        let (min, max) = match self {
            TimeRange::Ext4 => (i128::from(i32::MIN), (1 << 34) - 1 + i128::from(i32::MIN)),
            TimeRange::Tmpfs => (i128::from(i64::MIN), i128::from(i64::MAX)),
        };
        let sec = nanos.div_euclid(NANOS_PER_SECOND).clamp(min, max);
        if sec == min || sec == max {
            sec * NANOS_PER_SECOND
        } else {
            nanos
        }
    }
}

/// Does the single modeled (owning, non-root) identity hold every bit in `want`?
pub(super) fn owner_allows(mode: u32, want: u32) -> bool {
    ((mode >> 6) & 0o7) & want == want
}

/// A permission refusal. [`ErrorCode::Denied`] is the code the POSIX boundary
/// renders as `EACCES`, so a guest reads it as `PermissionDenied` — the answer
/// that has to stay distinguishable from "not found" and from a sandbox's own
/// confinement refusal.
pub(super) fn denied(path: &str, action: &str) -> EffectError {
    EffectError::new(
        ErrorCode::Denied,
        format!("virtual filesystem permissions do not allow {action}: {path}"),
    )
}

impl MemFs {
    /// A name appeared in or disappeared from `directory`: its `mtime` and
    /// `ctime`, as every namespace operation stamps its parent.
    pub(super) fn stamp_directory(&mut self, clock: FsClock, directory: &str) {
        if let Some(metadata) = self.directories.get_mut(directory) {
            metadata.times.data_changed(clock);
        }
    }

    /// The timestamps of the entry at `path`, whatever its kind.
    pub(super) fn times_mut(&mut self, path: &str) -> Option<&mut Times> {
        if let Some(inode) = self.names.get(path).copied() {
            return self.inodes.get_mut(&inode).map(|inode| &mut inode.times);
        }
        self.directories
            .get_mut(path)
            .map(|metadata| &mut metadata.times)
    }

    /// `2 + subdirectories`: a directory's link count is its own `.`, its
    /// parent's name for it, and every child's `..`.
    fn directory_links(&self, path: &str) -> u32 {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let children = self
            .directories
            .keys()
            .filter(|candidate| {
                candidate
                    .strip_prefix(&prefix)
                    .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
            })
            .count();
        2 + u32::try_from(children).unwrap_or(u32::MAX - 2)
    }

    /// The permission bits of an existing entry, or `None` when nothing is
    /// there. Symlink leaves answer [`SYMLINK_MODE`]: Linux never consults a
    /// link's own mode.
    pub(super) fn entry_mode(&self, path: &str) -> Option<u32> {
        if let Some(inode) = self.leaf(path) {
            return Some(inode.mode);
        }
        self.directories.get(path).map(|metadata| metadata.mode)
    }

    /// Resolving a path walks every directory ABOVE the final component, and
    /// each of those needs `x`. Checked before existence, as the kernel does:
    /// an unsearchable directory answers `EACCES`, never "not found", so the
    /// names behind it cannot be probed through the error code.
    pub(super) fn check_search_path(&self, path: &str) -> DriverResult<()> {
        if path != "/" {
            if let Some(root) = self.directories.get("/") {
                if !owner_allows(root.mode, SEARCH) {
                    return Err(denied("/", "search"));
                }
            }
        }
        let mut current = String::new();
        for component in path
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
        {
            current.push('/');
            current.push_str(component);
            if current.len() >= path.len() {
                // The final component is the entry itself, not a directory the
                // resolution passes THROUGH.
                break;
            }
            if let Some(metadata) = self.directories.get(&current) {
                if !owner_allows(metadata.mode, SEARCH) {
                    return Err(denied(&current, "search"));
                }
            } else if self.names.contains_key(&current) {
                // A component resolved THROUGH a non-directory is `ENOTDIR`,
                // never "not found": the name is there, it just cannot be
                // walked into. (An intermediate symlink is refused before this
                // walk; a missing component is the entry lookup's `NotFound`.)
                return Err(EffectError::new(
                    ErrorCode::NotDirectory,
                    format!("virtual filesystem path component is not a directory: {current}"),
                ));
            }
        }
        Ok(())
    }

    /// Creating, removing, or renaming a NAME inside a directory is a write to
    /// that directory: `w` and `x` both.
    pub(super) fn check_directory_write(&self, directory: &str) -> DriverResult<()> {
        if let Some(metadata) = self.directories.get(directory) {
            if !owner_allows(metadata.mode, WRITE | SEARCH) {
                return Err(denied(directory, "modify"));
            }
        }
        Ok(())
    }

    /// Metadata straight off a node, with no name involved — what a descriptor
    /// on an unlinked entry answers. A regular file's length is its bytes, a
    /// symlink's its target's; every other node holds none.
    pub(super) fn metadata_for_inode(&self, node: InodeId) -> DriverResult<FsMetadata> {
        let inode = self.inodes.get(&node).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {node}"),
            )
        })?;
        let len = match inode.kind {
            FsEntryKind::File | FsEntryKind::Symlink => inode.contents.len(),
            FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice => 0,
        };
        let blocks = match inode.kind {
            FsEntryKind::File => inode.contents.sectors(),
            // ext4 keeps a target shorter than the inode's 60-byte block map
            // in the inode itself (a fast symlink, no block); a longer one
            // takes one block.
            FsEntryKind::Symlink if len < FAST_SYMLINK_MAX => 0,
            FsEntryKind::Symlink => BLOCK_SIZE / 512,
            FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice => 0,
        };
        Ok(FsMetadata {
            kind: inode.kind,
            len,
            blocks,
            ino: node,
            nlink: inode.links,
            atime_nanos: inode.times.atime_nanos,
            mtime_nanos: inode.times.mtime_nanos,
            ctime_nanos: inode.times.ctime_nanos,
            btime_nanos: inode.times.btime_nanos,
            mode: inode.mode,
        })
    }

    /// A rename moved the node from `from` to `to`: both parents changed (a
    /// name left one, a name arrived in the other) and the node's own `ctime`
    /// moves, as every Linux filesystem's `rename` stamps it.
    pub(super) fn stamp_renamed(&mut self, clock: FsClock, from: &str, to: &str) {
        if let Some(times) = self.times_mut(to) {
            times.metadata_changed(clock);
        }
        self.stamp_directory(clock, parent_path(from));
        if parent_path(to) != parent_path(from) {
            self.stamp_directory(clock, parent_path(to));
        }
    }

    /// A node's metadata changed (an attribute set or removed): its `ctime`.
    pub(super) fn stamp_node(&mut self, clock: FsClock, ino: InodeId, kind: FsEntryKind) {
        let times = if kind == FsEntryKind::Directory {
            self.directories
                .values_mut()
                .find(|metadata| metadata.ino == ino)
                .map(|metadata| &mut metadata.times)
        } else {
            self.inodes.get_mut(&ino).map(|inode| &mut inode.times)
        };
        if let Some(times) = times {
            times.metadata_changed(clock);
        }
    }

    /// Write `mode`'s permission bits onto the entry `path` names, stamping
    /// `ctime`: the kernel writes the inode whether or not the bits changed.
    pub(super) fn apply_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        let mode = mode & MODE_MASK;
        if let Some(inode) = self.names.get(path).copied() {
            let inode = self
                .inodes
                .get_mut(&inode)
                .expect("name references an inode");
            inode.mode = mode;
            inode.times.metadata_changed(clock);
            return Ok(());
        }
        if let Some(metadata) = self.directories.get_mut(path) {
            metadata.mode = mode;
            metadata.times.metadata_changed(clock);
            return Ok(());
        }
        Err(not_found(path))
    }

    pub(super) fn metadata_for_path(&self, path: &str) -> DriverResult<FsMetadata> {
        if let Some(inode_id) = self.names.get(path) {
            return self.metadata_for_inode(*inode_id);
        }
        if let Some(metadata) = self.directories.get(path) {
            return Ok(FsMetadata {
                kind: FsEntryKind::Directory,
                len: 0,
                blocks: 0,
                ino: metadata.ino,
                nlink: self.directory_links(path),
                atime_nanos: metadata.times.atime_nanos,
                mtime_nanos: metadata.times.mtime_nanos,
                ctime_nanos: metadata.times.ctime_nanos,
                btime_nanos: metadata.times.btime_nanos,
                mode: metadata.mode,
            });
        }
        Err(not_found(path))
    }
}

#[cfg(test)]
mod tests;
