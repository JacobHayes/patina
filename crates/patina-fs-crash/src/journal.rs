//! The running jbd2 transaction: which inodes it holds changes for, when it
//! commits, and what a commit records.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{EffectError, ErrorCode, FsClock};
use patina_dst_driver_api::DriverResult;
use patina_dst_fs_mem::{BLOCK_SIZE, FileData};

use crate::baseline::{Baseline, enumerate};
use crate::{COMMIT_INTERVAL_NANOS, CrashFs};

/// The file bytes of a committed image, by inode.
pub(super) fn data_by_inode(image: &Baseline) -> BTreeMap<u64, FileData> {
    image
        .files
        .values()
        .map(|file| (file.inode, file.contents.clone()))
        .collect()
}

pub(super) fn parent_path(path: &str) -> &str {
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
    /// Commit the running transaction if it has been open for the commit
    /// interval by `clock`: jbd2's timer fired between the previous operation
    /// and this one, when the image was as it is now.
    pub(super) fn tick(&mut self, clock: FsClock) {
        self.now = clock.now_nanos;
        if self
            .opened
            .is_some_and(|opened| clock.now_nanos.saturating_sub(opened) >= COMMIT_INTERVAL_NANOS)
        {
            self.commit();
        }
    }

    /// The inodes `inodes` took a change at `clock`: they join the running
    /// transaction, which opens now if it was empty.
    pub(super) fn journal(&mut self, clock: FsClock, inodes: impl IntoIterator<Item = u64>) {
        self.opened.get_or_insert(clock.now_nanos);
        self.journaled.extend(inodes);
    }

    /// The node at `path` and its parent directory, as the live image has
    /// them now: what a namespace change there journals.
    pub(super) fn entry_and_parent(&self, path: &str) -> Vec<u64> {
        let Ok(path) = normalize_entry_path(path) else {
            return Vec::new();
        };
        [path.as_str(), parent_path(&path)]
            .into_iter()
            .filter_map(|path| self.live.entry_metadata(path).ok())
            .map(|metadata| metadata.ino)
            .collect()
    }

    /// Commit the running transaction: the live namespace and every inode's
    /// metadata become the committed image, each file at the bytes written
    /// back for it (`data=ordered`: they reached the disk before the commit
    /// record) and the size that writeback recorded.
    pub(super) fn commit(&mut self) {
        let mut disk = std::mem::take(&mut self.committed_data);
        disk.extend(std::mem::take(&mut self.written));
        let mut committed = enumerate(&self.live);
        for file in committed.files.values_mut() {
            file.contents = disk.get(&file.inode).cloned().unwrap_or_default();
        }
        self.committed_data = data_by_inode(&committed);
        self.committed = committed;
        self.shrunk.clear();
        self.freed.clear();
        self.journaled.clear();
        self.opened = None;
    }

    /// What the disk holds for `ino`: the bytes written back since the last
    /// commit, else the commit's.
    pub(super) fn disk_content(&self, ino: u64) -> FileData {
        self.written
            .get(&ino)
            .or_else(|| self.committed_data.get(&ino))
            .cloned()
            .unwrap_or_default()
    }

    /// Write `current`, the cached content of named file `ino`, back: every
    /// dirty page reaches the disk (a page a writeback error dropped is
    /// clean, so the disk keeps what it had there), and the size the next
    /// commit records becomes its length.
    pub(super) fn write_back(&mut self, ino: u64, current: &FileData) {
        let disk = self.disk_content(ino);
        let bytes = self.written_back(ino, &disk, current);
        self.dirty.remove(&ino);
        self.store(ino, &disk, bytes);
    }

    /// `auto_da_alloc`'s flush (`ext4_alloc_da_blocks`): write back only the
    /// delayed-allocation pages of `current`, the ones with no block on disk
    /// yet. A page overwriting an allocated block stays dirty, so it can still
    /// tear.
    pub(super) fn write_back_delayed(&mut self, ino: u64, current: &FileData) {
        let disk = self.disk_content(ino);
        let mut bytes = self.written_back(ino, &disk, current);
        let in_place: BTreeSet<u64> = disk
            .written()
            .map(|(index, _)| index)
            .filter(|index| bytes.is_written(*index))
            .collect();
        for index in &in_place {
            let start = index * BLOCK_SIZE;
            bytes.overlay(&disk, start, (start + BLOCK_SIZE).min(bytes.len()));
        }
        if let Some(pages) = self.dirty.get_mut(&ino) {
            pages.retain(|page| in_place.contains(page));
            if pages.is_empty() {
                self.dirty.remove(&ino);
            }
        }
        self.store(ino, &disk, bytes);
    }

    /// `bytes` reached the disk for `ino` over `disk`. A block allocated or a
    /// size recorded by it is a change in the running transaction.
    fn store(&mut self, ino: u64, disk: &FileData, bytes: FileData) {
        let allocated =
            bytes.len() != disk.len() || bytes.written().any(|(index, _)| !disk.is_written(index));
        if allocated {
            self.opened.get_or_insert(self.now);
            self.journaled.insert(ino);
        }
        self.written.insert(ino, bytes);
    }

    /// A write took `ino` to `len` bytes. Within the block the committed
    /// size ends in, no block is allocated, so ext4 records the new size at
    /// once (`ext4_da_should_update_i_disksize`): the next commit carries it,
    /// whether or not the bytes reach the block.
    pub(super) fn extended(&mut self, ino: u64, len: u64) {
        let mut disk = self.disk_content(ino);
        let end = disk.len();
        if end == 0 || len <= end {
            return;
        }
        let last = (end - 1) / BLOCK_SIZE;
        if !disk.is_written(last) {
            return;
        }
        disk.set_len(len.min((last + 1) * BLOCK_SIZE));
        self.written.insert(ino, disk);
    }

    /// The whole blocks of `offset..offset + len` in `ino` were punched or
    /// zeroed: freed until the next commit.
    pub(super) fn freed_range(&mut self, ino: u64, offset: u64, len: u64) {
        let first = offset.div_ceil(BLOCK_SIZE);
        let end = offset.saturating_add(len) / BLOCK_SIZE;
        if first < end {
            self.freed.entry(ino).or_default().extend(first..end);
        }
    }

    /// The size the next commit records for `ino` became `len`, outside a
    /// writeback (a truncation, or an allocation past the end): the disk's
    /// bytes past it are freed, and a larger size reads as a hole until
    /// written back.
    pub(super) fn resized_on_disk(&mut self, ino: u64, len: u64) {
        let mut disk = self.disk_content(ino);
        if len < disk.len() {
            let floor = self.shrunk.entry(ino).or_insert(len);
            *floor = (*floor).min(len);
        }
        disk.set_len(len);
        self.written.insert(ino, disk);
    }
}

#[cfg(test)]
mod tests;
