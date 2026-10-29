//! Writeback errors, as Linux has handled them since 4.13 (`errseq_t`).
//!
//! When an `fsync` fails because writing a file's dirty pages back failed
//! (`EIO`, `ENOSPC`), the kernel ends writeback on those pages without them
//! reaching the disk and marks them clean. They stay in the page cache, so a
//! read still returns the bytes the guest wrote, but nothing writes them again:
//! a retried `fsync` that succeeds makes none of them durable, and neither does
//! `sync(2)`. A machine crash, or dropping the clean pages from the cache,
//! brings back what the disk held. Writing a page again dirties it, and the
//! next successful `fsync` writes all of it.
//!
//! The error is recorded against the file's mapping and reported once per open
//! file description (`file_check_and_advance_wb_err`): the failing call reports
//! it, every other description open at the time reports it on its next
//! `fsync` (after writing back what is dirty), and a description opened later
//! never sees it, because it was already seen. Duplicates of a descriptor
//! share its description, so between them they see it once.
//!
//! This model loses every dirty page of the file on a writeback error, the
//! worst a failing device can do; a kernel can lose fewer. A failed directory
//! `fsync` changes nothing here: its namespace changes stay uncommitted.

use std::collections::BTreeSet;

use patina_dst_abi::{EffectError, ErrorCode, Fd, FsEntryKind};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::FileData;

use crate::CrashFs;
use crate::driver::DIRTY_PAGE;

impl CrashFs {
    /// See [`patina_dst_driver_api::FsDriver::fail_writeback`].
    pub(super) fn writeback_failed(&mut self, fd: Fd, code: ErrorCode) -> DriverResult<()> {
        let metadata = self.live.fd_metadata(fd)?;
        // An anonymous file has no writeback, and a directory's failure
        // leaves its namespace changes pending.
        if metadata.kind != FsEntryKind::File || !self.open_paths.contains_key(&fd) {
            return Ok(());
        }
        let failing = self.live.description_of(fd)?;
        if let Some(pages) = self.dirty.remove(&metadata.ino) {
            self.lost.entry(metadata.ino).or_default().extend(pages);
        }
        for other in self.open_paths.keys() {
            let Ok(description) = self.live.description_of(*other) else {
                continue;
            };
            let same_file = self
                .live
                .fd_metadata(*other)
                .is_ok_and(|other| other.kind == FsEntryKind::File && other.ino == metadata.ino);
            if same_file && description != failing {
                self.unseen_errors.insert(description, code);
            }
        }
        // The failing call reports the error itself, and with it any its
        // description had not seen yet.
        self.unseen_errors.remove(&failing);
        Ok(())
    }

    /// The writeback error `fd`'s description has not reported yet, taken:
    /// it reports once.
    pub(super) fn take_unseen_error(&mut self, fd: Fd) -> DriverResult<()> {
        let Ok(description) = self.live.description_of(fd) else {
            return Ok(());
        };
        match self.unseen_errors.remove(&description) {
            Some(code) => Err(EffectError::new(
                code,
                "a writeback of this file failed since this description last synced it",
            )),
            None => Ok(()),
        }
    }

    /// Forget the unseen error of `description` once no descriptor names it.
    pub(super) fn description_closed(&mut self, description: u64) {
        let open = self.open_paths.keys().any(|fd| {
            self.live
                .description_of(*fd)
                .is_ok_and(|open| open == description)
        });
        if !open {
            self.unseen_errors.remove(&description);
        }
    }

    /// What the disk holds for `ino` at its last durability point.
    pub(super) fn durable_content(&self, ino: u64) -> FileData {
        self.staged_content
            .get(&ino)
            .or_else(|| {
                self.durable
                    .files
                    .values()
                    .find(|file| file.inode == ino)
                    .map(|file| &file.contents)
            })
            .cloned()
            .unwrap_or_default()
    }

    /// `current`, the cached content of `ino`, with the pages a writeback
    /// error dropped back to `durable`: what writing every dirty page of it
    /// back leaves on disk.
    pub(super) fn written_back(
        &self,
        ino: u64,
        durable: &FileData,
        current: &FileData,
    ) -> FileData {
        match self.lost.get(&ino) {
            Some(lost) => without_lost_pages(durable, current, lost),
            None => current.clone(),
        }
    }

    /// The pages `first..=last` of `ino` were written, or dropped from the
    /// cache: none of them still holds bytes a writeback error lost.
    pub(super) fn rewritten(&mut self, ino: u64, first: u64, last: u64) {
        if let Some(pages) = self.lost.get_mut(&ino) {
            pages.retain(|page| *page < first || *page > last);
            if pages.is_empty() {
                self.lost.remove(&ino);
            }
        }
    }
}

/// `current` with the `lost` pages reverted to `durable`, past whose end
/// the disk holds zeros. The length stays `current`'s: ext4 journals the size
/// an append reached as metadata (at the write over an allocated block, at
/// block allocation otherwise), so the next commit keeps it whether or not
/// the data reached its blocks.
fn without_lost_pages(durable: &FileData, current: &FileData, lost: &BTreeSet<u64>) -> FileData {
    let mut result = current.clone();
    for page in lost {
        let start = page * DIRTY_PAGE;
        if start >= current.len() {
            break;
        }
        result.overlay(durable, start, ((page + 1) * DIRTY_PAGE).min(current.len()));
    }
    result
}

#[cfg(test)]
mod tests;
