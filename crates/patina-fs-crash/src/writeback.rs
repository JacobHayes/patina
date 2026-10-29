//! Writeback errors, as Linux has handled them since 4.13 (`errseq_t`), and
//! the clean pages `posix_fadvise(POSIX_FADV_DONTNEED)` drops.
//!
//! When writing a file's dirty pages back fails (`EIO`, `ENOSPC`), in an
//! `fsync` or in a `sync`/`syncfs` of the volume, the kernel ends writeback on
//! those pages without them reaching the disk and marks them clean. They stay
//! in the page cache, so a read still returns the bytes the guest wrote, but
//! nothing writes them again: a retried `fsync` that succeeds makes none of
//! them durable, and neither does `sync(2)`. A machine crash, or dropping the
//! clean pages from the cache (`DONTNEED`), brings back what the disk held.
//! Writing a page again dirties it, and the next successful `fsync` writes all
//! of it.
//!
//! The error is recorded twice (`mapping_set_error`): against the file's
//! mapping and against the filesystem (`s_wb_err`). Each is an `errseq_t`: an
//! open file description samples both at open (an error nobody has seen yet
//! samples as none, so a later open still sees it) and reports a change since
//! its sample once. `fsync`, `fdatasync` and `sync_file_range` with a `WAIT`
//! flag check the mapping's (`file_check_and_advance_wb_err`), `syncfs` the
//! filesystem's; `sync(2)` checks neither. So the failing `fsync` reports its
//! error, every other description open on the file reports it on its next
//! `fsync`, and every description reports it on its next `syncfs`.
//! Duplicates of a descriptor share its description, so between them they see
//! each error once.
//!
//! This model loses every dirty page a failed writeback covers, the worst a
//! failing device can do; a kernel can lose fewer. An `fsync` that reports an
//! error returns before it commits (`ext4_sync_file`), so its changes stay in
//! the running transaction. A failed `sync`/`syncfs` still commits the
//! namespace and the metadata (the journal commit is separate from data
//! writeback).

use std::collections::BTreeSet;

use patina_dst_abi::{EffectError, ErrorCode, Fd, FsEntryKind};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::FileData;

use crate::CrashFs;
use crate::driver::DIRTY_PAGE;

/// An `errseq_t`: the latest writeback error, a counter of errors recorded
/// after one was seen, and whether anybody has seen the latest.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ErrSeq {
    counter: u64,
    code: Option<ErrorCode>,
    seen: bool,
}

/// What an open file description last saw of an [`ErrSeq`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sample {
    counter: u64,
    code: Option<ErrorCode>,
}

impl ErrSeq {
    /// `errseq_set`: a new error, unseen. Recorded over an unseen one, it
    /// takes its place without counting.
    fn set(&mut self, code: ErrorCode) {
        if self.seen {
            self.counter += 1;
        }
        self.code = Some(code);
        self.seen = false;
    }

    fn current(&self) -> Sample {
        Sample {
            counter: self.counter,
            code: self.code,
        }
    }

    /// `errseq_sample`: what an open sees as already reported. An error
    /// nobody has seen samples as none, so the opener reports it.
    fn sample(&self) -> Sample {
        if self.seen {
            self.current()
        } else {
            Sample::default()
        }
    }

    /// `errseq_check_and_advance`: the error recorded since `since`, which
    /// is now seen and `since` advanced past.
    fn check_and_advance(&mut self, since: &mut Sample) -> Option<ErrorCode> {
        let current = self.current();
        if current == *since {
            return None;
        }
        self.seen = true;
        *since = current;
        current.code
    }
}

/// An open file description's samples: of its file's mapping (`f_wb_err`)
/// and of the filesystem (`f_sb_err`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Samples {
    file: Sample,
    filesystem: Sample,
}

fn reported(code: Option<ErrorCode>, what: &str) -> DriverResult<()> {
    match code {
        Some(code) => Err(EffectError::new(
            code,
            format!("a writeback of {what} failed since this description last checked"),
        )),
        None => Ok(()),
    }
}

impl CrashFs {
    /// A description of `fd` was opened: it samples the errors recorded so
    /// far. A description this model did not see open (one adopted across a
    /// crash, whose errors went with the cache) samples as none.
    pub(super) fn description_opened(&mut self, fd: Fd) {
        let Ok(description) = self.live.description_of(fd) else {
            return;
        };
        let ino = self.live.fd_metadata(fd).ok().map(|metadata| metadata.ino);
        let file = ino
            .and_then(|ino| self.file_errors.get(&ino))
            .map(ErrSeq::sample)
            .unwrap_or_default();
        self.samples.insert(
            description,
            Samples {
                file,
                filesystem: self.filesystem_errors.sample(),
            },
        );
    }

    /// The dirty pages of `ino` failed to write back with `code`: they are
    /// clean but lost, and the error is recorded against the file and the
    /// filesystem.
    fn lose_dirty_pages(&mut self, ino: u64, code: ErrorCode) {
        if let Some(pages) = self.dirty.remove(&ino) {
            self.lost.entry(ino).or_default().extend(pages);
        }
        self.file_errors.entry(ino).or_default().set(code);
        self.filesystem_errors.set(code);
    }

    /// See [`patina_dst_driver_api::FsDriver::fail_writeback`].
    pub(super) fn writeback_failed(&mut self, fd: Fd, code: ErrorCode) -> DriverResult<()> {
        let metadata = self.live.fd_metadata(fd)?;
        // An anonymous file has no writeback, and a directory has no pages.
        if metadata.kind != FsEntryKind::File || !self.named.contains(&fd) {
            return Ok(());
        }
        self.lose_dirty_pages(metadata.ino, code);
        // The failing call reports the error itself
        // (`file_write_and_wait_range`), and with it any its description had
        // not seen yet.
        let _ = self.check_file_error(fd);
        Ok(())
    }

    /// See [`patina_dst_driver_api::FsDriver::fail_writeback_all`]: every
    /// named file with dirty pages loses them.
    pub(super) fn writeback_failed_all(&mut self, code: ErrorCode) {
        let dirty: Vec<u64> = self.dirty.keys().copied().collect();
        for ino in dirty {
            self.lose_dirty_pages(ino, code);
        }
        self.filesystem_errors.set(code);
    }

    /// Report the writeback error of `fd`'s file its description has not
    /// seen yet, once.
    pub(super) fn check_file_error(&mut self, fd: Fd) -> DriverResult<()> {
        let (Ok(description), Ok(metadata)) =
            (self.live.description_of(fd), self.live.fd_metadata(fd))
        else {
            return Ok(());
        };
        let Some(errors) = self.file_errors.get_mut(&metadata.ino) else {
            return Ok(());
        };
        let since = &mut self.samples.entry(description).or_default().file;
        reported(errors.check_and_advance(since), "this file")
    }

    /// Report the writeback error on the filesystem `fd`'s description has
    /// not seen yet, once.
    pub(super) fn check_filesystem_error(&mut self, fd: Fd) -> DriverResult<()> {
        let Ok(description) = self.live.description_of(fd) else {
            return Ok(());
        };
        let since = &mut self.samples.entry(description).or_default().filesystem;
        reported(
            self.filesystem_errors.check_and_advance(since),
            "the filesystem",
        )
    }

    /// Forget the samples of `description` once no descriptor names it.
    pub(super) fn description_closed(&mut self, description: u64) {
        let open = self.named.iter().any(|fd| {
            self.live
                .description_of(*fd)
                .is_ok_and(|open| open == description)
        });
        if !open {
            self.samples.remove(&description);
        }
    }

    /// See [`patina_dst_driver_api::FsDriver::drop_cache`]: the clean pages of
    /// `fd`'s file that `offset..offset + len` covers whole (`len` 0: to the
    /// end) leave the cache, as `generic_fadvise` invalidates them. Only a
    /// page a writeback error dropped differs from the disk, so only those
    /// change: they read back what the disk holds. Dirty pages stay.
    pub(super) fn cache_dropped(&mut self, fd: Fd, offset: u64, len: u64) -> DriverResult<()> {
        let metadata = self.live.fd_metadata(fd)?;
        if metadata.kind != FsEntryKind::File || !self.named.contains(&fd) {
            return Ok(());
        }
        let Some((first, last)) = whole_pages(offset, len, metadata.len) else {
            return Ok(());
        };
        let Some(lost) = self.lost.get(&metadata.ino) else {
            return Ok(());
        };
        let dropped: BTreeSet<u64> = lost.range(first..=last).copied().collect();
        if dropped.is_empty() {
            return Ok(());
        }
        let durable = self.disk_content(metadata.ino);
        let current = self.live.fd_file_data(fd)?;
        let reverted = without_lost_pages(&durable, current, &dropped);
        *self.live.fd_file_data_mut(fd)? = reverted;
        self.rewritten_pages(metadata.ino, &dropped);
        Ok(())
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

    /// [`CrashFs::rewritten`] for a set of pages.
    fn rewritten_pages(&mut self, ino: u64, dropped: &BTreeSet<u64>) {
        if let Some(pages) = self.lost.get_mut(&ino) {
            pages.retain(|page| !dropped.contains(page));
            if pages.is_empty() {
                self.lost.remove(&ino);
            }
        }
    }
}

/// The pages `offset..offset + len` of a `size`-byte file covers whole (`len`
/// 0, or a range past the largest offset: to the end), as `generic_fadvise`
/// rounds a `DONTNEED` range: the first page from the first full one, the
/// last only if the range ends on its last byte or on the file's.
fn whole_pages(offset: u64, len: u64, size: u64) -> Option<(u64, u64)> {
    let first = offset.div_ceil(DIRTY_PAGE);
    let last = match offset.checked_add(len) {
        Some(end) if len != 0 && end <= i64::MAX as u64 => {
            let end_byte = end - 1;
            let last = end_byte / DIRTY_PAGE;
            if end_byte % DIRTY_PAGE == DIRTY_PAGE - 1 || end == size {
                last
            } else {
                last.checked_sub(1)?
            }
        }
        _ => u64::MAX,
    };
    (first <= last).then_some((first, last))
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
