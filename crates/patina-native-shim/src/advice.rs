//! Page-cache advice, accounting and writeback: `readahead(2)`,
//! `posix_fadvise(2)` (`fadvise64`), `cachestat(2)`, `sync_file_range(2)`,
//! `sync(2)` and `syncfs(2)`, one set of entries both doors call. Linux only.
//!
//! The deterministic filesystem has no page cache, so advice has nothing to
//! warm, drop or start writing back: each call answers exactly the refusals the
//! kernel judges (in its order) and is otherwise a no-op. What `cachestat`
//! counts follows from the same fact: the filesystem holds every file whole in
//! memory, so every page of a regular file up to its end is cached, none is
//! dirty or under writeback (there is no writeback to wait for), and none was
//! ever evicted; anything else has no pages. Durability is the one
//! effect with a model behind it — `sync` and `syncfs` make every change on the
//! volume durable, the checkpoint a crash model rolls back to. `sync_file_range`
//! promises no durability at all (it writes out no metadata and waits on no
//! journal), so it moves nothing into the crash model's durable image either.

use std::ffi::c_int;

use patina_dst_abi::Fd;

use crate::fdtable::{FdKind, Resolved};
use crate::{EBADF, EINVAL, ESPIPE, O_READ, fail, fdget, set_errno, thread, uaccess};

/// `POSIX_FADV_NORMAL` .. `POSIX_FADV_NOREUSE` (0..=5 on x86_64 and arm64).
const POSIX_FADV_NOREUSE: c_int = 5;

/// `sync_file_range(2)`'s defined flags (`SYNC_FILE_RANGE_WAIT_BEFORE|WRITE|
/// WAIT_AFTER`).
const SYNC_FILE_RANGE_VALID: u32 = 0x1 | 0x2 | 0x4;

fn answered(result: Result<(), c_int>) -> c_int {
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Whether the node behind a descriptor is a FIFO (`S_ISFIFO`): an anonymous
/// pipe or a FIFO's endpoint.
fn is_fifo(resolved: &Resolved) -> bool {
    resolved.kind == FdKind::Pipe
}

/// Whether the node is a regular file, a directory or a symlink — the kinds
/// with a mapping `sync_file_range` writes back (the rest are `ESPIPE`).
fn has_mapping(resolved: &Resolved) -> bool {
    match resolved.kind {
        // An mqueue inode is a regular file.
        FdKind::File | FdKind::Dir | FdKind::MessageQueue => true,
        FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket
        | FdKind::Pipe
        | FdKind::EventFd
        | FdKind::TimerFd
        | FdKind::Inotify
        | FdKind::SignalFd
        | FdKind::Epoll
        | FdKind::Pidfd => false,
    }
}

/// `posix_fadvise(2)`: every `POSIX_FADV_*` advice is accepted and changes
/// nothing. The refusals are `generic_fadvise`'s, in its order: an empty slot
/// or an `O_PATH` descriptor `EBADF`, a FIFO `ESPIPE` (before the advice is
/// looked at), a negative length or an unknown advice `EINVAL`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fadvise(raw_fd: c_int, _offset: i64, length: i64, advice: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered(fdget(raw_fd).and_then(|resolved| {
        if is_fifo(&resolved) {
            return Err(ESPIPE);
        }
        if length < 0 || !(0..=POSIX_FADV_NOREUSE).contains(&advice) {
            return Err(EINVAL);
        }
        Ok(())
    }))
}

/// `readahead(2)`: `fadvise(WILLNEED)` on a descriptor open for reading
/// (`EBADF` otherwise, `O_PATH` included) whose node is a regular file
/// (`EINVAL` otherwise). Past the end of the file it is the same no-op.
#[unsafe(no_mangle)]
pub extern "C" fn patina_readahead(raw_fd: c_int, _offset: i64, count: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered(fdget(raw_fd).and_then(|resolved| {
        if resolved.status & O_READ == 0 {
            return Err(EBADF);
        }
        if resolved.kind != FdKind::File || i64::try_from(count).is_err() {
            return Err(EINVAL);
        }
        Ok(())
    }))
}

/// `struct cachestat_range`: a byte range, a zero length meaning "to the
/// end".
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CachestatRange {
    off: u64,
    len: u64,
}

/// `struct cachestat`: page counts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Cachestat {
    nr_cache: u64,
    nr_dirty: u64,
    nr_writeback: u64,
    nr_evicted: u64,
    nr_recently_evicted: u64,
}

/// The pages of a `size`-byte file within `range` (`filemap_cachestat`
/// over the pages `range` spans, `first_index` to `last_index`).
fn cached_pages(size: u64, range: CachestatRange) -> u64 {
    let page = crate::mem::PAGE as u64;
    let first = range.off / page;
    let last = match range.len {
        0 => u64::MAX,
        len => range.off.wrapping_add(len).wrapping_sub(1) / page,
    };
    let pages = size.div_ceil(page);
    if first >= pages || last < first {
        return 0;
    }
    last.min(pages - 1) - first + 1
}

/// `cachestat(fd, range, out, flags)` (mm/filemap.c): an empty slot or an
/// `O_PATH` descriptor is `EBADF` (`fdget`), then the range is copied in
/// (`EFAULT`), then nonzero flags are `EINVAL`; the counts are copied out
/// last (`EFAULT`). What they count is the module's answer.
pub(crate) fn cachestat(raw_fd: c_int, range: usize, out: usize, flags: u32) -> i64 {
    let answer = (|| {
        let resolved = fdget(raw_fd)?;
        let range = uaccess::read::<CachestatRange>(range)?;
        if flags != 0 {
            return Err(EINVAL);
        }
        let mut stat = Cachestat::default();
        if resolved.kind == FdKind::File {
            let size = crate::with_context_raw(|context| {
                context.fs_fd_metadata_unrecorded(Fd(resolved.handle))
            })?
            .len;
            stat.nr_cache = cached_pages(size, range);
        }
        uaccess::write(out, &stat)
    })();
    match answer {
        Ok(()) => 0,
        Err(errno) => crate::neg_errno(errno),
    }
}

/// `sync_file_range(2)`: no durability to promise, so a no-op once the kernel's
/// refusals pass — the descriptor first (`EBADF`), then the flags and the range
/// (`EINVAL` for an unknown flag, a negative offset or end, or a range that
/// wraps), then the node's kind (`ESPIPE` for anything without a mapping).
#[unsafe(no_mangle)]
pub extern "C" fn patina_sync_file_range(
    raw_fd: c_int,
    offset: i64,
    length: i64,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered(fdget(raw_fd).and_then(|resolved| {
        let end = offset.wrapping_add(length);
        if flags & !SYNC_FILE_RANGE_VALID != 0 || offset < 0 || end < 0 || end < offset {
            return Err(EINVAL);
        }
        if !has_mapping(&resolved) {
            return Err(ESPIPE);
        }
        Ok(())
    }))
}

/// `sync(2)`: every change on the volume becomes durable. Never fails.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sync() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered(crate::fs_sync_volume())
}

/// `syncfs(2)`: the filesystem a descriptor is on made durable. An empty slot
/// or an `O_PATH` descriptor is `EBADF` (`fdget`); a descriptor on the volume
/// syncs it; one on a pseudo-filesystem (a pipe, a socket, an eventfd) has
/// nothing to write back.
#[unsafe(no_mangle)]
pub extern "C" fn patina_syncfs(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered(fdget(raw_fd).and_then(|resolved| {
        let on_volume = match resolved.kind {
            FdKind::File | FdKind::Dir => true,
            FdKind::Pipe => thread::pipe_filesystem(raw_fd) == Some(crate::PATINA_FS_VOLUME),
            FdKind::OPath
            | FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::Urandom
            | FdKind::Socket
            | FdKind::EventFd
            | FdKind::TimerFd
            | FdKind::Inotify
            | FdKind::SignalFd
            | FdKind::Epoll
            | FdKind::MessageQueue
            | FdKind::Pidfd => false,
        };
        if on_volume {
            crate::fs_sync_volume()
        } else {
            Ok(())
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{CachestatRange, cached_pages};

    const PAGE: u64 = crate::mem::PAGE as u64;

    #[test]
    fn a_range_counts_the_file_pages_it_spans() {
        let whole = CachestatRange { off: 0, len: 0 };
        assert_eq!(cached_pages(2 * PAGE, whole), 2);
        assert_eq!(cached_pages(2 * PAGE + 1, whole), 3);
        assert_eq!(cached_pages(0, whole), 0);
        // A byte range counts every page it touches.
        let straddle = CachestatRange {
            off: PAGE - 1,
            len: 2,
        };
        assert_eq!(cached_pages(4 * PAGE, straddle), 2);
        // Past the end of the file, nothing; a range reaching past it stops
        // at the last page.
        let past = CachestatRange {
            off: 1 << 20,
            len: PAGE,
        };
        assert_eq!(cached_pages(2 * PAGE, past), 0);
        let tail = CachestatRange {
            off: PAGE,
            len: 10 * PAGE,
        };
        assert_eq!(cached_pages(2 * PAGE, tail), 1);
    }
}
