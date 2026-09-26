//! Vectored I/O: `readv`/`writev`, `preadv`/`pwritev` and the `*v2` rows'
//! per-call `RWF_*` flags, one set of entries both doors call.
//!
//! The vector is imported the way `lib/iov_iter.c` imports one — a count past
//! `UIO_MAXIOV` (or negative) is `EINVAL`, a NULL vector with a count is
//! `EFAULT`, a segment whose length is negative as an `ssize_t` is `EINVAL`, a
//! count of zero touches nothing — after the descriptor and its access mode
//! have been judged, as `vfs_readv`/`vfs_writev` judge them. The transfer is
//! the single-buffer one (`read_resolved`/`write_resolved`, the positional
//! file reads and writes) applied segment by segment: a short segment ends the
//! call, and once bytes have moved a later segment never waits, so a stream
//! answers what it has exactly as one kernel read of the whole vector does.

use std::ffi::{c_int, c_void};
use std::slice;

use patina_dst_abi::{Fd, SeekWhence};

use crate::fdtable::{FdKind, Resolved};
use crate::{
    EBADF, EFAULT, EINVAL, EOPNOTSUPP, O_NONBLOCK, O_READ, O_WRITE, fail, fdget, fs_pread,
    fs_pwrite, positional_target, positional_write_offset, read_resolved, set_errno, transferred,
    with_context, write_resolved,
};

/// Linux and Darwin `UIO_MAXIOV`: the most segments one vector may carry.
pub(crate) const UIO_MAXIOV: usize = 1024;

/// `struct iovec`, identical on every supported target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GuestIovec {
    pub base: *mut c_void,
    pub len: usize,
}

/// The `RWF_*` bits the virtual kernel (Linux 6.8) accepts per call
/// (`RWF_SUPPORTED`); any other bit is `EOPNOTSUPP` (`kiocb_set_rw_flags`).
pub(crate) const RWF_HIPRI: i32 = 0x01;
pub(crate) const RWF_DSYNC: i32 = 0x02;
pub(crate) const RWF_SYNC: i32 = 0x04;
pub(crate) const RWF_NOWAIT: i32 = 0x08;
pub(crate) const RWF_APPEND: i32 = 0x10;
const RWF_SUPPORTED: i32 = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;

/// Import a guest vector: the segments, or the errno `lib/iov_iter.c` answers.
///
/// # Safety
/// A non-null `vector` must be readable for `count` segments.
pub(crate) unsafe fn import(
    vector: *const GuestIovec,
    count: i64,
) -> Result<Vec<GuestIovec>, c_int> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(count).map_err(|_| EINVAL)?;
    if count > UIO_MAXIOV {
        return Err(EINVAL);
    }
    if vector.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: non-null and readable for `count` segments per the contract.
    let segments = unsafe { slice::from_raw_parts(vector, count) }.to_vec();
    if segments
        .iter()
        .any(|segment| isize::try_from(segment.len).is_err())
    {
        return Err(EINVAL);
    }
    Ok(segments)
}

fn total(segments: &[GuestIovec]) -> usize {
    segments
        .iter()
        .fold(0usize, |total, segment| total.saturating_add(segment.len))
}

/// The flag word's refusal, judged once the call has bytes to move. A
/// directory has no `read_iter`, so the kernel's loop path refuses every flag
/// but `RWF_HIPRI` there (`do_loop_readv_writev`).
fn rwf_refusal(resolved: &Resolved, flags: i32) -> Option<c_int> {
    if flags & !RWF_SUPPORTED != 0 {
        return Some(EOPNOTSUPP);
    }
    (resolved.kind == FdKind::Dir && flags & !RWF_HIPRI != 0).then_some(EOPNOTSUPP)
}

/// Fold a transfer that stopped early: the bytes already moved are the answer,
/// the error is only when nothing moved.
fn finish(total: usize, errno: Option<c_int>) -> isize {
    match errno {
        Some(errno) if total == 0 => fail(errno) as isize,
        _ => {
            set_errno(0);
            isize::try_from(total).unwrap_or(isize::MAX)
        }
    }
}

/// The access-mode half of `vfs_readv`/`vfs_writev`, then the vector itself.
///
/// # Safety
/// As [`import`].
unsafe fn open_vector(
    resolved: &Resolved,
    mode: u32,
    vector: *const GuestIovec,
    count: i64,
) -> Result<Vec<GuestIovec>, c_int> {
    if resolved.status & mode == 0 {
        return Err(EBADF);
    }
    // SAFETY: forwarded from the caller's contract.
    unsafe { import(vector, count) }
}

/// Scatter reads at the description's cursor (`readv`, and `preadv2` at
/// position -1).
///
/// # Safety
/// `vector` must be a readable guest vector of `count` segments, each
/// writable for its length.
unsafe fn cursor_readv(resolved: Resolved, segments: &[GuestIovec], nonblocking: bool) -> isize {
    let mut moved = 0usize;
    for segment in segments.iter().filter(|segment| segment.len != 0) {
        // SAFETY: the segment is guest memory writable for its length.
        let got = unsafe {
            read_resolved(
                resolved,
                segment.base,
                segment.len,
                nonblocking || moved != 0,
            )
        };
        if got < 0 {
            return finish(moved, Some(crate::patina_errno()));
        }
        moved += got as usize;
        if (got as usize) < segment.len {
            break;
        }
    }
    finish(moved, None)
}

/// Gather writes at the description's cursor (`writev`, and `pwritev2` at
/// position -1). `RWF_APPEND` moves the cursor to the end first, as
/// `IOCB_APPEND` does, and `RWF_DSYNC`/`RWF_SYNC` make the written data
/// durable before the call returns (`generic_write_sync`).
///
/// # Safety
/// As [`cursor_readv`], each segment readable for its length.
unsafe fn cursor_writev(
    resolved: Resolved,
    segments: &[GuestIovec],
    nonblocking: bool,
    flags: i32,
) -> isize {
    let file = resolved.kind == FdKind::File;
    if file && flags & RWF_APPEND != 0 {
        if let Err(errno) =
            with_context(|context| context.fs_seek(Fd(resolved.handle), 0, SeekWhence::End))
        {
            return fail(errno) as isize;
        }
    }
    let mut moved = 0usize;
    let mut stopped = None;
    for segment in segments.iter().filter(|segment| segment.len != 0) {
        // SAFETY: the segment is guest memory readable for its length.
        let put = unsafe { write_resolved(resolved, segment.base, segment.len, nonblocking) };
        if put < 0 {
            stopped = Some(crate::patina_errno());
            break;
        }
        moved += put as usize;
        if (put as usize) < segment.len {
            break;
        }
    }
    sync_written(resolved, moved, flags, stopped)
}

/// `RWF_DSYNC`/`RWF_SYNC` after a write that moved bytes: the durability the
/// flags promise, through the same `fsync` the descriptor would take.
fn sync_written(resolved: Resolved, moved: usize, flags: i32, stopped: Option<c_int>) -> isize {
    if moved != 0 && resolved.kind == FdKind::File && flags & (RWF_DSYNC | RWF_SYNC) != 0 {
        if let Err(errno) = crate::fs_sync_handle(Fd(resolved.handle)) {
            return fail(errno) as isize;
        }
    }
    finish(moved, stopped)
}

/// `readv(2)`, and `preadv2` at position -1 with its `RWF_*` flags.
///
/// # Safety
/// `vector` must be a readable guest vector of `count` segments, each segment
/// writable for its length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_readv(
    raw_fd: c_int,
    vector: *const GuestIovec,
    count: i64,
    flags: i32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: forwarded from this function's own contract.
    let segments = match unsafe { open_vector(&resolved, O_READ, vector, count) } {
        Ok(segments) => segments,
        Err(errno) => return fail(errno) as isize,
    };
    if total(&segments) == 0 {
        set_errno(0);
        return 0;
    }
    if let Some(errno) = rwf_refusal(&resolved, flags) {
        return fail(errno) as isize;
    }
    let nonblocking = resolved.status & O_NONBLOCK != 0 || flags & RWF_NOWAIT != 0;
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { cursor_readv(resolved, &segments, nonblocking) };
    transferred(&resolved, moved, false)
}

/// `writev(2)`, and `pwritev2` at position -1 with its `RWF_*` flags.
///
/// # Safety
/// `vector` must be a readable guest vector of `count` segments, each segment
/// readable for its length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_writev(
    raw_fd: c_int,
    vector: *const GuestIovec,
    count: i64,
    flags: i32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: forwarded from this function's own contract.
    let segments = match unsafe { open_vector(&resolved, O_WRITE, vector, count) } {
        Ok(segments) => segments,
        Err(errno) => return fail(errno) as isize,
    };
    if total(&segments) == 0 {
        set_errno(0);
        return 0;
    }
    if let Some(errno) = rwf_refusal(&resolved, flags) {
        return fail(errno) as isize;
    }
    let nonblocking = resolved.status & O_NONBLOCK != 0 || flags & RWF_NOWAIT != 0;
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { cursor_writev(resolved, &segments, nonblocking, flags) };
    transferred(&resolved, moved, true)
}

/// `preadv(2)`/`preadv2` at a position: scatter reads at `offset` that leave
/// the cursor alone. A negative position is `EINVAL` before the descriptor, a
/// description without offset addressing `ESPIPE` (`do_preadv`).
///
/// # Safety
/// As [`patina_readv`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_preadv(
    raw_fd: c_int,
    vector: *const GuestIovec,
    count: i64,
    offset: i64,
    flags: i32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: forwarded from this function's own contract.
    let segments = match unsafe { open_vector(&resolved, O_READ, vector, count) } {
        Ok(segments) => segments,
        Err(errno) => return fail(errno) as isize,
    };
    if total(&segments) == 0 {
        set_errno(0);
        return 0;
    }
    if let Some(errno) = rwf_refusal(&resolved, flags) {
        return fail(errno) as isize;
    }
    let mut moved = 0usize;
    for segment in segments.iter().filter(|segment| segment.len != 0) {
        // SAFETY: the segment is guest memory writable for its length.
        let got = unsafe { fs_pread(resolved, segment.base, segment.len, offset + moved as u64) };
        if got < 0 {
            return transferred(&resolved, finish(moved, Some(crate::patina_errno())), false);
        }
        moved += got as usize;
        if (got as usize) < segment.len {
            break;
        }
    }
    transferred(&resolved, finish(moved, None), false)
}

/// `pwritev(2)`/`pwritev2` at a position: gather writes that leave the cursor
/// alone, landing at the end of the file instead under `O_APPEND` (Linux) or
/// `RWF_APPEND` — one end, taken once, so the segments stay contiguous.
///
/// # Safety
/// As [`patina_writev`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_pwritev(
    raw_fd: c_int,
    vector: *const GuestIovec,
    count: i64,
    offset: i64,
    flags: i32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: forwarded from this function's own contract.
    let segments = match unsafe { open_vector(&resolved, O_WRITE, vector, count) } {
        Ok(segments) => segments,
        Err(errno) => return fail(errno) as isize,
    };
    if total(&segments) == 0 {
        set_errno(0);
        return 0;
    }
    if let Some(errno) = rwf_refusal(&resolved, flags) {
        return fail(errno) as isize;
    }
    let base = match positional_write_offset(resolved, offset, flags & RWF_APPEND != 0) {
        Ok(base) => base,
        Err(errno) => return fail(errno) as isize,
    };
    let mut moved = 0usize;
    let mut stopped = None;
    for segment in segments.iter().filter(|segment| segment.len != 0) {
        // SAFETY: the segment is guest memory readable for its length.
        let at = i64::try_from(base + moved as u64).unwrap_or(i64::MAX);
        let put = unsafe { fs_pwrite(Fd(resolved.handle), segment.base, segment.len, at) };
        if put < 0 {
            stopped = Some(crate::patina_errno());
            break;
        }
        moved += put as usize;
        if (put as usize) < segment.len {
            break;
        }
    }
    transferred(
        &resolved,
        sync_written(resolved, moved, flags, stopped),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segments(lens: &[usize]) -> Vec<GuestIovec> {
        lens.iter()
            .map(|&len| GuestIovec {
                base: std::ptr::null_mut(),
                len,
            })
            .collect()
    }

    fn imported(vector: &[GuestIovec], count: i64) -> Result<usize, c_int> {
        // SAFETY: `vector` holds at least `count` segments whenever it is used.
        unsafe { import(vector.as_ptr(), count) }.map(|segments| segments.len())
    }

    #[test]
    fn a_count_of_zero_touches_nothing() {
        // SAFETY: a zero count never reads the vector.
        assert_eq!(unsafe { import(std::ptr::null(), 0) }.unwrap().len(), 0);
    }

    #[test]
    fn up_to_uio_maxiov_segments_import_and_one_more_is_einval() {
        let vector = segments(&[0; UIO_MAXIOV + 1]);
        assert_eq!(imported(&vector, UIO_MAXIOV as i64), Ok(UIO_MAXIOV));
        assert_eq!(imported(&vector, UIO_MAXIOV as i64 + 1), Err(EINVAL));
    }

    #[test]
    fn a_negative_count_is_einval() {
        assert_eq!(imported(&segments(&[1]), -1), Err(EINVAL));
    }

    #[test]
    fn a_null_vector_with_a_count_is_efault() {
        // SAFETY: a null vector is refused before it is read.
        assert_eq!(unsafe { import(std::ptr::null(), 1) }.err(), Some(EFAULT));
    }

    #[test]
    fn a_segment_length_negative_as_ssize_t_is_einval() {
        assert_eq!(imported(&segments(&[1, usize::MAX]), 2), Err(EINVAL));
        assert_eq!(imported(&segments(&[1, isize::MAX as usize]), 2), Ok(2));
    }

    #[test]
    fn unknown_rwf_bits_and_flags_on_a_directory_are_eopnotsupp() {
        let file = Resolved {
            desc: 0,
            kind: FdKind::File,
            handle: 0,
            status: O_READ,
            cloexec: false,
        };
        let dir = Resolved {
            kind: FdKind::Dir,
            ..file
        };
        assert_eq!(rwf_refusal(&file, RWF_NOWAIT | RWF_DSYNC), None);
        assert_eq!(rwf_refusal(&file, 1 << 30), Some(EOPNOTSUPP));
        assert_eq!(rwf_refusal(&dir, RWF_HIPRI), None);
        assert_eq!(rwf_refusal(&dir, RWF_NOWAIT), Some(EOPNOTSUPP));
    }
}
