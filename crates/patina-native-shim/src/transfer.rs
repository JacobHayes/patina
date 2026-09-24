//! In-kernel copies between descriptors: `copy_file_range(2)`, `sendfile(2)`,
//! `splice(2)`, `tee(2)` and `vmsplice(2)`, one set of entries both doors
//! call. Linux only.
//!
//! None of them is a new effect: a copy is the positional read and write the
//! filesystem already models, a splice into or out of a pipe is the pipe
//! channel's own take and put, and a descriptor's cursor moves by exactly the
//! bytes that moved, through the same recorded seek a guest's `lseek` makes.
//! What this layer owns is each call's contract — which descriptors it takes
//! (in the kernel's order of refusals), where it reads and writes, and what
//! it reports back through an offset pointer.

use std::ffi::{c_int, c_void};
use std::slice;

use patina_dst_abi::{Fd, SeekWhence};

use crate::fdtable::{FdKind, Resolved};
use crate::iov::{GuestIovec, import};
use crate::{
    EBADF, EINVAL, EISDIR, EOVERFLOW, ESPIPE, O_APPEND, O_NONBLOCK, O_READ, O_WRITE, fail, fdget,
    set_errno, thread, with_context, write_resolved,
};

/// `SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT`.
const SPLICE_F_NONBLOCK: u32 = 0x02;
const SPLICE_F_ALL: u32 = 0x01 | SPLICE_F_NONBLOCK | 0x04 | 0x08;

/// `MAX_RW_COUNT`: the most one transfer moves.
const MAX_RW_COUNT: usize = i32::MAX as usize & !4095;

fn answered(result: Result<usize, c_int>) -> isize {
    match result {
        Ok(moved) => {
            set_errno(0);
            isize::try_from(moved).unwrap_or(isize::MAX)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// The pipe a descriptor is, for a splice: an anonymous pipe's or a FIFO's
/// end (a socketpair end is a socket).
fn pipe_of(resolved: &Resolved) -> Option<u64> {
    (resolved.kind == FdKind::Pipe)
        .then(|| thread::splice_pipe(resolved.handle))
        .flatten()
        .map(|_| resolved.handle)
}

fn cursor(handle: Fd) -> Result<i64, c_int> {
    with_context(|context| context.fs_seek(handle, 0, SeekWhence::Current))
        .map(|position| i64::try_from(position).unwrap_or(i64::MAX))
}

fn set_cursor(handle: Fd, position: i64) -> Result<(), c_int> {
    with_context(|context| context.fs_seek(handle, position, SeekWhence::Start)).map(|_| ())
}

/// Where a transfer reads or writes a file: at `*offset` (written back
/// afterwards) or at the description's cursor (moved afterwards).
struct Position {
    at: i64,
    pointer: *mut i64,
}

impl Position {
    /// # Safety
    /// A non-null `pointer` is the guest's readable `loff_t`.
    unsafe fn of(handle: Fd, pointer: *mut i64) -> Result<Self, c_int> {
        let at = if pointer.is_null() {
            cursor(handle)?
        } else {
            // SAFETY: per this function's contract.
            unsafe { pointer.read_unaligned() }
        };
        Ok(Self { at, pointer })
    }

    /// Record that `moved` bytes went through this position.
    fn advance(&self, handle: Fd, moved: usize) -> Result<(), c_int> {
        let next = self.at + moved as i64;
        if self.pointer.is_null() {
            set_cursor(handle, next)
        } else {
            // SAFETY: the guest's `loff_t`, read in `of`.
            unsafe { self.pointer.write_unaligned(next) };
            Ok(())
        }
    }
}

fn read_file_at(handle: Fd, offset: i64, len: usize) -> Result<Vec<u8>, c_int> {
    let offset = u64::try_from(offset).map_err(|_| EINVAL)?;
    with_context(|context| context.fs_read_at(handle, offset, len))
}

fn write_file_at(handle: Fd, offset: i64, bytes: &[u8]) -> Result<usize, c_int> {
    let offset = u64::try_from(offset).map_err(|_| EINVAL)?;
    with_context(|context| context.fs_write_at(handle, offset, bytes))
}

/// `copy_file_range(2)`: both descriptors first (`EBADF`), the offsets read,
/// then the flags (`EINVAL` unless 0), then `generic_copy_file_checks`: a
/// directory on either side `EISDIR`, anything but two regular files `EINVAL`,
/// a source not open for reading or a destination not open for writing or
/// open `O_APPEND` `EBADF`, a range past the source's end shortened to it,
/// and overlapping ranges within one file `EINVAL`.
///
/// # Safety
/// `off_in`/`off_out`, when non-null, are the guest's `loff_t`s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_copy_file_range(
    fd_in: c_int,
    off_in: *mut i64,
    fd_out: c_int,
    off_out: *mut i64,
    len: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered((|| {
        let input = fdget(fd_in)?;
        let output = fdget(fd_out)?;
        if flags != 0 {
            return Err(EINVAL);
        }
        if input.kind == FdKind::Dir || output.kind == FdKind::Dir {
            return Err(EISDIR);
        }
        if input.kind != FdKind::File || output.kind != FdKind::File {
            return Err(EINVAL);
        }
        if input.status & O_READ == 0
            || output.status & O_WRITE == 0
            || output.status & O_APPEND != 0
        {
            return Err(EBADF);
        }
        let (from, to) = (Fd(input.handle), Fd(output.handle));
        // SAFETY: per this function's contract.
        let (source, destination) =
            unsafe { (Position::of(from, off_in)?, Position::of(to, off_out)?) };
        let len = len.min(MAX_RW_COUNT);
        if source.at.checked_add(len as i64).is_none()
            || destination.at.checked_add(len as i64).is_none()
        {
            return Err(EOVERFLOW);
        }
        let source_meta = with_context(|context| context.fs_fd_metadata(from))?;
        let count = u64::try_from(source.at).ok().map_or(len, |at| {
            source_meta.len.saturating_sub(at).min(len as u64) as usize
        });
        let same = with_context(|context| context.fs_fd_metadata(to))?.ino == source_meta.ino;
        if same
            && destination.at + count as i64 > source.at
            && destination.at < source.at + count as i64
        {
            return Err(EINVAL);
        }
        if source.at < 0 || destination.at < 0 {
            return Err(EINVAL);
        }
        if count == 0 {
            return Ok(0);
        }
        let bytes = read_file_at(from, source.at, count)?;
        let moved = write_file_at(to, destination.at, &bytes)?;
        source.advance(from, moved)?;
        destination.advance(to, moved)?;
        Ok(moved)
    })())
}

/// `sendfile(2)`: the input first — open for reading (`EBADF`), addressable
/// when an offset is given (`ESPIPE`), a non-negative position (`EINVAL`) —
/// then the output, open for writing (`EBADF`). Into a pipe it is a splice of
/// the file into the pipe; anywhere else a read of the file and a write at the
/// output's cursor (an `O_APPEND` output is `EINVAL`). The input must be a
/// regular file (`EINVAL`: a pipe or a directory has nothing to splice from).
///
/// # Safety
/// `offset`, when non-null, is the guest's `loff_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut i64,
    count: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered((|| {
        let input = fdget(in_fd)?;
        if input.status & O_READ == 0 {
            return Err(EBADF);
        }
        let addressable = matches!(input.kind, FdKind::File | FdKind::Dir);
        if !offset.is_null() && !addressable {
            return Err(ESPIPE);
        }
        let position = if input.kind == FdKind::File {
            // SAFETY: per this function's contract.
            Some(unsafe { Position::of(Fd(input.handle), offset)? })
        } else if offset.is_null() {
            None
        } else {
            // SAFETY: per this function's contract.
            Some(unsafe { Position::of(Fd(input.handle), offset)? })
        };
        if position.as_ref().is_some_and(|position| position.at < 0) {
            return Err(EINVAL);
        }
        let count = count.min(MAX_RW_COUNT);
        let output = fdget(out_fd)?;
        if output.status & O_WRITE == 0 {
            return Err(EBADF);
        }
        let into_pipe = pipe_of(&output);
        if into_pipe.is_none() && output.status & O_APPEND != 0 {
            return Err(EINVAL);
        }
        let (Some(position), FdKind::File) = (position, input.kind) else {
            return Err(EINVAL);
        };
        let from = Fd(input.handle);
        let moved = match into_pipe {
            Some(pipe) => {
                let nonblocking = (input.status | output.status) & O_NONBLOCK != 0;
                file_to_pipe(from, position.at, pipe, count, nonblocking)?
            }
            None => {
                if count == 0 {
                    return Ok(0);
                }
                let bytes = read_file_at(from, position.at, count)?;
                if bytes.is_empty() {
                    return Ok(0);
                }
                let nonblocking = output.status & O_NONBLOCK != 0;
                // SAFETY: `bytes` is readable for its length.
                let wrote = unsafe {
                    write_resolved(
                        output,
                        bytes.as_ptr().cast::<c_void>(),
                        bytes.len(),
                        nonblocking,
                    )
                };
                if wrote < 0 {
                    return Err(crate::patina_errno());
                }
                wrote as usize
            }
        };
        position.advance(from, moved)?;
        Ok(moved)
    })())
}

/// Splice a file into a pipe: wait for room, then read at most that much from
/// the file at `offset` and put it in the pipe.
fn file_to_pipe(
    from: Fd,
    offset: i64,
    pipe: u64,
    len: usize,
    nonblocking: bool,
) -> Result<usize, c_int> {
    if len == 0 {
        return Ok(0);
    }
    let room = thread::pipe_await_space(pipe, nonblocking)?;
    let bytes = read_file_at(from, offset, len.min(room))?;
    Ok(thread::pipe_put(pipe, &bytes))
}

/// Splice a pipe into anything that takes a write: wait for bytes, take at
/// most `len`, write them, and put back at the pipe's head what the write did
/// not accept.
fn pipe_to_sink(
    pipe: u64,
    len: usize,
    nonblocking: bool,
    sink: impl FnOnce(&[u8]) -> Result<usize, c_int>,
) -> Result<usize, c_int> {
    let available = thread::pipe_await_data(pipe, nonblocking)?;
    if available == 0 {
        return Ok(0);
    }
    let bytes = thread::pipe_take(pipe, len.min(available));
    match sink(&bytes) {
        Ok(wrote) => {
            thread::pipe_untake(pipe, &bytes[wrote.min(bytes.len())..]);
            Ok(wrote)
        }
        Err(errno) => {
            thread::pipe_untake(pipe, &bytes);
            Err(errno)
        }
    }
}

/// `splice(2)`, in `do_splice`'s order: a zero length is 0, an unknown flag
/// `EINVAL`, both descriptors (`EBADF`, as is a side not open for its
/// direction), an offset for a pipe side `ESPIPE`; then pipe to pipe (one pipe
/// on both ends is `EINVAL`), pipe to file (an `O_APPEND` file, or an offset
/// for a side without one, is `EINVAL`), or file to pipe; neither side a pipe
/// is `EINVAL`. `SPLICE_F_NONBLOCK`, or `O_NONBLOCK` on a pipe side, makes a
/// wait `EAGAIN`.
///
/// # Safety
/// `off_in`/`off_out`, when non-null, are the guest's `loff_t`s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_splice(
    fd_in: c_int,
    off_in: *mut i64,
    fd_out: c_int,
    off_out: *mut i64,
    len: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered((|| {
        if len == 0 {
            return Ok(0);
        }
        if flags & !SPLICE_F_ALL != 0 {
            return Err(EINVAL);
        }
        let input = fdget(fd_in)?;
        let output = fdget(fd_out)?;
        if input.status & O_READ == 0 || output.status & O_WRITE == 0 {
            return Err(EBADF);
        }
        let (from_pipe, to_pipe) = (pipe_of(&input), pipe_of(&output));
        if (from_pipe.is_some() && !off_in.is_null()) || (to_pipe.is_some() && !off_out.is_null()) {
            return Err(ESPIPE);
        }
        let flagged = flags & SPLICE_F_NONBLOCK != 0;
        match (from_pipe, to_pipe) {
            (Some(from), Some(to)) => {
                if thread::splice_pipe(from) == thread::splice_pipe(to) {
                    return Err(EINVAL);
                }
                let nonblocking = flagged || (input.status | output.status) & O_NONBLOCK != 0;
                thread::pipe_to_pipe(from, to, len, nonblocking, true)
            }
            (Some(from), None) => {
                let nonblocking = flagged || input.status & O_NONBLOCK != 0;
                match output.kind {
                    FdKind::File => {
                        if output.status & O_APPEND != 0 {
                            return Err(EINVAL);
                        }
                        let to = Fd(output.handle);
                        // SAFETY: per this function's contract.
                        let position = unsafe { Position::of(to, off_out)? };
                        if position.at < 0 {
                            return Err(EINVAL);
                        }
                        let moved = pipe_to_sink(from, len, nonblocking, |bytes| {
                            write_file_at(to, position.at, bytes)
                        })?;
                        position.advance(to, moved)?;
                        Ok(moved)
                    }
                    FdKind::Socket | FdKind::Stdout | FdKind::Stderr if off_out.is_null() => {
                        let sink_nonblocking = output.status & O_NONBLOCK != 0;
                        pipe_to_sink(from, len, nonblocking, |bytes| {
                            // SAFETY: `bytes` is readable for its length.
                            let wrote = unsafe {
                                write_resolved(
                                    output,
                                    bytes.as_ptr().cast::<c_void>(),
                                    bytes.len(),
                                    sink_nonblocking,
                                )
                            };
                            if wrote < 0 {
                                Err(crate::patina_errno())
                            } else {
                                Ok(wrote as usize)
                            }
                        })
                    }
                    _ => Err(EINVAL),
                }
            }
            (None, Some(to)) => {
                if input.kind != FdKind::File {
                    return Err(EINVAL);
                }
                let from = Fd(input.handle);
                // SAFETY: per this function's contract.
                let position = unsafe { Position::of(from, off_in)? };
                if position.at < 0 {
                    return Err(EINVAL);
                }
                let nonblocking = flagged || output.status & O_NONBLOCK != 0;
                let moved = file_to_pipe(from, position.at, to, len, nonblocking)?;
                position.advance(from, moved)?;
                Ok(moved)
            }
            (None, None) => Err(EINVAL),
        }
    })())
}

/// `tee(2)`: an unknown flag `EINVAL` first, then a zero length is 0, both
/// descriptors (`EBADF`), and then two distinct pipes (`EINVAL` otherwise):
/// up to `len` of the input's bytes copied into the output without consuming
/// them.
#[unsafe(no_mangle)]
pub extern "C" fn patina_tee(fd_in: c_int, fd_out: c_int, len: usize, flags: u32) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered((|| {
        if flags & !SPLICE_F_ALL != 0 {
            return Err(EINVAL);
        }
        if len == 0 {
            return Ok(0);
        }
        let input = fdget(fd_in)?;
        let output = fdget(fd_out)?;
        if input.status & O_READ == 0 || output.status & O_WRITE == 0 {
            return Err(EBADF);
        }
        match (pipe_of(&input), pipe_of(&output)) {
            (Some(from), Some(to)) if thread::splice_pipe(from) != thread::splice_pipe(to) => {
                let nonblocking = flags & SPLICE_F_NONBLOCK != 0
                    || (input.status | output.status) & O_NONBLOCK != 0;
                thread::pipe_to_pipe(from, to, len, nonblocking, false)
            }
            _ => Err(EINVAL),
        }
    })())
}

/// `vmsplice(2)`: an unknown flag `EINVAL`; the descriptor (`EBADF`) and its
/// direction — open for writing, the segments are gathered INTO the pipe;
/// open only for reading, the pipe's bytes are scattered OUT; then the vector
/// (`lib/iov_iter.c`'s refusals). An empty vector is 0; a descriptor that is
/// not a pipe is `EBADF`. It waits once — for room or for bytes, unless
/// `SPLICE_F_NONBLOCK` — and then moves what fits or what is there.
///
/// # Safety
/// `vector` must be a readable guest vector of `count` segments, each segment
/// readable (into a pipe) or writable (out of one) for its length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_vmsplice(
    raw_fd: c_int,
    vector: *const GuestIovec,
    count: i64,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    answered((|| {
        if flags & !SPLICE_F_ALL != 0 {
            return Err(EINVAL);
        }
        let resolved = fdget(raw_fd)?;
        let into_pipe = if resolved.status & O_WRITE != 0 {
            true
        } else if resolved.status & O_READ != 0 {
            false
        } else {
            return Err(EBADF);
        };
        // SAFETY: forwarded from this function's own contract.
        let segments = unsafe { import(vector, count)? };
        let total: usize = segments.iter().map(|segment| segment.len).sum();
        if total == 0 {
            return Ok(0);
        }
        let pipe = pipe_of(&resolved).ok_or(EBADF)?;
        // Only the call's own flag: `vmsplice` never reads the pipe's
        // `O_NONBLOCK`, unlike `splice` and `tee`.
        let nonblocking = flags & SPLICE_F_NONBLOCK != 0;
        if into_pipe {
            let room = thread::pipe_await_space(pipe, nonblocking)?;
            let mut gathered = Vec::with_capacity(total.min(room));
            for segment in &segments {
                let take = segment.len.min(room - gathered.len());
                // SAFETY: the segment is readable for its length.
                gathered.extend_from_slice(unsafe {
                    slice::from_raw_parts(segment.base.cast::<u8>(), take)
                });
                if gathered.len() == room {
                    break;
                }
            }
            Ok(thread::pipe_put(pipe, &gathered))
        } else {
            let available = thread::pipe_await_data(pipe, nonblocking)?;
            let bytes = thread::pipe_take(pipe, total.min(available));
            let mut scattered = 0;
            for segment in &segments {
                let put = segment.len.min(bytes.len() - scattered);
                // SAFETY: the segment is writable for its length.
                unsafe {
                    slice::from_raw_parts_mut(segment.base.cast::<u8>(), put)
                        .copy_from_slice(&bytes[scattered..scattered + put]);
                }
                scattered += put;
                if scattered == bytes.len() {
                    break;
                }
            }
            Ok(scattered)
        }
    })())
}
