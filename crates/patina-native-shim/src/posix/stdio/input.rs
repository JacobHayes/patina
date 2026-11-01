//! Reading a stream: libio's get side over the modeled `read`.
//!
//! The rules are glibc's (`libio/fileops.c`, `genops.c`, `iofgets.c`,
//! `iogetdelim.c`, glibc 2.39), with the Darwin port's differences named
//! where they fall. A refill is one modeled read of the whole buffer, so a
//! short read hands back what it got and the next call reads again; a read
//! error sets the stream's error indicator and leaves the errno, end of file
//! its end-of-file indicator, which stays set (no read is tried) until it is
//! cleared.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// One modeled read, as the libc `read` door makes it.
unsafe fn read_fd(fd: c_int, destination: *mut u8, length: usize) -> isize {
    super::super::cancel(c"read");
    // SAFETY: the caller keeps `destination` writable for `length` bytes.
    let result = unsafe { crate::fd::patina_read(fd, destination.cast(), length) };
    crate::abi::libc_result(crate::abi::from_model(result), result)
}

/// The bytes still unread: the buffered input plus any pushback.
pub(super) unsafe fn unread(stream: StreamId) -> usize {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream, a table entry.
    unsafe {
        if (*s).putting {
            0
        } else {
            (*s).get_end - (*s).get_pos + (*s).pushback.len()
        }
    }
}

/// Forget the buffered input and pushback.
pub(super) unsafe fn drop_input(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream, a table entry.
    unsafe {
        (*s).get_pos = 0;
        (*s).get_end = 0;
        (*s).pushback.clear();
    }
}

/// Leave get mode for put mode. The input read ahead goes back to the
/// descriptor first, so the write lands where the reader stopped (glibc
/// seeks back by what it buffered when a write follows a read); a stream
/// that cannot seek fails the write.
pub(super) unsafe fn leave_get_mode(stream: StreamId) -> bool {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream, a table entry.
    unsafe {
        let back = unread(stream);
        if back > 0 && !(*s).access.append {
            let moved = crate::abi::libc_result(crate::fd::seek((*s).fd, -(back as i64), 1), -1);
            if moved < 0 {
                return false;
            }
        }
        drop_input(stream);
        true
    }
}

/// Enter get mode: pending output is written first (glibc's
/// `_IO_switch_to_get_mode`); a failed flush fails the read.
unsafe fn enter_get_mode(stream: StreamId) -> bool {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream, a table entry.
    unsafe {
        if (*s).putting {
            if sync(stream) != 0 {
                return false;
            }
            (*s).putting = false;
            (*s).area = false;
            (*s).used = 0;
            drop_input(stream);
        }
        true
    }
}

/// A read from a stream opened without read access: the error indicator
/// and `EBADF`.
unsafe fn refuse(stream: StreamId) -> c_int {
    // SAFETY: the caller serializes the stream.
    unsafe { set_error(stream, true) };
    super::super::errno(libc::EBADF);
    EOF
}

/// The bytes readable without a refill: the newest pushed-back byte, or
/// the buffered input.
unsafe fn available(stream: StreamId) -> (*const u8, usize) {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream; the get area lies within the
    // active buffer.
    unsafe {
        if let Some(byte) = (*s).pushback.last() {
            (byte, 1)
        } else if (*s).putting || (*s).get_pos >= (*s).get_end {
            (ptr::null(), 0)
        } else {
            (
                buffer_ptr(stream).add((*s).get_pos).cast_const(),
                (*s).get_end - (*s).get_pos,
            )
        }
    }
}
/// Take `count` of the bytes [`available`] answered.
unsafe fn consume(stream: StreamId, count: usize) {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream.
    unsafe {
        if (*s).pushback.pop().is_none() {
            (*s).get_pos += count;
        }
    }
}

/// Before a line-buffered or unbuffered stream refills, flush the output a
/// reader may be waiting on: glibc flushes `stdout` when it is line
/// buffered; the BSD stdio flushes every line-buffered stream it is writing.
unsafe fn flush_for_input(stream: StreamId) {
    #[cfg(target_os = "linux")]
    {
        let _ = stream;
        // SAFETY: the `stdout` variable is read by value.
        let out = entry(unsafe { STDOUT });
        if let Some(out) = out
            // SAFETY: the entry lives for the process.
            && unsafe { (*out.0).life.load(Ordering::Acquire) } == OPEN
        {
            let o = stream_ptr(out);
            // SAFETY: stdout's lock serializes its state; it is recursive, so
            // the reading stream may be stdout itself.
            unsafe {
                let held = lock(out);
                if (*o).line && (*o).access.write {
                    sync(out);
                }
                unlock(out, held);
            }
        }
    }
    #[cfg(target_os = "macos")]
    for_each_open(|other| {
        if other == stream {
            return;
        }
        let o = stream_ptr(other);
        // SAFETY: each stream's lock serializes its state.
        unsafe {
            let held = lock(other);
            if (*o).line && (*o).putting {
                sync(other);
            }
            unlock(other, held);
        }
    });
}

/// glibc's `__underflow`: the next byte, without taking it, refilling the
/// buffer when it is empty; `EOF` at end of file or on an error.
pub(super) unsafe fn underflow(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream; the refill writes within the
    // active buffer.
    unsafe {
        // Darwin's `__srefill` refuses a stream without read access before
        // anything else; glibc writes out pending output first.
        #[cfg(target_os = "macos")]
        if !(*s).access.read {
            return refuse(stream);
        }
        if !enter_get_mode(stream) {
            return EOF;
        }
        let (next, count) = available(stream);
        if count > 0 {
            return c_int::from(next.read());
        }
        if at_eof(stream) {
            return EOF;
        }
        #[cfg(target_os = "linux")]
        if !(*s).access.read {
            return refuse(stream);
        }
        allocbuf(stream);
        if (*s).line || (*s).unbuffered {
            flush_for_input(stream);
        }
        drop_input(stream);
        let count = read_fd((*s).fd, buffer_ptr(stream), buffer_len(stream));
        if count <= 0 {
            if count == 0 {
                set_eof(stream, true);
            } else {
                set_error(stream, true);
            }
            return EOF;
        }
        (*s).get_end = count as usize;
        c_int::from(buffer_ptr(stream).read())
    }
}

/// glibc's `__uflow`: the next byte, taken.
pub(super) unsafe fn uflow(stream: StreamId) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe {
        let byte = underflow(stream);
        if byte != EOF {
            consume(stream, 1);
        }
        byte
    }
}

/// A byte read by `getc` and its spellings, under the stream's lock.
pub(super) fn get_char(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selected a table entry; its lock serializes it.
    unsafe {
        let held = lock(s);
        let byte = uflow(s);
        unlock(s, held);
        byte
    }
}

/// glibc's `_IO_file_xsgetn`: up to `length` bytes. A request of a whole
/// buffer or more reads straight into the caller's memory (a whole number
/// of buffers' worth), without consulting the end-of-file indicator, as
/// glibc's does; the BSD stdio always reads through its buffer.
unsafe fn read_into(stream: StreamId, destination: *mut u8, length: usize) -> usize {
    let s = stream_ptr(stream);
    // SAFETY: the caller keeps `destination` writable for `length` bytes and
    // serializes the stream.
    unsafe {
        let mut want = length;
        let mut at = destination;
        if !enter_get_mode(stream) {
            return 0;
        }
        while want > 0 {
            let (next, count) = available(stream);
            if count > 0 {
                let take = count.min(want);
                ptr::copy_nonoverlapping(next, at, take);
                consume(stream, take);
                at = at.add(take);
                want -= take;
                continue;
            }
            allocbuf(stream);
            let block = buffer_len(stream);
            if cfg!(target_os = "macos") || want < block {
                if underflow(stream) == EOF {
                    break;
                }
                continue;
            }
            drop_input(stream);
            let count = want - if block >= 128 { want % block } else { 0 };
            let got = read_fd((*s).fd, at, count);
            if got <= 0 {
                if got == 0 {
                    set_eof(stream, true);
                } else {
                    set_error(stream, true);
                }
                break;
            }
            at = at.add(got as usize);
            want -= got as usize;
        }
        length - want
    }
}

/// `fread`'s engine: whole items read, as glibc counts them.
pub(super) unsafe fn fread_impl(
    pointer: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> usize {
    let s = stream_of(stream, symbol);
    let request = size.wrapping_mul(count);
    if request == 0 {
        return 0;
    }
    // SAFETY: the C contract supplies `request` writable bytes; the lock
    // serializes the stream.
    unsafe {
        let held = lock(s);
        let taken = read_into(s, pointer.cast(), request);
        unlock(s, held);
        if taken == request {
            count
        } else {
            taken / size
        }
    }
}

/// glibc's `_IO_getline`: up to `limit` bytes into `buffer`, through the
/// first `delimiter` (kept); the count read.
unsafe fn get_line(stream: StreamId, buffer: *mut u8, limit: usize, delimiter: u8) -> usize {
    // SAFETY: the caller keeps `buffer` writable for `limit` bytes and
    // serializes the stream.
    unsafe {
        let mut got = 0;
        while got < limit {
            let (next, count) = available(stream);
            if count == 0 {
                let byte = uflow(stream);
                if byte == EOF {
                    break;
                }
                buffer.add(got).write(byte as u8);
                got += 1;
                if byte as u8 == delimiter {
                    break;
                }
                continue;
            }
            let span = count.min(limit - got);
            let slice = core::slice::from_raw_parts(next, span);
            let (take, found) = match slice.iter().position(|&byte| byte == delimiter) {
                Some(at) => (at + 1, true),
                None => (span, false),
            };
            ptr::copy_nonoverlapping(next, buffer.add(got), take);
            consume(stream, take);
            got += take;
            if found {
                break;
            }
        }
        got
    }
}

/// `fgets`'s engine, reading at most `limit` bytes before the terminator
/// (`__fgets_chk` passes its buffer's size there). glibc answers NULL when
/// nothing was read or a read failed (unless with `EAGAIN`), and keeps an
/// error indicator set before the call; the BSD stdio hands back a partial
/// line read before a failure.
pub(super) unsafe fn fgets_impl(
    buffer: *mut c_char,
    count: c_int,
    limit: usize,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> *mut c_char {
    let s = stream_of(stream, symbol);
    if count <= 0 {
        #[cfg(target_os = "macos")]
        super::super::errno(libc::EINVAL);
        return null_mut();
    }
    // SAFETY: the C contract supplies `count` writable bytes; the lock
    // serializes the stream.
    unsafe {
        if count == 1 {
            buffer.write(0);
            return buffer;
        }
        let held = lock(s);
        let before = has_error(s);
        #[cfg(target_os = "linux")]
        set_error(s, false);
        let got = get_line(s, buffer.cast(), (count as usize - 1).min(limit), b'\n');
        #[cfg(target_os = "linux")]
        let failed = got == 0 || (has_error(s) && super::super::get_errno() != libc::EAGAIN);
        #[cfg(target_os = "macos")]
        let failed = got == 0;
        // `__fgets_chk` reads at most the buffer's size; a line that fills
        // it leaves no room for the terminator: the fortify abort, before
        // anything is written past the buffer.
        #[cfg(target_os = "linux")]
        if !failed && got >= limit {
            unlock(s, held);
            super::super::chk_fail()
        }
        let result = if failed {
            null_mut()
        } else {
            buffer.add(got).write(0);
            buffer
        };
        if before {
            set_error(s, true);
        }
        unlock(s, held);
        result
    }
}

/// `getdelim`'s engine: a whole record into `*line` (grown with `realloc`,
/// first allocated with 120 bytes as glibc does), its length, or -1 at end
/// of file, on an error, or (glibc) when the stream's error indicator was
/// already set. glibc hands back the part of a record a read error ends;
/// the BSD stdio answers -1.
pub(super) unsafe fn getdelim_impl(
    line: *mut *mut c_char,
    capacity: *mut usize,
    delimiter: c_int,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> isize {
    let s = stream_of(stream, symbol);
    if line.is_null() || capacity.is_null() {
        super::super::errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: the C contract makes `*line` null or a `malloc` block of
    // `*capacity` bytes; the lock serializes the stream.
    unsafe {
        let held = lock(s);
        let result = getdelim_locked(s, line, capacity, delimiter as u8);
        unlock(s, held);
        result
    }
}

unsafe fn getdelim_locked(
    stream: StreamId,
    line: *mut *mut c_char,
    capacity: *mut usize,
    delimiter: u8,
) -> isize {
    // SAFETY: as `getdelim_impl`.
    unsafe {
        #[cfg(target_os = "linux")]
        if has_error(stream) {
            return -1;
        }
        if (*line).is_null() || *capacity == 0 {
            *capacity = 120;
            *line = libc::malloc(120).cast();
            if (*line).is_null() {
                set_error(stream, true);
                return -1;
            }
        }
        if available(stream).1 == 0 && underflow(stream) == EOF {
            #[cfg(target_os = "macos")]
            (*line).write(0);
            return -1;
        }
        let mut length = 0usize;
        loop {
            let (next, count) = available(stream);
            let slice = core::slice::from_raw_parts(next, count);
            let (take, found) = match slice.iter().position(|&byte| byte == delimiter) {
                Some(at) => (at + 1, true),
                None => (count, false),
            };
            let mut needed = length + take + 1;
            if needed > *capacity {
                needed = needed.max(2 * *capacity);
                let grown = libc::realloc((*line).cast(), needed).cast::<c_char>();
                if grown.is_null() {
                    set_error(stream, true);
                    return -1;
                }
                *line = grown;
                *capacity = needed;
            }
            ptr::copy_nonoverlapping(next, (*line).add(length).cast(), take);
            consume(stream, take);
            length += take;
            if found {
                break;
            }
            if underflow(stream) == EOF {
                // The BSD stdio drops a partial record a read error ends.
                #[cfg(target_os = "macos")]
                if has_error(stream) {
                    return -1;
                }
                break;
            }
        }
        (*line).add(length).write(0);
        length as isize
    }
}

/// `ungetc`'s engine. A byte equal to the one just read backs the buffer
/// up; any other goes onto the pushback, read first. Either clears the
/// end-of-file indicator. A stream without read access: glibc keeps a
/// pushback area even there, which is not modeled (a named stop); the BSD
/// stdio answers `EOF`. A stream holding output is a named stop on Linux
/// (glibc's backup area over a put area is not modeled); the BSD stdio
/// writes it out first.
pub(super) fn ungetc_impl(character: c_int, stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    if character == EOF {
        return EOF;
    }
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry; its lock serializes it.
    unsafe {
        if !(*state).access.read {
            #[cfg(target_os = "linux")]
            crate::trap_fatal(
                "ungetc onto a stream opened for writing only: its pushback area is not modeled",
            );
            #[cfg(target_os = "macos")]
            return EOF;
        }
        let held = lock(s);
        #[cfg(target_os = "linux")]
        if (*state).putting && (*state).used > 0 {
            unlock(s, held);
            crate::trap_fatal(
                "ungetc onto a stream holding unwritten output: glibc's backup area over a \
                 put area is not modeled",
            );
        }
        if !enter_get_mode(s) {
            unlock(s, held);
            return EOF;
        }
        let byte = character as u8;
        if (*state).pushback.is_empty()
            && (*state).get_pos > 0
            && buffer_ptr(s).add((*state).get_pos - 1).read() == byte
        {
            (*state).get_pos -= 1;
        } else {
            (*state).pushback.push(byte);
        }
        set_eof(s, false);
        unlock(s, held);
        c_int::from(byte)
    }
}

/// `fflush` on one stream (glibc's `_IO_new_file_sync`): pending output is
/// written; input read ahead goes back to the descriptor (a pipe, which
/// cannot seek, keeps it). Darwin's `fflush` does the same.
pub(super) unsafe fn sync_input(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream.
    unsafe {
        if (*s).putting {
            return sync(stream);
        }
        let back = unread(stream);
        if back == 0 {
            return 0;
        }
        let moved = crate::abi::libc_result(crate::fd::seek((*s).fd, -(back as i64), 1), -1);
        if moved >= 0 {
            drop_input(stream);
            0
        } else if super::super::get_errno() == libc::ESPIPE {
            0
        } else {
            EOF
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn getc(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"getc")
}
#[unsafe(no_mangle)]
extern "C" fn fgetc(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"fgetc")
}
/// `getchar`: `getc` on the stream the `stdin` variable names.
#[unsafe(no_mangle)]
extern "C" fn getchar() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the variable is read by value.
    get_char(unsafe { STDIN }, c"getchar")
}
/// # Safety
/// The buffer holds `count` writable bytes; stream obeys fgets's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fgets(
    buffer: *mut c_char,
    count: c_int,
    stream: *mut libc::FILE,
) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fgets_impl(buffer, count, usize::MAX, stream, c"fgets") }
}
/// # Safety
/// The destination holds size*count bytes; stream obeys fread's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fread(
    pointer: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fread_impl(pointer, size, count, stream, c"fread") }
}
/// # Safety
/// `line` and `capacity` obey getdelim's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn getdelim(
    line: *mut *mut c_char,
    capacity: *mut usize,
    delimiter: c_int,
    stream: *mut libc::FILE,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { getdelim_impl(line, capacity, delimiter, stream, c"getdelim") }
}
/// # Safety
/// `line` and `capacity` obey getline's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn getline(
    line: *mut *mut c_char,
    capacity: *mut usize,
    stream: *mut libc::FILE,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { getdelim_impl(line, capacity, c_int::from(b'\n'), stream, c"getline") }
}
#[unsafe(no_mangle)]
extern "C" fn ungetc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ungetc_impl(character, stream, c"ungetc")
}
