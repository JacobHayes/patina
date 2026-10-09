//! Linux buffering controls and assertion diagnostics.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
unsafe fn setbuf_impl(stream: StreamId, buffer: *mut u8, size: usize) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: the selected stream is static and callers serialize it; borrowed
    // storage remains live under the setvbuf/setbuffer contract.
    unsafe {
        if sync(stream) == EOF {
            return EOF;
        }
        if buffer.is_null() || size == 0 {
            (*s).unbuffered = true;
            (*s).buffer = Buffer::Short;
            (*s).inline_len = 0;
        } else {
            (*s).unbuffered = false;
            (*s).buffer = Buffer::Borrowed {
                ptr: buffer,
                len: size,
            };
            (*s).inline_len = 0;
        }
        (*s).area = true;
        (*s).used = 0;
        (*s).end = 0;
        0
    }
}
unsafe fn setvbuf_impl(
    stream: StreamId,
    mut buffer: *mut u8,
    mode: c_int,
    mut size: usize,
) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: the selected stream is static and protected by its recursive
    // mutex; any borrowed storage follows the caller's setvbuf contract.
    unsafe {
        let held = lock(stream);
        let result = match mode {
            libc::_IOFBF => {
                (*s).line = false;
                (*s).unbuffered = false;
                if buffer.is_null() {
                    if matches!((*s).buffer, Buffer::Unallocated) {
                        allocate(stream);
                        (*s).line = false;
                    }
                    0
                } else {
                    setbuf_impl(stream, buffer, size)
                }
            }
            libc::_IOLBF => {
                (*s).unbuffered = false;
                (*s).line = true;
                if buffer.is_null() {
                    0
                } else {
                    setbuf_impl(stream, buffer, size)
                }
            }
            libc::_IONBF => {
                (*s).line = false;
                (*s).unbuffered = true;
                buffer = null_mut();
                size = 0;
                setbuf_impl(stream, buffer, size)
            }
            _ => EOF,
        };
        unlock(stream, held);
        result
    }
}
unsafe fn setbuffer_impl(stream: StreamId, buffer: *mut u8, size: usize) {
    let s = stream_ptr(stream);
    // SAFETY: the selected stream is static and its recursive mutex protects
    // state; borrowed storage follows the caller's lifetime contract.
    unsafe {
        let held = lock(stream);
        (*s).line = false;
        setbuf_impl(stream, buffer, if buffer.is_null() { 0 } else { size });
        unlock(stream, held);
    }
}
/// # Safety
/// Caller buffer remains live under setvbuf's borrowing contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn setvbuf(
    stream: *mut libc::FILE,
    buffer: *mut c_char,
    mode: c_int,
    size: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels and the caller buffer remains
    // live according to setvbuf's contract.
    unsafe { setvbuf_impl(stream_of(stream, c"setvbuf"), buffer.cast(), mode, size) }
}
/// # Safety
/// Caller buffer remains live under setbuffer's borrowing contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn setbuffer(stream: *mut libc::FILE, buffer: *mut c_char, size: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels; a non-null buffer remains live
    // under setbuffer's caller-owned storage contract.
    unsafe {
        setbuffer_impl(stream_of(stream, c"setbuffer"), buffer.cast(), size);
    }
}
/// # Safety
/// Caller buffer is null or holds BUFSIZ bytes and remains live.
#[unsafe(no_mangle)]
unsafe extern "C" fn setbuf(stream: *mut libc::FILE, buffer: *mut c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels; a non-null buffer remains live
    // for BUFSIZ bytes under setbuf's caller-owned storage contract.
    unsafe {
        setbuffer_impl(stream_of(stream, c"setbuf"), buffer.cast(), BUFSIZ);
    }
}
#[unsafe(no_mangle)]
extern "C" fn setlinebuf(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels and null selects an internally
    // managed buffer for line buffering.
    unsafe {
        setvbuf_impl(
            stream_of(stream, c"setlinebuf"),
            null_mut(),
            libc::_IOLBF,
            0,
        );
    }
}

// The character, positioning and lifetime calls made on `stdout`/`stderr`
// beside the ones above: libstdc++'s `stdio_sync_filebuf` (`std::cout`,
// `std::cerr`, `std::clog`), which binds those objects to the shim's
// sentinels, and the alternate spellings and inline slow paths a C guest
// reaches (`fgetc`, `*_unlocked`, `_IO_getc`/`_IO_putc`, `__uflow`/
// `__overflow`, `_IO_flockfile`). Every one must be the shim's: glibc's would
// read a sentinel as a FILE. Like every stdio door they take their stream
// through `stream_of`, which stops by name on any other `FILE*`: no glibc
// stream (its stdin, or one an allowed host `fopen` made) is read or written.

/// A byte written by `putc` and its spellings: `fputc`'s model.
fn put_char(character: c_int, stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selected a process-lifetime sentinel stream.
    unsafe { put_byte(s, character) }
}

/// A read from a standard output stream, as glibc's `_IO_NO_READS` streams
/// answer it: leaving put mode flushes pending output, then the read fails
/// with `EBADF` and sets the error indicator. EOF if the flush failed.
unsafe fn refuse_read(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: the selected stream is static and its recursive mutex protects
    // the flush and the indicator update.
    unsafe {
        let held = lock(stream);
        if sync(stream) == 0 {
            // glibc's get mode collapses the write area: the next write
            // starts a new one.
            (*s).putting = false;
            (*s).area = false;
            set_error(stream, true);
            super::super::errno(libc::EBADF);
        }
        unlock(stream, held);
    }
    EOF
}

/// A byte read by `getc` and its spellings.
fn get_char(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selected a process-lifetime sentinel stream.
    unsafe { refuse_read(s) }
}

/// `putc`: `fputc` (`std::endl`, `put`).
#[unsafe(no_mangle)]
extern "C" fn putc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    put_char(character, stream, c"putc")
}
#[unsafe(no_mangle)]
extern "C" fn putc_unlocked(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    put_char(character, stream, c"putc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn fputc_unlocked(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    put_char(character, stream, c"fputc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn _IO_putc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    put_char(character, stream, c"_IO_putc")
}
#[unsafe(no_mangle)]
extern "C" fn putchar_unlocked(character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    put_char(character, (&raw mut OUT_TOKEN).cast(), c"putchar_unlocked")
}

/// `__overflow`: the slow path of the inline `putc_unlocked` bodies. A byte
/// is put; `EOF` flushes, answering 0 or `EOF` as glibc's file overflow does.
#[unsafe(no_mangle)]
extern "C" fn __overflow(stream: *mut libc::FILE, character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__overflow");
    // SAFETY: stream_of selected a process-lifetime sentinel stream.
    unsafe {
        if character == EOF {
            locked_flush(s)
        } else {
            put_byte(s, character)
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
#[unsafe(no_mangle)]
extern "C" fn getc_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"getc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn fgetc_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"fgetc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn _IO_getc(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"_IO_getc")
}
/// `getchar` and `getchar_unlocked` read glibc's own `stdin`, which is not
/// modeled: a named stop, never a read of the host's descriptor 0.
#[unsafe(no_mangle)]
extern "C" fn getchar() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::trap_fatal("getchar reads glibc's own stdin, which is not modeled")
}
#[unsafe(no_mangle)]
extern "C" fn getchar_unlocked() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::trap_fatal("getchar_unlocked reads glibc's own stdin, which is not modeled")
}
/// `__uflow`: the slow path of the inline `getc_unlocked` bodies.
#[unsafe(no_mangle)]
extern "C" fn __uflow(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    get_char(stream, c"__uflow")
}

/// `fileno`: the descriptor a standard stream writes, as glibc reports it
/// whatever that number now names.
#[unsafe(no_mangle)]
extern "C" fn fileno(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fileno");
    // SAFETY: stream_of selected a process-lifetime stream; its fd never
    // changes.
    unsafe { (*stream_ptr(s)).fd }
}

/// # Safety
/// The destination holds size*count bytes; stream obeys fread's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fread(
    _pointer: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fread");
    if size.wrapping_mul(count) != 0 {
        // SAFETY: stream_of selected a sentinel stream; nothing is copied out.
        unsafe { refuse_read(s) };
    }
    0
}

/// `ungetc`: `EOF` changes nothing; a byte pushed back onto a standard
/// output stream (glibc keeps a pushback area even there) is a named stop:
/// the pushback is not modeled.
#[unsafe(no_mangle)]
extern "C" fn ungetc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    stream_of(stream, c"ungetc");
    if character == EOF {
        return EOF;
    }
    crate::trap_fatal("ungetc onto a standard output stream: its pushback area is not modeled")
}

/// `ftello64`: the descriptor's offset plus the bytes still buffered, as
/// glibc's `do_ftell` counts them; a stream on a capture or a pipe answers
/// `ESPIPE`.
#[unsafe(no_mangle)]
extern "C" fn ftello64(stream: *mut libc::FILE) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"ftello64");
    let state = stream_ptr(s);
    // SAFETY: the selected stream is static and its recursive mutex protects
    // the buffered count read beside the descriptor's offset.
    unsafe {
        let held = lock(s);
        let mut position = crate::abi::libc_result(crate::fd::seek((*state).fd, 0, 1), -1);
        if position >= 0 && (*state).putting && (*state).area {
            position += (*state).used as i64;
        }
        unlock(s, held);
        position
    }
}

/// `fseeko64`: flush pending output, then move the descriptor's offset; 0 or
/// -1 with the descriptor's error. A whence other than `SEEK_SET`,
/// `SEEK_CUR` or `SEEK_END` is `EINVAL` first.
#[unsafe(no_mangle)]
extern "C" fn fseeko64(stream: *mut libc::FILE, offset: i64, whence: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fseeko64");
    if !(0..=2).contains(&whence) {
        super::super::errno(libc::EINVAL);
        return -1;
    }
    let state = stream_ptr(s);
    // SAFETY: the selected stream is static and its recursive mutex protects
    // the flush and the mode change around the descriptor seek.
    unsafe {
        let held = lock(s);
        let result = if sync(s) != 0 {
            -1
        } else {
            (*state).putting = false;
            (*state).area = false;
            let moved =
                crate::abi::libc_result(crate::fd::seek((*state).fd, offset, whence as u32), -1);
            if moved < 0 { -1 } else { 0 }
        };
        unlock(s, held);
        result
    }
}

/// `fclose`: flush, close the stream's descriptor, and retire the stream:
/// 0, or `EOF` when the flush or the close failed (the stream is closed
/// either way, as glibc's is). A later call on it stops by name.
#[unsafe(no_mangle)]
extern "C" fn fclose(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fclose");
    let state = stream_ptr(s);
    // SAFETY: the selected stream is static and its recursive mutex protects
    // the flush and the retirement.
    unsafe {
        let held = lock(s);
        let flushed = sync(s);
        let closed = crate::patina_close((*state).fd);
        (*state).closed = true;
        unlock(s, held);
        if flushed == 0 && closed == 0 { 0 } else { EOF }
    }
}

/// `freopen` onto a standard stream opens a file through glibc's FILE
/// layer, which is not modeled: a named stop.
///
/// # Safety
/// The path and mode are C strings or null, as freopen's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn freopen(
    _path: *const c_char,
    _mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    stream_of(stream, c"freopen");
    crate::trap_fatal(
        "freopen of a standard stream: reopening through glibc's FILE layer is not modeled",
    )
}

/// `_IO_flockfile`/`_IO_funlockfile`: glibc's internal spellings of
/// `flockfile`/`funlockfile`, which would lock the sentinel's (absent) lock.
#[unsafe(no_mangle)]
extern "C" fn _IO_flockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels whose static locks live for
    // the process lifetime.
    unsafe {
        lock(stream_of(stream, c"_IO_flockfile"));
    }
}
#[unsafe(no_mangle)]
extern "C" fn _IO_funlockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels; the teardown check preserves
    // funlockfile's rule about whether this call releases the stream lock.
    unsafe {
        unlock(
            stream_of(stream, c"_IO_funlockfile"),
            crate::patina_in_teardown() == 0,
        );
    }
}
