//! The Linux port: glibc's buffering controls and its spellings of the
//! stdio calls (the `_unlocked`, `_IO_` and `64` names, the fortified
//! `_chk` entries, the inline bodies' slow paths, `stdio_ext.h`).
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

// Every glibc spelling takes its stream through `stream_of`, which stops by
// name on any other `FILE*`: libstdc++'s `stdio_sync_filebuf` (`std::cout`,
// `std::cin`) binds the shim's standard streams, and a C guest reaches the
// `_unlocked` and `_IO_` names and the inline bodies' slow paths. The
// unlocked spellings take the stream's (recursive) lock all the same.

/// A byte written by `putc` and its spellings: `fputc`'s model.
fn put_char(character: c_int, stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selected a table entry.
    unsafe { put_byte(s, character) }
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
    // SAFETY: the `stdout` variable is read by value.
    put_char(character, unsafe { STDOUT }, c"putchar_unlocked")
}

/// `__overflow`: the slow path of the inline `putc_unlocked` bodies. A byte
/// is put; `EOF` flushes, answering 0 or `EOF` as glibc's file overflow does.
#[unsafe(no_mangle)]
extern "C" fn __overflow(stream: *mut libc::FILE, character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__overflow");
    // SAFETY: stream_of selected a table entry.
    unsafe {
        if character == EOF {
            locked_flush(s)
        } else {
            put_byte(s, character)
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn getc_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    input::get_char(stream, c"getc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn fgetc_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    input::get_char(stream, c"fgetc_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn _IO_getc(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    input::get_char(stream, c"_IO_getc")
}
#[unsafe(no_mangle)]
extern "C" fn getchar_unlocked() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the `stdin` variable is read by value.
    input::get_char(unsafe { STDIN }, c"getchar_unlocked")
}
/// `__uflow`: the slow path of the inline `getc_unlocked` bodies.
#[unsafe(no_mangle)]
extern "C" fn __uflow(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    input::get_char(stream, c"__uflow")
}

/// # Safety
/// The destination holds size*count bytes; stream obeys fread's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fread_unlocked(
    pointer: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { input::fread_impl(pointer, size, count, stream, c"fread_unlocked") }
}
/// glibc's `__fread_chk`: `fread` into a buffer of `capacity` bytes; a
/// request past it (or one whose size overflows) is the fortify abort.
unsafe fn fread_checked(
    pointer: *mut c_void,
    capacity: usize,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> usize {
    let Some(request) = size.checked_mul(count) else {
        super::super::chk_fail()
    };
    if request > capacity {
        super::super::chk_fail()
    }
    // SAFETY: forwarded from the C contract; the request fits the buffer.
    unsafe { input::fread_impl(pointer, size, count, stream, symbol) }
}
/// # Safety
/// The destination holds `capacity` bytes; stream obeys fread's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn __fread_chk(
    pointer: *mut c_void,
    capacity: usize,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fread_checked(pointer, capacity, size, count, stream, c"__fread_chk") }
}
/// # Safety
/// The destination holds `capacity` bytes; stream obeys fread's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn __fread_unlocked_chk(
    pointer: *mut c_void,
    capacity: usize,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe {
        fread_checked(
            pointer,
            capacity,
            size,
            count,
            stream,
            c"__fread_unlocked_chk",
        )
    }
}
/// # Safety
/// The buffer holds `count` writable bytes; stream obeys fgets's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fgets_unlocked(
    buffer: *mut c_char,
    count: c_int,
    stream: *mut libc::FILE,
) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { input::fgets_impl(buffer, count, usize::MAX, stream, c"fgets_unlocked") }
}
/// glibc's `__fgets_chk`: `fgets` reading at most the buffer's `capacity`;
/// a line that fills it is the fortify abort.
unsafe fn fgets_checked(
    buffer: *mut c_char,
    capacity: usize,
    count: c_int,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> *mut c_char {
    // SAFETY: forwarded from the C contract; the engine reads at most
    // `capacity` bytes and aborts before terminating a line that fills them.
    unsafe { input::fgets_impl(buffer, count, capacity, stream, symbol) }
}
/// # Safety
/// The buffer holds `capacity` writable bytes; stream obeys fgets's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn __fgets_chk(
    buffer: *mut c_char,
    capacity: usize,
    count: c_int,
    stream: *mut libc::FILE,
) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fgets_checked(buffer, capacity, count, stream, c"__fgets_chk") }
}
/// # Safety
/// The buffer holds `capacity` writable bytes; stream obeys fgets's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn __fgets_unlocked_chk(
    buffer: *mut c_char,
    capacity: usize,
    count: c_int,
    stream: *mut libc::FILE,
) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fgets_checked(buffer, capacity, count, stream, c"__fgets_unlocked_chk") }
}
/// `__getdelim`: the name glibc's inline `getline` body calls.
///
/// # Safety
/// `line` and `capacity` obey getdelim's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn __getdelim(
    line: *mut *mut c_char,
    capacity: *mut usize,
    delimiter: c_int,
    stream: *mut libc::FILE,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { input::getdelim_impl(line, capacity, delimiter, stream, c"__getdelim") }
}
/// # Safety
/// String is readable and NUL-terminated; stream obeys fputs's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fputs_unlocked(string: *const c_char, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fputs_impl(string, stream, c"fputs_unlocked") }
}
/// # Safety
/// The source holds size*count bytes; stream obeys fwrite's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fwrite_unlocked(
    pointer: *const c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fwrite_impl(pointer, size, count, stream, c"fwrite_unlocked") }
}
#[unsafe(no_mangle)]
extern "C" fn fflush_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded.
    unsafe { fflush_impl(stream, c"fflush_unlocked") }
}
#[unsafe(no_mangle)]
extern "C" fn feof_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    feof_impl(stream, c"feof_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn ferror_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ferror_impl(stream, c"ferror_unlocked")
}
#[unsafe(no_mangle)]
extern "C" fn clearerr_unlocked(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    clearerr_impl(stream, c"clearerr_unlocked");
}
#[unsafe(no_mangle)]
extern "C" fn fileno_unlocked(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fileno_impl(stream, c"fileno_unlocked")
}

/// `ftello64`/`fseeko64`: glibc's 64-bit names, the same calls on LP64.
#[unsafe(no_mangle)]
extern "C" fn ftello64(stream: *mut libc::FILE) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    files::ftello_impl(stream, c"ftello64")
}
#[unsafe(no_mangle)]
extern "C" fn fseeko64(stream: *mut libc::FILE, offset: i64, whence: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    files::fseeko_impl(stream, offset, whence, c"fseeko64")
}
/// # Safety
/// Path and mode are NUL-terminated strings.
#[unsafe(no_mangle)]
unsafe extern "C" fn fopen64(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { files::fopen_impl(path, mode) }
}
/// # Safety
/// Path is null or a C string; mode is a C string.
#[unsafe(no_mangle)]
unsafe extern "C" fn freopen64(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { files::freopen_impl(path, mode, stream, c"freopen64") }
}

/// `__fpending` (`stdio_ext.h`): the output bytes buffered.
#[unsafe(no_mangle)]
extern "C" fn __fpending(stream: *mut libc::FILE) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__fpending");
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry; glibc reads the count unlocked.
    unsafe {
        if (*state).putting && (*state).area {
            (*state).used
        } else {
            0
        }
    }
}
/// `__fpurge` (`stdio_ext.h`): discard the buffered output and input,
/// pushback included.
#[unsafe(no_mangle)]
extern "C" fn __fpurge(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__fpurge");
    // SAFETY: the stream is a table entry; glibc purges it unlocked.
    unsafe {
        (*stream_ptr(s)).used = 0;
        input::drop_input(s);
    }
}

/// `_IO_flockfile`/`_IO_funlockfile`: glibc's internal spellings of
/// `flockfile`/`funlockfile`.
#[unsafe(no_mangle)]
extern "C" fn _IO_flockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only table entries whose locks live for the
    // process lifetime.
    unsafe {
        lock(stream_of(stream, c"_IO_flockfile"));
    }
}
#[unsafe(no_mangle)]
extern "C" fn _IO_funlockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only table entries; the teardown check
    // preserves funlockfile's rule about whether this call releases the lock.
    unsafe {
        unlock(
            stream_of(stream, c"_IO_funlockfile"),
            crate::patina_in_teardown() == 0,
        );
    }
}
