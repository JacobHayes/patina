//! The Darwin port: libSystem's linker spellings of the stdio calls and the
//! slow paths of its inline character bodies.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// Darwin's `_r`/`_w` counts (`int`s at offsets 8 and 12 of `struct
/// __sFILE`): the inline `__sgetc`/`__sputc` bodies decrement them and call
/// `__srget`/`__swbuf` once they go negative. They are zero again before the
/// call returns, so every inline byte comes back into the shim.
unsafe fn reset_count(stream: StreamId, offset: usize) {
    // SAFETY: the count lies within the sentinel, aligned for an `int`.
    unsafe {
        (&raw mut (*stream.0).token.bytes)
            .cast::<u8>()
            .add(offset)
            .cast::<c_int>()
            .write_volatile(0);
    }
}

/// `__srget`: the slow path of the inline `getc_unlocked` body.
#[unsafe(no_mangle)]
extern "C" fn __srget(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__srget");
    // SAFETY: stream_of selected a table entry.
    unsafe { reset_count(s, 8) };
    input::get_char(stream, c"__srget")
}
/// `__swbuf`: the slow path of the inline `putc_unlocked` body.
#[unsafe(no_mangle)]
extern "C" fn __swbuf(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__swbuf");
    // SAFETY: stream_of selected a table entry; its lock serializes the put.
    unsafe {
        reset_count(s, 12);
        put_byte(s, character)
    }
}

/// `fopen` and `fdopen` as Darwin's headers spell them (`$DARWIN_EXTSN`);
/// the plain names are the stream engine's own doors.
///
/// # Safety
/// Path and mode are NUL-terminated strings.
#[unsafe(export_name = "fopen$DARWIN_EXTSN")]
unsafe extern "C" fn fopen_extsn(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { files::fopen_impl(path, mode) }
}
/// # Safety
/// The mode is a NUL-terminated string.
#[unsafe(export_name = "fdopen$DARWIN_EXTSN")]
unsafe extern "C" fn fdopen_extsn(fd: c_int, mode: *const c_char) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { files::fdopen_impl(fd, mode) }
}
