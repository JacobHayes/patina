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
pub unsafe extern "C" fn setvbuf(
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
pub unsafe extern "C" fn setbuffer(stream: *mut libc::FILE, buffer: *mut c_char, size: usize) {
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
pub unsafe extern "C" fn setbuf(stream: *mut libc::FILE, buffer: *mut c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels; a non-null buffer remains live
    // for BUFSIZ bytes under setbuf's caller-owned storage contract.
    unsafe {
        setbuffer_impl(stream_of(stream, c"setbuf"), buffer.cast(), BUFSIZ);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn setlinebuf(stream: *mut libc::FILE) {
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
