//! Linux buffering controls and assertion diagnostics.
use super::*;
unsafe fn setbuf_impl(s: *mut Stream, buffer: *mut u8, size: usize) -> c_int {
    unsafe {
        if sync(s) == EOF {
            return EOF;
        }
        if buffer.is_null() || size == 0 {
            (*s).unbuffered = true;
            (*s).bytes = &raw mut (*s).shortbuf;
            (*s).size = 1;
        } else {
            (*s).unbuffered = false;
            (*s).bytes = buffer;
            (*s).size = size;
        }
        (*s).area = true;
        (*s).used = 0;
        (*s).end = 0;
        0
    }
}
unsafe fn setvbuf_impl(s: *mut Stream, mut buffer: *mut u8, mode: c_int, mut size: usize) -> c_int {
    unsafe {
        let held = lock(s);
        let result = match mode {
            libc::_IOFBF => {
                (*s).line = false;
                (*s).unbuffered = false;
                if buffer.is_null() {
                    if (*s).bytes.is_null() {
                        allocate(s);
                        (*s).line = false;
                    }
                    0
                } else {
                    setbuf_impl(s, buffer, size)
                }
            }
            libc::_IOLBF => {
                (*s).unbuffered = false;
                (*s).line = true;
                if buffer.is_null() {
                    0
                } else {
                    setbuf_impl(s, buffer, size)
                }
            }
            libc::_IONBF => {
                (*s).line = false;
                (*s).unbuffered = true;
                buffer = null_mut();
                size = 0;
                setbuf_impl(s, buffer, size)
            }
            _ => EOF,
        };
        unlock(s, held);
        result
    }
}
unsafe fn setbuffer_impl(s: *mut Stream, buffer: *mut u8, size: usize) {
    unsafe {
        let held = lock(s);
        (*s).line = false;
        setbuf_impl(s, buffer, if buffer.is_null() { 0 } else { size });
        unlock(s, held);
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
    unsafe { setvbuf_impl(stream_of(stream, c"setvbuf"), buffer.cast(), mode, size) }
}
/// # Safety
/// Caller buffer remains live under setbuffer's borrowing contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setbuffer(stream: *mut libc::FILE, buffer: *mut c_char, size: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        setbuffer_impl(stream_of(stream, c"setbuffer"), buffer.cast(), size);
    }
}
/// # Safety
/// Caller buffer is null or holds BUFSIZ bytes and remains live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setbuf(stream: *mut libc::FILE, buffer: *mut c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        setbuffer_impl(stream_of(stream, c"setbuf"), buffer.cast(), BUFSIZ);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn setlinebuf(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        setvbuf_impl(
            stream_of(stream, c"setlinebuf"),
            null_mut(),
            libc::_IOLBF,
            0,
        );
    }
}
