//! Opening, reopening, closing and positioning streams.
//!
//! `fopen` and `fdopen` take a stream from the table (a retired one first,
//! else a new `malloc` block, as glibc allocates its own), over a descriptor
//! the modeled `open` made or the caller handed in. The mode rules are
//! glibc's (`libio/fileops.c` `_IO_new_file_fopen`, `iofdopen.c`,
//! `freopen.c`), which the BSD stdio's agree with for every mode spelled
//! with `r`, `w`, `a`, `+`, `b`, `x` and `e`.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// A parsed `fopen` mode: the `open` flags and the stream's access.
struct Mode {
    flags: c_int,
    access: Access,
}

/// glibc's mode string: `r`, `w` or `a`, then up to six modifiers (`+`; `x`
/// for `O_EXCL`; `e` for `O_CLOEXEC`; `b`, `m`, `c` and anything else
/// ignored), ending at a NUL or a `,`. A `,ccs=` wide-character conversion is
/// not modeled: a named stop. `None` is `EINVAL`.
unsafe fn parse_mode(mode: *const c_char) -> Option<Mode> {
    // SAFETY: the caller supplies a NUL-terminated mode string.
    unsafe {
        let bytes = CStr::from_ptr(mode).to_bytes();
        let (mut flags, mut access) = match bytes.first() {
            Some(b'r') => (libc::O_RDONLY, READ),
            Some(b'w') => (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, WRITE),
            Some(b'a') => (
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                Access {
                    append: true,
                    ..WRITE
                },
            ),
            _ => return None,
        };
        for &byte in bytes.iter().skip(1).take(6) {
            match byte {
                b',' => break,
                b'+' => {
                    flags = (flags & !libc::O_ACCMODE) | libc::O_RDWR;
                    access.read = true;
                    access.write = true;
                }
                b'x' => flags |= libc::O_EXCL,
                b'e' => flags |= libc::O_CLOEXEC,
                _ => {}
            }
        }
        if bytes.windows(5).any(|window| window == b",ccs=") {
            crate::trap_fatal("a stdio mode with ,ccs=: wide-character streams are not modeled");
        }
        Some(Mode { flags, access })
    }
}

/// A stream for `fd`: a retired table entry, else a new one. `None` when
/// `malloc` fails.
unsafe fn claim(fd: c_int, access: Access) -> Option<StreamId> {
    let mut at = TABLE.load(Ordering::Acquire);
    while !at.is_null() {
        // SAFETY: entries are never freed; claiming a free one is a
        // compare-exchange, so two opens never share it.
        unsafe {
            if !(*at).standard
                && (*at)
                    .life
                    .compare_exchange(FREE, OPEN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                (*at).token = Sentinel::new(fd);
                (*at).state = Stream::new(fd, access, false);
                return Some(StreamId(at));
            }
            at = (*at).next;
        }
    }
    // SAFETY: a fresh block of the entry's size, initialized before it is
    // published at the table's head.
    unsafe {
        let file = libc::malloc(size_of::<File>()).cast::<File>();
        if file.is_null() {
            return None;
        }
        file.write(File {
            token: Sentinel::new(fd),
            state: Stream::new(fd, access, false),
            next: null_mut(),
            life: AtomicU8::new(OPEN),
            standard: false,
        });
        loop {
            let head = TABLE.load(Ordering::Acquire);
            (*file).next = head;
            if TABLE
                .compare_exchange(head, file, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(StreamId(file));
            }
        }
    }
}

/// Close a descriptor through the model, leaving its errno.
fn close_fd(fd: c_int) -> c_int {
    let closed = crate::patina_close(fd);
    if closed < 0 {
        super::super::errno(crate::patina_errno());
    }
    closed
}

/// An append stream starts at the end of the file (a pipe, which cannot
/// seek, is fine); false on any other seek failure.
unsafe fn seek_to_end(access: Access, fd: c_int) -> bool {
    // glibc seeks for a write-only append stream; the BSD stdio for every
    // append stream, `a+` too.
    if !access.append || (cfg!(target_os = "linux") && access.read) {
        return true;
    }
    crate::abi::libc_result(crate::fd::seek(fd, 0, 2), -1) >= 0
        || super::super::get_errno() == libc::ESPIPE
}

/// Forget everything a closed file left in a stream: its buffer (a caller's
/// `setvbuf` buffer too), modes, indicators and descriptor, as glibc's
/// `_IO_file_close_it` resets the FILE.
unsafe fn reset(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: the caller serializes the stream.
    unsafe {
        (*s).putting = false;
        (*s).area = false;
        (*s).used = 0;
        (*s).end = 0;
        input::drop_input(stream);
        (*s).buffer = Buffer::Unallocated;
        (*s).inline_len = 0;
        (*s).line = false;
        (*s).unbuffered = false;
        set_error(stream, false);
        set_eof(stream, false);
        set_fd(stream, -1);
    }
}

pub(super) unsafe fn fopen_impl(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    // SAFETY: the caller supplies C strings, as fopen's contract.
    unsafe {
        let Some(mode) = parse_mode(mode) else {
            super::super::errno(libc::EINVAL);
            return null_mut();
        };
        super::super::cancel(c"open");
        let fd = crate::variadic::open::patina_openat_impl(libc::AT_FDCWD, path, mode.flags, 0o666);
        if fd < 0 {
            return null_mut();
        }
        if !seek_to_end(mode.access, fd) {
            let errno = super::super::get_errno();
            close_fd(fd);
            super::super::errno(errno);
            return null_mut();
        }
        match claim(fd, mode.access) {
            Some(stream) => stream.file(),
            None => {
                close_fd(fd);
                super::super::errno(libc::ENOMEM);
                null_mut()
            }
        }
    }
}
/// # Safety
/// Path and mode are NUL-terminated strings.
#[unsafe(no_mangle)]
unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fopen_impl(path, mode) }
}

pub(super) unsafe fn fdopen_impl(fd: c_int, mode: *const c_char) -> *mut libc::FILE {
    // SAFETY: the caller supplies a C string mode, as fdopen's contract.
    let Some(mode) = (unsafe { parse_mode(mode) }) else {
        super::super::errno(libc::EINVAL);
        return null_mut();
    };
    let status = crate::patina_fd_getfl(fd);
    if status < 0 {
        super::super::errno(crate::patina_errno());
        return null_mut();
    }
    let status = status as u32;
    let (readable, writable) = (status & crate::O_READ != 0, status & crate::O_WRITE != 0);
    if (mode.access.write && !writable) || (mode.access.read && !readable) {
        super::super::errno(libc::EINVAL);
        return null_mut();
    }
    #[cfg_attr(target_os = "macos", allow(unused_mut))]
    let mut seek = false;
    // glibc gives the descriptor `O_APPEND`; the BSD stdio leaves it and
    // seeks to the end before each write (`write_out`).
    #[cfg(target_os = "linux")]
    if mode.access.append && status & crate::O_APPEND == 0 {
        seek = true;
        if crate::patina_fd_setfl(fd, status | crate::O_APPEND) < 0 {
            super::super::errno(crate::patina_errno());
            return null_mut();
        }
    }
    // SAFETY: the descriptor was resolved above.
    if seek && !unsafe { seek_to_end(mode.access, fd) } {
        return null_mut();
    }
    // SAFETY: the stream is fresh or retired; nothing else holds it.
    match unsafe { claim(fd, mode.access) } {
        Some(stream) => stream.file(),
        None => {
            super::super::errno(libc::ENOMEM);
            null_mut()
        }
    }
}
/// # Safety
/// The mode is a NUL-terminated string.
#[unsafe(no_mangle)]
unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fdopen_impl(fd, mode) }
}

/// glibc's `freopen`: flush the stream, open `path` with `mode`, and keep
/// the stream's descriptor NUMBER (the new descriptor is `dup3`ed over the
/// old one and closed), so `freopen(path, "r", stdin)` makes descriptor 0
/// the file. A failed open closes the old descriptor and leaves the stream
/// with none. A null path (a mode change on the open file) is not modeled: a
/// named stop.
pub(super) unsafe fn freopen_impl(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> *mut libc::FILE {
    let s = stream_of(stream, symbol);
    if path.is_null() {
        crate::trap_fatal("freopen with a null path: reopening a stream's own file is not modeled");
    }
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry; its lock serializes it; path and
    // mode are C strings by contract.
    unsafe {
        let held = lock(s);
        let _ = input::sync_input(s);
        let old = (*state).fd;
        reset(s);
        let result = 'reopen: {
            let Some(mode) = parse_mode(mode) else {
                if old >= 0 {
                    close_fd(old);
                }
                super::super::errno(libc::EINVAL);
                break 'reopen null_mut();
            };
            super::super::cancel(c"open");
            let mut fd =
                crate::variadic::open::patina_openat_impl(libc::AT_FDCWD, path, mode.flags, 0o666);
            if fd < 0 {
                let errno = super::super::get_errno();
                if old >= 0 {
                    close_fd(old);
                }
                super::super::errno(errno);
                break 'reopen null_mut();
            }
            if !seek_to_end(mode.access, fd) {
                let errno = super::super::get_errno();
                close_fd(fd);
                super::super::errno(errno);
                break 'reopen null_mut();
            }
            if old >= 0 && fd != old {
                let cloexec = c_int::from(mode.flags & libc::O_CLOEXEC != 0);
                if crate::abi::libc_result(crate::fd::value::dup3(fd, old, cloexec), -1) < 0 {
                    let errno = super::super::get_errno();
                    close_fd(fd);
                    super::super::errno(errno);
                    break 'reopen null_mut();
                }
                close_fd(fd);
                fd = old;
            }
            (*state).access = mode.access;
            set_fd(s, fd);
            s.file()
        };
        unlock(s, held);
        result
    }
}
/// # Safety
/// Path is null or a C string; mode is a C string.
#[unsafe(no_mangle)]
unsafe extern "C" fn freopen(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { freopen_impl(path, mode, stream, c"freopen") }
}

/// `fclose`: flush, close the stream's descriptor, and retire the stream:
/// 0, or `EOF` when the flush or the close failed (the stream is closed
/// either way, as glibc's is). A later call on a closed standard stream
/// stops by name; a retired heap stream is reused by a later open.
#[unsafe(no_mangle)]
extern "C" fn fclose(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fclose");
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry and its lock serializes the flush
    // and the retirement.
    unsafe {
        let held = lock(s);
        let flushed = sync(s);
        let fd = (*state).fd;
        let closed = if fd >= 0 { close_fd(fd) } else { EOF };
        reset(s);
        let life = if (*s.0).standard { CLOSED } else { FREE };
        unlock(s, held);
        (*s.0).life.store(life, Ordering::Release);
        if flushed == 0 && closed == 0 { 0 } else { EOF }
    }
}

/// `ftello`: the descriptor's offset (the file's end, for output pending
/// on an append stream), plus the output still buffered or less the input
/// read ahead (pushback included), as glibc's `do_ftell` counts them; a
/// stream on a capture or a pipe answers `ESPIPE`.
pub(super) fn ftello_impl(stream: *mut libc::FILE, symbol: &CStr) -> i64 {
    let s = stream_of(stream, symbol);
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry and its lock serializes the
    // buffered counts read beside the descriptor's offset.
    unsafe {
        let held = lock(s);
        // Output pending on an append stream lands at the end of the file,
        // so glibc's `do_ftell` and the BSD `_ftello` count from there.
        let pending_append =
            (*state).putting && (*state).area && (*state).used > 0 && (*state).access.append;
        let whence = if pending_append { 2 } else { 1 };
        let mut position = crate::abi::libc_result(crate::fd::seek((*state).fd, 0, whence), -1);
        if position >= 0 {
            if (*state).putting && (*state).area {
                position += (*state).used as i64;
            } else {
                position -= input::unread(s) as i64;
            }
        }
        unlock(s, held);
        position
    }
}

/// `fseeko`: write out pending output, then move the descriptor's offset (a
/// `SEEK_CUR` offset counts from the reader's position, before the input
/// read ahead); on success the input read ahead is dropped and the
/// end-of-file indicator cleared. 0, or -1 with the descriptor's error. A
/// whence other than `SEEK_SET`, `SEEK_CUR` or `SEEK_END` is `EINVAL` first.
pub(super) fn fseeko_impl(
    stream: *mut libc::FILE,
    offset: i64,
    whence: c_int,
    symbol: &CStr,
) -> c_int {
    let s = stream_of(stream, symbol);
    if !(0..=2).contains(&whence) {
        super::super::errno(libc::EINVAL);
        return -1;
    }
    let state = stream_ptr(s);
    // SAFETY: the stream is a table entry and its recursive mutex protects
    // the flush and the mode change around the descriptor seek.
    unsafe {
        let held = lock(s);
        let result = if sync(s) != 0 {
            -1
        } else {
            let back = if whence == 1 {
                input::unread(s) as i64
            } else {
                0
            };
            (*state).putting = false;
            (*state).area = false;
            let moved = crate::abi::libc_result(
                crate::fd::seek((*state).fd, offset - back, whence as u32),
                -1,
            );
            if moved < 0 {
                -1
            } else {
                input::drop_input(s);
                set_eof(s, false);
                0
            }
        };
        unlock(s, held);
        result
    }
}

#[unsafe(no_mangle)]
extern "C" fn ftello(stream: *mut libc::FILE) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ftello_impl(stream, c"ftello")
}
#[unsafe(no_mangle)]
extern "C" fn ftell(stream: *mut libc::FILE) -> libc::c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ftello_impl(stream, c"ftell")
}
#[unsafe(no_mangle)]
extern "C" fn fseeko(stream: *mut libc::FILE, offset: i64, whence: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fseeko_impl(stream, offset, whence, c"fseeko")
}
#[unsafe(no_mangle)]
extern "C" fn fseek(stream: *mut libc::FILE, offset: libc::c_long, whence: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fseeko_impl(stream, offset, whence, c"fseek")
}
/// `rewind`: `fseek` to the start, then both indicators cleared.
#[unsafe(no_mangle)]
extern "C" fn rewind(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"rewind");
    // SAFETY: the stream is a table entry; its recursive lock covers both.
    unsafe {
        let held = lock(s);
        let _ = fseeko_impl(stream, 0, 0, c"rewind");
        set_error(s, false);
        set_eof(s, false);
        unlock(s, held);
    }
}
