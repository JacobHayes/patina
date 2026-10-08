//! Universal and positional descriptor I/O entry points.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---------------------------------------------------------------------------
// The universal descriptor operations. Each resolves the guest number ONCE and
// dispatches on what it names; a kind that has no such operation answers what
// the kernel answers for it. These are the entries the C `read`/`write`/... and
// the SUD rows call, so the two doors share one decode.

/// Read a filesystem description directly into the caller's buffer.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
unsafe fn fs_read(fd: Fd, destination: *mut c_void, length: usize) -> isize {
    #[cfg(target_os = "linux")]
    mem::reading(fd.0);
    match with_context(|context| context.fs_read(fd, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: the caller upholds this function's buffer contract,
                // and the filesystem returns at most `length` bytes.
                unsafe {
                    slice::from_raw_parts_mut(destination.cast::<u8>(), length)[..bytes.len()]
                        .copy_from_slice(&bytes);
                }
            }
            isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// The guest's standard input: EOF, deterministically. Still a boundary call
/// (a scheduling point), as a captured-stdio write is. A `--stdin` knob feeding
/// bytes here is a later slice; the registry row's reasoning names it.
fn stdin_read() -> isize {
    if let Err(errno) = thread::sched_point() {
        return fail(errno) as isize;
    }
    set_errno(0);
    0
}

/// A read (`write` false) or write through `resolved` moved `moved` bytes:
/// when something moved on a filesystem description or a FIFO endpoint, its
/// watches see `IN_ACCESS` or `IN_MODIFY` (`fsnotify_access`/
/// `fsnotify_modify`, once per call). Answers `moved`.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(crate) fn transferred(resolved: &Resolved, moved: isize, write: bool) -> isize {
    #[cfg(target_os = "linux")]
    if moved > 0 {
        let mask = if write {
            fsnotify::IN_MODIFY
        } else {
            fsnotify::IN_ACCESS
        };
        match resolved.kind {
            FdKind::File | FdKind::Dir => fsnotify::on_file(Fd(resolved.handle), mask),
            FdKind::Pipe => fsnotify::fifo_moved(resolved.handle, mask),
            _ => {}
        }
    }
    moved
}

#[unsafe(no_mangle)]
/// Read bytes into caller-owned memory.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub unsafe extern "C" fn patina_read(
    raw_fd: c_int,
    destination: *mut c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && destination.is_null() {
        return fail(EINVAL) as isize;
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let nonblocking = resolved.status & O_NONBLOCK != 0;
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { read_resolved(resolved, destination, length, nonblocking) };
    transferred(&resolved, moved, false)
}

/// The transfer `read(2)` makes on what a number names, by kind. `nonblocking`
/// is the call's own answer to "may this wait": the description's `O_NONBLOCK`,
/// or a vectored read that already has bytes in hand.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub(crate) unsafe fn read_resolved(
    resolved: Resolved,
    destination: *mut c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    match resolved.kind {
        FdKind::Stdin => stdin_read(),
        // The captured streams are write-only, like the pipe a supervisor
        // hands a child.
        FdKind::Stdout | FdKind::Stderr => fail(EBADF) as isize,
        // Secret memory has no read operation (`FMODE_CAN_READ`).
        #[cfg(target_os = "linux")]
        FdKind::File if mem::secret(resolved.handle) => fail(EINVAL) as isize,
        FdKind::File | FdKind::Dir | FdKind::OPath => {
            // SAFETY: `read_resolved`'s caller contract keeps `destination`
            // writable for `length` bytes; this file path accesses it directly.
            unsafe { fs_read(Fd(resolved.handle), destination, length) }
        }
        FdKind::Urandom => {
            // SAFETY: forwarded from this function's own contract.
            let result = unsafe { patina_entropy(destination, length) };
            if result == 0 {
                isize::try_from(length).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
            } else {
                fail(patina_errno()) as isize
            }
        }
        // SAFETY: forwarded from this function's own contract.
        FdKind::Socket => unsafe {
            thread::net::socket_read(resolved.handle, nonblocking, destination, length)
        },
        // SAFETY: as above.
        FdKind::Pipe => unsafe {
            thread::pipe_read(resolved.handle, nonblocking, destination, length)
        },
        // SAFETY: as above.
        #[cfg(target_os = "linux")]
        FdKind::SignalFd => unsafe {
            thread::signals::fd::read(resolved.handle, nonblocking, destination, length)
        },
        #[cfg(target_os = "linux")]
        // SAFETY: forwarded from `read_resolved`'s destination-buffer contract.
        FdKind::EventFd => unsafe {
            thread::eventfd_read(resolved.handle, nonblocking, destination, length)
        },
        #[cfg(target_os = "linux")]
        FdKind::TimerFd => {
            thread::timers::timerfd_read(resolved.handle, nonblocking, destination as usize, length)
        }
        #[cfg(target_os = "linux")]
        FdKind::Inotify => {
            thread::inotify::read(resolved.handle, nonblocking, destination as usize, length)
        }
        #[cfg(target_os = "linux")]
        FdKind::Epoll | FdKind::Pidfd | FdKind::LandlockRuleset => fail(EINVAL) as isize,
        // `vfs_read` judges the buffer's range (`access_ok`) before the
        // file's own read.
        #[cfg(target_os = "linux")]
        FdKind::Userfaultfd if !uaccess::access_ok(destination as usize, length) => {
            fail(EFAULT) as isize
        }
        #[cfg(target_os = "linux")]
        FdKind::Userfaultfd => match mem::userfaultfd::read(resolved.handle, nonblocking, length) {
            Ok(read) => read as isize,
            Err(errno) => fail(errno) as isize,
        },
        // `O_PATH` opened nothing to read (`fdget`).
        #[cfg(target_os = "linux")]
        FdKind::NamespacePath => fail(EBADF) as isize,
        // An nsfs inode has no read method (`FMODE_CAN_READ`).
        #[cfg(target_os = "linux")]
        FdKind::Namespace => fail(EINVAL) as isize,
        // SAFETY: forwarded from this function's own contract.
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue if resolved.status & O_READ != 0 => unsafe {
            thread::ipc::mq_read(resolved.handle, destination, length, None)
        },
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => fail(EBADF) as isize,
        // `vfs_read`'s `FMODE_READ`, then the tty's read.
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster | FdKind::PtySlave if resolved.status & O_READ == 0 => {
            fail(EBADF) as isize
        }
        // SAFETY: forwarded from this function's own contract.
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster | FdKind::PtySlave => unsafe {
            thread::pty::read(resolved, destination, length, nonblocking)
        },
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => fail(EINVAL) as isize,
    }
}

/// Write a filesystem description directly from the caller's buffer.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
unsafe fn fs_write(fd: Fd, source: *const c_void, length: usize) -> isize {
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: the caller upholds this function's buffer contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write(fd, bytes)) {
        Ok(written) => {
            #[cfg(target_os = "linux")]
            mem::written_at_cursor(fd.0, &bytes[..written.min(bytes.len())]);
            isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

#[unsafe(no_mangle)]
/// Write bytes from caller-owned memory.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub unsafe extern "C" fn patina_write(
    raw_fd: c_int,
    source: *const c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && source.is_null() {
        return fail(EINVAL) as isize;
    }
    let resolved = match resolve_fd(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let nonblocking = resolved.status & O_NONBLOCK != 0;
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { write_resolved(resolved, source, length, nonblocking) };
    transferred(&resolved, moved, true)
}

/// The transfer `write(2)` makes on what a number names, by kind; see
/// [`read_resolved`] for `nonblocking`.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub(crate) unsafe fn write_resolved(
    resolved: Resolved,
    source: *const c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    match resolved.kind {
        FdKind::Stdin | FdKind::Urandom => fail(EBADF) as isize,
        // SAFETY: forwarded from this function's own contract.
        FdKind::Stdout | FdKind::Stderr => unsafe {
            patina_stdio_write(resolved.handle as c_int, source, length)
        },
        // Secret memory has no write operation (`FMODE_CAN_WRITE`).
        #[cfg(target_os = "linux")]
        FdKind::File if mem::secret(resolved.handle) => fail(EINVAL) as isize,
        FdKind::File | FdKind::Dir | FdKind::OPath => {
            // SAFETY: `write_resolved`'s caller contract keeps `source`
            // readable for `length` bytes; this file path accesses it directly.
            unsafe { fs_write(Fd(resolved.handle), source, length) }
        }
        // SAFETY: forwarded from this function's own contract.
        FdKind::Socket => unsafe {
            thread::net::socket_write(resolved.handle, nonblocking, source, length)
        },
        // SAFETY: as above.
        FdKind::Pipe => unsafe {
            thread::pipe_write(resolved.handle, nonblocking, source, length, false)
        },
        #[cfg(target_os = "linux")]
        // SAFETY: forwarded from `write_resolved`'s source-buffer contract.
        FdKind::EventFd => unsafe { thread::eventfd_write(resolved.handle, source, length) },
        #[cfg(target_os = "linux")]
        FdKind::Epoll
        | FdKind::SignalFd
        | FdKind::TimerFd
        | FdKind::Pidfd
        | FdKind::LandlockRuleset => fail(EINVAL) as isize,
        // Opened read-only: `vfs_write`'s `FMODE_WRITE` check refuses first.
        #[cfg(target_os = "linux")]
        FdKind::Userfaultfd => fail(EBADF) as isize,
        // Read-only (or `O_PATH`): no write access.
        #[cfg(target_os = "linux")]
        FdKind::Namespace | FdKind::NamespacePath => fail(EBADF) as isize,
        // An instance is opened `O_RDONLY`.
        #[cfg(target_os = "linux")]
        FdKind::Inotify => fail(EBADF) as isize,
        // A queue file has no write method: EBADF without write access, EINVAL
        // with it.
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue if resolved.status & O_WRITE == 0 => fail(EBADF) as isize,
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => fail(EINVAL) as isize,
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster | FdKind::PtySlave if resolved.status & O_WRITE == 0 => {
            fail(EBADF) as isize
        }
        // SAFETY: forwarded from this function's own contract.
        #[cfg(target_os = "linux")]
        FdKind::PtyMaster | FdKind::PtySlave => unsafe {
            thread::pty::write(resolved, source, length, nonblocking)
        },
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => fail(EINVAL) as isize,
    }
}

/// What a positional transfer may address: the driver handle of a regular
/// file, in the kernel's order of refusals (`ksys_pread64`/`ksys_pwrite64`):
/// a negative position is `EINVAL` before the descriptor is looked at, an
/// empty slot or an `O_PATH` descriptor is `EBADF` (`fdget`), and a
/// description without offset addressing (a pipe, a socket, the captured
/// streams) is `ESPIPE`. A directory is addressable — its refusal is the read
/// itself (`EISDIR`), or the write mode it was never opened with (`EBADF`).
pub(crate) fn positional_target(raw_fd: c_int, offset: i64) -> Result<(Resolved, u64), c_int> {
    let Ok(offset) = u64::try_from(offset) else {
        return Err(EINVAL);
    };
    let resolved = fdget(raw_fd)?;
    match resolved.kind {
        // Secret memory has no position (`FMODE_PREAD`/`FMODE_PWRITE`).
        #[cfg(target_os = "linux")]
        FdKind::File if mem::secret(resolved.handle) => Err(ESPIPE),
        // An mqueue file is positioned (it reads its status line).
        FdKind::File | FdKind::Dir => Ok((resolved, offset)),
        #[cfg(target_os = "linux")]
        FdKind::MessageQueue => Ok((resolved, offset)),
        // An nsfs inode is a regular file: positioned, but it can neither
        // be read nor (read-only) written.
        #[cfg(target_os = "linux")]
        FdKind::Namespace => Ok((resolved, offset)),
        FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket
        | FdKind::Pipe => Err(ESPIPE),
        #[cfg(target_os = "linux")]
        FdKind::EventFd
        | FdKind::Epoll
        | FdKind::SignalFd
        | FdKind::TimerFd
        | FdKind::Inotify
        | FdKind::Pidfd
        | FdKind::LandlockRuleset
        | FdKind::Userfaultfd
        | FdKind::NamespacePath
        | FdKind::PtyMaster
        | FdKind::PtySlave => Err(ESPIPE),
        #[cfg(target_os = "macos")]
        FdKind::Kqueue => Err(ESPIPE),
    }
}

/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub(crate) unsafe fn fs_pread(
    resolved: Resolved,
    destination: *mut c_void,
    length: usize,
    offset: u64,
) -> isize {
    if resolved.status & O_READ == 0 {
        return fail(EBADF) as isize;
    }
    if resolved.kind == FdKind::Dir {
        return fail(EISDIR) as isize;
    }
    #[cfg(target_os = "linux")]
    if resolved.kind == FdKind::Namespace {
        return fail(EINVAL) as isize;
    }
    #[cfg(target_os = "linux")]
    if resolved.kind == FdKind::MessageQueue {
        // SAFETY: forwarded from this function's own contract.
        return unsafe { thread::ipc::mq_read(resolved.handle, destination, length, Some(offset)) };
    }
    #[cfg(target_os = "linux")]
    mem::reading(resolved.handle);
    match with_context(|context| context.fs_read_at(Fd(resolved.handle), offset, length)) {
        Ok(bytes) => {
            if !bytes.is_empty() {
                // SAFETY: Guaranteed by this function's contract.
                unsafe {
                    slice::from_raw_parts_mut(destination.cast::<u8>(), length)[..bytes.len()]
                        .copy_from_slice(&bytes);
                }
            }
            isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

#[unsafe(no_mangle)]
/// Positional read (`pread`): read at `offset` without moving the file cursor;
/// see [`positional_target`] for the refusals.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub unsafe extern "C" fn patina_pread(
    raw_fd: c_int,
    destination: *mut c_void,
    length: usize,
    offset: i64,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    if length != 0 && destination.is_null() {
        return fail(EFAULT) as isize;
    }
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { fs_pread(resolved, destination, length, offset) };
    transferred(&resolved, moved, false)
}

/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub(crate) unsafe fn fs_pwrite(
    handle: Fd,
    source: *const c_void,
    length: usize,
    offset: i64,
) -> isize {
    let offset = match u64::try_from(offset) {
        Ok(offset) => offset,
        Err(_) => return fail(EINVAL) as isize,
    };
    let bytes = if length == 0 {
        &[]
    } else {
        // SAFETY: Guaranteed by this function's contract.
        unsafe { slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    match with_context(|context| context.fs_write_at(handle, offset, bytes)) {
        Ok(written) => {
            #[cfg(target_os = "linux")]
            mem::written(handle.0, offset, &bytes[..written.min(bytes.len())]);
            isize::try_from(written).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Where a positional write lands. On Linux a write through an `O_APPEND`
/// description goes to the end of the file whatever the position (pwrite(2)
/// BUGS: `generic_write_checks` sets the position to `i_size` under
/// `IOCB_APPEND`), and so does one carrying `RWF_APPEND`; the file's cursor
/// stays where it was either way. Darwin's `pwrite` writes at the position.
pub(crate) fn positional_write_offset(
    resolved: Resolved,
    offset: u64,
    append: bool,
) -> Result<u64, c_int> {
    let append = append || (cfg!(target_os = "linux") && resolved.status & O_APPEND != 0);
    if !append || resolved.kind != FdKind::File {
        return Ok(offset);
    }
    with_context(|context| context.fs_fd_metadata(Fd(resolved.handle))).map(|metadata| metadata.len)
}

/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
unsafe fn fs_pwrite_resolved(
    resolved: Resolved,
    source: *const c_void,
    length: usize,
    offset: u64,
    append: bool,
) -> isize {
    if resolved.status & O_WRITE == 0 {
        return fail(EBADF) as isize;
    }
    let offset = if length == 0 {
        offset
    } else {
        match positional_write_offset(resolved, offset, append) {
            Ok(offset) => offset,
            Err(errno) => return fail(errno) as isize,
        }
    };
    let Ok(offset) = i64::try_from(offset) else {
        return fail(EFBIG) as isize;
    };
    // SAFETY: forwarded from this function's own contract.
    unsafe { fs_pwrite(Fd(resolved.handle), source, length, offset) }
}

#[unsafe(no_mangle)]
/// Positional write (`pwrite`): write at `offset` without moving the file
/// cursor; see [`positional_target`] for the refusals and
/// [`positional_write_offset`] for `O_APPEND`.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub unsafe extern "C" fn patina_pwrite(
    raw_fd: c_int,
    source: *const c_void,
    length: usize,
    offset: i64,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (resolved, offset) = match positional_target(raw_fd, offset) {
        Ok(target) => target,
        Err(errno) => return fail(errno) as isize,
    };
    if length != 0 && source.is_null() {
        return fail(EFAULT) as isize;
    }
    // SAFETY: forwarded from this function's own contract.
    let moved = unsafe { fs_pwrite_resolved(resolved, source, length, offset, false) };
    transferred(&resolved, moved, true)
}
