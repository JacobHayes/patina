//! Filesystem open resolution and descriptor binding.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// Bind a driver handle the filesystem just opened to a guest number. A table
/// full (`EMFILE`) closes the handle again — through the recorded close, as the
/// kernel's `fd_install` failure path releases the file — so nothing leaks.
pub(crate) fn bind_fs_handle(fd: Fd, kind: FdKind, status: u32, cloexec: bool) -> c_int {
    match install_fd(kind, fd.0, status, cloexec) {
        Ok(number) => {
            set_errno(0);
            number
        }
        Err(errno) => {
            let _ = with_context(|context| context.fs_close(fd));
            #[cfg(target_os = "linux")]
            fsnotify::unbound(fd);
            fail(errno)
        }
    }
}

/// A changed attribute of the node FIFO endpoint `raw_fd` is open on.
#[cfg(target_os = "linux")]
pub(crate) fn fifo_changed(raw_fd: c_int, mask: u32) {
    if let Ok(end) = resolve_fd(raw_fd) {
        fsnotify::fifo_changed(end.handle, mask);
    }
}

/// [`bind_fs_handle`] for a handle the filesystem opened on canonical `path`,
/// which it holds the name of (`fsnotify::bound`).
fn bound_fs_handle(fd: Fd, path: &str, kind: FdKind, status: u32, cloexec: bool) -> c_int {
    #[cfg(target_os = "linux")]
    fsnotify::bound(fd, path);
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    bind_fs_handle(fd, kind, status, cloexec)
}

/// The deny an `O_PATH|O_NOFOLLOW` open of a SYMLINK gets — the one spelling
/// that names the link entry itself, which the deterministic filesystem has no
/// descriptor for. One string, emitted from the one open entry both doors call,
/// so a raw-syscall guest and a libc guest record the same captured stderr.
pub(crate) const DENY_O_PATH_SYMLINK: &str = "patina: O_PATH|O_NOFOLLOW on a symlink is not modeled (the deterministic \
     filesystem has no descriptor for a link entry); failing closed\n";

/// A soft, diagnostic deny: the line goes to the CAPTURED stderr (the recorded
/// stream) and the call answers `ENOSYS`, exactly as the C `patina_posix_deny`
/// and the SUD `sud_deny` do.
pub(crate) fn deny(message: &str) -> c_int {
    // SAFETY: a byte slice handed to the captured-stderr entry.
    let _ = unsafe { patina_stdio_write(2, message.as_ptr().cast(), message.len()) };
    fail(ENOSYS)
}

#[unsafe(no_mangle)]
/// `openat(2)` over the deterministic filesystem: resolve `(dirfd, path)`
/// through the one resolver, then open what it names. Every success is a fresh
/// guest number from the descriptor table (lowest free, `EMFILE` past
/// `RLIMIT_NOFILE`), and the entry's KIND decides the description: a regular
/// file, a directory (whether or not `O_DIRECTORY` asked for one — the kernel
/// hands back a directory descriptor for `open(dir, O_RDONLY)` too, and it is
/// what `fchdir`, `*at` resolution and `getdents` key off), an `O_PATH`
/// location, the `/dev/urandom` device, or a FIFO's pipe endpoint.
///
/// `O_NOFOLLOW` leaves a trailing symlink unresolved, which is then `ELOOP`
/// (`cap-primitives` keys its manual symlink walk off it, and std's
/// `remove_dir_all` reads it as "not a directory"); the one exception is
/// `O_PATH|O_NOFOLLOW`, the spelling that names the link ENTRY, which has no
/// descriptor here and is a named deny. `O_DIRECTORY` on anything but a
/// directory is `ENOTDIR`; a write-mode open of a directory is `EISDIR`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    mode: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the caller.
    unsafe { open_at(dirfd, path, flags, mode, 0) }
}

#[unsafe(no_mangle)]
/// `openat2(2)` past its `struct open_how` checks: [`patina_openat`] with the
/// resolution confined by `resolve`, `PATINA_RESOLVE_*` restriction bits
/// (`paths::RESOLVE_SCOPE_FLAGS`); any other bit is `EINVAL`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
#[cfg(target_os = "linux")]
pub unsafe extern "C" fn patina_openat2(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    mode: u32,
    resolve: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if resolve & !paths::RESOLVE_SCOPE_FLAGS != 0 {
        return fail(EINVAL);
    }
    // SAFETY: forwarded from the caller.
    unsafe { open_at(dirfd, path, flags, mode, resolve) }
}

/// An open of an entry the resolver answers itself.
fn open_virtual(entry: paths::Virtual, flags: u32, cloexec: bool) -> c_int {
    match entry {
        paths::Virtual::Urandom => open_urandom(entry, flags, cloexec),
        #[cfg(target_os = "linux")]
        paths::Virtual::Namespace(index) => open_namespace(index, flags, cloexec),
        #[cfg(target_os = "linux")]
        paths::Virtual::Ptmx => thread::pty::open_master(flags, cloexec),
        #[cfg(target_os = "linux")]
        paths::Virtual::Pts(index) => thread::pty::open_slave(index, flags, cloexec),
        #[cfg(target_os = "linux")]
        paths::Virtual::Devpts => entry.unmodeled("an open"),
        #[cfg(target_os = "linux")]
        paths::Virtual::Tty => thread::pty::open_tty(flags),
    }
}

/// An open of the entropy device, a character device. On Linux, in
/// `do_open`'s order: `O_CREAT|O_EXCL` is `EEXIST`, `O_DIRECTORY` `ENOTDIR`;
/// a read-only open (`O_CREAT`, `O_TRUNC`, `O_APPEND`, `O_NONBLOCK` taken)
/// is a [`FdKind::Urandom`] description; an `O_PATH` or writing open (which
/// would feed the input pool) stops by name. On Darwin only a plain
/// read-only open is modeled; anything else is `EACCES`.
fn open_urandom(entry: paths::Virtual, flags: u32, cloexec: bool) -> c_int {
    let status = if cfg!(target_os = "linux") {
        if flags & O_PATH != 0 {
            entry.unmodeled("an O_PATH open");
        }
        if flags & (O_CREATE | O_EXCLUSIVE) == O_CREATE | O_EXCLUSIVE {
            return fail(EEXIST);
        }
        if flags & O_DIRECTORY != 0 {
            return fail(ENOTDIR);
        }
        if flags & O_WRITE != 0 {
            entry.unmodeled("an open for writing (feeding the input pool)");
        }
        O_READ | O_OPENED | (flags & (O_APPEND | O_NONBLOCK))
    } else {
        if flags & (O_WRITE | O_CREATE | O_TRUNCATE | O_APPEND | O_EXCLUSIVE | O_PATH) != 0
            || flags & O_READ == 0
        {
            return fail(EACCES);
        }
        O_READ | O_OPENED
    };
    match install_fd(FdKind::Urandom, 0, status, cloexec) {
        Ok(number) => {
            set_errno(0);
            number
        }
        Err(errno) => fail(errno),
    }
}

/// An open of a namespace file (`nsfs`): the link is followed to the
/// namespace's nsfs inode, a root-owned, immutable `0444` regular file. In
/// the kernel's order (`do_open`'s `O_DIRECTORY` check comes before
/// `may_open`'s): under `O_PATH`, `O_DIRECTORY` is `ENOTDIR`, then
/// `O_NOFOLLOW` names the link itself, which has no descriptor here (a named
/// deny), else an [`FdKind::NamespacePath`] description; otherwise
/// `O_CREAT|O_EXCL` is `EEXIST`, `O_DIRECTORY` `ENOTDIR`, `O_NOFOLLOW`
/// `ELOOP`, and write access or `O_TRUNC` `EPERM` (the inode is immutable);
/// a read-only open is a [`FdKind::Namespace`] description, `O_APPEND` and
/// `O_NONBLOCK` kept as status.
#[cfg(target_os = "linux")]
fn open_namespace(index: usize, flags: u32, cloexec: bool) -> c_int {
    let nofollow = flags & O_NOFOLLOW != 0;
    let (kind, status) = if flags & O_PATH != 0 {
        if flags & O_DIRECTORY != 0 {
            return fail(ENOTDIR);
        }
        if nofollow {
            return deny(DENY_O_PATH_SYMLINK);
        }
        (FdKind::NamespacePath, O_PATH)
    } else {
        if flags & (O_CREATE | O_EXCLUSIVE) == O_CREATE | O_EXCLUSIVE {
            return fail(EEXIST);
        }
        if flags & O_DIRECTORY != 0 {
            return fail(ENOTDIR);
        }
        if nofollow {
            return fail(ELOOP);
        }
        if flags & (O_WRITE | O_TRUNCATE) != 0 {
            return fail(EPERM);
        }
        (
            FdKind::Namespace,
            O_READ | O_OPENED | (flags & (O_APPEND | O_NONBLOCK)),
        )
    };
    nsfs::made(index);
    match install_fd(kind, index as u64, status, cloexec) {
        Ok(number) => {
            set_errno(0);
            number
        }
        Err(errno) => fail(errno),
    }
}

/// The one open behind [`patina_openat`] and `patina_openat2`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub(crate) unsafe fn open_at(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    mode: u32,
    scope: u32,
) -> c_int {
    if flags & !O_ALL != 0 {
        return fail(EINVAL);
    }
    // `O_CREAT|O_DIRECTORY` names no open (Linux `build_open_flags`, XNU
    // `open1`); under `O_PATH` the creating flag was never read.
    if flags & (O_CREATE | O_DIRECTORY | O_PATH) == O_CREATE | O_DIRECTORY {
        return fail(EINVAL);
    }
    if scope & paths::RESOLVE_CACHED != 0
        && flags & O_PATH == 0
        && flags & (O_CREATE | O_TRUNCATE) != 0
    {
        return fail(EWOULDBLOCK);
    }
    // SAFETY: `open_at`'s contract requires a readable NUL-terminated string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let nofollow = flags & O_NOFOLLOW != 0;
    let nonblocking = flags & O_NONBLOCK != 0;
    let path_only = flags & O_PATH != 0;
    let cloexec = flags & O_CLOEXEC != 0;
    let directory = flags & O_DIRECTORY != 0;
    let creating = flags & O_CREATE != 0 && !path_only;
    let resolved = match paths::resolve(
        dirfd,
        &path,
        scope | if nofollow { paths::RESOLVE_NOFOLLOW } else { 0 },
    ) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => return open_virtual(entry, flags, cloexec),
        Err(errno) => return fail(errno),
    };
    // The description's status flags as `F_GETFL` reports them: the access
    // mode, `O_APPEND`, `O_NONBLOCK`; an `O_PATH` description carries only
    // `O_PATH` (the kernel reads no access mode under it). `O_DIRECTORY` stays
    // on a description that asked for it (fs/open.c keeps it in `f_flags`,
    // under `O_PATH` too), which only a directory's can have.
    let status = if path_only {
        O_PATH | (flags & O_DIRECTORY)
    } else {
        (flags & (O_READ | O_WRITE | O_APPEND | O_NONBLOCK)) | O_OPENED
    };
    let kind = if path_only {
        FdKind::OPath
    } else {
        FdKind::File
    };
    let open_flags = OpenFlags {
        // Under `O_PATH` the kernel reads no access mode and creates nothing,
        // so neither does this: a path-only open is exactly one thing.
        read: flags & O_READ != 0 && !path_only,
        write: flags & O_WRITE != 0 && !path_only,
        create: creating,
        truncate: flags & O_TRUNCATE != 0 && !path_only,
        append: flags & O_APPEND != 0 && !path_only,
        exclusive: flags & O_EXCLUSIVE != 0 && !path_only,
        path_only,
        // POSIX reads `open`'s third argument only when the call can create the
        // entry; recording anything else here would put an argument in the trace
        // the kernel never looked at. Callers pass 0 without `O_CREAT`. The
        // process umask is applied HERE, where a kernel applies it, so the
        // driver stores — and the trace records — the mode the kernel would.
        mode: if creating {
            (mode & 0o7777) & !paths::umask()
        } else {
            0
        },
    };
    let writes = open_flags.write
        || open_flags.create
        || open_flags.truncate
        || open_flags.append
        || open_flags.exclusive;
    let entry = resolved.metadata.map(|metadata| metadata.kind);
    match entry {
        // Reachable only under `O_NOFOLLOW` (the resolver followed otherwise).
        Some(FsEntryKind::Symlink) => {
            if path_only {
                return deny(DENY_O_PATH_SYMLINK);
            }
            fail(ELOOP)
        }
        Some(FsEntryKind::Directory) => {
            // `O_PATH` opens nothing, so the kernel ignores the access mode
            // under it; a plain directory open must be read-only. The two cost
            // different things (nothing vs `r`), which is why they are two
            // driver opens.
            if !path_only && writes {
                return fail(EISDIR);
            }
            let (dir_flags, dir_status) = if path_only {
                (OpenFlags::path_only(), status)
            } else {
                (
                    OpenFlags::read_only(),
                    O_READ | O_OPENED | (flags & (O_NONBLOCK | O_DIRECTORY)),
                )
            };
            match with_context(|context| context.fs_open(&resolved.path, dir_flags)) {
                Ok(fd) => {
                    #[cfg(target_os = "linux")]
                    {
                        fsnotify::bound(fd, &resolved.path);
                        if !path_only {
                            fsnotify::opened(fd);
                        }
                    }
                    bind_fs_handle(fd, FdKind::Dir, dir_status, cloexec)
                }
                Err(errno) => fail(errno),
            }
        }
        Some(
            FsEntryKind::File | FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice,
        ) if directory => fail(ENOTDIR),
        None if directory => fail(ENOENT),
        Some(FsEntryKind::Fifo) => {
            // A FIFO has no filesystem descriptor, because its bytes are not
            // filesystem state. The driver still judges existence, resolution
            // AND permissions — and then declines to hand back a descriptor
            // (`EINVAL`), which is the seam where the pipe rendezvous begins.
            // Only an `O_PATH` open of a FIFO is a filesystem descriptor.
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => bound_fs_handle(fd, &resolved.path, kind, status, cloexec),
                Err(errno) if errno == EINVAL && !path_only => {
                    let ino = resolved.metadata.expect("a FIFO entry has metadata").ino;
                    thread::fifo_open(
                        ino,
                        &resolved.path,
                        open_flags.read,
                        open_flags.write,
                        nonblocking,
                        status,
                        cloexec,
                    )
                }
                Err(errno) => fail(errno),
            }
        }
        // A socket node or a whiteout has nothing behind it: past the
        // driver's existence and permission answers, and short of an `O_PATH`
        // descriptor, the open is the `ENXIO` the kernel's does (a socket
        // inode's `sock_no_open`, a device number no driver serves).
        Some(FsEntryKind::Socket | FsEntryKind::CharDevice) => {
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => bound_fs_handle(fd, &resolved.path, kind, status, cloexec),
                Err(errno) if errno == EINVAL && !path_only => fail(ENXIO),
                Err(errno) => fail(errno),
            }
        }
        Some(FsEntryKind::File) | None => {
            match with_context(|context| context.fs_open(&resolved.path, open_flags)) {
                Ok(fd) => {
                    // An `O_TRUNC` open of a mapped file empties its page cache.
                    #[cfg(target_os = "linux")]
                    if let (true, Some(metadata)) = (open_flags.truncate, resolved.metadata) {
                        mem::resized_ino(metadata.ino, 0);
                    }
                    // A creating open shows the new entry, then the open;
                    // an `O_TRUNC` one of an existing file the truncation
                    // after it (`handle_truncate`).
                    #[cfg(target_os = "linux")]
                    {
                        fsnotify::bound(fd, &resolved.path);
                        if resolved.metadata.is_none() {
                            fsnotify::created(&resolved.path);
                        }
                        if !path_only {
                            fsnotify::opened(fd);
                        }
                        if resolved.metadata.is_some() && open_flags.truncate {
                            fsnotify::on_handle(fd, fsnotify::IN_MODIFY);
                        }
                    }
                    bind_fs_handle(fd, kind, status, cloexec)
                }
                Err(errno) => fail(errno),
            }
        }
    }
}
