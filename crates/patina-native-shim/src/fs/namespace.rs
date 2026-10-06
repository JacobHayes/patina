//! Filesystem namespace mutation, resolution, cwd, and umask.

use super::*;

#[derive(Clone, Copy)]
enum Notice {
    /// The entry came into existence.
    Created,
    /// The entry, as resolved before, is gone.
    Removed,
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn notice(notice: Notice, resolved: &paths::Resolved) {
    #[cfg(target_os = "linux")]
    match (notice, &resolved.metadata) {
        (Notice::Created, _) => fsnotify::created(&resolved.path),
        (Notice::Removed, Some(before)) => fsnotify::removed(&resolved.path, before),
        (Notice::Removed, None) => {}
    }
}

/// Resolve `(dirfd, path)` once and run `invoke` on the canonical path; what
/// took effect is shown to the filesystem's watches as `notice`. An entry
/// the resolver answers itself exists, in a directory the caller cannot
/// write (`/dev`, `/proc/self/ns`): a creating call answers `EEXIST` (the
/// lookup finds it), a removing one `EACCES` (`may_delete`); that answer is
/// `virtual_answer`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
unsafe fn path_unit(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    virtual_answer: c_int,
    invoke: impl FnOnce(&mut Context, &str) -> Result<(), RuntimeError>,
    notice: Notice,
) -> c_int {
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        // A devpts name no pair has: nothing to remove, and no room to
        // create one (devpts's root is root's `0755`).
        Ok(paths::Resolution::Virtual(entry)) if !entry.exists() => {
            return fail(if virtual_answer == EEXIST {
                EACCES
            } else {
                ENOENT
            });
        }
        Ok(paths::Resolution::Virtual(_)) => return fail(virtual_answer),
        Err(errno) => return fail(errno),
    };
    match with_context(|context| invoke(context, &resolved.path)) {
        Ok(()) => {
            self::notice(notice, &resolved);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Create a deterministic directory (`mkdir`/`mkdirat`) at the caller's
/// requested `mode` under the process umask, exactly as the kernel applies it
/// to `mkdir(2)`. A trailing symlink is not followed: the name must be free.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_mkdir(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `vfs_mkdir` keeps the permission triads and the sticky bit of the
    // request and drops setuid/setgid: a directory never gets those from its
    // creation mode.
    let mode = (mode & 0o1777) & !paths::umask();
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            EEXIST,
            |context, path| context.fs_create_directory(path, mode),
            Notice::Created,
        )
    }
}

#[unsafe(no_mangle)]
/// Create a named pipe (`mkfifo`/`mkfifoat`, and `mknod`/`mknodat` with
/// `S_IFIFO`) at the caller's requested `mode` under the process umask. Only
/// the NAME is filesystem state, so this is one recorded boundary operation
/// and nothing else: the pipe behind the name comes into existence when the
/// first descriptor opens it, and vanishes with the last.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_mkfifo(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mode = (mode & 0o7777) & !paths::umask();
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            EEXIST,
            |context, path| context.fs_make_fifo(path, mode),
            Notice::Created,
        )
    }
}

/// `S_IFMT` and the file types a `mknod` mode carries (identical on Linux and
/// Darwin).
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;

#[unsafe(no_mangle)]
/// `mknod(2)`/`mknodat(2)`, in the kernel's order of refusals (Linux
/// `do_mknodat`): the type first (`may_mknod`: a directory is `EPERM`, an
/// unknown type `EINVAL`), then the name (`ENOENT` for a missing parent,
/// `EEXIST` for a taken name); the driver judges the rest (the parent's
/// `w`+`x`, then the `CAP_MKNOD` a device other than the whiteout needs). A
/// zero type or `S_IFREG` makes an empty regular file, `S_IFSOCK` a socket
/// node, `S_IFCHR` with device 0 a whiteout. `dev` is the kernel's 32-bit
/// device word. The mode's permission bits are applied under the process
/// umask. On Darwin (`mknod` in XNU) a FIFO is `mkfifo` and every other type
/// needs a privilege the one modeled identity lacks (`EPERM`, before the
/// path).
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_mknod(
    dirfd: c_int,
    path: *const c_char,
    mode: u32,
    dev: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let kind = mode & S_IFMT;
    if cfg!(target_os = "macos") && kind != S_IFIFO {
        return fail(EPERM);
    }
    let node = match kind {
        0 | S_IFREG => FsNode::File,
        S_IFIFO => FsNode::Fifo,
        S_IFSOCK => FsNode::Socket,
        S_IFCHR if dev == 0 => FsNode::Whiteout,
        S_IFCHR => FsNode::CharDevice { device: dev },
        S_IFBLK => FsNode::BlockDevice { device: dev },
        S_IFDIR => return fail(EPERM),
        _ => return fail(EINVAL),
    };
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let resolved = match paths::resolve(dirfd, &spelled, paths::RESOLVE_NOFOLLOW) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) if !entry.exists() => return fail(EACCES),
        // It exists.
        Ok(paths::Resolution::Virtual(_)) => return fail(EEXIST),
        Err(errno) => return fail(errno),
    };
    if resolved.metadata.is_some() || paths::last_component(&spelled) != paths::Last::Name {
        return fail(EEXIST);
    }
    let mode = (mode & 0o7777) & !paths::umask();
    let result = if node == FsNode::Fifo {
        with_context(|context| context.fs_make_fifo(&resolved.path, mode))
    } else {
        with_context(|context| context.fs_make_node(&resolved.path, node, mode))
    };
    match result {
        Ok(()) => {
            notice(Notice::Created, &resolved);
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Remove a name (`unlink`/`unlinkat`). Never follows a trailing symlink: the
/// link entry itself is what goes. A final `.`, `..` or `/` names no entry to
/// unlink: `EISDIR` once the parent resolved (`do_unlinkat`).
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_unlink(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::final_component(dirfd, &spelled) {
        Ok(paths::Last::Name) => {}
        Ok(paths::Last::Dot | paths::Last::DotDot | paths::Last::Root) => return fail(EISDIR),
        Err(errno) => return fail(errno),
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            EACCES,
            Context::fs_remove_file,
            Notice::Removed,
        )
    }
}

#[unsafe(no_mangle)]
/// Remove an empty deterministic directory (`rmdir`/`unlinkat(AT_REMOVEDIR)`).
/// A final component that names no entry is refused once the parent resolved
/// (`do_rmdir`): `.` is `EINVAL`, `..` is `ENOTEMPTY` (the directory it names
/// holds at least the one it was reached through), the root `EBUSY`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_rmdir(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let spelled = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::final_component(dirfd, &spelled) {
        Ok(paths::Last::Name) => {}
        Ok(paths::Last::Dot) => return fail(EINVAL),
        Ok(paths::Last::DotDot) => return fail(ENOTEMPTY),
        Ok(paths::Last::Root) => return fail(EBUSY),
        Err(errno) => return fail(errno),
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            path,
            paths::RESOLVE_NOFOLLOW,
            EACCES,
            Context::fs_remove_directory,
            Notice::Removed,
        )
    }
}

/// `renameat2(2)`'s flags (Linux values).
pub(crate) const RENAME_NOREPLACE: u32 = 1 << 0;
pub(crate) const RENAME_EXCHANGE: u32 = 1 << 1;
pub(crate) const RENAME_WHITEOUT: u32 = 1 << 2;

/// Judge a `renameat2` flag word as `do_renameat2` does before any path is
/// looked at: an unknown bit, or `RENAME_EXCHANGE` with either of the others,
/// is `EINVAL`.
pub(crate) fn rename_flags_valid(flags: u32) -> bool {
    flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) == 0
        && !(flags & RENAME_EXCHANGE != 0 && flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0)
}

#[cfg(test)]
mod open_flag_tests {
    use super::*;

    /// RED before: the shared open read `O_CREAT|O_DIRECTORY` as a directory
    /// open and went on to resolve the path (here `ENAMETOOLONG`).
    #[test]
    fn a_creating_directory_open_is_einval_before_the_path() {
        let long = std::ffi::CString::new("a".repeat(paths::PATH_MAX)).unwrap();
        let flags = O_READ | O_CREATE | O_DIRECTORY;
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(
            unsafe { patina_openat(-1, long.as_ptr(), flags, 0o644) },
            -1
        );
        assert_eq!(patina_errno(), EINVAL);
    }
}

#[cfg(test)]
mod rename_flag_tests {
    use super::*;

    #[test]
    fn renameat2_flags_are_judged_as_do_renameat2_judges_them() {
        for accepted in [
            0,
            RENAME_NOREPLACE,
            RENAME_EXCHANGE,
            RENAME_WHITEOUT,
            RENAME_NOREPLACE | RENAME_WHITEOUT,
        ] {
            assert!(
                rename_flags_valid(accepted),
                "{accepted:#x} is a kernel flag set"
            );
        }
        for refused in [
            RENAME_NOREPLACE | RENAME_EXCHANGE,
            RENAME_WHITEOUT | RENAME_EXCHANGE,
            1 << 3,
            RENAME_NOREPLACE | 1 << 31,
        ] {
            assert!(!rename_flags_valid(refused), "{refused:#x} is EINVAL");
        }
    }
}

#[unsafe(no_mangle)]
/// Rename a deterministic filesystem entry (`rename`/`renameat`, which pass no
/// flags, and `renameat2`). Neither side follows a trailing symlink: the kernel
/// renames link entries as entries. The refusals come in `do_renameat2`'s
/// order: the flag word, both paths' parents, a final `.`/`..`/`/` on either
/// side (`EBUSY`; `EEXIST` on the destination under `RENAME_NOREPLACE`), a
/// missing source (`ENOENT`), then the flag's own rule — `RENAME_NOREPLACE`
/// refuses an existing destination (`EEXIST`), `RENAME_EXCHANGE` needs one
/// (`ENOENT`) and swaps the two entries atomically, `RENAME_WHITEOUT` leaves a
/// whiteout (a 0:0 character device) at the old name — and last the rename's
/// own (`EISDIR`, `ENOTDIR`, `ENOTEMPTY`, `EINVAL` into itself).
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
pub unsafe extern "C" fn patina_renameat2(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !rename_flags_valid(flags) {
        return fail(EINVAL);
    }
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let (from_last, to_last) = match (
        paths::final_component(fromfd, &from),
        paths::final_component(tofd, &to),
    ) {
        (Ok(from_last), Ok(to_last)) => (from_last, to_last),
        (Err(errno), _) | (_, Err(errno)) => return fail(errno),
    };
    if from_last != paths::Last::Name {
        return fail(EBUSY);
    }
    if to_last != paths::Last::Name {
        return fail(if flags & RENAME_NOREPLACE != 0 {
            EEXIST
        } else {
            EBUSY
        });
    }
    let from = match paths::resolve(fromfd, &from, paths::RESOLVE_NOFOLLOW) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => entry.unmodeled("renaming"),
        Err(errno) => return fail(errno),
    };
    let to = match paths::resolve(tofd, &to, paths::RESOLVE_NOFOLLOW) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => entry.unmodeled("renaming onto"),
        Err(errno) => return fail(errno),
    };
    if from.metadata.is_none() {
        return fail(ENOENT);
    }
    let exchange = flags & RENAME_EXCHANGE != 0;
    let result = if exchange {
        if to.metadata.is_none() {
            return fail(ENOENT);
        }
        with_context(|context| context.fs_exchange(&from.path, &to.path))
    } else if flags & RENAME_NOREPLACE != 0 && to.metadata.is_some() {
        Err(EEXIST)
    } else if flags & RENAME_WHITEOUT != 0 {
        with_context(|context| context.fs_rename_whiteout(&from.path, &to.path))
    } else {
        with_context(|context| context.fs_rename(&from.path, &to.path))
    };
    match result {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            if let Some(source) = &from.metadata {
                match (exchange, &to.metadata) {
                    (true, Some(other)) => fsnotify::exchanged(&from.path, &to.path, source, other),
                    (_, target) => fsnotify::moved(&from.path, &to.path, source, target.as_ref()),
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = exchange;
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Create a deterministic symbolic link (`symlink`/`symlinkat`). Only the LINK
/// side resolves — `target` is the link's literal contents, stored verbatim —
/// and an empty target is `ENOENT`, as `symlink(2)` answers.
///
/// # Safety
/// `target` and `link_path` must point to valid NUL-terminated UTF-8 strings.
pub unsafe extern "C" fn patina_symlink(
    target: *const c_char,
    dirfd: c_int,
    link_path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let target = match path_from_c(target) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    if target.is_empty() {
        return fail(ENOENT);
    }
    // SAFETY: Forwarded from this function's C ABI contract.
    unsafe {
        path_unit(
            dirfd,
            link_path,
            paths::RESOLVE_NOFOLLOW,
            EEXIST,
            |context, link_path| context.fs_symlink(&target, link_path),
            Notice::Created,
        )
    }
}

#[unsafe(no_mangle)]
/// Create a deterministic hard link (`link`/`linkat`). The driver shares one
/// inode between `from` and `to`, or duplicates the symlink entry when `from`
/// is itself a symlink — the POSIX "hard link the symlink itself" behavior of
/// `linkat` without `AT_SYMLINK_FOLLOW`. With `follow` nonzero `from`'s
/// trailing symlink is resolved first, so the link targets the resolved file.
///
/// # Safety
/// `from` and `to` must point to valid NUL-terminated UTF-8 strings.
pub unsafe extern "C" fn patina_link(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    follow: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let from = match path_from_c(from) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let to = match path_from_c(to) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    let from_flags = if follow != 0 {
        0
    } else {
        paths::RESOLVE_NOFOLLOW
    };
    let from = match paths::resolve(fromfd, &from, from_flags) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        Ok(paths::Resolution::Virtual(entry)) => entry.unmodeled("linking"),
        Err(errno) => return fail(errno),
    };
    let to = match paths::resolve(tofd, &to, paths::RESOLVE_NOFOLLOW) {
        Ok(paths::Resolution::Volume(resolved)) => resolved.path,
        Ok(paths::Resolution::Virtual(entry)) if !entry.exists() => return fail(EACCES),
        // The new name exists (`filename_create`).
        Ok(paths::Resolution::Virtual(_)) => return fail(EEXIST),
        Err(errno) => return fail(errno),
    };
    match with_context(|context| context.fs_link(&from.path, &to)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            if let Some(source) = &from.metadata {
                fsnotify::linked(source, &to);
            }
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// Read a deterministic symbolic link's target bytes (`readlink`/
/// `readlinkat`). An empty path names the descriptor itself, as the kernel's
/// `readlinkat` allows; a name that is not a symlink is `EINVAL`, a zero-length
/// buffer is `EINVAL`. Returns the byte count copied, with no trailing NUL.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string and `buf` must be
/// writable for `len` bytes.
pub unsafe extern "C" fn patina_read_link(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // Bootstrap window (see `SHIM_BOOTSTRAP`): this is an allocator's init-time
    // config probe — tikv-jemallocator's `obtain_malloc_conf` does
    // `readlink("/etc/malloc.conf")` while holding its init lock. The deterministic
    // FS carries no such file, and — crucially — this MUST NOT allocate (the
    // `String` path would re-enter the half-initialized guest allocator and trip its
    // non-recursive init lock / deadlock), so answer ENOENT without building a path
    // or touching the runtime. A guest's own deterministic `read_link` runs after
    // bootstrap and is unaffected.
    if in_shim_bootstrap() {
        return fail(ENOENT) as isize;
    }
    if len == 0 || buf.is_null() {
        return fail(EINVAL) as isize;
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    // A descriptor whose node is not on the volume (a namespace file's nsfs
    // inode, the entropy device, a pipe, a socket, an anonymous inode) names
    // no link: an empty path is `ENOENT` (`do_readlinkat`).
    #[cfg(target_os = "linux")]
    if path.is_empty()
        && resolve_fd(dirfd).is_ok_and(|resolved| {
            !matches!(resolved.kind, FdKind::File | FdKind::Dir | FdKind::OPath)
        })
    {
        return fail(ENOENT) as isize;
    }
    let resolved = match paths::resolve(
        dirfd,
        &path,
        paths::RESOLVE_NOFOLLOW | paths::RESOLVE_EMPTY_PATH,
    ) {
        Ok(paths::Resolution::Volume(resolved)) => resolved,
        // The entropy device is no link.
        Ok(paths::Resolution::Virtual(paths::Virtual::Urandom)) => {
            return fail(EINVAL) as isize;
        }
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(paths::Virtual::Namespace(index))) => {
            return read_namespace_link(index, buf, len);
        }
        // The terminal nodes and devpts's root are no links either.
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(entry)) => {
            return fail(if entry.exists() { EINVAL } else { ENOENT }) as isize;
        }
        Err(errno) => return fail(errno) as isize,
    };
    match resolved.metadata.map(|metadata| metadata.kind) {
        None => return fail(ENOENT) as isize,
        Some(FsEntryKind::Symlink) => {}
        // The descriptor's own node, named by an empty path, is no link:
        // `ENOENT` rather than `EINVAL` (`do_readlinkat`).
        Some(_) if path.is_empty() => return fail(ENOENT) as isize,
        Some(
            FsEntryKind::File
            | FsEntryKind::Directory
            | FsEntryKind::Fifo
            | FsEntryKind::Socket
            | FsEntryKind::CharDevice,
        ) => {
            return fail(EINVAL) as isize;
        }
    }
    match with_context(|context| context.fs_read_link(&resolved.path)) {
        Ok(target) => {
            let bytes = target.as_bytes();
            let copied = bytes.len().min(len);
            // SAFETY: The destination buffer was checked and is required to be
            // writable for `len` bytes by this function's C ABI.
            unsafe {
                slice::from_raw_parts_mut(buf.cast::<u8>(), len)[..copied]
                    .copy_from_slice(&bytes[..copied]);
            }
            set_errno(0);
            isize::try_from(copied).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
        }
        Err(errno) => fail(errno) as isize,
    }
}

/// Copy a NUL-terminated `path` into `buf` when it fits, returning its length
/// in bytes (excluding the terminator); `ERANGE` when `len` is nonzero and too
/// small. With `len == 0` only the length is reported.
fn copy_path_out(path: &str, buf: *mut c_char, len: usize) -> isize {
    let bytes = path.as_bytes();
    if len != 0 {
        if buf.is_null() {
            return fail(EINVAL) as isize;
        }
        if bytes.len() >= len {
            return fail(ERANGE) as isize;
        }
        // SAFETY: The destination is writable for `len` bytes by the C ABI
        // contract, and `bytes.len() < len` leaves room for the terminator.
        unsafe {
            let destination = slice::from_raw_parts_mut(buf.cast::<u8>(), len);
            destination[..bytes.len()].copy_from_slice(bytes);
            destination[bytes.len()] = 0;
        }
    }
    set_errno(0);
    isize::try_from(bytes.len()).unwrap_or_else(|_| fail(EOVERFLOW) as isize)
}

#[unsafe(no_mangle)]
/// The one path resolver, exported for the caller that wants the canonical
/// NAME rather than an operation on it (`realpath`). Resolves `(dirfd, path)` — the
/// working directory for `PATINA_AT_FDCWD`, a directory descriptor's node
/// otherwise — applying `.`/`..` to the resolved directory, walking symlinks to
/// the kernel's 40-hop `ELOOP` limit, and answering `ENAMETOOLONG`, `ENOTDIR`
/// for a component through a non-directory, and the trailing-slash rule.
/// `flags` are `PATINA_RESOLVE_*`. Writes the NUL-terminated canonical path
/// into `buf` when it fits and returns its length; `*kind` receives the final
/// entry's `PATINA_ENTRY_*` kind, or 0 when the final component does not
/// exist.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string, `buf` must be
/// writable for `len` bytes when `len` is nonzero, and `kind` must be writable.
pub unsafe extern "C" fn patina_resolve_path(
    dirfd: c_int,
    path: *const c_char,
    flags: u32,
    buf: *mut c_char,
    len: usize,
    kind: *mut u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !paths::RESOLVE_AT_FLAGS != 0 || kind.is_null() {
        return fail(EINVAL) as isize;
    }
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno) as isize,
    };
    let (path, found) = match paths::resolve(dirfd, &path, flags) {
        Ok(paths::Resolution::Volume(resolved)) => (
            resolved.path,
            resolved
                .metadata
                .map_or(0, |metadata| metadata_kind(metadata.kind)),
        ),
        // The entropy device is a character device at its own name.
        Ok(paths::Resolution::Virtual(entry @ paths::Virtual::Urandom)) => {
            (entry.path(), PATINA_ENTRY_CHAR)
        }
        // A namespace file's link names no path (it reads `<type>:[<inode>]`).
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(entry @ paths::Virtual::Namespace(_))) => {
            entry.unmodeled("the canonical path")
        }
        // The pseudoterminal nodes are character devices at their own names,
        // devpts's root a directory.
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(entry @ (paths::Virtual::Ptmx | paths::Virtual::Pts(_)))) => {
            (
                entry.path(),
                if entry.exists() { PATINA_ENTRY_CHAR } else { 0 },
            )
        }
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(entry @ paths::Virtual::Devpts)) => {
            (entry.path(), PATINA_ENTRY_DIRECTORY)
        }
        #[cfg(target_os = "linux")]
        Ok(paths::Resolution::Virtual(entry @ paths::Virtual::Tty)) => {
            entry.unmodeled("the canonical path")
        }
        Err(errno) => return fail(errno) as isize,
    };
    // SAFETY: `kind` was checked non-null and is writable per the C ABI.
    unsafe { kind.write(found) };
    copy_path_out(&path, buf, len)
}

#[unsafe(no_mangle)]
/// `getcwd(2)`: where the working directory's NODE is now, NUL-terminated in
/// `buf` when it fits (`ERANGE` otherwise; `len == 0` reports the length
/// alone), returning the length. `ENOENT` once the directory has been
/// unlinked, exactly as Linux answers.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is nonzero.
pub unsafe extern "C" fn patina_getcwd(buf: *mut c_char, len: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match paths::cwd_path() {
        Ok(path) => copy_path_out(&path, buf, len),
        Err(errno) => fail(errno) as isize,
    }
}

#[unsafe(no_mangle)]
/// `chdir(2)`: resolve `(dirfd, path)` (symlinks followed) and make the
/// directory it names the working directory. `ENOENT` for a missing name,
/// `ENOTDIR` for anything but a directory, `EACCES` for one the modeled
/// identity cannot search.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn patina_chdir(dirfd: c_int, path: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::chdir(dirfd, &path) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `fchdir(2)`: a directory descriptor — opened plainly or `O_PATH` — becomes
/// the working directory. `EBADF` for a number that names nothing, `ENOTDIR`
/// for any other kind.
pub extern "C" fn patina_fchdir(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match paths::fchdir(raw_fd) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `umask(2)`: install `mask` (its permission bits) as the process umask every
/// creating entry applies, and return the previous one. Never fails.
pub extern "C" fn patina_umask(mask: u32) -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    set_errno(0);
    paths::set_umask(mask)
}
