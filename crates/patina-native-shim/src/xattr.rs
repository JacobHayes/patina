//! Extended attributes (`getxattr(2)`, `listxattr(2)`, `setxattr(2)`,
//! `removexattr(2)` and their `l*`/`f*` rows), one set of entries both doors
//! call. Linux only.
//!
//! This layer is the kernel's `fs/xattr.c` syscall half: it copies the name in
//! (1..=255 bytes, `ERANGE` otherwise), bounds a value at `XATTR_SIZE_MAX`
//! (`E2BIG`), answers the size protocol (a zero size asks for the length, a
//! short buffer is `ERANGE`), and names the node — a path resolved with or
//! without following a final symlink, or a descriptor (`fdget`: `O_PATH` is
//! `EBADF`). The refusals come in the kernel's order: `setxattr` judges its
//! flags, name and value before the path, `getxattr`/`removexattr` after it,
//! and every descriptor row resolves the descriptor first. What an attribute
//! IS — its namespace rules, the permission bits it is charged against, where
//! it is kept — is the filesystem's business; a descriptor on no filesystem
//! entry (an anonymous pipe, a socket, an eventfd) is on a pseudo-filesystem
//! with no attribute handlers.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::slice;

use patina_dst_abi::{EffectError, Fd, XattrTarget};
use patina_dst_driver_api::xattr_permission;

use crate::fdtable::FdKind;
use crate::{
    E2BIG, EFAULT, EINVAL, ENOENT, EOPNOTSUPP, ERANGE, fail, fdget, path_from_c, paths, set_errno,
    thread, with_context,
};

/// `XATTR_NAME_MAX` / `XATTR_SIZE_MAX` / `XATTR_LIST_MAX`.
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;
/// `XATTR_CREATE | XATTR_REPLACE`: the flags the set rows define.
const XATTR_FLAGS: c_int = 0x1 | 0x2;

/// Copy an attribute name in as `strncpy_from_user` into a
/// `XATTR_NAME_MAX + 1` buffer does: an empty or over-long name is `ERANGE`,
/// an unreadable one `EFAULT`.
fn copy_name(name: *const c_char) -> Result<String, c_int> {
    if name.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: a non-null name is the guest's NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    if bytes.is_empty() || bytes.len() > XATTR_NAME_MAX {
        return Err(ERANGE);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| EINVAL)
}

/// What an attribute row names.
enum Node {
    /// A node on the volume.
    Volume(XattrTarget),
    /// A descriptor on a pseudo-filesystem (pipefs, sockfs, anon_inodefs,
    /// mqueue): its node's mode, whether the node is a regular file (an
    /// mqueue inode is), and no attribute handlers.
    Pseudo { mode: u32, regular: bool },
}

/// The node a path names: resolved with or without following a final
/// symlink (the `l*` rows), and it must exist.
fn path_node(path: *const c_char, follow: bool) -> Result<Node, c_int> {
    let path = path_from_c(path)?;
    let flags = if follow { 0 } else { paths::RESOLVE_NOFOLLOW };
    let resolved = paths::resolve(paths::AT_FDCWD, &path, flags)?;
    if resolved.metadata.is_none() {
        return Err(ENOENT);
    }
    Ok(Node::Volume(XattrTarget::Path(resolved.path)))
}

/// The node a descriptor holds (`fdget`: an empty slot or an `O_PATH`
/// descriptor is `EBADF`).
fn descriptor_node(raw_fd: c_int) -> Result<Node, c_int> {
    let resolved = fdget(raw_fd)?;
    Ok(match resolved.kind {
        FdKind::File | FdKind::Dir => Node::Volume(XattrTarget::Fd(Fd(resolved.handle))),
        FdKind::Pipe => match thread::fifo_ino(raw_fd) {
            Some(ino) => Node::Volume(XattrTarget::Inode(ino)),
            None => Node::Pseudo {
                mode: thread::pipe_inode_metadata(raw_fd).map_or(ANON_INODE_MODE, |m| m.mode),
                regular: false,
            },
        },
        FdKind::OPath
        | FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::Urandom
        | FdKind::Socket
        | FdKind::EventFd
        | FdKind::TimerFd
        | FdKind::SignalFd
        | FdKind::Epoll => Node::Pseudo {
            mode: ANON_INODE_MODE,
            regular: false,
        },
        FdKind::MessageQueue => Node::Pseudo {
            mode: thread::ipc::mq_mode(resolved.handle).unwrap_or(0),
            regular: true,
        },
    })
}

/// The mode of an anonymous inode (`anon_inode_mkinode`: `S_IRUSR | S_IWUSR`).
const ANON_INODE_MODE: u32 = 0o600;

/// A pseudo-filesystem node's answer to an attribute access: the kernel's
/// judgment of it ([`xattr_permission`], the one every filesystem shares),
/// then no handler (`EOPNOTSUPP`).
fn pseudo_refusal(mode: u32, regular: bool, name: &str, write: bool) -> c_int {
    match xattr_permission(regular, mode, name, write) {
        Ok(_) => EOPNOTSUPP,
        Err(code) => crate::effect_errno(&EffectError::new(code, "")),
    }
}

/// Answer a value or a listing through the size protocol: a zero size asks
/// for the length, a buffer too short is `ERANGE`, a NULL one `EFAULT`.
fn copy_out(bytes: &[u8], buffer: *mut c_void, size: usize) -> isize {
    if size != 0 {
        if bytes.len() > size {
            return fail(ERANGE) as isize;
        }
        if buffer.is_null() {
            return fail(EFAULT) as isize;
        }
        // SAFETY: the guest's buffer is writable for `size >= bytes.len()` bytes.
        unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), bytes.len()) }
            .copy_from_slice(bytes);
    }
    set_errno(0);
    isize::try_from(bytes.len()).unwrap_or(isize::MAX)
}

/// The node `(fd, path, follow)` names: the path when `path` is non-null,
/// else the descriptor.
fn node(raw_fd: c_int, path: *const c_char, follow: c_int) -> Result<Node, c_int> {
    if path.is_null() {
        descriptor_node(raw_fd)
    } else {
        path_node(path, follow != 0)
    }
}

/// `getxattr`/`lgetxattr` (a non-null `path`, `follow` choosing) and
/// `fgetxattr` (a NULL `path`, `fd`).
///
/// # Safety
/// `path` and `name`, when non-null, must be NUL-terminated strings; `value`
/// must be writable for `size` bytes when `size` is nonzero and it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_getxattr(
    raw_fd: c_int,
    path: *const c_char,
    follow: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let node = match node(raw_fd, path, follow) {
        Ok(node) => node,
        Err(errno) => return fail(errno) as isize,
    };
    let name = match copy_name(name) {
        Ok(name) => name,
        Err(errno) => return fail(errno) as isize,
    };
    let target = match node {
        Node::Volume(target) => target,
        Node::Pseudo { mode, regular } => {
            return fail(pseudo_refusal(mode, regular, &name, false)) as isize;
        }
    };
    match with_context(|context| context.fs_get_xattr(&target, &name)) {
        Ok(bytes) => copy_out(&bytes, value, size.min(XATTR_SIZE_MAX)),
        Err(errno) => fail(errno) as isize,
    }
}

/// `listxattr`/`llistxattr`/`flistxattr`: the names, each NUL-terminated.
///
/// # Safety
/// As [`patina_getxattr`], `list` writable for `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_listxattr(
    raw_fd: c_int,
    path: *const c_char,
    follow: c_int,
    list: *mut c_void,
    size: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let target = match node(raw_fd, path, follow) {
        Ok(Node::Volume(target)) => target,
        Ok(Node::Pseudo { .. }) => return copy_out(&[], list, size),
        Err(errno) => return fail(errno) as isize,
    };
    match with_context(|context| context.fs_list_xattr(&target)) {
        Ok(bytes) => copy_out(&bytes, list, size),
        Err(errno) => fail(errno) as isize,
    }
}

/// `setxattr`/`lsetxattr` (path) and `fsetxattr` (descriptor). The path rows
/// judge the flags, the name and the value before the path; the descriptor
/// row after the descriptor.
///
/// # Safety
/// As [`patina_getxattr`], `value` readable for `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_setxattr(
    raw_fd: c_int,
    path: *const c_char,
    follow: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let descriptor = if path.is_null() {
        match descriptor_node(raw_fd) {
            Ok(node) => Some(node),
            Err(errno) => return fail(errno),
        }
    } else {
        None
    };
    if flags & !XATTR_FLAGS != 0 {
        return fail(EINVAL);
    }
    let name = match copy_name(name) {
        Ok(name) => name,
        Err(errno) => return fail(errno),
    };
    if size > XATTR_SIZE_MAX {
        return fail(E2BIG);
    }
    if size != 0 && value.is_null() {
        return fail(EFAULT);
    }
    let bytes = if size == 0 {
        &[][..]
    } else {
        // SAFETY: the guest's value is readable for `size` bytes.
        unsafe { slice::from_raw_parts(value.cast::<u8>(), size) }
    };
    let node = match descriptor {
        Some(node) => node,
        None => match path_node(path, follow != 0) {
            Ok(node) => node,
            Err(errno) => return fail(errno),
        },
    };
    let target = match node {
        Node::Volume(target) => target,
        Node::Pseudo { mode, regular } => return fail(pseudo_refusal(mode, regular, &name, true)),
    };
    match with_context(|context| context.fs_set_xattr(&target, &name, bytes, flags as u32)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `removexattr`/`lremovexattr` (path) and `fremovexattr` (descriptor).
///
/// # Safety
/// As [`patina_getxattr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_removexattr(
    raw_fd: c_int,
    path: *const c_char,
    follow: c_int,
    name: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let node = match node(raw_fd, path, follow) {
        Ok(node) => node,
        Err(errno) => return fail(errno),
    };
    let name = match copy_name(name) {
        Ok(name) => name,
        Err(errno) => return fail(errno),
    };
    let target = match node {
        Node::Volume(target) => target,
        Node::Pseudo { mode, regular } => return fail(pseudo_refusal(mode, regular, &name, true)),
    };
    match with_context(|context| context.fs_remove_xattr(&target, &name)) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ENODATA, EPERM};
    use std::ffi::CString;

    fn copied(name: &[u8]) -> Result<String, c_int> {
        let name = CString::new(name).unwrap();
        copy_name(name.as_ptr())
    }

    #[test]
    fn a_name_is_one_to_name_max_bytes() {
        assert_eq!(copied(b"user.a"), Ok("user.a".to_owned()));
        assert_eq!(copied(b""), Err(ERANGE));
        let longest = [b'n'; XATTR_NAME_MAX];
        assert_eq!(copied(&longest).map(|name| name.len()), Ok(XATTR_NAME_MAX));
        assert_eq!(copied(&[b'n'; XATTR_NAME_MAX + 1]), Err(ERANGE));
        assert_eq!(copy_name(std::ptr::null()), Err(EFAULT));
    }

    #[test]
    fn the_size_protocol_asks_for_the_length_and_refuses_a_short_buffer() {
        let mut buffer = [0u8; 4];
        assert_eq!(copy_out(b"value", std::ptr::null_mut(), 0), 5);
        assert_eq!(copy_out(b"value", buffer.as_mut_ptr().cast(), 4), -1);
        assert_eq!(crate::patina_errno(), ERANGE);
        assert_eq!(copy_out(b"val", buffer.as_mut_ptr().cast(), 4), 3);
        assert_eq!(&buffer[..3], b"val");
        assert_eq!(copy_out(b"val", std::ptr::null_mut(), 4), -1);
        assert_eq!(crate::patina_errno(), EFAULT);
    }

    /// RED before: the shim's own copy of the namespace rules never charged
    /// a name in no namespace against the node's permission bits.
    #[test]
    fn a_pseudo_filesystem_node_refuses_as_xattr_permission_does() {
        let mode = ANON_INODE_MODE;
        assert_eq!(pseudo_refusal(mode, false, "user.a", true), EPERM);
        assert_eq!(pseudo_refusal(mode, false, "user.a", false), ENODATA);
        assert_eq!(pseudo_refusal(mode, false, "trusted.a", false), ENODATA);
        assert_eq!(pseudo_refusal(mode, false, "security.a", true), EPERM);
        assert_eq!(pseudo_refusal(mode, false, "security.a", false), EOPNOTSUPP);
        assert_eq!(pseudo_refusal(mode, false, "plain", true), EOPNOTSUPP);
        assert_eq!(pseudo_refusal(0o400, false, "plain", true), crate::EACCES);
        assert_eq!(pseudo_refusal(0, false, "security.a", false), EOPNOTSUPP);
        // An mqueue inode is a regular file: `user.*` is charged against its
        // bits, and then no handler takes it.
        assert_eq!(pseudo_refusal(0o600, true, "user.a", true), EOPNOTSUPP);
        assert_eq!(pseudo_refusal(0o400, true, "user.a", true), crate::EACCES);
    }
}
