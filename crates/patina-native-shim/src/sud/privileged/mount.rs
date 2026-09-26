//! The mount rows (fs/namespace.c, fs/fsopen.c): the legacy `mount` and
//! `umount2`, the descriptor mount API, and `pivot_root`. Every row but
//! `fsconfig` and a non-cloning `open_tree` needs `CAP_SYS_ADMIN` in the
//! mount namespace's user namespace (`may_mount`), after the checks listed
//! on each. `fsconfig` needs a filesystem-context descriptor, which only
//! `fsopen` and `fspick` create, so every descriptor the model can hold is
//! refused.

use super::{Answer, Unmodeled, gate, lookup, refuse};
use crate::FdKind;
use crate::identity::Credential;
use crate::registry::Capability;
use linux_raw_sys::errno;
use linux_raw_sys::general::{
    AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW, MNT_DETACH,
    MNT_EXPIRE, MNT_FORCE, MOUNT_ATTR_SIZE_VER0, MS_MGC_MSK, MS_MGC_VAL, MS_NOUSER,
    OPEN_TREE_CLOEXEC, OPEN_TREE_CLONE, PATH_MAX, UMOUNT_NOFOLLOW, fsconfig_command,
};
use std::ffi::{CStr, c_char, c_int};

/// `copy_mount_string`: NULL is no string; otherwise `strndup_user`'s
/// `EFAULT` (unreadable) or `EINVAL` (longer than `PATH_MAX`).
fn copy_mount_string(address: u64) -> Result<(), c_int> {
    if address == 0 {
        return Ok(());
    }
    crate::uaccess::read::<u8>(address as usize)?;
    // SAFETY: the guest's NUL-terminated string; its first byte is readable.
    let length = unsafe { CStr::from_ptr(address as *const c_char) }.count_bytes();
    if length >= PATH_MAX as usize {
        return Err(errno::EINVAL as c_int);
    }
    Ok(())
}

/// `copy_mount_options`: NULL is no options; otherwise `EFAULT` only when
/// not one byte of the page can be read.
fn copy_mount_options(address: u64) -> Result<(), c_int> {
    if address == 0 {
        return Ok(());
    }
    crate::uaccess::read::<u8>(address as usize).map(drop)
}

/// `mount(source, target, type, flags, data)`: the type, source and options
/// are copied in, the target looked up (following links), `MS_NOUSER`
/// refused (after the old magic is discarded), then `may_mount`.
pub(in crate::sud) fn mount(credential: &Credential, a: &[u64; 6]) -> Answer {
    mount_finding(credential, a, |target| lookup(target, true).map(drop))
}

/// [`mount`], its target found by `find`.
pub(super) fn mount_finding(
    credential: &Credential,
    a: &[u64; 6],
    find: impl FnOnce(u64) -> Result<(), c_int>,
) -> Answer {
    let copied = copy_mount_string(a[2])
        .and_then(|()| copy_mount_string(a[0]))
        .and_then(|()| copy_mount_options(a[4]))
        .and_then(|()| find(a[1]));
    if let Err(code) = copied {
        return refuse(code);
    }
    let mut flags = a[3];
    if flags & u64::from(MS_MGC_MSK) == u64::from(MS_MGC_VAL) {
        flags &= !u64::from(MS_MGC_MSK);
    }
    if flags & u64::from(MS_NOUSER) != 0 {
        return refuse(errno::EINVAL);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `umount2(target, flags)` (`ksys_umount`): an unknown flag, then the
/// lookup (`UMOUNT_NOFOLLOW` leaves a final link unfollowed), then
/// `may_mount` (`can_umount`), before whether the path is a mount at all.
pub(in crate::sud) fn umount2(credential: &Credential, a: &[u64; 6]) -> Answer {
    umount2_finding(credential, a, |target, follow| {
        lookup(target, follow).map(drop)
    })
}

/// [`umount2`], its target found by `find` (following a final link or not).
pub(super) fn umount2_finding(
    credential: &Credential,
    a: &[u64; 6],
    find: impl FnOnce(u64, bool) -> Result<(), c_int>,
) -> Answer {
    let flags = a[1] as u32;
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return refuse(errno::EINVAL);
    }
    if let Err(code) = find(a[0], flags & UMOUNT_NOFOLLOW == 0) {
        return refuse(code);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `fsopen`, `fspick`, `fsmount`, `move_mount` and `pivot_root` (up to 7.0,
/// which looks its paths up first): `may_mount` before any argument.
pub(in crate::sud) fn may_mount(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `mount_setattr(dfd, path, flags, attr, size)`: an unknown flag, a size
/// past a page (`E2BIG`) or short of `MOUNT_ATTR_SIZE_VER0`, then
/// `may_mount`, before the attributes are read or the path looked up.
pub(in crate::sud) fn mount_setattr(credential: &Credential, a: &[u64; 6]) -> Answer {
    let flags = a[2] as u32;
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return refuse(errno::EINVAL);
    }
    if a[4] > crate::PAGE_SIZE as u64 {
        return refuse(errno::E2BIG);
    }
    if a[4] < u64::from(MOUNT_ATTR_SIZE_VER0) {
        return refuse(errno::EINVAL);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `open_tree(dfd, path, flags)`: an unknown flag, `AT_RECURSIVE` without
/// `OPEN_TREE_CLONE`, then — for a clone — `may_mount`, before a
/// descriptor is allocated or the path looked up. Without a clone any
/// caller may: it is `dentry_open(O_PATH)` of what the lookup finds, the
/// `O_PATH` open `openat` makes, following a final link unless
/// `AT_SYMLINK_NOFOLLOW`, the descriptor's own node for an empty path under
/// `AT_EMPTY_PATH`, and close-on-exec under `OPEN_TREE_CLOEXEC`.
pub(in crate::sud) fn open_tree(credential: &Credential, a: &[u64; 6]) -> Answer {
    let flags = a[2] as u32;
    let known = AT_EMPTY_PATH
        | AT_NO_AUTOMOUNT
        | AT_RECURSIVE
        | AT_SYMLINK_NOFOLLOW
        | OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC;
    if flags & !known != 0 {
        return refuse(errno::EINVAL);
    }
    if flags & (AT_RECURSIVE | OPEN_TREE_CLONE) == AT_RECURSIVE {
        return refuse(errno::EINVAL);
    }
    if flags & OPEN_TREE_CLONE != 0 {
        return gate(credential, Capability::SysAdmin, errno::EPERM);
    }
    let (dirfd, address) = (a[0] as c_int, a[1]);
    let path = match crate::sud::guest_path(address) {
        Ok(path) => path,
        Err(code) => return Ok(code),
    };
    if crate::sud::is_empty_path(address, u64::from(flags)) && dirfd != AT_FDCWD {
        match crate::resolve_fd(dirfd) {
            Err(code) => return refuse(code),
            Ok(resolved)
                if !matches!(resolved.kind, FdKind::File | FdKind::Dir | FdKind::OPath) =>
            {
                return Err(Unmodeled::Path(
                    "an open_tree of a descriptor that names no filesystem entry".into(),
                ));
            }
            Ok(_) => {}
        }
    }
    let mut open = crate::O_PATH;
    if flags & OPEN_TREE_CLOEXEC != 0 {
        open |= crate::O_CLOEXEC;
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        open |= crate::O_NOFOLLOW;
    }
    let scope = if flags & AT_EMPTY_PATH != 0 {
        crate::paths::RESOLVE_EMPTY_PATH
    } else {
        0
    };
    // SAFETY: `path` is the guest's non-null, NUL-terminated string.
    Ok(crate::sud::ret_i32(unsafe {
        crate::open_at(dirfd, path, open, 0, scope)
    }))
}

/// `fsconfig`'s commands.
const FSCONFIG_SET_FLAG: u32 = fsconfig_command::FSCONFIG_SET_FLAG as u32;
const FSCONFIG_SET_STRING: u32 = fsconfig_command::FSCONFIG_SET_STRING as u32;
const FSCONFIG_SET_BINARY: u32 = fsconfig_command::FSCONFIG_SET_BINARY as u32;
const FSCONFIG_SET_PATH: u32 = fsconfig_command::FSCONFIG_SET_PATH as u32;
const FSCONFIG_SET_PATH_EMPTY: u32 = fsconfig_command::FSCONFIG_SET_PATH_EMPTY as u32;
const FSCONFIG_SET_FD: u32 = fsconfig_command::FSCONFIG_SET_FD as u32;
const FSCONFIG_CMD_CREATE: u32 = fsconfig_command::FSCONFIG_CMD_CREATE as u32;
const FSCONFIG_CMD_RECONFIGURE: u32 = fsconfig_command::FSCONFIG_CMD_RECONFIGURE as u32;
const FSCONFIG_CMD_CREATE_EXCL: u32 = fsconfig_command::FSCONFIG_CMD_CREATE_EXCL as u32;

/// `fsconfig(fd, cmd, key, value, aux)` (fs/fsopen.c): a negative
/// descriptor, an unknown command (`EOPNOTSUPP`), a key, value or aux the
/// command does not take (`EINVAL`), a descriptor not open for use
/// (`EBADF`, `O_PATH` too), then one that is no filesystem context
/// (`EINVAL`): every descriptor the model can hold, since only `fsopen` and
/// `fspick` make one.
pub(in crate::sud) fn fsconfig(_: &Credential, a: &[u64; 6]) -> Answer {
    let fd = a[0] as i32;
    if fd < 0 {
        return refuse(errno::EINVAL);
    }
    let (key, value, aux) = (a[2] != 0, a[3] != 0, a[4] as i32);
    let shaped = match a[1] as u32 {
        FSCONFIG_SET_FLAG => key && !value && aux == 0,
        FSCONFIG_SET_STRING => key && value && aux == 0,
        FSCONFIG_SET_BINARY => key && value && aux > 0 && aux <= 1024 * 1024,
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            key && value && (aux == AT_FDCWD || aux >= 0)
        }
        FSCONFIG_SET_FD => key && !value && aux >= 0,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_RECONFIGURE | FSCONFIG_CMD_CREATE_EXCL => {
            !key && !value && aux == 0
        }
        _ => return refuse(errno::EOPNOTSUPP),
    };
    if !shaped {
        return refuse(errno::EINVAL);
    }
    match crate::fdget(fd) {
        Err(code) => refuse(code),
        // No kind the model has is a filesystem context: a new kind must
        // decide here whether it is one.
        Ok(resolved) => match resolved.kind {
            FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::File
            | FdKind::Dir
            | FdKind::OPath
            | FdKind::Urandom
            | FdKind::Socket
            | FdKind::Pipe
            | FdKind::EventFd
            | FdKind::SignalFd
            | FdKind::Epoll
            | FdKind::MessageQueue
            | FdKind::TimerFd
            | FdKind::Pidfd
            | FdKind::LandlockRuleset => refuse(errno::EINVAL),
        },
    }
}
