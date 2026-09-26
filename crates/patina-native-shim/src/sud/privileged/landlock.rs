//! Landlock (security/landlock/syscalls.c), as 6.8 answers it: any caller
//! may build a ruleset; enforcing one needs `no_new_privs` or
//! `CAP_SYS_ADMIN`, and is where the model ends.
//!
//! The virtual kernel runs Landlock (it is in the declared LSM stack), at
//! ABI [`KERNEL_CONFIG`]`.landlock_abi`. A ruleset is a descriptor-table
//! kind ([`FdKind::LandlockRuleset`]), 6.8's anonymous `[landlock-ruleset]`
//! inode: read-write, close-on-exec, its read and write `EINVAL`, no seek, no
//! poll method. Its handle is the access rights it handles, which is all a
//! rule's checks read; the rules themselves are only accepted, since nothing
//! ever enforces them: `landlock_restrict_self` past its checks is a named
//! fatal.

use super::{Answer, Unmodeled, gate, refuse};
use crate::FdKind;
use crate::identity::Credential;
use crate::registry::{Capability, KERNEL_CONFIG};
use linux_raw_sys::errno;
use std::ffi::c_int;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
/// 6.15's flag, which Ubuntu's 6.8 carries.
const LANDLOCK_CREATE_RULESET_ERRATA: u32 = 2;
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;
const LANDLOCK_RULE_NET_PORT: i32 = 2;

/// `LANDLOCK_MASK_ACCESS_FS` and `LANDLOCK_MASK_ACCESS_NET` at ABI 4: the
/// filesystem rights through `LANDLOCK_ACCESS_FS_TRUNCATE` (bit 14), and
/// `BIND_TCP`/`CONNECT_TCP`.
const ACCESS_FS: u64 = (1 << 15) - 1;
const ACCESS_NET: u64 = (1 << 2) - 1;

/// `struct landlock_ruleset_attr`: the size the kernel knows, and the
/// least it takes (`handled_access_fs` alone, ABI 1's).
const RULESET_ATTR_SIZE: u64 = 16;
const RULESET_ATTR_MIN: u64 = 8;

/// `copy_min_struct_from_user`'s ceiling on a user structure.
const PAGE_SIZE: u64 = 4096;

/// A ruleset descriptor's handle: the access rights it handles.
fn ruleset_handle(fs: u64, net: u64) -> u64 {
    fs | net << 32
}

/// The filesystem and network access rights a ruleset handle names.
fn handled(handle: u64) -> (u64, u64) {
    (handle & u64::from(u32::MAX), handle >> 32)
}

/// `landlock_create_ruleset(attr, size, flags)`: a flag asks for the ABI
/// version or the errata (only with no attribute), anything else is
/// `EINVAL`; then the attribute's copy (`copy_min_struct_from_user`), its
/// rights (`EINVAL` for one the ABI does not know, `ENOMSG` for none), and a
/// new descriptor.
pub(in crate::sud) fn landlock_create_ruleset(_: &Credential, a: &[u64; 6]) -> Answer {
    let (attr, size, flags) = (a[0], a[1], a[2] as u32);
    if flags != 0 {
        return match flags {
            _ if attr != 0 || size != 0 => refuse(errno::EINVAL),
            LANDLOCK_CREATE_RULESET_VERSION => Ok(KERNEL_CONFIG.landlock_abi),
            LANDLOCK_CREATE_RULESET_ERRATA => Ok(KERNEL_CONFIG.landlock_errata),
            _ => refuse(errno::EINVAL),
        };
    }
    let (fs, net) = match copy_ruleset_attr(attr, size) {
        Ok(rights) => rights,
        Err(code) => return refuse(code as u32),
    };
    if fs & !ACCESS_FS != 0 || net & !ACCESS_NET != 0 {
        return refuse(errno::EINVAL);
    }
    if fs == 0 && net == 0 {
        return refuse(errno::ENOMSG);
    }
    let status = crate::O_READ | crate::O_WRITE;
    match crate::install_fd(
        FdKind::LandlockRuleset,
        ruleset_handle(fs, net),
        status,
        true,
    ) {
        Ok(fd) => Ok(i64::from(fd)),
        Err(code) => refuse(code as u32),
    }
}

/// `copy_min_struct_from_user` of a `struct landlock_ruleset_attr`: NULL is
/// `EFAULT` before the size is looked at; a size short of
/// `handled_access_fs` is `EINVAL`, past a page `E2BIG`; then
/// `copy_struct_from_user`: bytes past the known structure must be zero
/// (`E2BIG`), and a short structure is zero-extended.
fn copy_ruleset_attr(attr: u64, size: u64) -> Result<(u64, u64), c_int> {
    if attr == 0 {
        return Err(errno::EFAULT as c_int);
    }
    if size < RULESET_ATTR_MIN {
        return Err(errno::EINVAL as c_int);
    }
    if size > PAGE_SIZE {
        return Err(errno::E2BIG as c_int);
    }
    if size > RULESET_ATTR_SIZE {
        let rest = (size - RULESET_ATTR_SIZE) as usize;
        let tail = crate::uaccess::read_bytes((attr + RULESET_ATTR_SIZE) as usize, rest)?;
        if tail.iter().any(|&byte| byte != 0) {
            return Err(errno::E2BIG as c_int);
        }
    }
    let mut bytes = [0u8; RULESET_ATTR_SIZE as usize];
    let known = size.min(RULESET_ATTR_SIZE) as usize;
    crate::uaccess::read_into(attr as usize, &mut bytes[..known])?;
    let word = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
    Ok((word(0), word(8)))
}

/// The ruleset a descriptor holds (`get_ruleset_from_fd`): `fdget`'s
/// `EBADF` (an `O_PATH` descriptor included), then `EBADFD` for any other
/// kind. Every ruleset descriptor is read-write, so the access-mode check
/// that follows always passes.
fn ruleset(fd: c_int) -> Result<(u64, u64), c_int> {
    let resolved = crate::fdget(fd)?;
    if resolved.kind != FdKind::LandlockRuleset {
        return Err(errno::EBADFD as c_int);
    }
    Ok(handled(resolved.handle))
}

/// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`: a flag,
/// then the ruleset, then the rule type; each rule's attribute is copied
/// (`EFAULT`) and must allow something (`ENOMSG`) the ruleset handles
/// (`EINVAL`); a path rule's parent is then looked up, a port rule's port
/// bounded by 65535 (`EINVAL`).
pub(in crate::sud) fn landlock_add_rule(_: &Credential, a: &[u64; 6]) -> Answer {
    if a[3] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    let (fs, net) = match ruleset(a[0] as c_int) {
        Ok(rights) => rights,
        Err(code) => return refuse(code as u32),
    };
    let allowed_within = |allowed: u64, handled: u64| {
        if allowed == 0 {
            Err(errno::ENOMSG)
        } else if allowed & !handled != 0 {
            Err(errno::EINVAL)
        } else {
            Ok(())
        }
    };
    match a[1] as i32 {
        LANDLOCK_RULE_PATH_BENEATH => {
            // `struct landlock_path_beneath_attr` (packed): the rights, then
            // the parent descriptor.
            let Ok(rule) = crate::uaccess::read::<[u8; 12]>(a[2] as usize) else {
                return refuse(errno::EFAULT);
            };
            let allowed = u64::from_ne_bytes(rule[..8].try_into().unwrap());
            let parent = i32::from_ne_bytes(rule[8..].try_into().unwrap());
            if let Err(code) = allowed_within(allowed, fs) {
                return refuse(code);
            }
            parent_beneath(parent)
        }
        LANDLOCK_RULE_NET_PORT => {
            let Ok([allowed, port]) = crate::uaccess::read::<[u64; 2]>(a[2] as usize) else {
                return refuse(errno::EFAULT);
            };
            if let Err(code) = allowed_within(allowed, net) {
                return refuse(code);
            }
            if port > u64::from(u16::MAX) {
                return refuse(errno::EINVAL);
            }
            Ok(0)
        }
        _ => refuse(errno::EINVAL),
    }
}

/// `get_path_from_fd` of a path rule's parent: `fdget_raw` (an `O_PATH`
/// descriptor names its entry) is `EBADF` for a number not open, then a
/// ruleset, or a node on an internal filesystem or mount (an anonymous
/// pipe's pipefs, sockfs, the anonymous inodes, a queue's internal mqueue
/// mount, a memfd's shmem or hugetlbfs mount, secret memory's), is
/// `EBADFD`. An entry on the volume, a FIFO there, and `/dev/urandom` on
/// devtmpfs pass, and the rule is added.
fn parent_beneath(parent: c_int) -> Answer {
    let resolved = match crate::resolve_fd(parent) {
        Ok(resolved) => resolved,
        Err(code) => return refuse(code as u32),
    };
    match resolved.kind {
        // `memfd_create` and `memfd_secret` files live on `kern_mount`s.
        FdKind::File
            if crate::mem::anonymous(resolved.handle).is_some()
                || crate::mem::secret(resolved.handle) =>
        {
            refuse(errno::EBADFD)
        }
        FdKind::File | FdKind::Dir | FdKind::OPath | FdKind::Urandom => Ok(0),
        FdKind::Pipe => match crate::thread::pipe_filesystem(parent) {
            Some(crate::PATINA_FS_PIPEFS) => refuse(errno::EBADFD),
            Some(_) => Ok(0),
            None => refuse(errno::EBADF),
        },
        FdKind::Socket
        | FdKind::EventFd
        | FdKind::SignalFd
        | FdKind::Epoll
        | FdKind::MessageQueue
        | FdKind::TimerFd
        | FdKind::Pidfd
        | FdKind::LandlockRuleset
        | FdKind::Userfaultfd => refuse(errno::EBADFD),
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Err(Unmodeled::Path(
            "a captured standard stream as a path rule's parent (the stream has no modeled node)"
                .into(),
        )),
    }
}

/// `landlock_restrict_self(ruleset_fd, flags)` for the guest, whose
/// `no_new_privs` is prctl's.
pub(in crate::sud) fn landlock_restrict_self(credential: &Credential, a: &[u64; 6]) -> Answer {
    restrict_self_as(credential, a, super::super::no_new_privs())
}

/// `landlock_restrict_self` for a caller with `no_new_privs` as given:
/// without it, `CAP_SYS_ADMIN` (`EPERM`) before the flags and the
/// descriptor; then a flag (`EINVAL`) and the ruleset. Enforcing it is
/// where the model ends.
pub(super) fn restrict_self_as(
    credential: &Credential,
    a: &[u64; 6],
    no_new_privs: bool,
) -> Answer {
    if !no_new_privs {
        return gate(credential, Capability::SysAdmin, errno::EPERM);
    }
    if a[1] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    match ruleset(a[0] as c_int) {
        Ok(_) => Err(Unmodeled::Path(
            "enforcing a Landlock ruleset (patina does not enforce Landlock)".into(),
        )),
        Err(code) => refuse(code as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;

    /// The flags answer the ABI version and the errata only when nothing
    /// else is passed; the attribute's copy refuses in
    /// `copy_min_struct_from_user`'s order.
    #[test]
    fn create_ruleset_answers_flags_and_copies_in_order() {
        let create = |attr: u64, size: u64, flags: u64| {
            landlock_create_ruleset(credential(), &[attr, size, flags, 0, 0, 0])
        };
        assert_eq!(create(0, 0, 1), Ok(KERNEL_CONFIG.landlock_abi));
        assert_eq!(create(0, 0, 2), Ok(KERNEL_CONFIG.landlock_errata));
        assert_eq!(create(0, 0, 3), refuse(errno::EINVAL));
        assert_eq!(create(0, 8, 2), refuse(errno::EINVAL));
        static NONZERO_TAIL: [u64; 3] = [1, 0, 1];
        let attr = NONZERO_TAIL.as_ptr() as u64;
        assert_eq!(create(attr, 24, 0), refuse(errno::E2BIG));
        assert_eq!(create(0, 2, 0), refuse(errno::EFAULT));
        assert_eq!(create(8, 16, 0), refuse(errno::EFAULT));
        static UNKNOWN_NET: [u64; 2] = [1, 1 << 2];
        assert_eq!(
            create(UNKNOWN_NET.as_ptr() as u64, 16, 0),
            refuse(errno::EINVAL)
        );
    }

    /// With `no_new_privs`, the flags and the descriptor are checked, and
    /// no descriptor names a ruleset here.
    #[test]
    fn restrict_self_checks_flags_then_the_ruleset_with_no_new_privs() {
        let restrict = |fd: i32, flags: u64| {
            restrict_self_as(credential(), &[fd as u64, flags, 0, 0, 0, 0], true)
        };
        assert_eq!(restrict(-1, 1 << 31), refuse(errno::EINVAL));
        assert_eq!(restrict(-1, 0), refuse(errno::EBADF));
    }
}
