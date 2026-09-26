//! The Linux Security Module attribute rows (security/lsm_syscalls.c,
//! security/security.c), which need no privilege, over the declared module
//! stack ([`KERNEL_CONFIG`]`.lsm_modules`: capability, Landlock, Yama).
//!
//! Every size is a `u32`, the 6.9 fix "lsm: use 32-bit compatible data
//! types in LSM syscalls" that Ubuntu's 6.8 carries (the v6.8 tag had
//! `size_t`): a size in memory is read and written as 4 bytes, a size
//! argument's upper half is ignored. None of the declared modules keeps a
//! process attribute, so after their argument checks both attribute rows
//! answer `EOPNOTSUPP`, the default of their hooks.

use super::{Answer, refuse};
use crate::identity::Credential;
use crate::registry::KERNEL_CONFIG;
use linux_raw_sys::errno;

const LSM_ATTR_UNDEF: u32 = 0;
const LSM_FLAG_SINGLE: u32 = 1;
const LSM_ID_UNDEF: u64 = 0;

/// `struct lsm_ctx`'s header: `id`, `flags`, `len`, `ctx_len`.
type ContextHeader = [u64; 4];
const CONTEXT_HEADER_SIZE: u32 = 32;

/// `lsm_set_self_attr`'s ceiling on a context.
const PAGE_SIZE: u32 = 4096;

/// `lsm_list_modules(ids, size, flags)`: a flag is `EINVAL`; the room is
/// read (`EFAULT`) and the room needed written back; too little is `E2BIG`;
/// then each module's id, in load order, and the count.
pub(in crate::sud) fn lsm_list_modules(_: &Credential, a: &[u64; 6]) -> Answer {
    let (ids, size) = (a[0] as usize, a[1] as usize);
    if a[2] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    let Ok(room) = crate::uaccess::read::<u32>(size) else {
        return refuse(errno::EFAULT);
    };
    let modules = KERNEL_CONFIG.lsm_modules;
    let needed = size_of_val(modules) as u32;
    if crate::uaccess::write(size, &needed).is_err() {
        return refuse(errno::EFAULT);
    }
    if room < needed {
        return refuse(errno::E2BIG);
    }
    for (index, id) in modules.iter().enumerate() {
        if crate::uaccess::write(ids + index * size_of::<u64>(), id).is_err() {
            return refuse(errno::EFAULT);
        }
    }
    Ok(modules.len() as i64)
}

/// `lsm_get_self_attr(attr, ctx, size, flags)` (`security_getselfattr`):
/// `LSM_ATTR_UNDEF` and a NULL size are `EINVAL`, an unreadable size
/// `EFAULT`; a flag other than `LSM_FLAG_SINGLE`, or it without a context,
/// is `EINVAL`, its context unreadable `EFAULT`, naming no module `EINVAL`.
/// No declared module answers, so 0 bytes are written to `size` and the
/// answer is `EOPNOTSUPP`.
pub(in crate::sud) fn lsm_get_self_attr(_: &Credential, a: &[u64; 6]) -> Answer {
    let (attr, ctx, size, flags) = (a[0] as u32, a[1], a[2] as usize, a[3] as u32);
    if attr == LSM_ATTR_UNDEF || size == 0 {
        return refuse(errno::EINVAL);
    }
    if crate::uaccess::read::<u32>(size).is_err() {
        return refuse(errno::EFAULT);
    }
    if flags != 0 {
        if flags != LSM_FLAG_SINGLE || ctx == 0 {
            return refuse(errno::EINVAL);
        }
        let Ok([id, ..]) = crate::uaccess::read::<ContextHeader>(ctx as usize) else {
            return refuse(errno::EFAULT);
        };
        if id == LSM_ID_UNDEF {
            return refuse(errno::EINVAL);
        }
    }
    if crate::uaccess::write(size, &0u32).is_err() {
        return refuse(errno::EFAULT);
    }
    refuse(errno::EOPNOTSUPP)
}

/// `lsm_set_self_attr(attr, ctx, size, flags)` (`security_setselfattr`): a
/// flag is `EINVAL`; a size short of a context header `EINVAL`, past a page
/// `E2BIG`; the context's copy `EFAULT`; a `len` past the size, or short of
/// the header plus `ctx_len`, `EINVAL`. No declared module sets an
/// attribute: `EOPNOTSUPP`.
pub(in crate::sud) fn lsm_set_self_attr(_: &Credential, a: &[u64; 6]) -> Answer {
    let (ctx, size, flags) = (a[1] as usize, a[2] as u32, a[3] as u32);
    if flags != 0 || size < CONTEXT_HEADER_SIZE {
        return refuse(errno::EINVAL);
    }
    if size > PAGE_SIZE {
        return refuse(errno::E2BIG);
    }
    let Ok(context) = crate::uaccess::read_bytes(ctx, size as usize) else {
        return refuse(errno::EFAULT);
    };
    let word =
        |index: usize| u64::from_ne_bytes(context[index * 8..index * 8 + 8].try_into().unwrap());
    let (len, ctx_len) = (word(2), word(3));
    let required = u64::from(CONTEXT_HEADER_SIZE).checked_add(ctx_len);
    if u64::from(size) < len || required.is_none_or(|required| len < required) {
        return refuse(errno::EINVAL);
    }
    refuse(errno::EOPNOTSUPP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;

    /// The list is the declared stack, in load order, 8 bytes a module,
    /// into room for one more.
    #[test]
    fn list_modules_answers_the_declared_stack() {
        let declared = KERNEL_CONFIG.lsm_modules;
        let mut ids = vec![0u64; declared.len() + 1];
        let mut size = std::mem::size_of_val(ids.as_slice()) as u32;
        let listed = lsm_list_modules(
            credential(),
            &[ids.as_mut_ptr() as u64, &raw mut size as u64, 0, 0, 0, 0],
        );
        assert_eq!(listed, Ok(declared.len() as i64));
        assert_eq!(size as usize, std::mem::size_of_val(declared));
        assert_eq!(ids[..declared.len()], *declared);
        assert_eq!(ids[declared.len()], 0);
    }

    /// A context whose `len` is past the size, or short of its header plus
    /// `ctx_len` (overflow included), is refused before any module is
    /// asked.
    #[test]
    fn set_self_attr_checks_the_context_lengths() {
        let set = |header: ContextHeader| {
            lsm_set_self_attr(credential(), &[100, header.as_ptr() as u64, 32, 0, 0, 0])
        };
        assert_eq!(set([999, 0, 32, 0]), refuse(errno::EOPNOTSUPP));
        assert_eq!(set([999, 0, 40, 0]), refuse(errno::EINVAL));
        assert_eq!(set([999, 0, 32, 1]), refuse(errno::EINVAL));
        assert_eq!(set([999, 0, 32, u64::MAX]), refuse(errno::EINVAL));
    }
}
