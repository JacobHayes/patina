//! Anonymous files: `memfd_create(2)` over the deterministic filesystem and
//! the `fcntl` seal commands.
//!
//! The virtual kernel runs with `vm.memfd_noexec = 0` and reserves no huge
//! pages: a memfd is executable (`0o777`, no umask) unless `MFD_NOEXEC_SEAL`
//! asks otherwise, and `MFD_HUGETLB` makes a hugetlbfs file that exists but
//! can never hold a page (see [`super::huge_page_size`]).

use super::{Mappings, huge_page_size};
use crate::fdtable::FdKind;
use crate::{EBADF, EINVAL, SpinMutex};
use patina_dst_abi::Fd;
use patina_dst_abi::seals::{F_ALL_SEALS, F_SEAL_EXEC, F_SEAL_SEAL};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int};

/// `memfd_create(2)` flags (uapi/linux/memfd.h).
const MFD_CLOEXEC: u32 = 0x1;
const MFD_ALLOW_SEALING: u32 = 0x2;
const MFD_HUGETLB: u32 = 0x4;
const MFD_NOEXEC_SEAL: u32 = 0x8;
const MFD_EXEC: u32 = 0x10;
const MFD_ALL_FLAGS: u32 =
    MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
/// The huge-page size field `MFD_HUGETLB` may carry.
const MFD_HUGE_SHIFT: u32 = 26;
const MFD_HUGE_MASK: u32 = 0x3f;
/// `MFD_NAME_MAX_LEN`: `NAME_MAX` less the `memfd:` prefix.
const MFD_NAME_MAX_LEN: usize = 249;

/// The driver handles of anonymous files and their huge page sizes (0 for
/// shmem): the one kind of file seals and hugetlbfs rules apply to. A handle
/// leaves when its description's last reference does ([`released`]).
static MEMFDS: SpinMutex<BTreeMap<u64, u64>> = SpinMutex::new(BTreeMap::new());

/// Whether driver handle `handle` is an anonymous file, and its huge page
/// size (0 for shmem).
pub(crate) fn anonymous(handle: u64) -> Option<u64> {
    MEMFDS.lock().get(&handle).copied()
}

/// A filesystem description's last reference went.
pub(crate) fn released(handle: u64) {
    MEMFDS.lock().remove(&handle);
}

/// `memfd_create(2)` in its order: the flags, `MFD_EXEC` with
/// `MFD_NOEXEC_SEAL`, the name, then the file (`ENODEV` for a huge page size
/// the machine has no pool for). A new descriptor, or -1 with the errno.
///
/// # Safety
/// `name` must be NULL or point to a string readable up to its NUL or to
/// 250 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_memfd_create(name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let allowed = if flags & MFD_HUGETLB != 0 {
        MFD_ALL_FLAGS | (MFD_HUGE_MASK << MFD_HUGE_SHIFT)
    } else {
        MFD_ALL_FLAGS
    };
    if flags & !allowed != 0 || (flags & MFD_EXEC != 0 && flags & MFD_NOEXEC_SEAL != 0) {
        return crate::fail(EINVAL);
    }
    if name.is_null() {
        return crate::fail(crate::EFAULT);
    }
    // `strnlen_user(name, MFD_NAME_MAX_LEN + 1)`: the terminator must lie
    // within the limit.
    let mut bytes = Vec::with_capacity(MFD_NAME_MAX_LEN);
    loop {
        // SAFETY: per this function's contract, every byte up to the NUL (or
        // the limit) is readable.
        let byte = unsafe { *name.cast::<u8>().add(bytes.len()) };
        if byte == 0 {
            break;
        }
        if bytes.len() == MFD_NAME_MAX_LEN {
            return crate::fail(EINVAL);
        }
        bytes.push(byte);
    }
    let huge_page = if flags & MFD_HUGETLB != 0 {
        match huge_page_size((flags >> MFD_HUGE_SHIFT) & MFD_HUGE_MASK) {
            Some(size) => size as u64,
            None => return crate::fail(crate::ENODEV),
        }
    } else {
        0
    };
    let (mode, seals) = if flags & MFD_NOEXEC_SEAL != 0 {
        (0o666, F_SEAL_EXEC)
    } else if flags & MFD_ALLOW_SEALING != 0 {
        (0o777, 0)
    } else {
        (0o777, F_SEAL_SEAL)
    };
    let name = String::from_utf8_lossy(&bytes);
    let created =
        crate::with_context(|context| context.fs_create_anonymous(&name, mode, seals, huge_page));
    match created {
        Ok(fd) => {
            MEMFDS.lock().insert(fd.0, huge_page);
            crate::bind_fs_handle(
                fd,
                FdKind::File,
                crate::O_READ | crate::O_WRITE | crate::O_OPENED,
                flags & MFD_CLOEXEC != 0,
            )
        }
        Err(errno) => crate::fail(errno),
    }
}

/// The descriptor `fcntl`'s seal commands act on: `EBADF` for a closed or
/// `O_PATH` one.
fn sealable(fd: c_int) -> Result<crate::fdtable::Resolved, c_int> {
    let resolved = crate::resolve_fd(fd)?;
    if resolved.kind == FdKind::OPath || resolved.status & crate::O_PATH != 0 {
        return Err(EBADF);
    }
    Ok(resolved)
}

/// `fcntl(F_GET_SEALS)`: the seals of an anonymous file; every other
/// descriptor is `EINVAL`. -1 with the errno on failure.
#[unsafe(no_mangle)]
pub extern "C" fn patina_get_seals(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match sealable(fd) {
        Ok(resolved) if resolved.kind == FdKind::File && anonymous(resolved.handle).is_some() => {
            resolved.handle
        }
        Ok(_) => return crate::fail(EINVAL),
        Err(errno) => return crate::fail(errno),
    };
    match crate::with_context(|context| context.fs_seals(Fd(handle))) {
        Ok(seals) => seals as c_int,
        Err(errno) => crate::fail(errno),
    }
}

/// `fcntl(F_ADD_SEALS)`, in `memfd_add_seals`' order: a description not open
/// for writing `EPERM`, an unknown seal or a file that cannot be sealed
/// `EINVAL`, then the filesystem's judgment. -1 with the errno on failure.
#[unsafe(no_mangle)]
pub extern "C" fn patina_add_seals(fd: c_int, seals: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match sealable(fd) {
        Ok(resolved) => resolved,
        Err(errno) => return crate::fail(errno),
    };
    if resolved.status & crate::O_WRITE == 0 {
        return crate::fail(crate::EPERM);
    }
    if seals & !F_ALL_SEALS != 0
        || resolved.kind != FdKind::File
        || anonymous(resolved.handle).is_none()
    {
        return crate::fail(EINVAL);
    }
    let handle = resolved.handle;
    let writably_mapped = Mappings::writably_mapped(handle);
    match crate::with_context(|context| context.fs_add_seals(Fd(handle), seals, writably_mapped)) {
        Ok(()) => 0,
        Err(errno) => crate::fail(errno),
    }
}
