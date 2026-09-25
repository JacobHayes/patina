//! The x86 I/O port rows (arch/x86/kernel/ioport.c). The virtual thread's
//! I/O privilege level is 0 and it holds no port bitmap, since raising
//! either needs `CAP_SYS_RAWIO` (and no lockdown), which is where the model
//! ends; so keeping or dropping them needs nothing.

use super::{Answer, gate, refuse};
use crate::identity::Credential;
use crate::registry::Capability;
use linux_raw_sys::errno;

/// `IO_BITMAP_BITS`: the ports a bitmap covers.
const IO_BITMAP_BITS: u64 = 65536;

/// `iopl(level)`: a level past 3 is `EINVAL`; the current level (0) is 0
/// without a privilege (nothing changes); raising it needs
/// `CAP_SYS_RAWIO`.
pub(in crate::sud) fn iopl(credential: &Credential, a: &[u64; 6]) -> Answer {
    let level = a[0] as u32;
    if level > 3 {
        return refuse(errno::EINVAL);
    }
    if level == 0 {
        return Ok(0);
    }
    gate(credential, Capability::SysRawio, errno::EPERM)
}

/// `ioperm(from, num, turn_on)` (`ksys_ioperm`): a range that wraps, is
/// empty or passes the last port is `EINVAL`; turning ports on needs
/// `CAP_SYS_RAWIO`; turning them off is 0 (no bitmap, nothing to clear).
pub(in crate::sud) fn ioperm(credential: &Credential, a: &[u64; 6]) -> Answer {
    let (from, num) = (a[0], a[1]);
    let end = from.wrapping_add(num);
    if end <= from || end > IO_BITMAP_BITS {
        return refuse(errno::EINVAL);
    }
    if a[2] as i32 != 0 {
        return gate(credential, Capability::SysRawio, errno::EPERM);
    }
    Ok(0)
}
