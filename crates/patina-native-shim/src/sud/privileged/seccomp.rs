//! `seccomp` and prctl's `PR_SET_SECCOMP` (kernel/seccomp.c `do_seccomp`,
//! `prctl_set_seccomp`), as 6.8 answers them.
//!
//! The queries (`SECCOMP_GET_ACTION_AVAIL`, `SECCOMP_GET_NOTIF_SIZES`) are
//! answered to any caller. Entering a mode is checked in the kernel's order
//! up to the point where the mode would bind the process: strict mode past
//! its argument check, and a filter past its flags, its program's copy and
//! length, and `seccomp_prepare_filter`'s privilege check (`no_new_privs`,
//! else `CAP_SYS_ADMIN`, else `EACCES`). There patina stops by name: it does
//! not enforce a guest's seccomp mode, so no mode is ever entered and
//! `PR_GET_SECCOMP` always reads 0 (`SECCOMP_MODE_DISABLED`).
//!
//! The program itself is never read: the instructions' copy (`EFAULT`) and
//! the classic-BPF checks (`bpf_check_classic`, `seccomp_check_filter`:
//! `EINVAL`) come after the privilege check, so a program they would refuse
//! ends at the same stop as one they would accept.

use super::{Answer, Unmodeled, gate, refuse};
use crate::identity::Credential;
use crate::registry::Capability;
use linux_raw_sys::errno;

const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

/// prctl's `PR_SET_SECCOMP` modes.
const SECCOMP_MODE_STRICT: u64 = 1;
const SECCOMP_MODE_FILTER: u64 = 2;

/// `SECCOMP_FILTER_FLAG_*`: 6.8's whole mask, and the three the combination
/// checks name.
const FILTER_FLAG_TSYNC: u32 = 1 << 0;
const FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
const FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
const FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;
const FILTER_FLAG_MASK: u32 = (1 << 6) - 1;

/// Every `SECCOMP_RET_*` action 6.8 knows: `KILL_PROCESS`, `KILL_THREAD`,
/// `TRAP`, `ERRNO`, `USER_NOTIF`, `TRACE`, `LOG`, `ALLOW`.
const ACTIONS: [u32; 8] = [
    0x8000_0000,
    0x0000_0000,
    0x0003_0000,
    0x0005_0000,
    0x7fc0_0000,
    0x7ff0_0000,
    0x7ffc_0000,
    0x7fff_0000,
];

/// `struct seccomp_notif_sizes`: `sizeof` the notification (80), the
/// response (24) and `struct seccomp_data` (64) on 64-bit Linux.
const NOTIF_SIZES: [u16; 3] = [80, 24, 64];

/// `BPF_MAXINSNS`: the longest program a filter may be.
const BPF_MAXINSNS: u16 = 4096;

/// `struct sock_fprog` as a 64-bit caller lays it out: the instruction
/// count, padding, then the instructions' address.
type Fprog = [u64; 2];

/// `seccomp(op, flags, args)` for the calling thread, whose `no_new_privs`
/// is prctl's.
pub(in crate::sud) fn seccomp(credential: &Credential, a: &[u64; 6]) -> Answer {
    seccomp_as(credential, a, super::super::no_new_privs())
}

/// `seccomp` for a caller with `no_new_privs` as given. The kernel reads
/// `op` and `flags` as `unsigned int`.
pub(super) fn seccomp_as(credential: &Credential, a: &[u64; 6], no_new_privs: bool) -> Answer {
    do_seccomp(credential, a[0] as u32, a[1] as u32, a[2], no_new_privs)
}

/// `prctl(PR_SET_SECCOMP, mode, filter)` (`prctl_set_seccomp`): strict mode
/// ignores `filter`, a filter takes no flags, any other mode is `EINVAL`.
pub(in crate::sud) fn prctl_set_seccomp(credential: &Credential, a: &[u64; 6]) -> Answer {
    let no_new_privs = super::super::no_new_privs();
    match a[0] {
        SECCOMP_MODE_STRICT => do_seccomp(credential, SECCOMP_SET_MODE_STRICT, 0, 0, no_new_privs),
        SECCOMP_MODE_FILTER => {
            do_seccomp(credential, SECCOMP_SET_MODE_FILTER, 0, a[1], no_new_privs)
        }
        _ => refuse(errno::EINVAL),
    }
}

/// `do_seccomp`: the operation, then its own checks.
fn do_seccomp(
    credential: &Credential,
    op: u32,
    flags: u32,
    args: u64,
    no_new_privs: bool,
) -> Answer {
    match op {
        SECCOMP_SET_MODE_STRICT if flags != 0 || args != 0 => refuse(errno::EINVAL),
        SECCOMP_SET_MODE_STRICT => Err(Unmodeled::Path(
            "entering strict mode (patina does not enforce a seccomp mode)".into(),
        )),
        SECCOMP_SET_MODE_FILTER => set_mode_filter(credential, flags, args, no_new_privs),
        SECCOMP_GET_ACTION_AVAIL if flags != 0 => refuse(errno::EINVAL),
        SECCOMP_GET_ACTION_AVAIL => match crate::uaccess::read::<u32>(args as usize) {
            Err(_) => refuse(errno::EFAULT),
            Ok(action) if ACTIONS.contains(&action) => Ok(0),
            Ok(_) => refuse(errno::EOPNOTSUPP),
        },
        SECCOMP_GET_NOTIF_SIZES if flags != 0 => refuse(errno::EINVAL),
        SECCOMP_GET_NOTIF_SIZES => match crate::uaccess::write(args as usize, &NOTIF_SIZES) {
            Ok(()) => Ok(0),
            Err(_) => refuse(errno::EFAULT),
        },
        _ => refuse(errno::EINVAL),
    }
}

/// `seccomp_set_mode_filter`: the flags and their combinations, then
/// `seccomp_prepare_user_filter` (the program's copy and length, then the
/// privilege check), all before the program is looked at.
fn set_mode_filter(credential: &Credential, flags: u32, args: u64, no_new_privs: bool) -> Answer {
    if flags & !FILTER_FLAG_MASK != 0 {
        return refuse(errno::EINVAL);
    }
    let has = |flag: u32| flags & flag != 0;
    if has(FILTER_FLAG_TSYNC) && has(FILTER_FLAG_NEW_LISTENER) && !has(FILTER_FLAG_TSYNC_ESRCH) {
        return refuse(errno::EINVAL);
    }
    if has(FILTER_FLAG_WAIT_KILLABLE_RECV) && !has(FILTER_FLAG_NEW_LISTENER) {
        return refuse(errno::EINVAL);
    }
    let Ok(program) = crate::uaccess::read::<Fprog>(args as usize) else {
        return refuse(errno::EFAULT);
    };
    let length = program[0] as u16;
    if length == 0 || length > BPF_MAXINSNS {
        return refuse(errno::EINVAL);
    }
    if !no_new_privs {
        return gate(credential, Capability::SysAdmin, errno::EACCES);
    }
    Err(Unmodeled::Path(
        "installing a seccomp filter (patina does not enforce guest filters)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;

    /// With `no_new_privs` the privilege check passes for any credential,
    /// and a filter that clears every earlier check ends the model by name;
    /// the checks before it still refuse.
    #[test]
    fn no_new_privs_reaches_the_install() {
        static ONE_INSTRUCTION: Fprog = [1, 0];
        let program = ONE_INSTRUCTION.as_ptr() as u64;
        let filter = |flags: u64, args: u64| {
            seccomp_as(
                credential(),
                &[u64::from(SECCOMP_SET_MODE_FILTER), flags, args, 0, 0, 0],
                true,
            )
        };
        assert!(matches!(filter(0, program), Err(Unmodeled::Path(_))));
        assert_eq!(filter(1 << 31, program), refuse(errno::EINVAL));
        assert_eq!(filter(0, 0), refuse(errno::EFAULT));
    }

    /// Entering strict mode is where the model ends, from either door;
    /// prctl's ignores its filter argument.
    #[test]
    fn strict_mode_ends_by_name() {
        let strict = do_seccomp(credential(), SECCOMP_SET_MODE_STRICT, 0, 0, false);
        assert!(matches!(strict, Err(Unmodeled::Path(_))));
        let prctl = prctl_set_seccomp(credential(), &[SECCOMP_MODE_STRICT, 1, 0, 0, 0, 0]);
        assert!(matches!(prctl, Err(Unmodeled::Path(_))));
    }
}
