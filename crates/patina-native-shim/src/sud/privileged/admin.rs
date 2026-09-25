//! The system administration rows: process accounting, the terminal hangup,
//! swap, reboot and kexec, kernel modules (each checks its capability before
//! any argument, `swapon`'s flags aside), and disk quotas, whose capability
//! check comes only after the filesystem is found to support quotas — which
//! no filesystem of the virtual machine does.

use super::{Answer, gate, lookup, refuse};
use crate::identity::Credential;
use crate::registry::Capability;
use linux_raw_sys::errno;
use std::ffi::c_int;

/// `acct(path)` (kernel/acct.c): `CAP_SYS_PACCT` before the path is read.
pub(in crate::sud) fn acct(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysPacct, errno::EPERM)
}

/// `vhangup()` (fs/open.c): `CAP_SYS_TTY_CONFIG`.
pub(in crate::sud) fn vhangup(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysTtyConfig, errno::EPERM)
}

/// `SWAP_FLAGS_VALID`: the priority, `SWAP_FLAG_PREFER` and the discard
/// flags.
const SWAP_FLAGS_VALID: u32 = 0x7_ffff;

/// `swapon(path, flags)` (mm/swapfile.c): a flag outside
/// `SWAP_FLAGS_VALID`, then `CAP_SYS_ADMIN` before the path is read.
pub(in crate::sud) fn swapon(credential: &Credential, a: &[u64; 6]) -> Answer {
    if a[1] as u32 & !SWAP_FLAGS_VALID != 0 {
        return refuse(errno::EINVAL);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `swapoff(path)`: `CAP_SYS_ADMIN` before the path is read.
pub(in crate::sud) fn swapoff(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `reboot` (kernel/reboot.c), `kexec_load` (`kexec_load_check`) and
/// `kexec_file_load`: `CAP_SYS_BOOT` before the magic numbers, the command,
/// the flags and the segments or descriptors.
pub(in crate::sud) fn boot(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysBoot, errno::EPERM)
}

/// `init_module`, `finit_module` (`may_init_module`) and `delete_module`
/// (kernel/module/main.c): `CAP_SYS_MODULE` before the image, flags,
/// descriptor or name.
pub(in crate::sud) fn module(credential: &Credential, _: &[u64; 6]) -> Answer {
    gate(credential, Capability::SysModule, errno::EPERM)
}

/// The quota commands `QCMD` packs above the type: `Q_SYNC`.
const Q_SYNC: u32 = 0x80_0001;
/// `MAXQUOTAS`: user, group and project quotas.
const MAXQUOTAS: u32 = 3;
/// `SUBCMDSHIFT`/`SUBCMDMASK`.
const SUBCMDSHIFT: u32 = 8;
const SUBCMDMASK: u32 = 0xff;

/// `quotactl(cmd, special, id, addr)` (fs/quota/quota.c): a type past
/// `MAXQUOTAS`; with no device, `Q_SYNC` syncs every filesystem's quotas
/// (none has any: 0) and any other command is `ENODEV`; then the device is
/// looked up (`lookup_bdev`: the lookup's refusals, and `ENOTBLK` for an
/// entry that is no block device — the virtual machine has none), before
/// any capability check.
pub(in crate::sud) fn quotactl(_: &Credential, a: &[u64; 6]) -> Answer {
    let cmd = a[0] as u32;
    if cmd & SUBCMDMASK >= MAXQUOTAS {
        return refuse(errno::EINVAL);
    }
    if a[1] == 0 {
        return if cmd >> SUBCMDSHIFT == Q_SYNC {
            Ok(0)
        } else {
            refuse(errno::ENODEV)
        };
    }
    // `Q_QUOTAON` looks its quota file up first, but only the command
    // reads that lookup's answer, and the command is never reached.
    match lookup(a[1], true) {
        Err(code) => refuse(code),
        Ok(_) => refuse(errno::ENOTBLK),
    }
}

/// `quotactl_fd(fd, cmd, id, addr)`: a descriptor not open (`O_PATH`
/// included: `fdget_raw`) is `EBADF`, then a type past `MAXQUOTAS`; the
/// descriptor's filesystem has no quota operations (`ENOSYS`), checked
/// before the capability. A write command's `mnt_want_write` passes on the
/// writable virtual volume.
pub(in crate::sud) fn quotactl_fd(_: &Credential, a: &[u64; 6]) -> Answer {
    if let Err(code) = crate::resolve_fd(a[0] as u32 as c_int) {
        return refuse(code);
    }
    if a[1] as u32 & SUBCMDMASK >= MAXQUOTAS {
        return refuse(errno::EINVAL);
    }
    refuse(errno::ENOSYS)
}
