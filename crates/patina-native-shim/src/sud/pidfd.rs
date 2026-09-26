//! SUD rows — process descriptors (kernel/pid.c `pidfd_open`, `pidfd_getfd`;
//! kernel/signal.c `pidfd_send_signal`; mm/oom_kill.c `process_mrelease`), as
//! 6.8 answers them.
//!
//! A pidfd is a descriptor-table kind ([`FdKind::Pidfd`]) whose handle is the
//! virtual pid it names: the guest's own process, or init. It is 6.8's
//! anonymous `[pidfd]` inode: read-write, always close-on-exec, never readable
//! while its process runs (and neither process ever exits while the guest
//! runs), with no read, write or seek of its own. `pidfd_getfd` is answered
//! with the credential (`privileged::pidfd_getfd`): taking a descriptor from
//! init is a ptrace-mode check.

use super::*;
use crate::FdKind;
use crate::identity::Process;
use crate::registry::{IDENTITY_PID, INIT_PID};
use crate::thread::current_tid;

/// `PIDFD_NONBLOCK` (`O_NONBLOCK`, on both architectures): the only flag
/// 6.8's `pidfd_open` takes (6.9 added `PIDFD_THREAD`).
const PIDFD_NONBLOCK: u32 = uapi::O_NONBLOCK;

/// The process a descriptor names, as `pidfd_pid` finds it: `EBADF` for a
/// descriptor not open (`fdget`, which an `O_PATH` one does not pass) or one
/// that is no pidfd. `pidfd_send_signal` also takes a procfs `/proc/<pid>`
/// directory (`tgid_pidfd_to_pid`), but the virtual machine mounts no procfs,
/// so no directory it holds is one.
pub(super) fn target(fd: c_int) -> Result<Process, u32> {
    let resolved = crate::fdget(fd).map_err(|code| code as u32)?;
    if resolved.kind != FdKind::Pidfd {
        return Err(errno::EBADF);
    }
    Ok(if resolved.handle == u64::from(INIT_PID) {
        Process::Init
    } else {
        Process::Guest
    })
}

/// `pidfd_open(pid, flags)`: an unknown flag, then a pid that is no process
/// (`EINVAL` for 0 or less), no such pid (`ESRCH`), a thread that leads no
/// thread group (`EINVAL`); then a new descriptor (`EMFILE`).
pub(super) fn sys_pidfd_open(pid: u64, flags: u64) -> i64 {
    let (pid, flags) = (pid as i32, flags as u32);
    if flags & !PIDFD_NONBLOCK != 0 || pid <= 0 {
        return -EINVAL;
    }
    match crate::identity::lookup(pid) {
        None => -i64::from(errno::ESRCH),
        Some((_, false)) => -EINVAL,
        Some((_, true)) => {
            let nonblock = if flags & PIDFD_NONBLOCK != 0 {
                crate::O_NONBLOCK
            } else {
                0
            };
            let status = crate::O_READ | crate::O_WRITE | nonblock;
            match crate::install_fd(FdKind::Pidfd, pid as u64, status, true) {
                Ok(fd) => i64::from(fd),
                Err(code) => -i64::from(code),
            }
        }
    }
}

/// The part of a `siginfo_t` `copy_siginfo_from_user` reads first (`struct
/// kernel_siginfo`, 48 bytes on a 64-bit kernel).
type KernelSiginfo = [u64; 6];

/// `pidfd_send_signal(pidfd, sig, info, flags)`: a flag (6.8 defines none),
/// then the descriptor ([`target`]); with `info`, its copy (`EFAULT`), a
/// signal number other than `sig` (`EINVAL`), and a kernel or `tkill` code
/// sent anywhere but to the caller's own thread's pid (`EPERM`); then the
/// signal goes to the process as `kill` sends it (`SI_USER` without `info`),
/// under the same rules: an invalid signal is `EINVAL`, and init takes
/// nothing.
pub(super) fn sys_pidfd_send_signal(a: [u64; 6]) -> i64 {
    if a[3] as u32 != 0 {
        return -EINVAL;
    }
    let pid = match target(arg_fd(a[0]) as c_int) {
        Ok(Process::Init) => INIT_PID as i32,
        Ok(Process::Guest) => IDENTITY_PID as i32,
        Err(code) => return -i64::from(code),
    };
    let sig = a[1] as i32;
    let target = GenerationTarget::Process { pid };
    if a[2] == 0 {
        // SAFETY: a process-directed kill carries no pointer.
        return unsafe { generate_signal(target, sig, GenerationInfo::User) };
    }
    let Ok(words) = crate::uaccess::read::<KernelSiginfo>(a[2] as usize) else {
        return -EFAULT;
    };
    let mut info = Info { words: [0; 16] };
    info.words[..words.len()].copy_from_slice(&words);
    if words[0] as u32 as i32 != sig {
        return -EINVAL;
    }
    let code = words[1] as i32;
    if (code >= 0 || code == SI_TKILL) && pid != current_tid() {
        return -i64::from(errno::EPERM);
    }
    // SAFETY: `info` is a local record, alive for the call.
    unsafe { generate_signal(target, sig, GenerationInfo::Queued(&info)) }
}

/// `SI_TKILL`: the code `tkill`/`tgkill` send with.
const SI_TKILL: i32 = -6;

/// `process_mrelease(pidfd, flags)`: a flag, then the descriptor
/// ([`target`]); a process whose memory is not being freed (every process
/// the guest can name: neither is exiting) is `EINVAL`.
pub(super) fn sys_process_mrelease(pidfd: u64, flags: u64) -> i64 {
    if flags as u32 != 0 {
        return -EINVAL;
    }
    match target(pidfd as c_int) {
        Ok(_) => -EINVAL,
        Err(code) => -i64::from(code),
    }
}
