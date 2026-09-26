//! The rows that reach other processes and namespaces: `ptrace`, `unshare`
//! and `setns`. The virtual pid namespace holds init and the guest, the
//! guest traces no one and nothing traces it, and the machine has one of
//! each namespace, none of which the guest can name by a descriptor.

use super::{Answer, Unmodeled, refuse};
use crate::FdKind;
use crate::identity::{Credential, Process, lookup as find_process};
use crate::registry::{Capability, KERNEL_CONFIG};
use linux_raw_sys::errno;
use linux_raw_sys::general::{
    CLONE_FILES, CLONE_FS, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID,
    CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD,
    CLONE_VM,
};
use linux_raw_sys::ptrace::{
    PTRACE_ATTACH, PTRACE_O_MASK, PTRACE_O_SUSPEND_SECCOMP, PTRACE_SEIZE, PTRACE_TRACEME,
};
use std::ffi::c_int;

/// `ptrace(request, pid, addr, data)` (kernel/ptrace.c).
/// `PTRACE_TRACEME` would hand the guest to its parent, outside the
/// simulation: the model ends there. Otherwise the pid is looked up first
/// (`ESRCH`); a request other than `PTRACE_ATTACH`/`PTRACE_SEIZE` wants a
/// tracee the caller traces, which it never does (`ESRCH`). Attaching:
/// `PTRACE_SEIZE`'s address and options (`EIO`), `PTRACE_O_SUSPEND_SECCOMP`
/// without `CAP_SYS_ADMIN` (`EPERM`), the caller's own thread group
/// (`EPERM`), then init, which is not dumpable: `CAP_SYS_PTRACE`
/// (`__ptrace_may_access`), then Yama's scope (`kernel.yama.ptrace_scope`:
/// init is no descendant, and scope 3 refuses every attach).
pub(in crate::sud) fn ptrace(credential: &Credential, a: &[u64; 6]) -> Answer {
    let request = a[0] as i64;
    if request == i64::from(PTRACE_TRACEME) {
        return Err(Unmodeled::Path(
            "PTRACE_TRACEME (its tracer would be the guest's parent, outside the simulation)"
                .into(),
        ));
    }
    let Some((process, _)) = find_process(a[1] as i32) else {
        return refuse(errno::ESRCH);
    };
    if request != i64::from(PTRACE_ATTACH) && request != i64::from(PTRACE_SEIZE) {
        return refuse(errno::ESRCH);
    }
    if request == i64::from(PTRACE_SEIZE) {
        let options = a[3];
        if a[2] != 0 || options & !u64::from(PTRACE_O_MASK) != 0 {
            return refuse(errno::EIO);
        }
        // `check_ptrace_options`: past the capability, the caller runs no
        // seccomp filter (installing one is a named fatal) and suspends none.
        if options & u64::from(PTRACE_O_SUSPEND_SECCOMP) != 0
            && !credential.capable(Capability::SysAdmin)
        {
            return refuse(errno::EPERM);
        }
    }
    if process == Process::Guest {
        return refuse(errno::EPERM);
    }
    if !credential.capable(Capability::SysPtrace) || KERNEL_CONFIG.yama_ptrace_scope >= 3 {
        return refuse(errno::EPERM);
    }
    Err(Unmodeled::Granted(Capability::SysPtrace))
}

/// `unshare`'s flags, as the `unsigned long` it takes.
const THREAD: u64 = CLONE_THREAD as u64;
const FS: u64 = CLONE_FS as u64;
const SIGHAND: u64 = CLONE_SIGHAND as u64;
const VM: u64 = CLONE_VM as u64;
const FILES: u64 = CLONE_FILES as u64;
const SYSVSEM: u64 = CLONE_SYSVSEM as u64;
const NEWNS: u64 = CLONE_NEWNS as u64;
const NEWUSER: u64 = CLONE_NEWUSER as u64;
/// The namespaces `unshare_nsproxy_namespaces` makes, which need
/// `CAP_SYS_ADMIN`.
const NEW_NAMESPACES: u64 = (CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWPID
    | CLONE_NEWCGROUP
    | CLONE_NEWTIME) as u64;

/// `unshare(flags)` (`ksys_unshare`): the implied flags (a new user
/// namespace unshares the thread group and filesystem state, the address
/// space the signal handlers, the handlers the thread group, a mount
/// namespace the filesystem state); a new user namespace needs
/// `CAP_SYS_ADMIN` when Ubuntu's `kernel.unprivileged_userns_clone` is off
/// (`EPERM`); an unknown flag (`EINVAL`), splitting the thread group while
/// another thread lives (`EINVAL`), a new user namespace
/// (`user.max_user_namespaces` 0: `ENOSPC`), then the other new namespaces
/// need `CAP_SYS_ADMIN` (`EPERM`). What passes is the caller's own state:
/// nothing to do for the thread group, handlers and address space of a
/// lone thread, nor for a filesystem state or descriptor table no other
/// thread shares; `CLONE_SYSVSEM` applies the process's semaphore
/// adjustments (`exit_sem`). With another thread alive, giving this thread
/// its own filesystem state, descriptor table or undo list is where the
/// model ends.
pub(in crate::sud) fn unshare(credential: &Credential, a: &[u64; 6]) -> Answer {
    let mut flags = a[0];
    if flags & NEWUSER != 0 {
        flags |= THREAD | FS;
    }
    if flags & VM != 0 {
        flags |= SIGHAND;
    }
    if flags & SIGHAND != 0 {
        flags |= THREAD;
    }
    if flags & NEWNS != 0 {
        flags |= FS;
    }
    if flags & NEWUSER != 0
        && !KERNEL_CONFIG.unprivileged_userns_clone
        && !credential.capable(Capability::SysAdmin)
    {
        return refuse(errno::EPERM);
    }
    let known = THREAD | FS | SIGHAND | VM | FILES | SYSVSEM | NEWUSER | NEW_NAMESPACES;
    if flags & !known != 0 {
        return refuse(errno::EINVAL);
    }
    let alone = crate::thread::live_threads() == 1;
    if flags & (THREAD | SIGHAND | VM) != 0 && !alone {
        return refuse(errno::EINVAL);
    }
    if flags & NEWUSER != 0 {
        if KERNEL_CONFIG.max_user_namespaces == 0 {
            return refuse(errno::ENOSPC);
        }
        return Err(Unmodeled::Path("a new user namespace".into()));
    }
    if flags & NEW_NAMESPACES != 0 {
        if credential.capable(Capability::SysAdmin) {
            return Err(Unmodeled::Granted(Capability::SysAdmin));
        }
        return refuse(errno::EPERM);
    }
    let own = flags & (FS | FILES | SYSVSEM);
    if own != 0 && !alone {
        return Err(Unmodeled::Path(format!(
            "unsharing {own:#x} while another thread shares it"
        )));
    }
    if flags & SYSVSEM != 0 {
        crate::thread::ipc::exit_sem();
    }
    Ok(0)
}

/// `setns(fd, nstype)` (kernel/nsproxy.c): a descriptor not open (`O_PATH`
/// included: `fdget`) is `EBADF`, then one that is neither a namespace file
/// nor a pidfd `EINVAL` — every descriptor the model holds, so the
/// capability checks of joining are never reached.
pub(in crate::sud) fn setns(_: &Credential, a: &[u64; 6]) -> Answer {
    match crate::fdget(a[0] as c_int) {
        Err(code) => refuse(code),
        // No kind the model has is a namespace file or a pidfd: a new kind
        // (a pidfd) must decide here whether it is one.
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
            | FdKind::TimerFd => refuse(errno::EINVAL),
        },
    }
}

/// `get_robust_list(pid, head_ptr, len_ptr)` (kernel/futex/syscalls.c): the
/// pid is looked up first; init belongs to root, so reading its head is
/// `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)`'s `CAP_SYS_PTRACE`
/// (`EPERM`). Every other pid is the thread model's: the caller's own
/// threads, or `ESRCH`.
pub(in crate::sud) fn get_robust_list(credential: &Credential, a: &[u64; 6]) -> Answer {
    let pid = a[0] as i32;
    if matches!(find_process(pid), Some((Process::Init, _))) {
        return super::gate(credential, Capability::SysPtrace, errno::EPERM);
    }
    Ok(crate::thread::registrations::get_robust_list(
        pid,
        a[1] as usize,
        a[2] as usize,
    ))
}
