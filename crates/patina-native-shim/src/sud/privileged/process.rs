//! The rows that reach other processes and namespaces: `ptrace`, `unshare`,
//! `setns`, and those that inspect a process (`get_robust_list`,
//! `process_vm_*`, `kcmp`). The virtual pid namespace holds init and the guest, the
//! guest traces no one and nothing traces it, and the machine has one of
//! each namespace, which the guest names only through a process's pidfd.

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
use linux_raw_sys::general::{MADV_COLD, MADV_COLLAPSE, MADV_PAGEOUT, MADV_WILLNEED};
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

/// The namespaces `setns` may join through a pidfd (`check_setns_flags`).
const JOINABLE: u64 = NEW_NAMESPACES | NEWUSER;

/// `setns(fd, nstype)` (kernel/nsproxy.c): a descriptor not open (`O_PATH`
/// included: `fdget`) is `EBADF`, then one that is neither a namespace file
/// nor a pidfd `EINVAL`. The model holds no namespace file; through a pidfd,
/// no namespace or an unknown one is `EINVAL`, then [`join_namespaces`].
pub(in crate::sud) fn setns(credential: &Credential, a: &[u64; 6]) -> Answer {
    match crate::fdget(a[0] as c_int) {
        Err(code) => refuse(code),
        Ok(resolved) => match resolved.kind {
            FdKind::Pidfd => {
                let nstype = u64::from(a[1] as u32);
                if nstype == 0 || nstype & !JOINABLE != 0 {
                    return refuse(errno::EINVAL);
                }
                match crate::sud::pidfd::target(a[0] as c_int) {
                    Ok(process) => join_namespaces(credential, nstype, process),
                    Err(code) => refuse(code),
                }
            }
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

/// `validate_nsset`: joining the namespaces of the process a pidfd names.
/// Reading them is `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)`, which
/// init, not dumpable, allows only with `CAP_SYS_PTRACE` (`EPERM`). Then each
/// namespace asked for is installed in the kernel's order. The machine has
/// one of each, so the user namespace is the caller's own (`userns_install`:
/// `EINVAL`), a time namespace asked alone meets `timens_install`'s
/// single-thread rule (`EUSERS`) before its capability, and every install
/// needs `CAP_SYS_ADMIN` (`EPERM`); holding it is where the model ends.
pub(super) fn join_namespaces(credential: &Credential, nstype: u64, process: Process) -> Answer {
    if process == Process::Init && !credential.capable(Capability::SysPtrace) {
        return refuse(errno::EPERM);
    }
    if nstype & NEWUSER != 0 {
        return refuse(errno::EINVAL);
    }
    if nstype == u64::from(CLONE_NEWTIME) && crate::thread::live_threads() != 1 {
        return refuse(errno::EUSERS);
    }
    super::gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `pidfd_getfd(pidfd, fd, flags)` (kernel/pid.c); see [`getfd_from`].
pub(in crate::sud) fn pidfd_getfd(credential: &Credential, a: &[u64; 6]) -> Answer {
    getfd_from(credential, a, || crate::sud::pidfd::target(a[0] as c_int))
}

/// `pidfd_getfd` with the process the pidfd names found by `target`: a flag
/// (`EINVAL`), then the descriptor (`EBADF`). Taking a descriptor of init,
/// which is not dumpable, is `ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS)`:
/// `CAP_SYS_PTRACE` (`EPERM`). One of the guest's own (`O_PATH` included:
/// `fget_task` takes any) is duplicated in the one table, sharing its open
/// file, close-on-exec (`receive_fd`): `EBADF` for a number not open, then
/// `EMFILE`.
pub(super) fn getfd_from(
    credential: &Credential,
    a: &[u64; 6],
    target: impl FnOnce() -> Result<Process, u32>,
) -> Answer {
    if a[2] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    match target() {
        Err(code) => refuse(code),
        Ok(Process::Init) => super::gate(credential, Capability::SysPtrace, errno::EPERM),
        Ok(Process::Guest) => Ok(match crate::fd_table().lock().dup(a[1] as c_int, 0, true) {
            Ok(fd) => i64::from(fd),
            Err(code) => -i64::from(code),
        }),
    }
}

/// `get_robust_list(pid, head_ptr, len_ptr)` (kernel/futex/syscalls.c): the
/// pid is looked up first; init is not dumpable, so reading its head is
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

/// `UIO_MAXIOV`: the most ranges one vector may hold.
const UIO_MAXIOV: u64 = 1024;
/// `MAX_RW_COUNT` (`INT_MAX & PAGE_MASK`): the most one call moves, and the
/// length a single local range is clamped to before its range is checked.
const MAX_RW_COUNT: u64 = 0x7fff_f000;
/// `sizeof(struct iovec)`.
const IOVEC_BYTES: u64 = 16;
/// The page size `process_vm_rw_core` counts remote pages in.
const PAGE_SIZE: u64 = 4096;

/// One side's vector as `iovec_from_user` takes it: at most `UIO_MAXIOV`
/// ranges (`EINVAL`), the vector itself a user range (`EFAULT`), then each
/// range read in turn (`EFAULT`) and refused if longer than `SSIZE_MAX`
/// (`EINVAL`). Answers the ranges.
fn ranges(at: u64, count: u64) -> Result<Vec<[u64; 2]>, u32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > UIO_MAXIOV {
        return Err(errno::EINVAL);
    }
    if !user_range(at, count * IOVEC_BYTES) {
        return Err(errno::EFAULT);
    }
    let mut ranges = Vec::with_capacity(count as usize);
    for index in 0..count {
        let range = crate::uaccess::read::<[u64; 2]>((at + index * IOVEC_BYTES) as usize)
            .map_err(|_| errno::EFAULT)?;
        if (range[1] as i64) < 0 {
            return Err(errno::EINVAL);
        }
        ranges.push(range);
    }
    Ok(ranges)
}

/// The local vector as `import_iovec` takes it (its count is an `unsigned
/// int`): answers the bytes it spans. A single range is clamped to
/// `MAX_RW_COUNT` before its range check (`import_ubuf`); several are each
/// checked unclamped, the running total then clamped (`__import_iovec`).
fn local_bytes(at: u64, count: u64) -> Result<u64, u32> {
    let local = ranges(at, u64::from(count as u32))?;
    if let [[base, len]] = local[..] {
        let len = len.min(MAX_RW_COUNT);
        return if user_range(base, len) {
            Ok(len)
        } else {
            Err(errno::EFAULT)
        };
    }
    let mut total = 0;
    for [base, len] in local {
        if !user_range(base, len) {
            return Err(errno::EFAULT);
        }
        total += len.min(MAX_RW_COUNT - total);
    }
    Ok(total)
}

/// Whether the remote vector names a page to copy (`process_vm_rw_core`'s
/// `nr_pages`, counted before the target is looked up).
fn remote_pages(remote: &[[u64; 2]]) -> bool {
    remote.iter().any(|[base, len]| {
        *len > 0
            && (base.wrapping_add(*len).wrapping_sub(1) / PAGE_SIZE)
                .wrapping_sub(base / PAGE_SIZE)
                .wrapping_add(1)
                != 0
    })
}

/// `process_vm_readv`/`process_vm_writev(pid, local, liovcnt, remote,
/// riovcnt, flags)` (mm/process_vm_access.c `process_vm_rw`). The guest's own
/// process (by its pid or any of its threads' tids) is the host kernel's to
/// answer, on this process. Any other pid meets the checks made before the
/// target is looked up, in their order: a flag (`EINVAL`), the local vector
/// ([`local_bytes`]), nothing to copy (0), the remote vector, no remote page
/// to copy (0); then no such process (`ESRCH`), or init, whose memory needs
/// `CAP_SYS_PTRACE` (`mm_access`'s `EACCES`, reported `EPERM`).
fn process_vm(credential: &Credential, a: &[u64; 6], write: bool) -> Answer {
    let found = find_process(a[0] as i32);
    if matches!(found, Some((Process::Guest, _))) {
        return Ok(crate::uaccess::guest_process_vm(write, a));
    }
    if a[5] != 0 {
        return refuse(errno::EINVAL);
    }
    match local_bytes(a[1], a[2]) {
        Ok(0) => return Ok(0),
        Ok(_) => {}
        Err(code) => return refuse(code),
    }
    match ranges(a[3], a[4]) {
        Ok(remote) if !remote_pages(&remote) => return Ok(0),
        Ok(_) => {}
        Err(code) => return refuse(code),
    }
    match found {
        Some((Process::Init, _)) => super::gate(credential, Capability::SysPtrace, errno::EPERM),
        _ => refuse(errno::ESRCH),
    }
}

/// Whether `len` bytes at `base` are a user range, as `access_ok` judges it
/// (no wrap, and the end inside the user address space).
fn user_range(base: u64, len: u64) -> bool {
    base.checked_add(len).is_some_and(user_end)
}

/// Whether a range ending at `end` is inside the user address space, as
/// `access_ok` judges it (x86_64: below the sign bit; arm64: 48 bits).
fn user_end(end: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    return (end as i64) >= 0;
    #[cfg(target_arch = "aarch64")]
    return end <= 1 << 48;
}

/// `process_madvise(pidfd, vec, vlen, advice, flags)` (mm/madvise.c); see
/// [`madvise_from`].
pub(in crate::sud) fn process_madvise(credential: &Credential, a: &[u64; 6]) -> Answer {
    madvise_from(credential, a, || crate::sud::pidfd::target(a[0] as c_int))
}

/// `process_madvise` with the process the pidfd names found by `target`, in
/// 6.8's order: a flag (`EINVAL`); the vector (`import_iovec`, as
/// [`local_bytes`] takes it); the descriptor (`EBADF`); an advice outside
/// the non-destructive set a pidfd takes (`EINVAL`); init's memory
/// (`mm_access`: `CAP_SYS_PTRACE`, else `EACCES`); then `CAP_SYS_NICE`, which
/// 6.8 requires even of a process advising itself (`EPERM`; the exemption
/// came in 6.13), before any range is looked at. Past it, the advice itself
/// is where the model ends.
pub(super) fn madvise_from(
    credential: &Credential,
    a: &[u64; 6],
    target: impl FnOnce() -> Result<Process, u32>,
) -> Answer {
    if a[4] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    if let Err(code) = local_bytes(a[1], a[2]) {
        return refuse(code);
    }
    let process = match target() {
        Ok(process) => process,
        Err(code) => return refuse(code),
    };
    if !matches!(
        a[3] as i32 as u32,
        MADV_COLD | MADV_PAGEOUT | MADV_WILLNEED | MADV_COLLAPSE
    ) {
        return refuse(errno::EINVAL);
    }
    if process == Process::Init && !credential.capable(Capability::SysPtrace) {
        return refuse(errno::EACCES);
    }
    super::gate(credential, Capability::SysNice, errno::EPERM)
}

/// `process_vm_readv`; see [`process_vm`].
pub(in crate::sud) fn process_vm_readv(credential: &Credential, a: &[u64; 6]) -> Answer {
    process_vm(credential, a, false)
}

/// `process_vm_writev`; see [`process_vm`].
pub(in crate::sud) fn process_vm_writev(credential: &Credential, a: &[u64; 6]) -> Answer {
    process_vm(credential, a, true)
}

/// `enum kcmp_type` (include/uapi/linux/kcmp.h).
const KCMP_FILE: i32 = 0;
const KCMP_VM: i32 = 1;
const KCMP_FILES: i32 = 2;
const KCMP_FS: i32 = 3;
const KCMP_SIGHAND: i32 = 4;
const KCMP_IO: i32 = 5;
const KCMP_SYSVSEM: i32 = 6;
const KCMP_EPOLL_TFD: i32 = 7;

/// `kcmp_ptr`: 0 for one object, else 1 or 2 by the order of the two
/// objects' identities (natively their obfuscated addresses, an order only
/// the host knows; here the identities' own).
fn order<T: Ord>(first: T, second: T) -> i64 {
    i64::from(first < second) | i64::from(first > second) << 1
}

/// The description a task's descriptor names (`get_file_raw_ptr`, whose
/// index is an `unsigned int`): an `O_PATH` descriptor's too.
fn description(index: u64) -> Option<crate::fdtable::DescId> {
    crate::resolve_fd(index as u32 as c_int)
        .ok()
        .map(|resolved| resolved.desc)
}

/// `kcmp(pid1, pid2, type, idx1, idx2)` (kernel/kcmp.c): both pids are
/// looked up first (`ESRCH`); init belongs to root, so inspecting it is
/// `ptrace_may_access`'s `CAP_SYS_PTRACE` (`EPERM`), before the type. Two
/// tasks of the guest share their address space, descriptor table,
/// filesystem state, signal handlers and semaphore undo list (0), and each
/// has its own I/O context once it has one
/// (`crate::thread::sched::io_context`). `KCMP_FILE` compares the
/// descriptions two descriptors name (`EBADF` for either not open);
/// `KCMP_EPOLL_TFD` is [`epoll_target`]'s; another type is `EINVAL`.
pub(in crate::sud) fn kcmp(credential: &Credential, a: &[u64; 6]) -> Answer {
    let (first, second) = (a[0] as i32, a[1] as i32);
    let (Some((one, _)), Some((other, _))) = (find_process(first), find_process(second)) else {
        return refuse(errno::ESRCH);
    };
    if one == Process::Init || other == Process::Init {
        return super::gate(credential, Capability::SysPtrace, errno::EPERM);
    }
    match a[2] as i32 {
        KCMP_FILE => match (description(a[3]), description(a[4])) {
            (Some(one), Some(other)) => Ok(order(one, other)),
            _ => refuse(errno::EBADF),
        },
        KCMP_VM | KCMP_FILES | KCMP_FS | KCMP_SIGHAND | KCMP_SYSVSEM => Ok(0),
        KCMP_IO => Ok(order(
            crate::thread::sched::io_context(first),
            crate::thread::sched::io_context(second),
        )),
        KCMP_EPOLL_TFD => epoll_target(a[3], a[4]),
        _ => refuse(errno::EINVAL),
    }
}

/// `struct kcmp_epoll_slot`: the epoll descriptor, and the target
/// descriptor number and its offset among that number's interests.
#[repr(C)]
#[derive(Clone, Copy)]
struct EpollSlot {
    efd: u32,
    tfd: u32,
    toff: u32,
}

/// `kcmp_epoll_target`: the slot copied in (`EFAULT`), the first task's
/// descriptor (`EBADF`), the second task's epoll descriptor (`EBADF` when
/// not open, `EINVAL` when not an epoll instance), the interest it holds for
/// `(tfd, toff)` (`ENOENT`), then the two descriptions as `KCMP_FILE`
/// compares them.
fn epoll_target(index: u64, slot: u64) -> Answer {
    let Ok(slot) = crate::uaccess::read::<EpollSlot>(slot as usize) else {
        return refuse(errno::EFAULT);
    };
    let Some(file) = description(index) else {
        return refuse(errno::EBADF);
    };
    let Ok(epoll) = crate::resolve_fd(slot.efd as c_int) else {
        return refuse(errno::EBADF);
    };
    if epoll.kind != FdKind::Epoll {
        return refuse(errno::EINVAL);
    }
    match crate::thread::epoll_target(epoll.handle, slot.tfd as c_int, slot.toff) {
        Some(target) => Ok(order(file, target)),
        None => refuse(errno::ENOENT),
    }
}
