//! The rows that reach another process through a pidfd or a pid:
//! `pidfd_getfd`, `process_madvise` and `get_robust_list`. The virtual pid
//! namespace holds init and the guest; init is root's, so reaching it is
//! `CAP_SYS_PTRACE`, and what follows is where the model ends.

use super::{Answer, Unmodeled, refuse};
use crate::identity::{Credential, Process, lookup as find_process, ptrace_may_access};
use crate::registry::Capability;
use linux_raw_sys::errno;
use linux_raw_sys::general::{MADV_COLD, MADV_COLLAPSE, MADV_PAGEOUT, MADV_WILLNEED};
use std::ffi::c_int;

/// `pidfd_getfd(pidfd, fd, flags)` (kernel/pid.c); see [`getfd_from`].
pub(in crate::sud) fn pidfd_getfd(credential: &Credential, a: &[u64; 6]) -> Answer {
    getfd_from(credential, a, || crate::sud::pidfd::target(a[0] as c_int))
}

/// `pidfd_getfd` with the process the pidfd names found by `target`: a flag
/// (`EINVAL`), then the descriptor (`EBADF`). Taking a descriptor of init,
/// root's, is [`ptrace_may_access`] (`PTRACE_MODE_ATTACH_REALCREDS`):
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
        Ok(process) if process == Process::current() => Ok(
            match crate::at_free_numbers(|| crate::fd_table().lock().dup(a[1] as c_int, 0, true)) {
                Ok(fd) => i64::from(fd),
                Err(code) => -i64::from(code),
            },
        ),
        Ok(process) => other_process(credential, process, errno::EPERM),
    }
}

/// `get_robust_list(pid, head_ptr, len_ptr)` (kernel/futex/syscalls.c): the
/// pid is looked up first; reading another process's head is
/// [`ptrace_may_access`] (`PTRACE_MODE_READ_REALCREDS`): init is root's, so
/// `CAP_SYS_PTRACE` (`EPERM`). Every other pid is the thread model's: the
/// caller's own threads, or `ESRCH`.
pub(in crate::sud) fn get_robust_list(credential: &Credential, a: &[u64; 6]) -> Answer {
    let pid = a[0] as i32;
    if let Some((process, _)) =
        find_process(pid).filter(|(process, _)| *process != Process::current())
    {
        return other_process(credential, process, errno::EPERM);
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

/// Another process's state behind the ptrace-mode check: `refusal` unless
/// the caller may reach it ([`ptrace_may_access`]). The only other process
/// is init, root's, which the guest's credential reaches only through
/// `CAP_SYS_PTRACE`; what follows is where the model ends.
fn other_process(credential: &Credential, process: Process, refusal: u32) -> Answer {
    if ptrace_may_access(credential, process) {
        Err(Unmodeled::Granted(Capability::SysPtrace))
    } else {
        refuse(refusal)
    }
}

/// Whether `len` bytes at `base` are a user range ([`crate::uaccess::access_ok`]).
fn user_range(base: u64, len: u64) -> bool {
    crate::uaccess::access_ok(base as usize, len as usize)
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
/// (`mm_access`, [`ptrace_may_access`]: init is root's, so `CAP_SYS_PTRACE`,
/// else `EACCES`); then `CAP_SYS_NICE`, which
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
    if !ptrace_may_access(credential, process) {
        return refuse(errno::EACCES);
    }
    super::gate(credential, Capability::SysNice, errno::EPERM)
}
