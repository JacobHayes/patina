//! Guest memory the kernel would reach through `copy_from_user` /
//! `copy_to_user`: every copy either moves the whole range or answers
//! `EFAULT`, and never faults in the shim.
//!
//! A shim entry that dereferences a guest pointer itself turns the guest's bad
//! argument into a fault in shim code — often while a shim lock is held, where
//! whatever handler the guest installed then runs over half-done shim state
//! (Rust std's `SIGSEGV` handler calls `sigaction`, which re-enters the shim).
//! The kernel instead copies the argument and reports `EFAULT`. On Linux the
//! copy vehicle is `process_vm_readv`/`process_vm_writev` on this process: the
//! kernel copies the range with the page protections a user access sees (an
//! unmapped page, a `PROT_NONE` page, or a write to a read-only page is
//! `EFAULT`), and nothing faults in user space. On Darwin the vehicle is
//! `mach_vm_read_overwrite`/`mach_vm_write` against this task's own port,
//! which answer `KERN_INVALID_ADDRESS` for the same ranges — a write to a
//! read-only page included, a private file mapping too (no copy-on-write
//! break), and a range that wraps the address space — so they are `EFAULT`
//! alike (`KERN_PROTECTION_FAILURE` is taken as one too).
//! A refused vehicle is never an `EFAULT` the guest runs on: it is a named
//! fatal (and, on Linux, a run refused at install by [`probe`]). An
//! embedding that links the prefixed C ABI alone, without the host-alias
//! table (`-Wl,--wrap=dlsym`), passes the runtime its own memory, which is
//! then copied directly.

use std::ffi::c_int;
use std::mem::MaybeUninit;

use crate::EFAULT;

/// One contiguous range of this process's address space, as the kernel's
/// `struct iovec` describes it.
#[cfg(target_os = "linux")]
#[repr(C)]
struct Range {
    base: usize,
    len: usize,
}

/// This process's HOST pid, the target `process_vm_readv` names (the guest's
/// `getpid` answers the virtual process's). It is kept on a page of its own,
/// read-only once the pid is written (a wild or hostile guest store cannot
/// retarget the copies at another host process) and mapped `MADV_WIPEONFORK`,
/// so a forked child (the test harness forks) finds it zeroed and publishes a
/// page of its own rather than copying through its parent's pid; where no
/// such page can be had, the pid is asked every time.
#[cfg(target_os = "linux")]
fn host_pid() -> std::ffi::c_long {
    use std::sync::atomic::{AtomicI64, Ordering};
    let page = PID_PAGE.load(Ordering::Acquire);
    if page != 0 && page != usize::MAX {
        // SAFETY: a live page this module mapped and never unmaps once
        // published; its first eight bytes are the slot.
        let known = unsafe { &*(page as *const AtomicI64) }.load(Ordering::Relaxed);
        if known != 0 {
            return known;
        }
    }
    // SAFETY: `getpid` takes no arguments and cannot fail.
    let pid = unsafe {
        crate::sud_host_syscall(
            patina_dst_syscalls::Syscall::N_getpid.number() as std::ffi::c_long,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    };
    if page == usize::MAX {
        return pid;
    }
    // No page yet, or a parent's wiped by a fork: publish one holding this
    // process's pid. A wiped page stays mapped (another thread may be reading
    // it); one page per fork generation.
    let fresh = pid_page(pid).unwrap_or(usize::MAX);
    if PID_PAGE
        .compare_exchange(page, fresh, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
        && fresh != usize::MAX
    {
        // Another thread published first: give this page back.
        host_munmap(fresh);
    }
    pid
}

/// [`host_pid`]'s page: 0 before the first, `usize::MAX` when there is none
/// to be had.
#[cfg(target_os = "linux")]
static PID_PAGE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One page holding `pid` in its first eight bytes, then made read-only and
/// advised `MADV_WIPEONFORK` (a forked child sees it zeroed).
#[cfg(target_os = "linux")]
fn pid_page(pid: std::ffi::c_long) -> Option<usize> {
    use patina_dst_syscalls::Syscall;
    const PROT_READ: std::ffi::c_long = 0x1;
    const PROT_READ_WRITE: std::ffi::c_long = 0x3;
    const MAP_PRIVATE_ANONYMOUS: std::ffi::c_long = 0x22;
    const MADV_WIPEONFORK: std::ffi::c_long = 18;
    // SAFETY: an anonymous private mapping of one page, written once before
    // it is protected and advised.
    unsafe {
        let page = crate::sud_host_syscall(
            Syscall::N_mmap.number() as std::ffi::c_long,
            0,
            4096,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        );
        if page == -1 {
            return None;
        }
        (page as *mut std::ffi::c_long).write(pid);
        let call = |row: Syscall, arg: std::ffi::c_long| {
            crate::sud_host_syscall(row.number() as std::ffi::c_long, page, 4096, arg, 0, 0, 0)
        };
        if call(Syscall::N_mprotect, PROT_READ) != 0
            || call(Syscall::N_madvise, MADV_WIPEONFORK) != 0
        {
            host_munmap(page as usize);
            return None;
        }
        Some(page as usize)
    }
}

#[cfg(target_os = "linux")]
fn host_munmap(page: usize) {
    // SAFETY: a page this module mapped and never published.
    unsafe {
        crate::sud_host_syscall(
            patina_dst_syscalls::Syscall::N_munmap.number() as std::ffi::c_long,
            page as std::ffi::c_long,
            4096,
            0,
            0,
            0,
            0,
        );
    }
}

/// Why a kernel copy did not move the whole range.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum CopyFailure {
    /// The range is not accessible as a user access sees it (`EFAULT`, or a
    /// short copy that stopped at an inaccessible page): the guest's `EFAULT`.
    Fault,
    /// The copy vehicle itself was refused (a seccomp profile or sandbox
    /// answering `EPERM`/`ENOSYS`, …): no answer the guest could be given.
    Unavailable(c_int),
}

/// The raw result of a call through glibc's `syscall(2)` (the host alias
/// `sud_host_syscall` reaches): the value, or `-errno` for its `-1`.
#[cfg(target_os = "linux")]
fn raw_result(result: std::ffi::c_long) -> std::ffi::c_long {
    if result == -1 {
        -std::ffi::c_long::from(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(crate::EIO),
        )
    } else {
        result
    }
}

/// The guest's own `process_vm_readv` (`write` false) or `process_vm_writev`
/// of its own process: the host kernel's, on this process's host pid, with the
/// guest's vectors, counts and flags as given, so every refusal, fault and
/// short count is the kernel's own. Raw result: `-errno` on failure.
#[cfg(target_os = "linux")]
pub(crate) fn guest_process_vm(write: bool, args: &[u64; 6]) -> i64 {
    let row = if write {
        patina_dst_syscalls::Syscall::N_process_vm_writev
    } else {
        patina_dst_syscalls::Syscall::N_process_vm_readv
    };
    // SAFETY: the kernel judges every guest pointer; this process is the target.
    let result = unsafe {
        crate::sud_host_syscall(
            row.number() as std::ffi::c_long,
            host_pid(),
            args[1] as std::ffi::c_long,
            args[2] as std::ffi::c_long,
            args[3] as std::ffi::c_long,
            args[4] as std::ffi::c_long,
            args[5] as std::ffi::c_long,
        )
    };
    raw_result(result)
}

/// What a `process_vm_readv`/`writev` of `len` bytes that returned `copied`
/// means.
#[cfg(target_os = "linux")]
fn classify(copied: std::ffi::c_long, len: usize) -> Result<(), CopyFailure> {
    match copied {
        whole if whole == len as std::ffi::c_long => Ok(()),
        short if short >= 0 => Err(CopyFailure::Fault),
        error if error == -std::ffi::c_long::from(EFAULT) => Err(CopyFailure::Fault),
        error => Err(CopyFailure::Unavailable((-error) as c_int)),
    }
}

/// Move `len` bytes between shim memory at `local` and the range at `remote`
/// of process `pid` through the kernel: `reading` copies the remote range in
/// (`process_vm_readv`), otherwise out (`process_vm_writev`).
#[cfg(target_os = "linux")]
fn copy_with(
    pid: std::ffi::c_long,
    local: usize,
    remote: usize,
    len: usize,
    reading: bool,
) -> Result<(), CopyFailure> {
    use patina_dst_syscalls::Syscall;
    let row = if reading {
        Syscall::N_process_vm_readv
    } else {
        Syscall::N_process_vm_writev
    };
    let local = Range { base: local, len };
    let remote = Range { base: remote, len };
    // SAFETY: both iovecs describe `len` bytes: the local one is shim-owned
    // memory of that size, the remote one the range the kernel judges.
    let copied = unsafe {
        crate::sud_host_syscall(
            row.number() as std::ffi::c_long,
            pid,
            &local as *const Range as std::ffi::c_long,
            1,
            &remote as *const Range as std::ffi::c_long,
            1,
            0,
        )
    };
    classify(raw_result(copied), len)
}

/// The refusal a copy vehicle the host will not run is reported as, named
/// by what its errno means.
#[cfg(target_os = "linux")]
fn unavailable(errno: c_int) -> String {
    let why = match errno {
        crate::EPERM | crate::ENOSYS => {
            "a seccomp profile or sandbox refusing them, or a kernel without them; allow \
             them (for Docker, a seccomp profile permitting \
             process_vm_readv/process_vm_writev)"
        }
        crate::ENOMEM => "the host is out of memory for the copy's page array",
        _ => "an answer patina does not expect from them; please report it",
    };
    format!(
        "process_vm_readv/process_vm_writev on this process failed with errno {errno} \
         ({why}): patina copies guest memory through them and cannot run here"
    )
}

/// A copy between shim memory and the guest's range on this process: a range
/// the guest cannot access is `EFAULT`; a refused vehicle is a named fatal,
/// never an errno the guest would run on.
#[cfg(target_os = "linux")]
fn kernel_copy(local: usize, remote: usize, len: usize, reading: bool) -> Result<(), c_int> {
    if !crate::hostapi::available() {
        // SAFETY: an embedding of the prefixed C ABI alone (no host-alias
        // table) hands the runtime its own memory; see the module doc.
        unsafe {
            if reading {
                std::ptr::copy_nonoverlapping(remote as *const u8, local as *mut u8, len);
            } else {
                std::ptr::copy_nonoverlapping(local as *const u8, remote as *mut u8, len);
            }
        }
        return Ok(());
    }
    match copy_with(host_pid(), local, remote, len, reading) {
        Ok(()) => Ok(()),
        Err(CopyFailure::Fault) => Err(EFAULT),
        Err(CopyFailure::Unavailable(errno)) => crate::trap_fatal(&unavailable(errno)),
    }
}

/// `KERN_INVALID_ADDRESS`, `KERN_PROTECTION_FAILURE`: a range a user access
/// could not touch. (macOS answers the first for every such range the tests
/// try, read-only pages included.)
#[cfg(target_os = "macos")]
const KERN_FAULTS: [c_int; 2] = [1, 2];

/// A copy between shim memory and the guest's range in this task through the
/// Mach VM calls: a range the guest cannot access is `EFAULT`; any other
/// refusal is a named fatal.
#[cfg(target_os = "macos")]
fn kernel_copy(local: usize, remote: usize, len: usize, reading: bool) -> Result<(), c_int> {
    let api = crate::hostapi::get();
    let mut at = 0;
    while at < len {
        let chunk = (len - at).min(u32::MAX as usize);
        let (result, copied) = if reading {
            let mut copied = 0u64;
            // SAFETY: `local + at` is shim memory of `chunk` bytes the kernel
            // fills; the remote range is judged by the kernel.
            let result = unsafe {
                (api.mach_vm_read_overwrite)(
                    api.task_self,
                    (remote + at) as u64,
                    chunk as u64,
                    (local + at) as u64,
                    &mut copied,
                )
            };
            (result, copied as usize)
        } else {
            // SAFETY: `local + at` is shim memory of `chunk` bytes the kernel
            // reads; the remote range is judged by the kernel.
            let result = unsafe {
                (api.mach_vm_write)(
                    api.task_self,
                    (remote + at) as u64,
                    local + at,
                    chunk as u32,
                )
            };
            (result, chunk)
        };
        match result {
            0 if copied == chunk => at += chunk,
            0 => return Err(EFAULT),
            fault if KERN_FAULTS.contains(&fault) => return Err(EFAULT),
            other => crate::trap_fatal(&format!(
                "mach_vm_read_overwrite/mach_vm_write on this task failed with kern_return_t \
                 {other}: patina copies guest memory through them and cannot run here"
            )),
        }
    }
    Ok(())
}

/// Copy one byte of this process to itself in each direction, as the runtime
/// installs: a host that refuses the copy vehicle refuses the run by name
/// before the guest starts.
#[cfg(target_os = "linux")]
pub(crate) fn probe() -> Result<(), String> {
    if !crate::hostapi::available() {
        return Ok(());
    }
    let source = 0x5au8;
    let mut target = 0u8;
    let local = &mut target as *mut u8 as usize;
    let remote = &source as *const u8 as usize;
    for reading in [true, false] {
        let (local, remote) = if reading {
            (local, remote)
        } else {
            (remote, local)
        };
        match copy_with(host_pid(), local, remote, 1, reading) {
            Ok(()) => {}
            Err(CopyFailure::Unavailable(errno)) => return Err(unavailable(errno)),
            Err(CopyFailure::Fault) => {
                return Err(
                    "process_vm_readv/process_vm_writev could not copy a byte of \
                            this process to itself; patina copies guest memory through \
                            them and cannot run here"
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

/// Fill `into` from the guest's `addr`.
pub(crate) fn read_into(addr: usize, into: &mut [u8]) -> Result<(), c_int> {
    if into.is_empty() {
        return Ok(());
    }
    if addr == 0 {
        return Err(EFAULT);
    }
    kernel_copy(into.as_mut_ptr() as usize, addr, into.len(), true)
}

/// Fill `into` from the guest ranges `ranges` in order (their lengths sum to
/// `into.len()`): one kernel copy for the lot on Linux, as `copy_from_iter`
/// walks an iovec.
pub(crate) fn read_gather(ranges: &[(usize, usize)], into: &mut [u8]) -> Result<(), c_int> {
    #[cfg(target_os = "linux")]
    if ranges.len() > 1 && crate::hostapi::available() {
        return gather(ranges, into);
    }
    let mut filled = 0;
    for &(base, len) in ranges {
        read_into(base, &mut into[filled..filled + len])?;
        filled += len;
    }
    Ok(())
}

/// [`read_gather`] as one `process_vm_readv` per `UIO_MAXIOV` ranges.
#[cfg(target_os = "linux")]
fn gather(ranges: &[(usize, usize)], into: &mut [u8]) -> Result<(), c_int> {
    /// `UIO_MAXIOV`: the most ranges one call takes.
    const BATCH: usize = 1024;
    let mut filled = 0;
    for batch in ranges.chunks(BATCH) {
        let remote: Vec<Range> = batch
            .iter()
            .filter(|(_, len)| *len != 0)
            .map(|&(base, len)| Range { base, len })
            .collect();
        let len: usize = remote.iter().map(|range| range.len).sum();
        if len == 0 {
            continue;
        }
        let local = Range {
            base: into[filled..].as_mut_ptr() as usize,
            len,
        };
        // SAFETY: the local iovec is `len` bytes of `into`; the remote
        // ranges are the guest's, judged by the kernel.
        let copied = unsafe {
            crate::sud_host_syscall(
                patina_dst_syscalls::Syscall::N_process_vm_readv.number() as std::ffi::c_long,
                host_pid(),
                &local as *const Range as std::ffi::c_long,
                1,
                remote.as_ptr() as std::ffi::c_long,
                remote.len() as std::ffi::c_long,
                0,
            )
        };
        match classify(raw_result(copied), len) {
            Ok(()) => filled += len,
            Err(CopyFailure::Fault) => return Err(EFAULT),
            Err(CopyFailure::Unavailable(errno)) => crate::trap_fatal(&unavailable(errno)),
        }
    }
    Ok(())
}

/// A name at the guest's `addr`, as `getname` copies one in
/// (`strncpy_from_user` up to `PATH_MAX`): `EFAULT` where a byte before the
/// terminator cannot be read, `ENAMETOOLONG` with no terminator within
/// `PATH_MAX` bytes, `ENOENT` for an empty name. It is read a page at a time,
/// so a name that ends before an unmapped page reads.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn read_name(addr: usize) -> Result<Vec<u8>, c_int> {
    const PATH_MAX: usize = crate::paths::PATH_MAX;
    let mut name = Vec::new();
    while name.len() < PATH_MAX {
        let at = addr.checked_add(name.len()).ok_or(EFAULT)?;
        let room = (crate::PAGE_SIZE - at % crate::PAGE_SIZE).min(PATH_MAX - name.len());
        let chunk = read_bytes(at, room)?;
        match chunk.iter().position(|byte| *byte == 0) {
            Some(end) => {
                name.extend_from_slice(&chunk[..end]);
                return if name.is_empty() {
                    Err(crate::ENOENT)
                } else {
                    Ok(name)
                };
            }
            None => name.extend_from_slice(&chunk),
        }
    }
    Err(crate::ENAMETOOLONG)
}

/// The kernel's `access_ok(addr, size)`: whether the range lies in the
/// user address space, without touching it. On x86_64 6.8's `__access_ok`
/// takes a range that does not wrap and ends below the sign bit
/// (`valid_user_address`), never `TASK_SIZE_MAX`; its constant-size form
/// (`size <= PAGE_SIZE` known at compile time) checks only the pointer's
/// sign, which the same test gives for every size this is called with that
/// small. On aarch64 it is asm-generic's, against `1 << VA_BITS` (48,
/// Ubuntu's config; derived, not yet read live on an arm64 6.8). A NULL
/// range passes: only the copy then faults.
#[cfg(target_os = "linux")]
pub(crate) fn access_ok(addr: usize, size: usize) -> bool {
    #[cfg(target_arch = "x86_64")]
    return addr
        .checked_add(size)
        .is_some_and(|end| (end as isize) >= 0);
    #[cfg(target_arch = "aarch64")]
    {
        const TASK_SIZE_MAX: usize = 1 << 48;
        size <= TASK_SIZE_MAX && addr <= TASK_SIZE_MAX - size
    }
}

/// The `len` guest bytes at `addr`.
pub(crate) fn read_bytes(addr: usize, len: usize) -> Result<Vec<u8>, c_int> {
    let mut bytes = vec![0u8; len];
    read_into(addr, &mut bytes)?;
    Ok(bytes)
}

/// A plain-data value of type `T` at the guest's `addr`.
pub(crate) fn read<T: Copy>(addr: usize) -> Result<T, c_int> {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: the byte view covers exactly the uninitialized value, and a
    // successful copy initializes every byte of a plain-data `T`.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>()) };
    read_into(addr, bytes)?;
    // SAFETY: fully written above; `T: Copy` carries no invariants beyond its
    // bytes for the plain C structures this module is used with.
    Ok(unsafe { value.assume_init() })
}

/// `count` plain-data values of type `T` from the guest array at `addr`.
#[cfg(target_os = "linux")]
pub(crate) fn read_vec<T: Copy + Default>(addr: usize, count: usize) -> Result<Vec<T>, c_int> {
    let mut values = vec![T::default(); count];
    // SAFETY: the byte view covers exactly the vector's initialized values.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            values.as_mut_ptr().cast::<u8>(),
            count.checked_mul(size_of::<T>()).ok_or(EFAULT)?,
        )
    };
    read_into(addr, bytes)?;
    Ok(values)
}

/// Copy `values` to the guest array at `addr`.
#[cfg(target_os = "linux")]
pub(crate) fn write_slice<T: Copy>(addr: usize, values: &[T]) -> Result<(), c_int> {
    // SAFETY: plain-data values viewed as their own bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), size_of_val(values)) };
    write_bytes(addr, bytes)
}

/// Copy `bytes` to the guest's `addr`.
pub(crate) fn write_bytes(addr: usize, bytes: &[u8]) -> Result<(), c_int> {
    if bytes.is_empty() {
        return Ok(());
    }
    if addr == 0 {
        return Err(EFAULT);
    }
    kernel_copy(bytes.as_ptr() as usize, addr, bytes.len(), false)
}

/// Copy a plain-data value to the guest's `addr`.
pub(crate) fn write<T: Copy>(addr: usize, value: &T) -> Result<(), c_int> {
    // SAFETY: a plain-data value viewed as its own bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
    write_bytes(addr, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page the test maps with `prot`, unmapped on drop.
    struct Page(usize);

    fn page_size() -> usize {
        // SAFETY: `sysconf` reads a constant.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    impl Page {
        fn new(prot: i32) -> Page {
            // SAFETY: an anonymous private mapping of one page.
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page_size(),
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED);
            Page(addr as usize)
        }
    }

    impl Drop for Page {
        fn drop(&mut self) {
            // SAFETY: the mapping this page made.
            unsafe { libc::munmap(self.0 as *mut libc::c_void, page_size()) };
        }
    }

    #[test]
    fn a_readable_range_copies_whole() {
        let source = *b"guest bytes";
        assert_eq!(
            read_bytes(source.as_ptr() as usize, source.len()),
            Ok(source.to_vec())
        );
        assert_eq!(read::<[u8; 5]>(source.as_ptr() as usize), Ok(*b"guest"));
        let mut target = [0u8; 4];
        assert_eq!(write(target.as_mut_ptr() as usize, &[1u8, 2, 3, 4]), Ok(()));
        assert_eq!(target, [1, 2, 3, 4]);
    }

    #[test]
    fn an_unmapped_or_protected_range_is_efault_without_faulting() {
        assert_eq!(read_bytes(1, 8), Err(EFAULT));
        assert_eq!(read_bytes(0, 8), Err(EFAULT));
        let none = Page::new(libc::PROT_NONE);
        assert_eq!(read_bytes(none.0, 4), Err(EFAULT));
        assert_eq!(write_bytes(none.0, b"x"), Err(EFAULT));
        let read_only = Page::new(libc::PROT_READ);
        assert_eq!(read_bytes(read_only.0, 4), Ok(vec![0; 4]));
        assert_eq!(write_bytes(read_only.0, b"x"), Err(EFAULT));
    }

    #[test]
    fn a_range_running_into_an_inaccessible_page_is_efault() {
        let readable = Page::new(libc::PROT_READ | libc::PROT_WRITE);
        let guard = Page::new(libc::PROT_NONE);
        // Only a straddling range when the kernel placed the two adjacently;
        // otherwise the tail of `readable` alone is still a whole copy.
        let end = readable.0 + page_size();
        if guard.0 == end {
            assert_eq!(read_bytes(end - 6, 12), Err(EFAULT));
        }
        assert_eq!(read_bytes(end - 6, 6), Ok(vec![0; 6]));
    }

    /// Only an inaccessible range is the guest's `EFAULT`: a refused copy
    /// (here one aimed at a process that is not there, forced through the
    /// same call; in a sandbox `EPERM` or `ENOSYS`) is a different failure.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_copy_is_not_efault() {
        let source = [1u8; 4];
        let mut target = [0u8; 4];
        let refused = copy_with(
            i32::MAX as std::ffi::c_long,
            target.as_mut_ptr() as usize,
            source.as_ptr() as usize,
            4,
            true,
        );
        assert!(
            matches!(refused, Err(CopyFailure::Unavailable(errno)) if errno != EFAULT),
            "{refused:?}"
        );
        assert_eq!(
            classify(-(libc::EPERM as std::ffi::c_long), 4),
            Err(CopyFailure::Unavailable(libc::EPERM))
        );
        assert_eq!(
            classify(-(libc::ENOSYS as std::ffi::c_long), 4),
            Err(CopyFailure::Unavailable(libc::ENOSYS))
        );
        assert_eq!(
            classify(-(libc::EFAULT as std::ffi::c_long), 4),
            Err(CopyFailure::Fault)
        );
        assert_eq!(classify(2, 4), Err(CopyFailure::Fault));
        assert_ne!(unavailable(libc::EPERM), unavailable(libc::ENOMEM));
        assert_ne!(unavailable(libc::ENOMEM), unavailable(libc::EINVAL));
        assert_eq!(classify(4, 4), Ok(()));
        assert_eq!(probe(), Ok(()));
    }

    #[test]
    fn gathered_ranges_fill_in_order_and_a_bad_one_is_efault() {
        let (first, second) = (*b"gath", *b"ered");
        let ranges = [
            (first.as_ptr() as usize, 4),
            (0, 0),
            (second.as_ptr() as usize, 4),
        ];
        let mut into = [0u8; 8];
        assert_eq!(read_gather(&ranges, &mut into), Ok(()));
        assert_eq!(&into, b"gathered");
        let none = Page::new(libc::PROT_NONE);
        let bad = [(first.as_ptr() as usize, 4), (none.0, 4)];
        assert_eq!(read_gather(&bad, &mut into), Err(EFAULT));
    }

    /// A write to a read-only private file mapping is `EFAULT` and leaves
    /// the page as it was: the vehicle breaks no copy-on-write the way a
    /// debugger's forced write would (`FOLL_FORCE` on Linux, a
    /// `VM_PROT_WRITE` maximum protection on Darwin).
    #[test]
    fn a_write_to_a_read_only_file_mapping_is_efault() {
        use std::os::fd::AsRawFd;
        let path =
            std::env::temp_dir().join(format!("patina-uaccess-{}-read-only", std::process::id()));
        std::fs::write(&path, vec![7u8; page_size()]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        // SAFETY: a private read-only mapping of the file's one page.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size(),
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let mapped = Page(addr as usize);
        assert_eq!(write_bytes(mapped.0, b"x"), Err(EFAULT));
        assert_eq!(read_bytes(mapped.0, 1), Ok(vec![7]));
    }

    /// A range whose end wraps past the top of the address space is no
    /// user range: `EFAULT` both ways, as `access_ok` (and on Linux the copy
    /// vehicle) answers.
    /// The host pid the copies target sits on a read-only page: a guest
    /// store through the kernel's own user access is refused, and the pid
    /// stays this process's.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_pid_slot_is_read_only() {
        let pid = host_pid();
        assert_eq!(pid, std::process::id() as std::ffi::c_long);
        let page = PID_PAGE.load(std::sync::atomic::Ordering::Acquire);
        assert_ne!(page, 0);
        assert_eq!(write_bytes(page, &[0; 8]), Err(EFAULT));
        assert_eq!(host_pid(), pid);
    }

    #[test]
    fn a_range_that_wraps_the_address_space_is_efault() {
        assert_eq!(read_bytes(usize::MAX - 3, 8), Err(EFAULT));
        assert_eq!(write_bytes(usize::MAX - 3, &[0; 8]), Err(EFAULT));
    }

    /// The Darwin vehicle itself, called as `kernel_copy` calls it: an
    /// inaccessible range answers one of the two fault codes (never a
    /// signal, and never another code that would be the named fatal).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_mach_vehicle_answers_a_fault_code_for_an_inaccessible_range() {
        let api = crate::hostapi::get();
        let none = Page::new(libc::PROT_NONE);
        let read_only = Page::new(libc::PROT_READ);
        let mut into = [0u8; 4];
        let mut copied = 0u64;
        // SAFETY: `into` is 4 bytes of test memory the call may fill.
        let read = unsafe {
            (api.mach_vm_read_overwrite)(
                api.task_self,
                none.0 as u64,
                4,
                into.as_mut_ptr() as u64,
                &mut copied,
            )
        };
        assert!(
            KERN_FAULTS.contains(&read),
            "mach_vm_read_overwrite: {read}"
        );
        let bytes = [1u8; 4];
        for page in [&none, &read_only] {
            // SAFETY: `bytes` is 4 bytes of test memory the call reads.
            let wrote = unsafe {
                (api.mach_vm_write)(api.task_self, page.0 as u64, bytes.as_ptr() as usize, 4)
            };
            assert!(KERN_FAULTS.contains(&wrote), "mach_vm_write: {wrote}");
        }
        // SAFETY: a readable page of the test's own.
        assert_eq!(unsafe { *(read_only.0 as *const u8) }, 0);
    }

    #[test]
    fn an_empty_range_touches_nothing() {
        assert_eq!(read_bytes(1, 0), Ok(Vec::new()));
        assert_eq!(write_bytes(1, &[]), Ok(()));
    }
}
