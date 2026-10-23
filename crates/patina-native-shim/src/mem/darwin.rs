//! XNU's address-space rows: `mmap`, `munmap`, `mprotect` and `msync` as
//! libSystem and the kernel judge them, over the views in `views`.
//!
//! A file mapping is judged where XNU judges it. The request alone comes
//! first: libSystem's wrapper refuses a zero length or a mapping of neither
//! type, and the kernel then judges the offset, a fixed address and the
//! flags, all before it looks the descriptor up. Those judgments are the
//! host's own: the same request on descriptor -1 answers what the kernel
//! refuses before the lookup, or `EBADF` from the lookup, having mapped
//! nothing. The guest's descriptor and its access come next, judged here as
//! XNU judges them, and what is left of the request (its length, protection
//! and placement) the host judges again when it maps the page file.
//!
//! Anonymous memory is the host's, as on Linux: its descriptor is a VM tag
//! (`VM_MAKE_TAG`), never a file.

#![deny(clippy::undocumented_unsafe_blocks)]
// The rows' only callers are the libc interposers of the guest build.
#![cfg_attr(not(patina_posix_exports), allow(dead_code))]

use super::*;
use crate::abi::{Errno, SysResult};

/// A raw host answer as the row's result.
fn answer(result: i64) -> SysResult<i64> {
    if result < 0 {
        Err(Errno::new((-result) as c_int))
    } else {
        Ok(result)
    }
}

/// `mmap(2)`: the address, or the errno.
pub(crate) fn mmap(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> SysResult<usize> {
    let result = if flags & MAP_ANON != 0 {
        let result = host_map(addr, len, prot, flags, fd, offset as usize);
        if result >= 0 && flags & MAP_FIXED != 0 && tracking() {
            crate::LAST_BOUNDARY_SYMBOL.store(c"mmap".as_ptr().cast_mut(), Ordering::Relaxed);
            forget(result as usize, len);
        }
        result
    } else {
        map_file(addr, len, prot, flags, fd, offset)
    };
    answer(result).map(|address| address as usize)
}

/// A mapping of a guest descriptor, in XNU's order of refusals: the address,
/// or `-errno`.
fn map_file(addr: usize, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> i64 {
    let judged = host_map(addr, len, prot, flags, -1, offset as usize);
    if judged >= 0 {
        host_unmap(judged as usize, len);
        crate::trap_fatal("the host mapped a file mapping of descriptor -1");
    }
    if judged != fail(crate::EBADF) {
        return judged;
    }
    let resolved = match crate::fdget(fd) {
        Ok(resolved) => resolved,
        Err(_) => return fail(crate::EBADF),
    };
    // Only a vnode maps: a character device has no pager (`ENODEV`), and
    // what is not a vnode, or not a regular one, is `EINVAL`.
    match resolved.kind {
        FdKind::File => {}
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::MemDevice => {
            return fail(crate::ENODEV);
        }
        FdKind::Dir | FdKind::OPath | FdKind::Socket | FdKind::Pipe | FdKind::Kqueue => {
            return fail(crate::EINVAL);
        }
    }
    // A description not open for reading maps only without access; a shared
    // mapping that writes needs one open for writing.
    let readable = resolved.status & crate::O_READ != 0;
    let writable = resolved.status & crate::O_WRITE != 0;
    let shared = flags & MAP_SHARED != 0;
    let access = prot & (libc::PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!readable && access != 0) || (shared && prot & PROT_WRITE != 0 && !writable) {
        return fail(crate::EACCES);
    }
    // The inode and size a kernel reads off the file's vnode: bookkeeping,
    // so no injected `fstat` fault reaches it, and no `mmap` fails for one.
    let handle = resolved.handle;
    let metadata =
        match crate::with_context(|context| context.fs_fd_metadata_unrecorded(Fd(handle))) {
            Ok(metadata) => metadata,
            Err(errno) => return fail(errno),
        };
    if metadata.kind != FsEntryKind::File {
        return fail(crate::EINVAL);
    }
    let Some(rounded) = round_up(len) else {
        return fail(crate::ENOMEM);
    };
    crate::LAST_BOUNDARY_SYMBOL.store(c"mmap".as_ptr().cast_mut(), Ordering::Relaxed);
    let pages = match cache_for(metadata.ino, handle, metadata.len) {
        Ok(pages) => pages,
        Err(result) => return result,
    };
    let object = Object::File {
        ino: metadata.ino,
        desc: resolved.desc,
        shared,
        maywrite: !shared || writable,
        secret: false,
    };
    let fixed = (flags & MAP_FIXED != 0).then_some(addr);
    let result = alias(
        pages,
        offset as usize,
        rounded,
        fixed,
        prot,
        flags & !MAP_FIXED,
        object,
    );
    if result >= 0 {
        MAPPINGS.lock().handles.insert(handle, metadata.ino);
    } else {
        settle(&[metadata.ino]);
    }
    result
}

/// `munmap(2)`: the host's answer, and the views of the range leave the
/// table.
pub(crate) fn munmap(addr: usize, len: usize) -> SysResult<i64> {
    let result = host_unmap(addr, len);
    if result == 0 && tracking() {
        crate::LAST_BOUNDARY_SYMBOL.store(c"munmap".as_ptr().cast_mut(), Ordering::Relaxed);
        forget(addr, len);
    }
    answer(result)
}

/// `mprotect(2)`: write access to a shared view that may not write is
/// `EACCES`, as the first violation of the range `vm_map_protect` meets.
/// It checks every entry, in address order, before anything changes, so an
/// unmapped page below the first refusing view is `ENOMEM` first, and a hole
/// above it is never reached. The rest is the host's.
pub(crate) fn mprotect(addr: usize, len: usize, prot: c_int) -> SysResult<i64> {
    if prot & PROT_WRITE != 0
        && addr.is_multiple_of(PAGE)
        && len != 0
        && tracking()
        && let Some(end) = round_up(len).and_then(|len| addr.checked_add(len))
        && let Some(refused) = MAPPINGS
            .lock()
            .views
            .within(addr, end)
            .into_iter()
            .find(|(_, _, object)| object.refuses(prot))
            .map(|(start, _, _)| start)
    {
        let errno = if mapped_through(addr, refused) {
            crate::EACCES
        } else {
            crate::ENOMEM
        };
        return Err(Errno::new(errno));
    }
    // SAFETY: a protection change of the process's own address space through
    // the real libSystem entry, never the interposed one.
    let result =
        unsafe { (crate::hostapi::get().host_mprotect)(addr as *mut std::ffi::c_void, len, prot) };
    answer(if result == -1 { host_failure() } else { 0 })
}

/// Whether every page of `[from, to)` is mapped, as the host's address space
/// says (`mach_vm_region` answers the region at or above an address).
fn mapped_through(from: usize, to: usize) -> bool {
    /// `VM_REGION_BASIC_INFO_64` and its `vm_region_basic_info_64`, in `int`s.
    const BASIC_INFO_64: c_int = 9;
    const BASIC_INFO_COUNT_64: u32 = 9;
    let api = crate::hostapi::get();
    let mut at = from;
    while at < to {
        let mut address = at as u64;
        let mut size = 0u64;
        let mut info = [0 as c_int; BASIC_INFO_COUNT_64 as usize];
        let mut count = BASIC_INFO_COUNT_64;
        let mut object = 0u32;
        // SAFETY: a query of this task's own address space into locals sized
        // for the flavor; the kernel writes no more than `count` ints.
        let result = unsafe {
            (api.mach_vm_region)(
                api.task_self,
                &mut address,
                &mut size,
                BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if result != 0 || address > at as u64 {
            return false;
        }
        at = address.saturating_add(size) as usize;
    }
    true
}

/// The refusal `msync(MS_KILLPAGES)` of a shared file view gets.
const DENY_KILLPAGES: &str = "patina: msync(MS_KILLPAGES) over a shared file mapping has no model \
    (it discards the changed pages for what the host last wrote of the page file, on the host's \
    schedule); failing closed\n";

/// Whether `msync` with `flags` writes the range's changes to their files
/// and waits (`msync_nocancel`): it does unless it is asked to only start
/// that (`MS_ASYNC`), or to dispose of the pages instead (`MS_KILLPAGES`,
/// `MS_DEACTIVATE`), whatever `MS_SYNC` says.
fn synchronizes(flags: c_int) -> bool {
    flags & (MS_ASYNC | MS_KILLPAGES | MS_DEACTIVATE) == 0
}

/// `msync(2)`: the host's answer for the range, then, when the call
/// synchronizes, a write-back and a sync of every file a shared view in it
/// maps. A hole in the range is `ENOMEM` once the mapped parts on both sides
/// are synchronized, as `vm_map_msync` walks past it. `MS_KILLPAGES` over a
/// shared view is refused by name (`ENOSYS`): what it leaves behind depends
/// on when the host wrote the page file.
pub(crate) fn msync(addr: usize, len: usize, flags: c_int) -> SysResult<i64> {
    let tracked = tracking();
    let end = addr.saturating_add(round_up(len).unwrap_or(usize::MAX));
    if flags & MS_KILLPAGES != 0
        && tracked
        && MAPPINGS
            .lock()
            .views
            .within(addr, end)
            .iter()
            .any(|(_, _, object)| object.is_shared())
    {
        crate::deny(DENY_KILLPAGES);
        return Err(Errno::new(crate::ENOSYS));
    }
    // SAFETY: a synchronization of the process's own address space through
    // the real libSystem entry, never the interposed one.
    let result =
        unsafe { (crate::hostapi::get().host_msync)(addr as *mut std::ffi::c_void, len, flags) };
    let result = if result == -1 { host_failure() } else { 0 };
    if (result != 0 && result != fail(crate::ENOMEM)) || !tracked || !synchronizes(flags) {
        return answer(result);
    }
    let mut files: Vec<(u64, u64)> = {
        let mappings = MAPPINGS.lock();
        mappings
            .views
            .within(addr, end)
            .into_iter()
            .filter(|(_, _, object)| object.is_shared())
            .filter_map(|(_, _, object)| {
                let handle = mappings.descs.get(&object.desc()?)?;
                Some((object.ino()?, *handle))
            })
            .collect()
    };
    files.sort_unstable();
    files.dedup_by_key(|(ino, _)| *ino);
    crate::LAST_BOUNDARY_SYMBOL.store(c"msync".as_ptr().cast_mut(), Ordering::Relaxed);
    for (ino, handle) in files {
        if let Some(writer) = writer_of(ino) {
            write_back(ino, writer).map_err(Errno::new)?;
        }
        crate::with_context(|context| context.fs_sync(Fd(handle))).map_err(Errno::new)?;
    }
    answer(result)
}
