//! Address-space mappings and mapped-view bookkeeping.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---------------------------------------------------------------- mappings

/// `mmap(2)`: the address, or `-errno` at the prefixed ABI boundary.
pub(crate) fn mmap(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> crate::abi::SysResult<usize> {
    let result = if flags & MAP_ANONYMOUS != 0 {
        map_anonymous(addr, len, prot, flags, offset)
    } else {
        map_file(addr, len, prot, flags, fd, offset)
    };
    crate::abi::LinuxReturn::new(result)
        .decode()
        .map(|address| address as usize)
}

/// `mmap(2)`: the address, or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_mmap(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::raw(mmap(addr, len, prot, flags, fd, offset).map(|address| address as i64))
}

/// An anonymous mapping: host address space. Linux ignores its descriptor,
/// and a guest number means nothing to the host kernel, so it never gets one.
fn map_anonymous(addr: usize, len: usize, prot: c_int, flags: c_int, offset: i64) -> i64 {
    let fixed = flags & MAP_FIXED != 0;
    if flags & MAP_HUGETLB != 0 {
        // `ksys_mmap_pgoff`: the pool first, the length rounded to its page.
        let Some(size) = huge_page_size(((flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK) as u32) else {
            return fail(EINVAL);
        };
        let len = len.next_multiple_of(size);
        if len == 0 || !(offset as usize).is_multiple_of(PAGE) {
            return fail(EINVAL);
        }
        // `MAP_FIXED_NOREPLACE` is `MAP_FIXED` to `hugetlb_get_unmapped_area`.
        if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 && !addr.is_multiple_of(size) {
            return fail(EINVAL);
        }
        return map_huge_pages(addr, len, prot, flags, size);
    }
    let lock = if flags & MAP_LOCKED != 0 || TRACKED.load(Ordering::Acquire) {
        // The judgments `do_mmap` makes before a lock is weighed.
        if len == 0
            || !(offset as usize).is_multiple_of(PAGE)
            || (fixed && !addr.is_multiple_of(PAGE))
        {
            None
        } else {
            match lock_request(flags, len) {
                Ok(lock) => lock,
                Err(errno) => return fail(errno),
            }
        }
    } else {
        None
    };
    let result = host(
        Syscall::N_mmap,
        [
            addr,
            len,
            prot as usize,
            (flags & !MAP_LOCKED) as usize,
            usize::MAX,
            offset as usize,
        ],
    );
    if result >= 0 {
        let start = result as usize;
        let rounded = round_up(len).unwrap_or(len);
        if fixed && tracking() {
            crate::LAST_BOUNDARY_SYMBOL.store(c"mmap".as_ptr().cast_mut(), Ordering::Relaxed);
            forget(start, rounded);
        }
        if let Some(onfault) = lock {
            let _ignore_errors = lock_range(start, rounded, onfault);
        }
    }
    result
}

/// A mapping of a guest descriptor, in `ksys_mmap_pgoff`/`do_mmap`'s order
/// of refusals.
fn map_file(addr: usize, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> i64 {
    if !(offset as u64).is_multiple_of(PAGE as u64) {
        return fail(EINVAL);
    }
    // `fget` never returns an `O_PATH` file.
    let resolved = match crate::fdget(fd) {
        Ok(resolved) => resolved,
        Err(_) => return fail(EBADF),
    };
    // A hugetlbfs file maps in whole huge pages; any other file refuses
    // `MAP_HUGETLB`.
    let huge = match resolved.kind {
        FdKind::File => anonymous(resolved.handle).filter(|size| *size != 0),
        _ => None,
    };
    let len = match huge {
        Some(size) => len.next_multiple_of(size as usize),
        None if flags & MAP_HUGETLB != 0 => return fail(EINVAL),
        None => len,
    };
    if len == 0 {
        return fail(EINVAL);
    }
    let Some(rounded) = round_up(len).filter(|rounded| *rounded != 0) else {
        return fail(ENOMEM);
    };
    let pgoff = offset as u64 / PAGE as u64;
    if pgoff.checked_add((rounded / PAGE) as u64).is_none() {
        return fail(EOVERFLOW);
    }
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let align = huge.map_or(PAGE, |size| size as usize);
    if fixed && !addr.is_multiple_of(align) {
        return fail(EINVAL);
    }
    // `MAP_FIXED_NOREPLACE` is refused over a live mapping before the file is
    // judged; the claim holds the range until the view replaces it.
    let claimed = flags & MAP_FIXED_NOREPLACE != 0;
    if claimed {
        let claim = host(
            Syscall::N_mmap,
            [
                addr,
                rounded,
                0,
                (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE) as usize,
                usize::MAX,
                0,
            ],
        );
        if claim < 0 {
            return claim;
        }
    }
    let result = map_file_judged(addr, rounded, prot, flags, &resolved, offset, huge);
    if result < 0 && claimed {
        host(Syscall::N_munmap, [addr, rounded, 0, 0, 0, 0]);
    }
    result
}

fn map_file_judged(
    addr: usize,
    rounded: usize,
    prot: c_int,
    flags: c_int,
    resolved: &crate::fdtable::Resolved,
    offset: i64,
    huge: Option<u64>,
) -> i64 {
    let lock = match lock_request(flags, rounded) {
        Ok(lock) => lock,
        Err(errno) => return fail(errno),
    };
    // `file_mmap_ok`: the range must fit a file offset.
    if (offset as u64)
        .checked_add(rounded as u64)
        .is_none_or(|end| end > i64::MAX as u64)
    {
        return fail(EOVERFLOW);
    }
    let writable = resolved.status & crate::O_WRITE != 0;
    let secret = resolved.kind == FdKind::File && secret(resolved.handle);
    let shared = match judge(
        flags,
        prot,
        resolved.status & crate::O_READ != 0,
        writable,
        resolved.kind == FdKind::File,
        secret,
    ) {
        Ok(shared) => shared,
        Err(errno) => return fail(errno),
    };
    // `secretmem_mmap`: a shared mapping only, and its pages are locked
    // (`mlock_future_ok`: `EAGAIN` past the limit) as they fault in, unless
    // `MAP_LOCKED` populates them. It runs inside `mmap_region`, after a
    // `MAP_FIXED` mapping has unmapped what it replaces, so the locked pages
    // in that range no longer count.
    let lock = if secret {
        if !shared {
            return fail(EINVAL);
        }
        let locked = {
            let mappings = MAPPINGS.lock();
            let replaced = if flags & MAP_FIXED != 0 {
                mappings.locks.covered(addr, addr + rounded)
            } else {
                0
            };
            mappings.locks.total() - replaced
        };
        if locked / PAGE + rounded / PAGE > lock_limit_pages() {
            return fail(crate::EWOULDBLOCK);
        }
        Some(lock.unwrap_or(true))
    } else {
        lock
    };
    crate::LAST_BOUNDARY_SYMBOL.store(c"mmap".as_ptr().cast_mut(), Ordering::Relaxed);
    let handle = resolved.handle;
    if let Some(size) = huge {
        // `hugetlbfs_file_mmap`: a huge-page-aligned offset, then the pool.
        let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        if !(offset as u64).is_multiple_of(size) || (fixed && !(addr as u64).is_multiple_of(size)) {
            return fail(EINVAL);
        }
        let flags = flags & (MAP_TYPE | MAP_NORESERVE | MAP_FIXED | MAP_FIXED_NOREPLACE);
        return map_huge_pages(addr, rounded, prot, flags, size as usize);
    }
    let metadata = match crate::with_context(|context| context.fs_fd_metadata(Fd(handle))) {
        Ok(metadata) => metadata,
        Err(errno) => return fail(errno),
    };
    if metadata.kind != FsEntryKind::File {
        return fail(ENODEV);
    }
    // `seal_check_write`: a write-sealed file takes no new shared writable
    // mapping, and a shared read-only one can never be made writable. Only an
    // anonymous file carries seals.
    let sealed = shared
        && anonymous(handle).is_some()
        && matches!(
            crate::with_context_raw(|context| context.fs_seals(Fd(handle))),
            Ok(seals) if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0
        );
    if sealed && prot & PROT_WRITE != 0 {
        return fail(crate::EPERM);
    }
    let maywrite = !shared || (writable && !sealed);
    let memfd = match cache_for(metadata.ino, handle, metadata.len) {
        Ok(memfd) => memfd,
        Err(result) => return result,
    };
    let fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0).then_some(addr);
    let object = Object::File {
        ino: metadata.ino,
        desc: resolved.desc,
        shared,
        maywrite,
        secret,
    };
    let result = alias(
        memfd,
        offset as usize,
        rounded,
        fixed,
        prot,
        (if shared { MAP_SHARED } else { MAP_PRIVATE }) | (flags & VIEW_HINTS),
        object,
        lock,
    );
    if result >= 0 {
        MAPPINGS.lock().handles.insert(handle, metadata.ino);
    } else {
        settle(&[metadata.ino]);
    }
    result
}

/// `do_mmap`'s judgment of a file mapping's type, protection and descriptor,
/// in its order: whether the mapping is shared, or the errno. `MAP_TYPE` is a
/// two-bit field, not two flags — `MAP_SHARED_VALIDATE` (3) is `MAP_SHARED |
/// MAP_PRIVATE` — so the type is decoded as a value.
pub(super) fn judge(
    flags: c_int,
    prot: c_int,
    readable: bool,
    writable: bool,
    regular: bool,
    noexec: bool,
) -> Result<bool, c_int> {
    let shared = match flags & MAP_TYPE {
        MAP_SHARED | MAP_SHARED_VALIDATE => {
            // Plain `MAP_SHARED` drops the flags it does not know; the
            // validating spelling refuses them.
            let known = if flags & MAP_TYPE == MAP_SHARED {
                flags & LEGACY_MAP_MASK
            } else {
                flags
            };
            if known & !LEGACY_MAP_MASK != 0 {
                return Err(EOPNOTSUPP);
            }
            if prot & PROT_WRITE != 0 && !writable {
                return Err(EACCES);
            }
            true
        }
        MAP_PRIVATE => false,
        _ => return Err(EINVAL),
    };
    if !readable {
        return Err(EACCES);
    }
    // A file on a `noexec` mount (secret memory's) never maps executable.
    if noexec && prot & PROT_EXEC != 0 {
        return Err(crate::EPERM);
    }
    // Only a regular file has byte-addressable contents: a directory, a pipe,
    // a socket, the streams and the entropy device have no `mmap`.
    if !regular {
        return Err(ENODEV);
    }
    if flags & MAP_GROWSDOWN != 0 {
        return Err(EINVAL);
    }
    Ok(shared)
}

/// Map `rounded` bytes of the memfd `fd` from `offset` as a view of `object`
/// — anywhere, or at `fixed`, replacing what it lands on — then lock it when
/// `lock` asks. `flags` is the mapping type and the host hints. The address,
/// or `-errno`.
#[allow(clippy::too_many_arguments)]
pub(super) fn alias(
    fd: c_int,
    offset: usize,
    rounded: usize,
    fixed: Option<usize>,
    prot: c_int,
    flags: c_int,
    object: Object,
    lock: Option<bool>,
) -> i64 {
    // The pieces a fixed view replaces leave the table before the host call
    // and are finished after the new view joins it, so a replaced view of the
    // same file never tears its page cache down.
    let replaced = fixed
        .map(|addr| take_all(addr, addr + rounded))
        .unwrap_or_default();
    let view = host(
        Syscall::N_mmap,
        [
            fixed.unwrap_or(0),
            rounded,
            prot as usize,
            (flags | if fixed.is_some() { MAP_FIXED } else { 0 }) as usize,
            fd as usize,
            offset,
        ],
    );
    if view < 0 {
        restore(replaced);
        return view;
    }
    let start = view as usize;
    if let Some(desc) = object.desc()
        && hold(desc).is_err()
    {
        host(Syscall::N_munmap, [start, rounded, 0, 0, 0, 0]);
        finish(replaced);
        return fail(EBADF);
    }
    {
        let mut mappings = MAPPINGS.lock();
        mappings.views.set(start, start + rounded, object);
        if let Some(ino) = object.ino()
            && object.writes_back(ino)
            && let Some(cache) = mappings.caches.get_mut(&ino)
        {
            cache.track(true);
        }
        mappings.publish();
    }
    finish(replaced);
    if let Some(onfault) = lock {
        let _ignore_errors = lock_range(start, rounded, onfault);
    }
    view
}

/// Hold `desc` for a view: the first view of a description takes a hidden
/// reference in the descriptor table, as a kernel mapping's `get_file`.
pub(super) fn hold(desc: DescId) -> Result<(), c_int> {
    if MAPPINGS.lock().descs.contains_key(&desc) {
        return Ok(());
    }
    let handle = {
        let mut table = crate::fd_table().lock();
        table.retain(desc)?;
        table
            .description(desc)
            .map(|description| description.handle)
            .expect("a retained description exists")
    };
    MAPPINGS.lock().descs.insert(desc, handle);
    Ok(())
}

/// The memfd of `ino`'s page cache, created and loaded from the filesystem
/// through `handle` when the file is first mapped.
fn cache_for(ino: u64, handle: u64, size: u64) -> Result<c_int, i64> {
    if let Some(cache) = MAPPINGS.lock().caches.get(&ino) {
        return Ok(cache.pages.fd);
    }
    let size = usize::try_from(size).map_err(|_| fail(EOVERFLOW))?;
    let contents = if size == 0 {
        Vec::new()
    } else {
        crate::with_context_raw(|context| context.fs_read_at(Fd(handle), 0, size)).map_err(fail)?
    };
    let cache = Cache::new(Memfd::new(), &contents);
    let fd = cache.pages.fd;
    let mut mappings = MAPPINGS.lock();
    mappings.caches.insert(ino, cache);
    mappings.publish();
    Ok(fd)
}

/// `mprotect(2)`: 0, or `-errno`. A range reaching a view that may not be
/// written (a shared view of a description not open for writing or of a
/// write-sealed file, a `SHM_RDONLY` attachment) cannot gain `PROT_WRITE`
/// (`EACCES`, `!VM_MAYWRITE`); the mappings before it are changed first, as
/// the kernel walks them. The rest is the host's.
#[unsafe(no_mangle)]
pub extern "C" fn patina_mprotect(addr: usize, len: usize, prot: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::raw(mprotect(addr, len, prot))
}

pub(crate) fn mprotect(addr: usize, len: usize, prot: c_int) -> crate::abi::SysResult<i64> {
    'result: {
        if prot & (PROT_WRITE | PROT_EXEC) != 0
            && addr.is_multiple_of(PAGE)
            && len != 0
            && tracking()
            && let Some(end) = round_up(len).and_then(|len| addr.checked_add(len))
        {
            let refused = MAPPINGS
                .lock()
                .views
                .within(addr, end)
                .into_iter()
                .find(|(_, _, object)| object.refuses(prot))
                .map(|(start, _, _)| start);
            if let Some(refused) = refused {
                if refused > addr {
                    let before = host(
                        Syscall::N_mprotect,
                        [addr, refused - addr, prot as usize, 0, 0, 0],
                    );
                    if before < 0 {
                        break 'result crate::abi::LinuxReturn::new(before)
                            .decode()
                            .map(|result| result as i64);
                    }
                }
                break 'result Err(crate::abi::Errno::new(EACCES));
            }
        }
        crate::abi::LinuxReturn::new(host(
            Syscall::N_mprotect,
            [addr, len, prot as usize, 0, 0, 0],
        ))
        .decode()
        .map(|result| result as i64)
    }
}

/// `munmap(2)`: 0, or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_munmap(addr: usize, len: usize) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::raw(munmap(addr, len))
}

pub(crate) fn munmap(addr: usize, len: usize) -> crate::abi::SysResult<i64> {
    let result = host(Syscall::N_munmap, [addr, len, 0, 0, 0, 0]);
    if result == 0 && tracking() {
        crate::LAST_BOUNDARY_SYMBOL.store(c"munmap".as_ptr().cast_mut(), Ordering::Relaxed);
        forget(addr, len);
    }
    crate::abi::LinuxReturn::new(result)
        .decode()
        .map(|result| result as i64)
}

/// `mremap(2)`: the new address, or `-errno`. A view moved, grown, shrunk or
/// duplicated stays a view of the same object; a lock and a memory policy
/// move with their range, and the growth of a locked range is judged against
/// the lock limit (`EAGAIN`) and populated.
#[unsafe(no_mangle)]
pub extern "C" fn patina_mremap(
    old: usize,
    old_len: usize,
    new_len: usize,
    flags: usize,
    new_addr: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::raw(mremap(old, old_len, new_len, flags, new_addr).map(|address| address as i64))
}

pub(crate) fn mremap(
    old: usize,
    old_len: usize,
    new_len: usize,
    flags: usize,
    new_addr: usize,
) -> crate::abi::SysResult<usize> {
    'result: {
        let tracked = tracking();
        let locked = tracked && old.is_multiple_of(PAGE) && MAPPINGS.lock().locks.at(old).is_some();
        if locked && new_len > old_len {
            let growth =
                round_up(new_len).unwrap_or(new_len) - round_up(old_len).unwrap_or(old_len);
            let total = MAPPINGS.lock().locks.total() + growth;
            if total / PAGE > lock_limit_pages() {
                break 'result Err(crate::abi::Errno::new(crate::EWOULDBLOCK));
            }
        }
        let result = host(
            Syscall::N_mremap,
            [old, old_len, new_len, flags, new_addr, 0],
        );
        if result < 0 || !tracked {
            break 'result crate::abi::LinuxReturn::new(result)
                .decode()
                .map(|address| address as usize);
        }
        crate::LAST_BOUNDARY_SYMBOL.store(c"mremap".as_ptr().cast_mut(), Ordering::Relaxed);
        let moved_to = result as usize;
        let (Some(old_len), Some(new_len)) = (round_up(old_len), round_up(new_len)) else {
            break 'result Ok(result as usize);
        };
        // Old size 0 duplicates a shared mapping and `MREMAP_DONTUNMAP` leaves the
        // old range mapped: either way the old range stays, and the new one is a
        // second mapping of its object.
        let duplicated = old_len == 0 || flags & MREMAP_DONTUNMAP != 0;
        let replaced = if flags & MREMAP_FIXED != 0 {
            take_all(moved_to, moved_to + new_len)
        } else {
            Vec::new()
        };
        let mut mappings = MAPPINGS.lock();
        let source_end = old + old_len.max(PAGE);
        let views = if duplicated {
            mappings.views.within(old, source_end)
        } else {
            mappings.views.cut(old, old + old_len)
        };
        let policies = if duplicated {
            mappings.policies.within(old, source_end)
        } else {
            mappings.policies.cut(old, old + old_len)
        };
        let locks = if duplicated {
            Vec::new()
        } else {
            mappings.locks.cut(old, old + old_len)
        };
        // A piece keeps its place relative to the old start; the piece that ended
        // the old range is the one a growth extends.
        let place = |start: usize, end: usize| {
            let from = moved_to + (start - old);
            let to = if end >= old + old_len {
                moved_to + new_len
            } else {
                (moved_to + (end - old)).min(moved_to + new_len)
            };
            (from < to).then_some((from, to))
        };
        let mut dropped = replaced;
        for (start, end, object) in views {
            match place(start, end) {
                Some((from, to)) => mappings.views.set(from, to, object),
                None if !duplicated => dropped.push((start, end, object)),
                None => {}
            }
        }
        for (start, end, policy) in policies {
            if let Some((from, to)) = place(start, end) {
                mappings.policies.set(from, to, policy);
            }
        }
        let mut grown = None;
        for (start, end, onfault) in locks {
            if let Some((from, to)) = place(start, end) {
                mappings.locks.set(from, to, onfault);
                if end >= old + old_len && new_len > old_len && !onfault {
                    grown = Some((moved_to + old_len, new_len - old_len));
                }
            }
        }
        mappings.publish();
        drop(mappings);
        finish(dropped);
        if let Some((start, len)) = grown {
            let _ignore_errors = populate(start, len);
        }
        Ok(result as usize)
    }
}

/// Remove `[from, to)` from the address space's per-range state, answering
/// the views it covered (they still hold their descriptions until
/// [`finish`]).
fn take_all(from: usize, to: usize) -> Vec<(usize, usize, Object)> {
    let mut mappings = MAPPINGS.lock();
    mappings.locks.cut(from, to);
    mappings.policies.cut(from, to);
    let pieces = mappings.views.cut(from, to);
    mappings.publish();
    pieces
}

/// `[addr, addr + len)` is no longer mapped as it was.
pub(super) fn forget(addr: usize, len: usize) {
    if let Some(len) = round_up(len) {
        finish(take_all(addr, addr.saturating_add(len)));
    }
}

/// Put back views [`take_all`] removed for a replacement that did not happen.
fn restore(pieces: Vec<(usize, usize, Object)>) {
    let mut mappings = MAPPINGS.lock();
    for (start, end, object) in pieces {
        mappings.views.set(start, end, object);
    }
    mappings.publish();
}

/// The views [`take_all`] removed are gone from the address space: write back
/// and stop shadowing the page caches they leave without a view that may
/// write, drop the page caches they leave without any view, release the
/// descriptions no view holds any more, and tell each segment it lost an
/// attachment.
pub(super) fn finish(pieces: Vec<(usize, usize, Object)>) {
    if pieces.is_empty() {
        return;
    }
    let mut inos: Vec<u64> = pieces
        .iter()
        .filter_map(|(_, _, object)| object.ino())
        .collect();
    inos.sort_unstable();
    inos.dedup();
    for ino in &inos {
        // The write-back goes through a description a dropped view holds.
        let (writer, without_writer) = {
            let mappings = MAPPINGS.lock();
            let writer = pieces
                .iter()
                .filter(|(_, _, object)| object.writes_back(*ino))
                .find_map(|(_, _, object)| {
                    object
                        .desc()
                        .and_then(|desc| mappings.descs.get(&desc).copied())
                });
            let without_writer = !mappings
                .views
                .all()
                .any(|(_, _, object)| object.writes_back(*ino));
            (writer, without_writer)
        };
        if let (Some(writer), true) = (writer, without_writer) {
            // Nothing is left to fail: a write-back the filesystem refuses here
            // loses those stores, as a kernel's failed writeback of an evicted
            // page does.
            let _ = write_back(*ino, writer);
            if let Some(cache) = MAPPINGS.lock().caches.get_mut(ino) {
                cache.track(false);
            }
        }
    }
    settle(&inos);
    let released: Vec<DescId> = {
        let mut mappings = MAPPINGS.lock();
        let held: Vec<DescId> = mappings
            .views
            .all()
            .filter_map(|(_, _, o)| o.desc())
            .collect();
        let gone: Vec<DescId> = mappings
            .descs
            .keys()
            .copied()
            .filter(|desc| !held.contains(desc))
            .collect();
        for desc in &gone {
            mappings.descs.remove(desc);
        }
        gone
    };
    for desc in released {
        let released = crate::fd_table().lock().release(desc);
        if let Ok(Some(release)) = released {
            let _ = crate::release_description(release);
        }
    }
    for (_, _, object) in pieces {
        if let Object::Segment { id, .. } = object {
            crate::thread::ipc::shm_detached(id);
        }
    }
}

/// Drop the page caches of `inos` no view maps any more.
pub(super) fn settle(inos: &[u64]) {
    let mut unused = Vec::new();
    {
        let mut mappings = MAPPINGS.lock();
        for ino in inos {
            if !mappings
                .views
                .all()
                .any(|(_, _, object)| object.ino() == Some(*ino))
            {
                if let Some(cache) = mappings.caches.remove(ino) {
                    unused.push(cache);
                }
                mappings.handles.retain(|_, mapped| mapped != ino);
            }
        }
        mappings.publish();
    }
    drop(unused);
}

/// Write back the pages the views of `ino` changed since the last
/// write-back, through `handle` (a description open for writing), one
/// recorded write per page. A page the filesystem refused stays dirty for
/// the next write-back.
pub(super) fn write_back(ino: u64, handle: u64) -> Result<(), c_int> {
    write_back_counted(ino, handle).1
}

/// [`write_back`], also answering whether it wrote to the file at all: a
/// write-back that fails partway may have written its first pages.
pub(super) fn write_back_counted(ino: u64, handle: u64) -> (bool, Result<(), c_int>) {
    let pages = match MAPPINGS.lock().caches.get(&ino) {
        Some(cache) => cache.dirty_pages(),
        None => return (false, Ok(())),
    };
    let tried = !pages.is_empty();
    let written_all = || {
        for (offset, bytes) in pages {
            let written = crate::with_context_raw(|context| {
                context.fs_write_back_at(Fd(handle), offset, &bytes)
            })?;
            if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
                cache.accept(offset, &bytes[..written.min(bytes.len())]);
            }
            if written < bytes.len() {
                return Err(crate::EIO);
            }
        }
        Ok(())
    };
    (tried, written_all())
}

/// The pages of the file `handle` is open on that a store through a shared
/// view changed and no write-back has written yet, by index: dirty on 6.8
/// from the write fault on (`cachestat`).
pub(crate) fn view_dirty_pages(handle: u64) -> Vec<u64> {
    let Some(ino) = cached_ino(handle) else {
        return Vec::new();
    };
    MAPPINGS
        .lock()
        .caches
        .get(&ino)
        .map(|cache| {
            cache
                .dirty_pages()
                .into_iter()
                .map(|(offset, _)| offset / PAGE as u64)
                .collect()
        })
        .unwrap_or_default()
}

/// The inode `handle` is open on, when a page cache exists for it.
pub(super) fn cached_ino(handle: u64) -> Option<u64> {
    if !caching() {
        return None;
    }
    let known = MAPPINGS.lock().handles.get(&handle).copied();
    let ino = match known {
        Some(ino) => ino,
        None => {
            let ino =
                crate::with_context_raw(|context| context.fs_fd_metadata_unrecorded(Fd(handle)))
                    .ok()?
                    .ino;
            MAPPINGS.lock().handles.insert(handle, ino);
            ino
        }
    };
    MAPPINGS.lock().caches.contains_key(&ino).then_some(ino)
}

/// A handle a write-back of `ino` can go through: a view that may write.
pub(super) fn writer_of(ino: u64) -> Option<u64> {
    let mappings = MAPPINGS.lock();
    writer_among(&mappings, ino)
}

/// The driver handle of the writable shared views of `ino` that was opened
/// first (the lowest handle), whatever address each view sits at. The
/// write-back is a recorded operation that names its handle, and view
/// addresses come from the host (ASLR), so choosing by address would let
/// two runs of one seed, or a record and its replay, write back through
/// different descriptions.
pub(super) fn writer_among(mappings: &Mappings, ino: u64) -> Option<u64> {
    mappings
        .views
        .all()
        .filter(|(_, _, object)| object.writes_back(ino))
        .filter_map(|(_, _, object)| object.desc())
        .filter_map(|desc| mappings.descs.get(&desc).copied())
        .min()
}
