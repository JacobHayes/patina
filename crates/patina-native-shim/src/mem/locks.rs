//! Huge-page mappings and deterministic page-lock accounting.

use super::*;

// ---------------------------------------------------------------- huge pages

/// The huge page sizes the virtual machine has pools for, by `log2`: the
/// architecture's own (`hstate_sizelog`), none of them with a page reserved.
#[cfg(target_arch = "x86_64")]
const HUGE_PAGE_SHIFTS: &[u32] = &[21, 30];
#[cfg(not(target_arch = "x86_64"))]
const HUGE_PAGE_SHIFTS: &[u32] = &[16, 21, 25, 30];
/// The default huge page size's shift.
const DEFAULT_HUGE_SHIFT: u32 = 21;

/// `hstate_sizelog`: the huge page size a `*_HUGE_*` size field names (0 is
/// the default size), or `None` for a size the machine has no pool for.
pub(crate) fn huge_page_size(sizelog: u32) -> Option<usize> {
    let shift = if sizelog == 0 {
        DEFAULT_HUGE_SHIFT
    } else {
        sizelog
    };
    HUGE_PAGE_SHIFTS.contains(&shift).then_some(1 << shift)
}

/// A mapping of hugetlbfs pages on a machine that reserves none
/// (`hugetlbfs_file_mmap`): `ENOMEM` unless `MAP_NORESERVE` defers the
/// reservation, when every touch then faults `SIGBUS` — a shared mapping of
/// an empty memfd, placed at a huge-page-aligned address. The address, or
/// `-errno`.
pub(super) fn map_huge_pages(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    size: usize,
) -> i64 {
    if flags & MAP_NORESERVE == 0 {
        return fail(ENOMEM);
    }
    let empty = Memfd::new();
    let target = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        addr
    } else {
        // Reserve a huge page more than asked, take the aligned part.
        let reserved = host(
            Syscall::N_mmap,
            [
                0,
                len + size,
                0,
                (MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE) as usize,
                usize::MAX,
                0,
            ],
        );
        if reserved < 0 {
            return reserved;
        }
        let reserved = reserved as usize;
        let aligned = reserved.next_multiple_of(size);
        if aligned > reserved {
            host(
                Syscall::N_munmap,
                [reserved, aligned - reserved, 0, 0, 0, 0],
            );
        }
        let tail = aligned + len;
        if reserved + len + size > tail {
            host(
                Syscall::N_munmap,
                [tail, reserved + len + size - tail, 0, 0, 0, 0],
            );
        }
        aligned
    };
    host(
        Syscall::N_mmap,
        [
            target,
            len,
            prot as usize,
            // `MAP_FIXED_NOREPLACE` stays: over a live mapping it is `EEXIST`.
            ((flags & (MAP_TYPE | MAP_FIXED_NOREPLACE)) | MAP_FIXED) as usize,
            empty.fd as usize,
            0,
        ],
    )
}

// ---------------------------------------------------------------- locks

/// The virtual `RLIMIT_MEMLOCK` in pages (`src/limits.rs`).
pub(super) fn lock_limit_pages() -> usize {
    (crate::limits::soft(crate::limits::RLIMIT_MEMLOCK) / PAGE as u64) as usize
}

/// `can_do_mlock`: a nonzero limit (the identity has no `CAP_IPC_LOCK`).
fn can_lock() -> bool {
    crate::limits::soft(crate::limits::RLIMIT_MEMLOCK) != 0
}

/// How a new guest mapping of `len` bytes is locked (`MAP_LOCKED`, or
/// `mlockall(MCL_FUTURE)`): `Ok(None)` unlocked, `Ok(Some(onfault))` locked,
/// or the refusal — `EPERM` for `MAP_LOCKED` without a limit, `EAGAIN` past it
/// (`mlock_future_ok`).
pub(super) fn lock_request(flags: c_int, len: usize) -> Result<Option<bool>, c_int> {
    if flags & MAP_LOCKED != 0 && !can_lock() {
        return Err(crate::EPERM);
    }
    let requested = if flags & MAP_LOCKED != 0 {
        Some(false)
    } else if crate::in_shim_critical() {
        None
    } else {
        MAPPINGS.lock().future
    };
    if requested.is_some() {
        let locked = MAPPINGS.lock().locks.total() / PAGE + len.div_ceil(PAGE);
        if locked > lock_limit_pages() {
            return Err(crate::EWOULDBLOCK);
        }
    }
    Ok(requested)
}

/// `[start, start + len)` is locked now: bookkeeping, then populate it unless
/// it locks on fault, as `__mm_populate` does — without the host's lock
/// accounting, which would answer from the host's `RLIMIT_MEMLOCK`. The
/// populate's refusal, which only `mlock` answers (`MAP_LOCKED`,
/// `MCL_FUTURE` and `mremap` growth populate with `ignore_errors`).
pub(super) fn lock_range(start: usize, len: usize, onfault: bool) -> Result<(), c_int> {
    {
        let mut mappings = MAPPINGS.lock();
        mappings.locks.set(start, start + len, onfault);
        mappings.publish();
    }
    if onfault {
        return Ok(());
    }
    populate(start, len)
}

/// Fault `[start, start + len)` in as `populate_vma_page_range` does: a read
/// fault on a shared view (the kernel does not dirty shared pages for
/// nothing), a write fault on other pages where the host allows one, so a
/// private page is the process's own, else a read fault. Stops at the first
/// page no fault reaches, with `madvise`'s errno: `EINVAL` for a page without
/// access (`faultin_vma_page_range`'s spelling of `__get_user_pages`'s
/// `EFAULT`), `EFAULT` for one that would raise `SIGBUS`, `ENOMEM`. Gap: an
/// execute-only page, which the kernel populates with `FOLL_FORCE`, is
/// refused here as a page without access.
pub(super) fn populate(start: usize, len: usize) -> Result<(), c_int> {
    require_populate();
    // `get_user_pages` refuses secret memory: the walk stops there, `EFAULT`.
    let secret = MAPPINGS
        .lock()
        .views
        .within(start, start + len)
        .into_iter()
        .find(|(_, _, object)| object.is_secret())
        .map(|(from, _, _)| from.max(start));
    if let Some(from) = secret {
        if from > start {
            populate(start, from - start)?;
        }
        return Err(crate::EFAULT);
    }
    let end = start + len;
    let shared: Vec<(usize, usize)> = MAPPINGS
        .lock()
        .views
        .within(start, end)
        .into_iter()
        .filter(|(_, _, object)| object.is_shared())
        .map(|(from, to, _)| (from, to))
        .collect();
    let advise = |from: usize, to: usize, advice: usize| -> Result<(), c_int> {
        match host(Syscall::N_madvise, [from, to - from, advice, 0, 0, 0]) {
            0 => Ok(()),
            error => Err((-error) as c_int),
        }
    };
    // The common cases in one call each: nothing shared, or all of it.
    if shared.is_empty() && advise(start, end, MADV_POPULATE_WRITE).is_ok() {
        return Ok(());
    }
    if advise(start, end, MADV_POPULATE_READ).is_ok()
        && (shared.is_empty() || shared == [(start, end)])
    {
        return Ok(());
    }
    for page in (start..end).step_by(PAGE) {
        let is_shared = shared.iter().any(|(from, to)| (*from..*to).contains(&page));
        if is_shared || advise(page, page + PAGE, MADV_POPULATE_WRITE).is_err() {
            advise(page, page + PAGE, MADV_POPULATE_READ)?;
        }
    }
    Ok(())
}

/// `MADV_POPULATE_READ`/`_WRITE` arrived in Linux 5.14; syscall user dispatch
/// in 5.11. On an older host no populate works, and every lock and residency
/// answer would silently depend on the host's version: the first populate
/// probes once and stops the run by name there. A guest that never locks,
/// populates or asks a page's node runs on 5.11-5.13.
pub(super) fn require_populate() {
    static PROBED: AtomicBool = AtomicBool::new(false);
    static PAGE_OF_DATA: u8 = 0;
    if PROBED.load(Ordering::Acquire) {
        return;
    }
    let page = std::ptr::addr_of!(PAGE_OF_DATA) as usize & !(PAGE - 1);
    let result = host(
        Syscall::N_madvise,
        [page, PAGE, MADV_POPULATE_READ, 0, 0, 0],
    );
    if result != 0 {
        crate::trap_fatal(&format!(
            "the host kernel refused MADV_POPULATE_READ (errno {}): locking and populating \
             guest memory needs Linux 5.14 or later",
            -result
        ));
    }
    PROBED.store(true, Ordering::Release);
}

/// The first page of `[start, start + len)` no mapping covers, if any.
fn first_hole(start: usize, len: usize) -> Option<usize> {
    if mapped(start, len) {
        return None;
    }
    (start..start + len)
        .step_by(PAGE)
        .find(|page| !mapped(*page, PAGE))
}

/// `mlock`/`mlock2` (mm/mlock.c `do_mlock`): 0 or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_mlock(start: usize, len: usize, flags: u32) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !MLOCK_ONFAULT != 0 {
        return fail(EINVAL);
    }
    if !can_lock() {
        return fail(crate::EPERM);
    }
    let Some(len) = round_up(len.saturating_add(start & (PAGE - 1))) else {
        return fail(ENOMEM);
    };
    let start = start & !(PAGE - 1);
    let Some(end) = start.checked_add(len) else {
        return fail(EINVAL);
    };
    {
        let mappings = MAPPINGS.lock();
        let mut locked = len / PAGE + mappings.locks.total() / PAGE;
        if locked > lock_limit_pages() {
            locked -= mappings.locks.covered(start, end) / PAGE;
        }
        if locked > lock_limit_pages() {
            return fail(ENOMEM);
        }
    }
    if len == 0 {
        return 0;
    }
    let onfault = flags & MLOCK_ONFAULT != 0;
    // `apply_vma_lock_flags`: the mappings before a hole are locked, then the
    // hole is `ENOMEM`, and nothing is populated.
    if let Some(hole) = first_hole(start, len) {
        if hole > start {
            let mut mappings = MAPPINGS.lock();
            mappings.locks.set(start, hole, onfault);
            mappings.publish();
        }
        return fail(ENOMEM);
    }
    match lock_range(start, len, onfault) {
        Ok(()) => 0,
        // `__mlock_posix_error_return`: a page no fault reaches is `ENOMEM`,
        // no memory to fault it in `EAGAIN`; the lock stays applied.
        Err(EINVAL | crate::EFAULT) => fail(ENOMEM),
        Err(ENOMEM) => fail(crate::EWOULDBLOCK),
        Err(errno) => fail(errno),
    }
}

/// `munlock` (`apply_vma_lock_flags` with no flag): 0 or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_munlock(start: usize, len: usize) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(len) = round_up(len.saturating_add(start & (PAGE - 1))) else {
        return fail(ENOMEM);
    };
    let start = start & !(PAGE - 1);
    let Some(end) = start.checked_add(len) else {
        return fail(EINVAL);
    };
    if len == 0 {
        return 0;
    }
    let unlocked = first_hole(start, len).unwrap_or(end);
    let mut mappings = MAPPINGS.lock();
    mappings.locks.cut(start, unlocked);
    mappings.publish();
    if unlocked < end {
        return fail(ENOMEM);
    }
    0
}

/// The refusal `mlockall(MCL_CURRENT)` gets: what the kernel judges it by is
/// the whole address space's size (`total_vm`) against the limit, and the
/// address space holds the shim's own mappings beside the guest's.
const DENY_MCL_CURRENT: &str = "patina: mlockall(MCL_CURRENT) has no model (the kernel judges \
    it by total_vm, which is unreadable without /proc); failing closed\n";

/// `mlockall` (`apply_mlockall_flags`): 0 or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_mlockall(flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 || flags == MCL_ONFAULT
    {
        return fail(EINVAL);
    }
    if !can_lock() {
        return fail(crate::EPERM);
    }
    if flags & MCL_CURRENT != 0 {
        return i64::from(crate::deny(DENY_MCL_CURRENT));
    }
    let mut mappings = MAPPINGS.lock();
    mappings.future = Some(flags & MCL_ONFAULT != 0);
    mappings.publish();
    0
}

/// `munlockall`: every lock and `MCL_FUTURE` end.
#[unsafe(no_mangle)]
pub extern "C" fn patina_munlockall() -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut mappings = MAPPINGS.lock();
    mappings.locks.clear();
    mappings.future = None;
    mappings.publish();
    0
}
