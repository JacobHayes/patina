//! Memory: the one model behind the C `mmap`/`mmap64`/`munmap`/`mremap`/
//! `mprotect`/`msync`/`mlock*` interposers and the SUD rows of the same names,
//! plus the page cache the descriptor funnels keep coherent with the
//! deterministic filesystem, memory locking against the virtual
//! `RLIMIT_MEMLOCK`, `memfd_create` and seals (`memfd`), and `membarrier`
//! (`barrier`).
//!
//! Anonymous memory is process-local address space: it goes to the host kernel
//! (through the glibc `syscall(2)` host alias), unrecorded, because the
//! allocator reaches it on every arena growth and a scheduling point there
//! would make the guest's allocation pattern part of the simulated schedule.
//!
//! A mapping of a deterministic-filesystem file is a VIEW of that file's page
//! cache: a host memfd the shim holds, sized to the file and loaded from the
//! filesystem when the file is first mapped. A `MAP_SHARED` view maps the
//! memfd shared and a `MAP_PRIVATE` view maps it private, so every view is the
//! kernel's own shmem semantics: views of any shape see one set of bytes, a
//! private view shows the file until its own store copies a page, and a page
//! wholly past the end of the file faults `SIGBUS`.
//!
//! The filesystem and the page cache meet at the descriptor I/O funnels in
//! `lib.rs`, `iov.rs`, `transfer.rs` and `advice.rs`: a read of a mapped file
//! first writes back the pages a shared view changed since the last write-back
//! ([`reading`]); a write, truncation or allocation is mirrored into the page
//! cache as soon as the filesystem accepted it ([`written`], [`resized`],
//! [`allocated`]). The write-back is a recorded filesystem operation
//! (`fs_write_back_at`, one per dirty page, through a description a writable
//! view holds), so what a guest stores through a mapping reaches the crash
//! model exactly as a `write` would, and becomes durable at `fsync`, `sync` or
//! `msync(MS_SYNC)`. A view holds its description the way a kernel mapping
//! holds its `struct file`, so the guest closing its number changes nothing.
//!
//! Each page cache and each System V segment holds one host descriptor (its
//! memfd), so the host's soft `RLIMIT_NOFILE` bounds how many files and
//! segments a guest can map at once; `__libc_start_main` raises it to the hard
//! limit, and a memfd the host still refuses stops the run by name
//! (`cache::Memfd::new`) instead of answering the guest an errno the kernel
//! being modeled would not.
//!
//! The address-space rows that create, move or destroy mappings keep the
//! per-range state in step with the host's: the views (and System V
//! attachments, which are views of a segment's memfd), the memory locks and the
//! memory policies (`crate::numa`).

mod barrier;
mod cache;
mod memfd;
mod ranges;

pub(crate) use barrier::membarrier;
pub(crate) use memfd::{anonymous, released, secret, secret_resizable, secret_resized};

use crate::fdtable::{DescId, FdKind};
use crate::numa::Policy;
use crate::registry::Syscall;
use crate::{EACCES, EBADF, EINVAL, ENODEV, ENOMEM, EOPNOTSUPP, EOVERFLOW, SpinMutex};
use cache::{Cache, Memfd, Pages};
use linux_raw_sys::general as uapi;
use patina_dst_abi::seals::{F_SEAL_FUTURE_WRITE, F_SEAL_WRITE};
use patina_dst_abi::{Fd, FsEntryKind};
use ranges::Ranges;
use std::collections::BTreeMap;
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicBool, Ordering};

/// The page size the guest computes offsets and lengths against: patina pins
/// `sysconf(_SC_PAGESIZE)` to it.
pub(crate) const PAGE: usize = 4096;

const MAP_SHARED: c_int = uapi::MAP_SHARED as c_int;
const MAP_PRIVATE: c_int = 2;
const MAP_SHARED_VALIDATE: c_int = 3;
const MAP_TYPE: c_int = uapi::MAP_TYPE as c_int;
const MAP_FIXED: c_int = uapi::MAP_FIXED as c_int;
const MAP_ANONYMOUS: c_int = uapi::MAP_ANONYMOUS as c_int;
const MAP_FIXED_NOREPLACE: c_int = uapi::MAP_FIXED_NOREPLACE as c_int;
const MAP_GROWSDOWN: c_int = uapi::MAP_GROWSDOWN as c_int;
const MAP_HUGETLB: c_int = uapi::MAP_HUGETLB as c_int;
const MAP_LOCKED: c_int = uapi::MAP_LOCKED as c_int;
const MAP_NORESERVE: c_int = uapi::MAP_NORESERVE as c_int;
const MAP_POPULATE: c_int = uapi::MAP_POPULATE as c_int;
const MAP_NONBLOCK: c_int = uapi::MAP_NONBLOCK as c_int;
const MAP_STACK: c_int = uapi::MAP_STACK as c_int;
#[cfg(target_arch = "x86_64")]
const MAP_32BIT: c_int = uapi::MAP_32BIT as c_int;
#[cfg(not(target_arch = "x86_64"))]
const MAP_32BIT: c_int = 0;
const MAP_HUGE_SHIFT: c_int = 26;
const MAP_HUGE_MASK: c_int = 0x3f;
/// `LEGACY_MAP_MASK` (include/linux/mman.h): the flags plain `MAP_SHARED`
/// keeps (every other bit is ignored) and `MAP_SHARED_VALIDATE` accepts
/// (every other bit is `EOPNOTSUPP`).
const LEGACY_MAP_MASK: c_int = MAP_SHARED
    | MAP_PRIVATE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | uapi::MAP_DENYWRITE as c_int
    | uapi::MAP_EXECUTABLE as c_int
    | uapi::MAP_UNINITIALIZED as c_int
    | MAP_GROWSDOWN
    | MAP_LOCKED
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK
    | MAP_HUGETLB
    | MAP_32BIT
    | (21 << MAP_HUGE_SHIFT)
    | (30 << MAP_HUGE_SHIFT);
/// The host flags a view passes on: placement and commitment hints. The
/// mapping type and `MAP_FIXED` are the model's; `MAP_LOCKED` is the model's
/// lock bookkeeping, never the host's.
const VIEW_HINTS: c_int = MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_32BIT;
pub(crate) const PROT_READ: c_int = uapi::PROT_READ as c_int;
pub(crate) const PROT_WRITE: c_int = uapi::PROT_WRITE as c_int;
pub(crate) const PROT_EXEC: c_int = uapi::PROT_EXEC as c_int;
const MREMAP_FIXED: usize = uapi::MREMAP_FIXED as usize;
const MREMAP_DONTUNMAP: usize = uapi::MREMAP_DONTUNMAP as usize;
const MS_SYNC: c_int = uapi::MS_SYNC as c_int;
const MS_INVALIDATE: c_int = uapi::MS_INVALIDATE as c_int;
const MADV_POPULATE_READ: usize = 22;
const MADV_POPULATE_WRITE: usize = 23;
const MLOCK_ONFAULT: u32 = uapi::MLOCK_ONFAULT;
const MCL_CURRENT: c_int = uapi::MCL_CURRENT as c_int;
const MCL_FUTURE: c_int = uapi::MCL_FUTURE as c_int;
const MCL_ONFAULT: c_int = uapi::MCL_ONFAULT as c_int;

/// What a view's pages are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Object {
    /// A mapping of a file: its page cache. The view holds `desc` as a kernel
    /// mapping holds its `struct file`.
    File {
        ino: u64,
        desc: DescId,
        shared: bool,
        /// `VM_MAYWRITE`: a private mapping may always be made writable (its
        /// stores are its own); a shared one only on a description open for
        /// writing, on a file no write seal forbids it.
        maywrite: bool,
        /// Secret memory (`memfd_secret`): on a `noexec` mount (never
        /// executable, `!VM_MAYEXEC`), locked, out of every page walk's reach
        /// (`get_user_pages` refuses it), with no file to write back.
        secret: bool,
    },
    /// A System V shared memory attachment of segment `id` (`shmat`); a
    /// segment's attachment count is the number of these, as the kernel's
    /// `shm_nattch` counts the segment's mappings.
    Segment { id: i32, maywrite: bool },
}

impl Object {
    /// A `MAP_SHARED` view: a shared file mapping or an attachment.
    fn is_shared(self) -> bool {
        match self {
            Object::File { shared, .. } => shared,
            Object::Segment { .. } => true,
        }
    }

    fn ino(self) -> Option<u64> {
        match self {
            Object::File { ino, .. } => Some(ino),
            Object::Segment { .. } => None,
        }
    }

    fn desc(self) -> Option<DescId> {
        match self {
            Object::File { desc, .. } => Some(desc),
            Object::Segment { .. } => None,
        }
    }

    /// A shared view of `ino` that can store into its page cache: the page
    /// cache keeps a shadow for it and writes back through it.
    fn writes_back(self, ino: u64) -> bool {
        matches!(self, Object::File { ino: mapped, shared: true, maywrite: true, .. } if mapped == ino)
    }

    /// `mprotect(PROT_WRITE)` of it is `EACCES` (`!VM_MAYWRITE`).
    fn refuses_write(self) -> bool {
        match self {
            Object::File { maywrite, .. } | Object::Segment { maywrite, .. } => !maywrite,
        }
    }

    /// A secret-memory view.
    fn is_secret(self) -> bool {
        matches!(self, Object::File { secret: true, .. })
    }

    /// `mprotect(prot)` of it is `EACCES`: writing without `VM_MAYWRITE`, or
    /// executing without `VM_MAYEXEC` (secret memory's `noexec` mount).
    fn refuses(self, prot: c_int) -> bool {
        (prot & PROT_WRITE != 0 && self.refuses_write())
            || (prot & PROT_EXEC != 0 && self.is_secret())
    }
}

struct Mappings {
    views: Ranges<Object>,
    caches: BTreeMap<u64, Cache<Memfd>>,
    /// Driver handle → the inode it is open on, for the handles the funnels
    /// have asked about while a page cache existed. Driver handles are never
    /// reused within a process, so an entry cannot go stale by reuse.
    handles: BTreeMap<u64, u64>,
    /// The descriptions views hold, and their driver handles.
    descs: BTreeMap<DescId, u64>,
    /// The memory policies of address ranges (`mbind`).
    policies: Ranges<Policy>,
    /// Locked ranges (`VM_LOCKED`), each with whether it locks on fault.
    locks: Ranges<bool>,
    /// `mlockall(MCL_FUTURE)`: later mappings are locked, on fault or not.
    future: Option<bool>,
}

static MAPPINGS: SpinMutex<Mappings> = SpinMutex::new(Mappings {
    views: Ranges::new(),
    caches: BTreeMap::new(),
    handles: BTreeMap::new(),
    descs: BTreeMap::new(),
    policies: Ranges::new(),
    locks: Ranges::new(),
    future: None,
});
/// Whether any per-range state exists: the address-space rows' fast path
/// reads only this.
static TRACKED: AtomicBool = AtomicBool::new(false);
/// Whether any page cache exists: the descriptor funnels' fast path reads
/// only this.
static CACHES: AtomicBool = AtomicBool::new(false);

impl Mappings {
    fn publish(&self) {
        TRACKED.store(
            !(self.views.is_empty()
                && self.policies.is_empty()
                && self.locks.is_empty()
                && self.future.is_none()),
            Ordering::Release,
        );
        CACHES.store(!self.caches.is_empty(), Ordering::Release);
    }

    /// Whether a shared view of `handle`'s file that may write is live
    /// (`mapping_writably_mapped`, what refuses a new `F_SEAL_WRITE`).
    fn writably_mapped(handle: u64) -> bool {
        cached_ino(handle).is_some_and(|ino| {
            MAPPINGS
                .lock()
                .views
                .all()
                .any(|(_, _, object)| object.writes_back(ino))
        })
    }
}

/// A process-local memory syscall through the glibc `syscall(2)` host alias,
/// in the raw ABI: the value, or `-errno`.
fn host(row: Syscall, args: [usize; 6]) -> i64 {
    host_number(i64::from(row.number()), args)
}

/// [`host`] by number: the SUD pass-through rows hand over the number they
/// trapped.
pub(crate) fn host_number(nr: i64, args: [usize; 6]) -> i64 {
    // SAFETY: process-local memory management on address space the guest or
    // this module owns; the vehicle is glibc's `syscall`, resolved as a host
    // alias, never the interposed one.
    let result = unsafe {
        crate::sud_host_syscall(
            nr as c_long,
            args[0] as c_long,
            args[1] as c_long,
            args[2] as c_long,
            args[3] as c_long,
            args[4] as c_long,
            args[5] as c_long,
        )
    };
    if result == -1 {
        -i64::from(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(crate::EIO),
        )
    } else {
        result as i64
    }
}

fn round_up(len: usize) -> Option<usize> {
    len.checked_add(PAGE - 1).map(|len| len & !(PAGE - 1))
}

fn fail(errno: c_int) -> i64 {
    -i64::from(errno)
}

/// Whether an address-space row has to see this call: per-range state exists
/// and the caller is not the shim itself (an allocator-internal `mmap`/
/// `munmap` reached while a shim spinlock is held is the shim's own memory,
/// never a view).
fn tracking() -> bool {
    TRACKED.load(Ordering::Acquire) && !crate::in_shim_critical()
}

/// Whether a descriptor funnel has to see this call: a page cache exists.
fn caching() -> bool {
    CACHES.load(Ordering::Acquire) && !crate::in_shim_critical()
}

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
fn map_huge_pages(addr: usize, len: usize, prot: c_int, flags: c_int, size: usize) -> i64 {
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
fn lock_limit_pages() -> usize {
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
fn lock_request(flags: c_int, len: usize) -> Result<Option<bool>, c_int> {
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
fn lock_range(start: usize, len: usize, onfault: bool) -> Result<(), c_int> {
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
fn populate(start: usize, len: usize) -> Result<(), c_int> {
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
fn require_populate() {
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

// ---------------------------------------------------------------- mappings

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
    if flags & MAP_ANONYMOUS != 0 {
        return map_anonymous(addr, len, prot, flags, offset);
    }
    map_file(addr, len, prot, flags, fd, offset)
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
        if len == 0 || offset as usize % PAGE != 0 {
            return fail(EINVAL);
        }
        // `MAP_FIXED_NOREPLACE` is `MAP_FIXED` to `hugetlb_get_unmapped_area`.
        if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 && addr % size != 0 {
            return fail(EINVAL);
        }
        return map_huge_pages(addr, len, prot, flags, size);
    }
    let lock = if flags & MAP_LOCKED != 0 || TRACKED.load(Ordering::Acquire) {
        // The judgments `do_mmap` makes before a lock is weighed.
        if len == 0 || offset as usize % PAGE != 0 || (fixed && addr % PAGE != 0) {
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
    if offset as u64 % PAGE as u64 != 0 {
        return fail(EINVAL);
    }
    // `fget` never returns an `O_PATH` file.
    let resolved = match crate::resolve_fd(fd) {
        Ok(resolved) if resolved.kind != FdKind::OPath && resolved.status & crate::O_PATH == 0 => {
            resolved
        }
        _ => return fail(EBADF),
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
    if fixed && addr % align != 0 {
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
        if offset as u64 % size != 0 || (fixed && addr as u64 % size != 0) {
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
fn judge(
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
fn alias(
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
    if let Some(desc) = object.desc() {
        if hold(desc).is_err() {
            host(Syscall::N_munmap, [start, rounded, 0, 0, 0, 0]);
            finish(replaced);
            return fail(EBADF);
        }
    }
    {
        let mut mappings = MAPPINGS.lock();
        mappings.views.set(start, start + rounded, object);
        if let Some(ino) = object.ino() {
            if object.writes_back(ino) {
                if let Some(cache) = mappings.caches.get_mut(&ino) {
                    cache.track(true);
                }
            }
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
fn hold(desc: DescId) -> Result<(), c_int> {
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
    if prot & (PROT_WRITE | PROT_EXEC) != 0 && addr % PAGE == 0 && len != 0 && tracking() {
        if let Some(end) = round_up(len).and_then(|len| addr.checked_add(len)) {
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
                        return before;
                    }
                }
                return fail(EACCES);
            }
        }
    }
    host(Syscall::N_mprotect, [addr, len, prot as usize, 0, 0, 0])
}

/// `munmap(2)`: 0, or `-errno`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_munmap(addr: usize, len: usize) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let result = host(Syscall::N_munmap, [addr, len, 0, 0, 0, 0]);
    if result == 0 && tracking() {
        crate::LAST_BOUNDARY_SYMBOL.store(c"munmap".as_ptr().cast_mut(), Ordering::Relaxed);
        forget(addr, len);
    }
    result
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
    let tracked = tracking();
    let locked = tracked && old % PAGE == 0 && MAPPINGS.lock().locks.at(old).is_some();
    if locked && new_len > old_len {
        let growth = round_up(new_len).unwrap_or(new_len) - round_up(old_len).unwrap_or(old_len);
        let total = MAPPINGS.lock().locks.total() + growth;
        if total / PAGE > lock_limit_pages() {
            return fail(crate::EWOULDBLOCK);
        }
    }
    let result = host(
        Syscall::N_mremap,
        [old, old_len, new_len, flags, new_addr, 0],
    );
    if result < 0 || !tracked {
        return result;
    }
    crate::LAST_BOUNDARY_SYMBOL.store(c"mremap".as_ptr().cast_mut(), Ordering::Relaxed);
    let moved_to = result as usize;
    let (Some(old_len), Some(new_len)) = (round_up(old_len), round_up(new_len)) else {
        return result;
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
    result
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
fn forget(addr: usize, len: usize) {
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
fn finish(pieces: Vec<(usize, usize, Object)>) {
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
fn settle(inos: &[u64]) {
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
fn write_back(ino: u64, handle: u64) -> Result<(), c_int> {
    let pages = match MAPPINGS.lock().caches.get(&ino) {
        Some(cache) => cache.dirty_pages(),
        None => return Ok(()),
    };
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
}

/// The inode `handle` is open on, when a page cache exists for it.
fn cached_ino(handle: u64) -> Option<u64> {
    if !caching() {
        return None;
    }
    let known = MAPPINGS.lock().handles.get(&handle).copied();
    let ino = match known {
        Some(ino) => ino,
        None => {
            let ino =
                crate::with_context_raw(|context| context.fs_ino_unrecorded(Fd(handle))).ok()?;
            MAPPINGS.lock().handles.insert(handle, ino);
            ino
        }
    };
    MAPPINGS.lock().caches.contains_key(&ino).then_some(ino)
}

/// A handle a write-back of `ino` can go through: a view that may write.
fn writer_of(ino: u64) -> Option<u64> {
    let mappings = MAPPINGS.lock();
    mappings
        .views
        .all()
        .find(|(_, _, object)| object.writes_back(ino))
        .and_then(|(_, _, object)| object.desc())
        .and_then(|desc| mappings.descs.get(&desc).copied())
}

// ---------------------------------------------------------------- the funnels' hooks

/// Before a read of `handle`'s file: what the views stored is what the read
/// returns. A write-back the filesystem refuses stays dirty for the next one;
/// the read itself is not failed for it.
pub(crate) fn reading(handle: u64) {
    if let Some(ino) = cached_ino(handle) {
        if let Some(writer) = writer_of(ino) {
            let _ = write_back(ino, writer);
        }
    }
}

/// Before `fsync`/`fdatasync` of `handle`'s file: what the views stored
/// becomes durable with the rest of the file.
pub(crate) fn syncing(handle: u64) -> Result<(), c_int> {
    match cached_ino(handle).and_then(|ino| writer_of(ino).map(|writer| (ino, writer))) {
        Some((ino, writer)) => write_back(ino, writer),
        None => Ok(()),
    }
}

/// Before `sync`/`syncfs` of the volume: every mapped file's stores.
pub(crate) fn syncing_all() -> Result<(), c_int> {
    if !caching() {
        return Ok(());
    }
    let inos: Vec<u64> = MAPPINGS.lock().caches.keys().copied().collect();
    for ino in inos {
        if let Some(writer) = writer_of(ino) {
            write_back(ino, writer)?;
        }
    }
    Ok(())
}

/// After the filesystem accepted `bytes` for `handle`'s file at `offset`.
pub(crate) fn written(handle: u64, offset: u64, bytes: &[u8]) {
    let Some(ino) = cached_ino(handle) else {
        return;
    };
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        cache.store(offset, bytes);
    }
}

/// After a cursor write of `bytes` to `handle`'s file: they end at the
/// cursor.
pub(crate) fn written_at_cursor(handle: u64, bytes: &[u8]) {
    if cached_ino(handle).is_none() || bytes.is_empty() {
        return;
    }
    if let Ok(cursor) = crate::with_context_raw(|context| context.fs_cursor_unrecorded(Fd(handle)))
    {
        written(handle, cursor.saturating_sub(bytes.len() as u64), bytes);
    }
}

/// After `handle`'s file became `len` bytes long.
pub(crate) fn resized(handle: u64, len: u64) {
    if let Some(ino) = cached_ino(handle) {
        resized_ino(ino, len);
    }
}

/// After the file `ino` became `len` bytes long (a truncation by path, an
/// `O_TRUNC` open).
pub(crate) fn resized_ino(ino: u64, len: u64) {
    if !caching() {
        return;
    }
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        cache.resize(len);
    }
}

/// After `fallocate` of `[offset, offset + len)` on `handle`'s file: a zeroing
/// mode cleared the range, and without `keep_size` the file reaches its end.
pub(crate) fn allocated(handle: u64, offset: u64, len: u64, zero: bool, keep_size: bool) {
    let Some(ino) = cached_ino(handle) else {
        return;
    };
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        let end = offset.saturating_add(len);
        if zero {
            cache.zero(offset, end);
        }
        if !keep_size && end > cache.size() {
            cache.resize(end);
        }
    }
}

/// After the filesystem rolled back to its durable image
/// ([`crate::patina_crash`]): every page cache reloads what its file holds
/// now, so a store no write-back or sync made durable is lost with the other
/// unsynced writes, and the views follow their files to the inode numbers the
/// rebuilt image gave them; a file the image lost leaves its views empty.
pub(crate) fn crashed() {
    if !caching() {
        return;
    }
    let files: Vec<(u64, u64)> = {
        let mappings = MAPPINGS.lock();
        mappings
            .caches
            .keys()
            .filter_map(|ino| {
                let desc = mappings
                    .views
                    .all()
                    .find(|(_, _, object)| object.ino() == Some(*ino))
                    .and_then(|(_, _, object)| object.desc())?;
                mappings.descs.get(&desc).map(|handle| (*ino, *handle))
            })
            .collect()
    };
    let mut reloaded = Vec::new();
    for (old, handle) in files {
        let recovered = crate::with_context_raw(|context| {
            let metadata = context.fs_fd_metadata(Fd(handle))?;
            let contents = context.fs_read_at(Fd(handle), 0, metadata.len as usize)?;
            Ok((metadata.ino, contents))
        });
        // A file the durable image does not hold (its name never became
        // durable) has nothing to reload: the views map an empty file, and a
        // touch is `SIGBUS` as after a truncation. The in-process crash has no
        // kernel analogue; this is the page cache agreeing with the image.
        reloaded.push(match recovered {
            Ok((ino, contents)) => (old, ino, contents),
            Err(_) => (old, old, Vec::new()),
        });
    }
    let mut mappings = MAPPINGS.lock();
    mappings.handles.clear();
    let mut rekeyed = BTreeMap::new();
    for (old, ino, contents) in reloaded {
        let Some(mut cache) = mappings.caches.remove(&old) else {
            continue;
        };
        cache.reload(&contents);
        rekeyed.insert(ino, cache);
        let moved: Vec<(usize, usize, Object)> = mappings
            .views
            .all()
            .filter(|(_, _, object)| object.ino() == Some(old))
            .collect();
        for (start, end, object) in moved {
            if let Object::File {
                desc,
                shared,
                maywrite,
                secret,
                ..
            } = object
            {
                let object = Object::File {
                    ino,
                    desc,
                    shared,
                    maywrite,
                    secret,
                };
                mappings.views.set(start, end, object);
            }
        }
    }
    mappings.caches.extend(rekeyed);
    mappings.publish();
}

/// `msync(2)`: 0, or `-errno`. The host judges the flags and the alignment
/// (`EINVAL`) and finds the holes (`ENOMEM`, every view being host memory);
/// then the walk of mm/msync.c: `MS_INVALIDATE` over a locked page is `EBUSY`
/// there (the locks are this module's, so the host cannot see them), and
/// `MS_SYNC` writes back and syncs the file of each SHARED view before that
/// point (`vfs_fsync_range` only `if (vma->vm_flags & VM_SHARED)`), a hole
/// answering `ENOMEM` only after the views past it are synced.
#[unsafe(no_mangle)]
pub extern "C" fn patina_msync(addr: usize, len: usize, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let result = host(Syscall::N_msync, [addr, len, flags as usize, 0, 0, 0]);
    if (result != 0 && result != -i64::from(ENOMEM)) || !tracking() {
        return result;
    }
    let end = addr.saturating_add(round_up(len).unwrap_or(usize::MAX));
    let (files, busy) = {
        let mappings = MAPPINGS.lock();
        let busy = (flags & MS_INVALIDATE != 0)
            .then(|| {
                mappings
                    .locks
                    .within(addr, end)
                    .first()
                    .map(|(from, _, _)| *from)
            })
            .flatten();
        let mut files: Vec<(u64, u64, bool)> = if flags & MS_SYNC == 0 {
            Vec::new()
        } else {
            mappings
                .views
                .within(addr, busy.unwrap_or(end))
                .into_iter()
                .filter(|(_, _, object)| object.is_shared())
                .filter_map(|(_, _, object)| {
                    let handle = mappings.descs.get(&object.desc()?)?;
                    Some((object.ino()?, *handle, object.is_secret()))
                })
                .collect()
        };
        files.sort_unstable();
        files.dedup_by_key(|(ino, _, _)| *ino);
        (files, busy)
    };
    crate::LAST_BOUNDARY_SYMBOL.store(c"msync".as_ptr().cast_mut(), Ordering::Relaxed);
    for (ino, handle, secret) in files {
        // Secret memory has no `fsync` operation (`vfs_fsync_range`).
        if secret {
            return fail(EINVAL);
        }
        if let Some(writer) = writer_of(ino) {
            if let Err(errno) = write_back(ino, writer) {
                return fail(errno);
            }
        }
        if let Err(errno) = crate::with_context(|context| context.fs_sync(Fd(handle))) {
            return fail(errno);
        }
    }
    if busy.is_some() {
        return fail(crate::EBUSY);
    }
    result
}

// ---------------------------------------------------------------- System V segments

/// The pages of a System V shared memory segment: a host memfd of the
/// segment's size, which attachments map.
pub(crate) struct Segment(Memfd);

impl Segment {
    pub(crate) fn new(size: usize) -> Segment {
        let mut memfd = Memfd::new();
        memfd.set_len(size as u64);
        Segment(memfd)
    }

    pub(crate) fn fd(&self) -> c_int {
        self.0.fd
    }
}

/// `shmat`'s mapping of segment `id`: the whole segment (`len` bytes),
/// anywhere or at `addr`, with `prot`. Without `remap` a fixed address must be
/// free (`EINVAL`, as `do_shmat`'s intersection check answers); with it the
/// attachment replaces what it lands on. The address, or `-errno`.
pub(crate) fn attach(
    id: i32,
    fd: c_int,
    len: usize,
    addr: Option<usize>,
    remap: bool,
    prot: c_int,
) -> i64 {
    let Some(rounded) = round_up(len) else {
        return fail(EINVAL);
    };
    let lock = match lock_request(0, rounded) {
        Ok(lock) => lock,
        Err(errno) => return fail(errno),
    };
    let claimed = matches!((addr, remap), (Some(_), false));
    if let (Some(addr), true) = (addr, claimed) {
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
            return fail(if claim == fail(crate::EEXIST) {
                EINVAL
            } else {
                (-claim) as c_int
            });
        }
    }
    let object = Object::Segment {
        id,
        maywrite: prot & PROT_WRITE != 0,
    };
    let view = alias(fd, 0, rounded, addr, prot, MAP_SHARED, object, lock);
    if view < 0 && claimed {
        host(Syscall::N_munmap, [addr.unwrap_or(0), rounded, 0, 0, 0, 0]);
    }
    view
}

/// `shmdt`: unmap the attachment that starts at `addr` — every piece of it
/// within the segment's `len` bytes from there — and answer its segment's id,
/// or `EINVAL` when no attachment starts at `addr`.
pub(crate) fn detach(addr: usize, len: impl Fn(i32) -> Option<usize>) -> Result<i32, c_int> {
    let id = match MAPPINGS.lock().views.containing(addr) {
        Some((start, _, Object::Segment { id, .. })) if start == addr => id,
        _ => return Err(EINVAL),
    };
    let end = addr.saturating_add(len(id).and_then(round_up).unwrap_or(PAGE));
    let pieces: Vec<(usize, usize)> = MAPPINGS
        .lock()
        .views
        .within(addr, end)
        .into_iter()
        .filter(
            |(_, _, object)| matches!(object, Object::Segment { id: mapped, .. } if *mapped == id),
        )
        .map(|(start, piece_end, _)| (start, piece_end))
        .collect();
    for (start, piece_end) in pieces {
        host(Syscall::N_munmap, [start, piece_end - start, 0, 0, 0, 0]);
        forget(start, piece_end - start);
    }
    Ok(id)
}

/// How many views attach segment `id`: its `shm_nattch`.
pub(crate) fn attachments(id: i32) -> usize {
    MAPPINGS
        .lock()
        .views
        .all()
        .filter(
            |(_, _, object)| matches!(object, Object::Segment { id: mapped, .. } if *mapped == id),
        )
        .count()
}

// ---------------------------------------------------------------- memory policies

/// The policy of the range `[from, to)`: `None` is the default one.
pub(crate) fn set_policy(from: usize, to: usize, policy: Option<Policy>) {
    let mut mappings = MAPPINGS.lock();
    mappings.policies.cut(from, to);
    if let Some(policy) = policy {
        mappings.policies.set(from, to, policy);
    }
    mappings.publish();
}

/// The policy `addr` has, if its range has one of its own.
pub(crate) fn policy_at(addr: usize) -> Option<Policy> {
    MAPPINGS.lock().policies.at(addr)
}

/// The ranges within `[from, to)` that have a policy of their own.
pub(crate) fn policies_in(from: usize, to: usize) -> Vec<(usize, usize, Policy)> {
    MAPPINGS.lock().policies.within(from, to)
}

/// Whether every page of `[addr, addr + len)` is mapped: host `mincore`,
/// which answers `ENOMEM` for a range with a hole and touches nothing, over
/// chunks a stack vector holds.
pub(crate) fn mapped(addr: usize, len: usize) -> bool {
    const CHUNK: usize = 256;
    let mut vector = [0u8; CHUNK];
    let end = addr.saturating_add(len.max(1));
    let mut at = addr;
    while at < end {
        let span = (end - at).min(CHUNK * PAGE);
        if host(
            Syscall::N_mincore,
            [at, span, vector.as_mut_ptr() as usize, 0, 0, 0],
        ) != 0
        {
            return false;
        }
        at += span;
    }
    true
}

/// Whether the page at `addr` is mapped and resident.
pub(crate) fn resident(addr: usize) -> Option<bool> {
    let mut vector = [0u8; 1];
    let page = addr & !(PAGE - 1);
    (host(
        Syscall::N_mincore,
        [page, PAGE, vector.as_mut_ptr() as usize, 0, 0, 0],
    ) == 0)
        .then_some(vector[0] & 1 != 0)
}

/// Read-fault the page at `addr` in, as `get_user_pages` does for a lookup:
/// `false` when no fault reaches it (unmapped, or `PROT_NONE`).
pub(crate) fn fault_in(addr: usize) -> bool {
    require_populate();
    host(
        Syscall::N_madvise,
        [addr & !(PAGE - 1), PAGE, MADV_POPULATE_READ, 0, 0, 0],
    ) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: c_int = PROT_READ | PROT_WRITE;
    /// A bit no architecture defines as a mapping flag.
    const UNKNOWN: c_int = 0x0020_0000;

    #[test]
    fn a_private_mapping_is_private_whatever_the_type_bits_share() {
        // MAP_SHARED_VALIDATE (3) contains MAP_PRIVATE's bit: testing the type
        // as flags made every private mapping read as shared-and-private.
        assert_eq!(judge(MAP_PRIVATE, RW, true, false, true, false), Ok(false));
        assert_eq!(
            judge(MAP_PRIVATE | UNKNOWN, RW, true, false, true, false),
            Ok(false)
        );
        assert_eq!(
            judge(MAP_SHARED, PROT_READ, true, false, true, false),
            Ok(true)
        );
        assert_eq!(
            judge(MAP_SHARED_VALIDATE, RW, true, true, true, false),
            Ok(true)
        );
        assert_eq!(judge(0, RW, true, true, true, false), Err(EINVAL));
        assert_eq!(judge(MAP_TYPE, RW, true, true, true, false), Err(EINVAL));
    }

    #[test]
    fn unknown_flags_are_ignored_by_map_shared_and_refused_by_validate() {
        assert_eq!(
            judge(MAP_SHARED | UNKNOWN, PROT_READ, true, false, true, false),
            Ok(true)
        );
        assert_eq!(
            judge(
                MAP_SHARED_VALIDATE | UNKNOWN,
                PROT_READ,
                true,
                false,
                true,
                false
            ),
            Err(EOPNOTSUPP)
        );
        // `MAP_FIXED_NOREPLACE` is not a legacy flag either.
        assert_eq!(
            judge(
                MAP_SHARED_VALIDATE | MAP_FIXED_NOREPLACE,
                PROT_READ,
                true,
                false,
                true,
                false
            ),
            Err(EOPNOTSUPP)
        );
    }

    #[test]
    fn access_modes_are_judged_before_the_file_kind() {
        // Shared and writable needs a writable description; any mapping needs
        // a readable one; both before a non-file's ENODEV.
        assert_eq!(judge(MAP_SHARED, RW, true, false, true, false), Err(EACCES));
        assert_eq!(judge(MAP_PRIVATE, RW, true, false, true, false), Ok(false));
        assert_eq!(
            judge(MAP_SHARED, PROT_READ, false, true, true, false),
            Err(EACCES)
        );
        assert_eq!(
            judge(MAP_PRIVATE, PROT_READ, false, true, false, false),
            Err(EACCES)
        );
        assert_eq!(
            judge(MAP_SHARED, PROT_READ, true, false, false, false),
            Err(ENODEV)
        );
        assert_eq!(
            judge(
                MAP_PRIVATE | MAP_GROWSDOWN,
                PROT_READ,
                true,
                false,
                true,
                false
            ),
            Err(EINVAL)
        );
        // A file on a `noexec` mount maps executable `EPERM`, after the
        // access modes and before the file kind and `MAP_GROWSDOWN`.
        let exec = PROT_READ | PROT_EXEC;
        assert_eq!(
            judge(MAP_SHARED, exec, true, true, true, true),
            Err(crate::EPERM)
        );
        assert_eq!(
            judge(MAP_SHARED, exec, false, true, true, true),
            Err(EACCES)
        );
        assert_eq!(
            judge(MAP_PRIVATE | MAP_GROWSDOWN, exec, true, false, false, true),
            Err(crate::EPERM)
        );
    }

    #[test]
    fn a_huge_page_size_names_a_pool_the_machine_has() {
        assert_eq!(huge_page_size(0), Some(2 << 20));
        assert_eq!(huge_page_size(21), Some(2 << 20));
        assert_eq!(huge_page_size(30), Some(1 << 30));
        assert_eq!(huge_page_size(22), None);
        assert_eq!(huge_page_size(12), None);
    }

    #[test]
    fn a_read_only_shared_view_or_attachment_refuses_write() {
        let view = |shared, maywrite| Object::File {
            ino: 1,
            desc: 1,
            shared,
            maywrite,
            secret: false,
        };
        assert!(view(true, false).refuses_write());
        assert!(!view(true, true).refuses_write());
        assert!(!view(false, true).refuses_write());
        assert!(
            Object::Segment {
                id: 0,
                maywrite: false
            }
            .refuses_write()
        );
        assert!(view(true, true).writes_back(1));
        assert!(!view(false, true).writes_back(1));
        assert!(!view(true, true).writes_back(2));
    }
}
