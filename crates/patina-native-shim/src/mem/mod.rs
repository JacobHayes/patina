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
pub(crate) mod userfaultfd;

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

mod hooks;
mod locks;
mod mapping;
mod segments;

#[cfg(test)]
mod tests;

pub(crate) use hooks::{
    allocated, crashed, inspecting, inspecting_ino, reading, resized, resized_ino, syncing,
    syncing_all, written, written_at_cursor,
};
pub(crate) use locks::huge_page_size;
use locks::{
    lock_limit_pages, lock_range, lock_request, map_huge_pages, populate, require_populate,
};
pub(crate) use mapping::view_dirty_pages;
use mapping::{alias, cached_ino, forget, write_back, write_back_counted, writer_of};
#[cfg(test)]
use mapping::{judge, writer_among};
pub(crate) use segments::{
    Segment, attach, attachments, detach, fault_in, mapped, policies_in, policy_at, resident,
    set_policy,
};

pub(crate) use hooks::patina_msync;
pub(crate) use locks::{patina_mlock, patina_mlockall, patina_munlock, patina_munlockall};
pub(crate) use mapping::{patina_mmap, patina_mprotect, patina_mremap, patina_munmap};
pub(crate) use memfd::{
    patina_add_seals, patina_get_seals, patina_memfd_create, patina_memfd_secret,
};
