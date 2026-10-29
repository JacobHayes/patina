//! Memory: the one model behind the C `mmap`/`mmap64`/`munmap`/`mremap`/
//! `mprotect`/`madvise`/`msync`/`mlock*` interposers and the SUD rows of the same names,
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
//! cache: a host page file the shim holds (a memfd on Linux, an unlinked host
//! file on macOS: `cache::PageFile`), sized to the file and loaded from the
//! filesystem when the file is first mapped, by unrecorded reads no injected
//! filesystem fault reaches (`cache::file_bytes`). A `MAP_SHARED` view maps the
//! page file shared and a `MAP_PRIVATE` view maps it private, so every view is
//! the host kernel's own semantics for a mapped file: views of any shape see
//! one set of bytes, a private view copies a page on its own store, and a
//! page wholly past the end of the file faults `SIGBUS`.
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
//! page file), so the host's soft `RLIMIT_NOFILE` bounds how many files and
//! segments a guest can map at once; on Linux `__libc_start_main` raises it to
//! the hard limit, and a page file the host still refuses stops the run by
//! name (`cache::PageFile::new`) instead of answering the guest an errno the
//! kernel being modeled would not.
//!
//! The address-space rows that create, move or destroy mappings keep the
//! per-range state in step with the host's: the views (`views`; on Linux also
//! the System V attachments, which are views of a segment's memfd), and on
//! Linux the memory locks. The rows
//! are each platform's own (`mapping` judges as Linux does, `darwin` as XNU
//! does), over the one view table and page cache.
//!
//! On Linux the runtime arena's region (`crate::arena`) is no part of the
//! guest's address space, however much of it the arena has mapped: every row
//! here answers a range in it as the kernel answers a range past the address
//! space's end, or one nothing maps (`in_arena`).

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
mod barrier;
mod cache;
#[cfg(target_os = "linux")]
mod memfd;
mod ranges;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
pub(crate) use barrier::membarrier;
#[cfg(target_os = "linux")]
pub(crate) use memfd::{anonymous, released, secret, secret_resizable, secret_resized};

use crate::SpinMutex;
use crate::fdtable::{DescId, FdKind};
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
use crate::registry::Syscall;
#[cfg(target_os = "linux")]
use crate::{EACCES, EBADF, EINVAL, ENODEV, ENOMEM, EOPNOTSUPP, EOVERFLOW};
use cache::{Cache, PageFile};
#[cfg(target_os = "linux")]
use cache::{Memfd, Pages};
#[cfg(target_os = "linux")]
use patina_dst_abi::seals::{F_SEAL_FUTURE_WRITE, F_SEAL_WRITE};
use patina_dst_abi::{Fd, FsEntryKind};
use ranges::Ranges;
use std::collections::BTreeMap;
use std::ffi::c_int;
#[cfg(target_os = "linux")]
use std::ffi::c_long;
use std::sync::atomic::{AtomicBool, Ordering};

/// The page the views are kept in. On Linux it is the page the guest computes
/// offsets and lengths against: patina pins `sysconf(_SC_PAGESIZE)` to it.
/// On macOS it is the host's page, which XNU maps and faults in: 16 KiB on
/// Apple silicon, where the guest's `sysconf(_SC_PAGESIZE)` still answers
/// the virtual machine's 4 KiB (a residual, `ESCAPE-CLASSES.md`).
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) const PAGE: usize = 4096;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const PAGE: usize = 16384;

/// The Linux mapping ABI the rows decode, in the kernel's own values.
#[cfg(target_os = "linux")]
mod abi {
    use linux_raw_sys::general as uapi;
    use std::ffi::c_int;

    pub(super) const MAP_SHARED: c_int = uapi::MAP_SHARED as c_int;
    pub(super) const MAP_PRIVATE: c_int = 2;
    pub(super) const MAP_SHARED_VALIDATE: c_int = 3;
    pub(super) const MAP_TYPE: c_int = uapi::MAP_TYPE as c_int;
    pub(super) const MAP_FIXED: c_int = uapi::MAP_FIXED as c_int;
    pub(super) const MAP_ANONYMOUS: c_int = uapi::MAP_ANONYMOUS as c_int;
    pub(super) const MAP_FIXED_NOREPLACE: c_int = uapi::MAP_FIXED_NOREPLACE as c_int;
    pub(super) const MAP_GROWSDOWN: c_int = uapi::MAP_GROWSDOWN as c_int;
    pub(super) const MAP_HUGETLB: c_int = uapi::MAP_HUGETLB as c_int;
    pub(super) const MAP_LOCKED: c_int = uapi::MAP_LOCKED as c_int;
    pub(super) const MAP_NORESERVE: c_int = uapi::MAP_NORESERVE as c_int;
    pub(super) const MAP_POPULATE: c_int = uapi::MAP_POPULATE as c_int;
    pub(super) const MAP_NONBLOCK: c_int = uapi::MAP_NONBLOCK as c_int;
    pub(super) const MAP_STACK: c_int = uapi::MAP_STACK as c_int;
    #[cfg(target_arch = "x86_64")]
    pub(super) const MAP_32BIT: c_int = uapi::MAP_32BIT as c_int;
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) const MAP_32BIT: c_int = 0;
    pub(super) const MAP_HUGE_SHIFT: c_int = 26;
    pub(super) const MAP_HUGE_MASK: c_int = 0x3f;
    /// `LEGACY_MAP_MASK` (include/linux/mman.h): the flags plain `MAP_SHARED`
    /// keeps (every other bit is ignored) and `MAP_SHARED_VALIDATE` accepts
    /// (every other bit is `EOPNOTSUPP`).
    pub(super) const LEGACY_MAP_MASK: c_int = MAP_SHARED
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
    pub(super) const VIEW_HINTS: c_int =
        MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_32BIT;
    pub(crate) const PROT_READ: c_int = uapi::PROT_READ as c_int;
    pub(crate) const PROT_WRITE: c_int = uapi::PROT_WRITE as c_int;
    pub(crate) const PROT_EXEC: c_int = uapi::PROT_EXEC as c_int;
    pub(super) const MREMAP_MAYMOVE: usize = uapi::MREMAP_MAYMOVE as usize;
    pub(super) const MREMAP_FIXED: usize = uapi::MREMAP_FIXED as usize;
    pub(super) const MREMAP_DONTUNMAP: usize = uapi::MREMAP_DONTUNMAP as usize;
    pub(super) const MS_SYNC: c_int = uapi::MS_SYNC as c_int;
    pub(super) const MS_INVALIDATE: c_int = uapi::MS_INVALIDATE as c_int;
    pub(super) const MADV_POPULATE_READ: usize = 22;
    pub(super) const MADV_POPULATE_WRITE: usize = 23;
    pub(super) const MLOCK_ONFAULT: u32 = uapi::MLOCK_ONFAULT;
    pub(super) const MCL_CURRENT: c_int = uapi::MCL_CURRENT as c_int;
    pub(super) const MCL_FUTURE: c_int = uapi::MCL_FUTURE as c_int;
    pub(super) const MCL_ONFAULT: c_int = uapi::MCL_ONFAULT as c_int;
}
#[cfg(target_os = "linux")]
use abi::*;
#[cfg(target_os = "linux")]
pub(crate) use abi::{PROT_EXEC, PROT_READ, PROT_WRITE};

/// The Darwin mapping ABI the rows decode, in libSystem's values.
#[cfg(target_os = "macos")]
mod abi {
    use std::ffi::c_int;

    pub(super) const MAP_SHARED: c_int = libc::MAP_SHARED;
    pub(super) const MAP_FIXED: c_int = libc::MAP_FIXED;
    pub(super) const MAP_ANON: c_int = libc::MAP_ANON;
    pub(super) const PROT_WRITE: c_int = libc::PROT_WRITE;
    pub(super) const PROT_EXEC: c_int = libc::PROT_EXEC;
    pub(super) const MS_ASYNC: c_int = libc::MS_ASYNC;
    pub(super) const MS_KILLPAGES: c_int = libc::MS_KILLPAGES;
    pub(super) const MS_DEACTIVATE: c_int = libc::MS_DEACTIVATE;
}
#[cfg(target_os = "macos")]
use abi::*;

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
    #[cfg(target_os = "linux")]
    Segment { id: i32, maywrite: bool },
}

impl Object {
    /// A `MAP_SHARED` view: a shared file mapping or an attachment.
    fn is_shared(self) -> bool {
        match self {
            Object::File { shared, .. } => shared,
            #[cfg(target_os = "linux")]
            Object::Segment { .. } => true,
        }
    }

    fn ino(self) -> Option<u64> {
        match self {
            Object::File { ino, .. } => Some(ino),
            #[cfg(target_os = "linux")]
            Object::Segment { .. } => None,
        }
    }

    fn desc(self) -> Option<DescId> {
        match self {
            Object::File { desc, .. } => Some(desc),
            #[cfg(target_os = "linux")]
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
            Object::File { maywrite, .. } => !maywrite,
            #[cfg(target_os = "linux")]
            Object::Segment { maywrite, .. } => !maywrite,
        }
    }

    /// The same view of the file `ino` (a crash renumbered its inode).
    fn renumbered(self, ino: u64) -> Self {
        match self {
            Object::File {
                desc,
                shared,
                maywrite,
                secret,
                ..
            } => Object::File {
                ino,
                desc,
                shared,
                maywrite,
                secret,
            },
            #[cfg(target_os = "linux")]
            segment @ Object::Segment { .. } => segment,
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
    caches: BTreeMap<u64, Cache<PageFile>>,
    /// Driver handle → the inode it is open on, for the handles the funnels
    /// have asked about while a page cache existed. Driver handles are never
    /// reused within a process, so an entry cannot go stale by reuse.
    handles: BTreeMap<u64, u64>,
    /// The descriptions views hold, and their driver handles.
    descs: BTreeMap<DescId, u64>,
    /// Locked ranges (`VM_LOCKED`), each with whether it locks on fault.
    #[cfg(target_os = "linux")]
    locks: Ranges<bool>,
    /// `mlockall(MCL_FUTURE)`: later mappings are locked, on fault or not.
    #[cfg(target_os = "linux")]
    future: Option<bool>,
}

static MAPPINGS: SpinMutex<Mappings> = SpinMutex::new(Mappings {
    views: Ranges::new(),
    caches: BTreeMap::new(),
    handles: BTreeMap::new(),
    descs: BTreeMap::new(),
    #[cfg(target_os = "linux")]
    locks: Ranges::new(),
    #[cfg(target_os = "linux")]
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
        #[cfg(target_os = "linux")]
        let ranges = !(self.locks.is_empty() && self.future.is_none());
        #[cfg(target_os = "macos")]
        let ranges = false;
        TRACKED.store(!self.views.is_empty() || ranges, Ordering::Release);
        CACHES.store(!self.caches.is_empty(), Ordering::Release);
    }

    /// Whether a shared view of `handle`'s file that may write is live
    /// (`mapping_writably_mapped`, what refuses a new `F_SEAL_WRITE`).
    #[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
fn host(row: Syscall, args: [usize; 6]) -> i64 {
    host_number(i64::from(row.number()), args)
}

/// [`host`] by number: the SUD pass-through rows hand over the number they
/// trapped.
#[cfg(target_os = "linux")]
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

/// Whether the guest's range `[addr, addr + len)`, in whole pages, reaches
/// into the runtime arena's region, which is no part of the guest's address
/// space (`crate::arena`): a request about it is answered here, never by the
/// host, whose answer would depend on how much of the region the arena has
/// mapped.
#[cfg(target_os = "linux")]
pub(crate) fn in_arena(addr: usize, len: usize) -> bool {
    crate::arena::reserved(addr, round_up(len).unwrap_or(usize::MAX))
}

/// A host mapping of `len` bytes of `fd` from `offset` at `addr` (a hint, or
/// the place under `MAP_FIXED`), in the raw ABI: the address, or `-errno`.
#[cfg(target_os = "linux")]
fn host_map(addr: usize, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: usize) -> i64 {
    host(
        Syscall::N_mmap,
        [
            addr,
            len,
            prot as usize,
            flags as usize,
            fd as usize,
            offset,
        ],
    )
}

/// Unmap `[addr, addr + len)` on the host: 0, or `-errno`.
#[cfg(target_os = "linux")]
fn host_unmap(addr: usize, len: usize) -> i64 {
    host(Syscall::N_munmap, [addr, len, 0, 0, 0, 0])
}

/// [`host_map`] through libSystem's `mmap`, reached through the host-alias
/// table.
#[cfg(target_os = "macos")]
fn host_map(addr: usize, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: usize) -> i64 {
    // SAFETY: a mapping on address space the guest or this module owns,
    // through the real libSystem entry, never the interposed one.
    let address = unsafe {
        (crate::hostapi::get().host_mmap)(
            addr as *mut std::ffi::c_void,
            len,
            prot,
            flags,
            fd,
            offset as libc::off_t,
        )
    };
    if address == libc::MAP_FAILED {
        host_failure()
    } else {
        address as i64
    }
}

/// [`host_unmap`] through libSystem's `munmap`.
#[cfg(target_os = "macos")]
fn host_unmap(addr: usize, len: usize) -> i64 {
    // SAFETY: as for `host_map`.
    let result = unsafe { (crate::hostapi::get().host_munmap)(addr as *mut std::ffi::c_void, len) };
    if result == -1 { host_failure() } else { 0 }
}

/// The host errno a libSystem call just left, in the raw ABI.
#[cfg(target_os = "macos")]
fn host_failure() -> i64 {
    -i64::from(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(crate::EIO),
    )
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

#[cfg(target_os = "macos")]
mod darwin;
mod hooks;
#[cfg(target_os = "linux")]
mod locks;
#[cfg(target_os = "linux")]
mod mapping;
#[cfg(target_os = "linux")]
mod segments;
mod views;

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg_attr(
    not(any(target_os = "linux", patina_posix_exports)),
    allow(unused_imports)
)]
pub(crate) use hooks::resized;
#[cfg(target_os = "linux")]
pub(crate) use hooks::written;
#[cfg(target_os = "linux")]
pub(crate) use hooks::{allocated, syncing_all};
pub(crate) use hooks::{
    crashed, inspecting, inspecting_ino, reading, reading_in, resized_ino, syncing,
    unwritten_stores, written_at_cursor_in, written_in,
};
#[cfg(target_os = "linux")]
pub(crate) use locks::huge_page_size;
#[cfg(target_os = "linux")]
use locks::{lock_limit_pages, lock_range, lock_request, map_huge_pages, populate};
#[cfg(all(test, target_os = "linux"))]
use mapping::judge;
#[cfg(target_os = "linux")]
pub(crate) use segments::{Segment, attach, attachments, detach, mapped};
#[cfg(all(test, target_os = "linux"))]
use views::writer_among;
use views::{
    alias, cache_for, cached_ino, forget, settle, write_back, write_back_counted,
    write_back_through, writer_of,
};
#[cfg(target_os = "linux")]
use views::{finish, take_all};
#[cfg(target_os = "linux")]
pub(crate) use views::{mapped_file, view_dirty_pages};

#[cfg(target_os = "macos")]
#[cfg_attr(not(patina_posix_exports), allow(unused_imports))]
pub(crate) use darwin::{mmap, mprotect, msync, munmap};
#[cfg(target_os = "linux")]
pub(crate) use hooks::msync;
#[cfg(target_os = "linux")]
pub(crate) use locks::{patina_mlock, patina_mlockall, patina_munlock, patina_munlockall};
#[cfg(all(target_os = "linux", patina_posix_exports))]
pub(crate) use mapping::patina_mremap;
#[cfg(target_os = "linux")]
pub(crate) use mapping::{madvise, mmap, mprotect, mremap, munmap};
#[cfg(target_os = "linux")]
pub(crate) use memfd::{
    patina_add_seals, patina_get_seals, patina_memfd_create, patina_memfd_secret,
};
