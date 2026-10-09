//! Explicit native C ABI entry points for Patina.
//!
//! Internal crate: the native interposition layer that `cargo patina build`
//! links below a guest binary. The Rust side here exposes prefixed
//! `patina_*` C ABI entry points over the deterministic runtime; the bundled C
//! glue (the staged `patina_posix.c` and its slices under `c/posix/`,
//! exported as [`POSIX_C_SOURCE`] and [`POSIX_C_FAMILY_SOURCES`]) retains startup,
//! callback, clock-store and cancellation seams. Guest-only Rust adapters
//! provide ordinary libc symbols over the same prefixed models. The prefixed
//! Rust surface
//! exports ambient libc names only in the guest build (`patina_posix_exports`), so
//! linking this crate alone cannot silently alter unrelated host operations.
//! Adopters never depend on this crate; see [ARCHITECTURE.md] for the shim
//! design and its fail-closed doctrine.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

// Enabled only on the guest archive, never the runner's dependency rlib.
#[cfg(patina_posix_exports)]
mod posix;
#[cfg(patina_posix_exports)]
mod posix_env;
#[cfg(patina_posix_exports)]
mod variadic;
#[cfg(all(patina_posix_exports, target_os = "linux"))]
include!(concat!(env!("OUT_DIR"), "/route_aliases.rs"));

mod abi;
mod plain;

mod bundle;
mod charge;
mod coverage;
mod entropy;
mod environment;
mod fd;
mod fs;
mod host;
mod process;
mod runtime;
mod sdk;
mod shutdown;
mod startup;
mod state;
mod support;
mod time_abi;

pub use bundle::*;
pub(crate) use coverage::LAST_ERRNO;
pub use coverage::*;
pub use entropy::*;
pub use environment::*;
pub use fd::*;
pub use fs::*;
pub(crate) use host::*;
pub(crate) use host::{hostapi, hostcoll};
#[cfg(test)]
pub(crate) use process::host_abort;
pub use process::*;
pub use runtime::*;
pub use sdk::*;
pub use shutdown::*;
pub use startup::*;
pub(crate) use state::*;
pub(crate) use support::*;
pub use time_abi::*;

// The syscall registry: every kernel number with its disposition, the symbol
// layer mapped onto it, and the vendored-table gates. Platform-independent
// data; `cargo patina syscalls` reads it and the Linux SUD dispatcher is
// generated from it. See `registry/mod.rs`.
pub mod registry;

// Syscall-user-dispatch (SUD) dispatch table — Linux only. The C layer arms SUD
// and installs the SIGSYS handler; this module owns the per-arch decode and the
// routing of trapped raw syscalls into the same `patina_*` entry points the C
// interposers use. See `sud.rs` and `SUD-DESIGN.md`.
#[cfg(target_os = "linux")]
mod sud;

// Timestamp-counter trap (`rdtsc`/`rdtscp`) — armed by the C layer via
// `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` on x86-64 Linux. This module owns the
// instruction decode and the virtual-clock derivation the SIGSEGV handler writes
// back into the guest's registers. See `tsc.rs`.
//
// Built on every Linux target (the decode is pure byte matching, and the audit's
// second condition is a live `PR_SET_TSC` probe, so an arm64 build carrying the
// dispatcher still never downgrades), and under `cfg(test)` everywhere so the
// decode's fail-closed behaviour is covered on a macOS host too.
#[cfg(any(target_os = "linux", test))]
mod tsc;

// The guest descriptor table: guest fd numbers → open file descriptions, for
// every class the shim models. The single global instance and every entry that
// consults it live below (`fd_table`, `patina_fd_kind`, the universal
// `patina_read`/`patina_close`/`patina_dupfd` entries); the data structure and
// its allocation/refcount rules are the module's own. See `fdtable.rs`.
mod fdtable;
// `ioctl(2)`'s generic descriptor requests (`FIOCLEX`/`FIONCLEX`/`FIONBIO`/
// `FIONREAD`), one entry both doors call. See `ioctl.rs`.
mod ioctl;
// Vectored I/O (`readv`/`writev`/`preadv`/`pwritev` and the `*v2` flags): the
// iovec import the kernel's `lib/iov_iter.c` does, over the single-buffer
// transfers below. See `iov.rs`.
mod iov;
// Page-cache advice and writeback (`readahead`, `fadvise64`,
// `sync_file_range`, `sync`, `syncfs`). See `advice.rs`.
#[cfg(target_os = "linux")]
mod advice;
#[cfg(target_os = "linux")]
mod clocks;
// The filesystem's notification hooks: what an inotify watch sees of each
// filesystem entry. See `fsnotify.rs`.
#[cfg(target_os = "linux")]
mod fsnotify;
#[cfg(target_os = "linux")]
mod identity;
// The virtual Darwin kernel's self-description (`uname` on macOS). Built
// under `cfg(test)` everywhere so its field model is covered on a Linux host
// too. See `darwin_identity.rs`.
#[cfg(any(target_os = "macos", test))]
mod darwin_identity;
// `localtime_r`'s time zone: glibc's TZ rules over the virtual machine. See
// `localtime.rs`.
#[cfg(target_os = "linux")]
mod limits;
mod localtime;
#[cfg(target_os = "linux")]
mod mem;
// The caller's namespace files, `/proc/self/ns/*`. See `nsfs.rs`.
#[cfg(target_os = "linux")]
mod nsfs;
#[cfg(target_os = "linux")]
mod numa;
mod panic_boundary;
mod paths;
mod watchdog;
// Guest memory copied the way the kernel's `copy_from_user`/`copy_to_user` do:
// whole or `EFAULT`, never a fault in shim code. See `uaccess.rs`.
mod uaccess;
// What `statfs`/`fstatfs`/`ustat` report: the one deterministic volume and the
// kernel's pseudo-filesystems. See `volume.rs`.
// In-kernel copies (`copy_file_range`, `sendfile`, `splice`, `tee`,
// `vmsplice`) over the positional file I/O and the pipe channels. See
// `transfer.rs`.
#[cfg(target_os = "linux")]
mod transfer;
#[cfg(target_os = "linux")]
mod volume;
// Extended attributes: the `fs/xattr.c` syscall half over the filesystem's
// attribute store. See `xattr.rs`.
#[cfg(target_os = "linux")]
mod xattr;

use std::cell::{Cell, UnsafeCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use fdtable::{DescId, FdKind, GuestFdTable, Release, Resolved};

use patina_dst_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsAllocateMode, FsEntryKind, FsNode, OpenFlags,
    SeekWhence, TaskId,
};

use patina_dst_fs_crash::CrashFs;
use patina_dst_fs_mem::{FsImage, FsSnapshot, MemFs};
use patina_dst_runtime::{
    BuggifyKind, Context, CustomOpMode, MAX_TRACE_BYTES, RuntimeBuilder, RuntimeConfig,
    RuntimeError, SiteOutcome, TraceTransport, VerdictKind,
};
use patina_dst_trace::{
    HandoffSealKey, IncarnationHandoff, TraceError, abandoned_trace_marker,
    resource_limit_infra_line,
};
pub use thread::{
    patina_cond_broadcast, patina_cond_destroy, patina_cond_init, patina_cond_signal,
    patina_cond_timedwait, patina_cond_wait, patina_futex_wait, patina_futex_wait_timed,
    patina_futex_wake, patina_mutex_destroy, patina_mutex_init, patina_mutex_lock,
    patina_mutex_trylock, patina_mutex_unlock, patina_rwlock_destroy, patina_rwlock_init,
    patina_rwlock_rdlock, patina_rwlock_tryrdlock, patina_rwlock_trywrlock, patina_rwlock_unlock,
    patina_rwlock_wrlock, patina_thread_create, patina_thread_detach, patina_thread_exit,
    patina_thread_join,
};
#[cfg(target_os = "macos")]
pub use thread::{
    patina_dispatch_release, patina_dispatch_semaphore_create, patina_dispatch_semaphore_signal,
    patina_dispatch_semaphore_wait, patina_dispatch_time,
};

/// Deterministic managed threads and pthread synchronization.
///
/// The guest's `pthread_create`/`join`, `pthread_mutex_*`, and
/// `pthread_cond_*` calls (and thereby Rust `std::thread`, `Mutex`, and
/// `Condvar`) execute under Patina's [`DetScheduler`](patina_dst_sched_det). Real
/// host OS threads back each managed task, but a single execution baton ensures
/// exactly one runs at a time; every handoff is a seeded scheduler decision
/// recorded and replayed like any other boundary operation.
///
/// # Staying out of its own interposition
///
/// The shim interposes the guest's pthread symbols, so it must never call them
/// to implement itself, or it would recurse. Two choices keep the shim off its
/// own interposers, reaching each host vehicle through the sanctioned host-alias
/// table instead:
///
/// * Shim-internal synchronization never uses `std::sync` (which lowers to the
///   interposed pthread symbols). The short state sections use an atomics
///   [`SpinMutex`], and the execution baton is a per-task host OS semaphore
///   (`dispatch_semaphore` on macOS, POSIX `sem_t` on Linux) — pure blocking
///   primitives that carry no scheduling decision. Neither touches the
///   interposed pthread layer.
/// * A real host OS thread is created through a *distinct*, non-interposed
///   path: `pthread_create_suspended_np` (plus a mach `thread_resume`) on
///   macOS. glibc has no such variant, so on Linux the shim resolves the genuine
///   glibc `pthread_create` through the host-alias table's `dlsym(RTLD_NEXT, ...)`
///   primitive (`RTLD_NEXT` skips the shim's own strong-def interposer), exactly
///   as it reaches the real `read`/`write`/`sem_*`.
///
/// Every scheduling decision — which task runs next at each boundary — is made
/// by [`DetScheduler`](patina_dst_sched_det) and recorded/replayed; the OS
/// primitives only provide the vehicle and the blocking.
mod thread;

#[cfg(test)]
#[path = "process/private_abort_tests.rs"]
mod private_abort_tests;
#[cfg(test)]
mod tests;
