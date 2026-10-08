//! Syscall-user-dispatch (SUD) dispatch table — Linux only.
//!
//! Startup (`posix::lifecycle`) arms SUD (`prctl(PR_SET_SYSCALL_USER_DISPATCH,
//! …)` with allowed region = glibc's executable segment, NULL selector) and
//! installs the C `SIGSYS` handler. When guest code executes a raw `syscall`/`svc`
//! instruction outside glibc's text, the kernel rolls the instruction back and
//! delivers a synchronous, thread-directed `SIGSYS` at the exact faulting IP.
//! The handler decodes the syscall number and its six argument registers from
//! the `ucontext` (in Rust), then calls [`patina_sud_dispatch`], which routes the call
//! into the *same* `patina_*` entry points the C interposers use and returns the
//! value the handler writes back into the syscall's return register (raw ABI:
//! a negative value is `-errno`, there is no libc `errno` step).
//!
//! Soundness: the trap is synchronous — it *is* the guest's own effect boundary,
//! semantically identical to the guest having called an interposed `read()` — so
//! re-entering the deterministic runtime (taking `lock_state`, parking on the
//! baton) is exactly what every C interposer already does. See `SUD-DESIGN.md`
//! §4.2. The one invariant that must hold is that shim/runtime code never itself
//! traps while servicing a dispatch; [`with_dispatch_guard`] is the standalone
//! RED detector for a violation of it.
//!
//! Dispatch is GENERATED from the syscall registry (`crate::registry`): every
//! number the vendored kernel table lists has a row with a disposition, the
//! routed rows bind a handler in [`BINDINGS`], and [`build_dispatch`] turns the
//! rows for this arch into the number → row index at compile time. A number
//! the table does not list is a distinct diagnostic from a row whose
//! disposition is a trap. This module is `x86_64`-first (the only arch with
//! kernel SUD today); the arm64 rows carry their own numbers so the dispatcher
//! lights up unchanged when generic-entry arm64 kernels ship, and the libc
//! `syscall(2)` interposer already forwards into it on every Linux arch.

use crate::thread::signals::{
    Action, GenerationInfo, GenerationTarget, Info, Stack, WaitMode, deliver, generate_signal,
    patina_signal_action, patina_signal_altstack, patina_signal_mask, patina_signal_pending,
    patina_signal_wait,
};
use std::cell::Cell;

use crate::registry::{Arch, Disposition, SYSCALLS, SyscallRow};
use crate::{PatinaFlock, PatinaMetadata, PatinaTimestamp};

pub(crate) mod arming;
mod fd_io;
mod fs;
mod mem;
mod net;
mod pidfd;
mod privileged;
mod readiness;
mod sched_identity;
mod signal_process;
pub(crate) use signal_process::auxv_value;
#[cfg(patina_posix_exports)]
pub(crate) use signal_process::{PATINA_SUD_AUXV_BASE, PATINA_SUD_AUXV_LEN};
#[cfg(target_arch = "x86_64")]
mod thread_pointer;
mod time;
#[cfg(target_arch = "x86_64")]
mod x86_64;
use fd_io::*;
use fs::*;
use mem::*;
use net::*;
use readiness::*;
use sched_identity::*;
use signal_process::*;
use time::*;
#[cfg(target_arch = "x86_64")]
use x86_64::*;

// The row-side entries the descriptor close and seek paths in `lib.rs` call.
pub(crate) use fs::{release_dir_iteration, seek_dir_iteration};
/// A new thread inherits its creator's locked shadow-stack features.
#[cfg(target_arch = "x86_64")]
pub(crate) use thread_pointer::spawned as thread_pointer_spawned;

/// A new thread `child`, created by `parent`, inherits the per-task state
/// the kernel copies at `clone`: `no_new_privs`, and its credentials'
/// process keyring.
pub(crate) fn task_spawned(parent: c_int, child: c_int) {
    signal_process::no_new_privs_spawned(parent, child);
    privileged::keyring_spawned(parent, child);
}

/// Thread `tid` exited: its per-task state goes with it.
pub(crate) fn task_exited(tid: c_int) {
    signal_process::no_new_privs_exited(tid);
    privileged::keyring_exited(tid);
}

use linux_raw_sys::errno;
use linux_raw_sys::general as uapi;
use std::ffi::{c_char, c_int, c_long, c_void};

// SUD rows call the `patina_*` entries the C interposers call, by module path:
// there is no second implementation of any effect, and the compiler checks
// every signature.

// The kernel ABI's own values, from its uapi headers for the target
// architecture (`linux-raw-sys`): errno values shape raw-syscall returns
// (`-errno`), and every flag word below is decoded with them.
const ERANGE: i64 = errno::ERANGE as i64;

const EBADF: i64 = errno::EBADF as i64;

const EFAULT: i64 = errno::EFAULT as i64;

const ECHILD: i64 = errno::ECHILD as i64;

const ESRCH: i64 = errno::ESRCH as i64;

const ENOTDIR: i64 = errno::ENOTDIR as i64;

const EINVAL: i64 = errno::EINVAL as i64;

const ENOSYS: i64 = errno::ENOSYS as i64;

const EINTR: i64 = errno::EINTR as i64;

const EOPNOTSUPP: i64 = errno::EOPNOTSUPP as i64;

const EOVERFLOW: i64 = errno::EOVERFLOW as i64;

const E2BIG: i64 = errno::E2BIG as i64;

// Patina clock ids (see `patina_native.h`).
const PATINA_CLOCK_REALTIME: u32 = 0;

const PATINA_CLOCK_MONOTONIC: u32 = 1;

// Patina open flags (see `patina_native.h`).
const PATINA_O_READ: u32 = 1 << 0;

const PATINA_O_WRITE: u32 = 1 << 1;

const PATINA_O_CREATE: u32 = 1 << 2;

const PATINA_O_TRUNCATE: u32 = 1 << 3;

const PATINA_O_APPEND: u32 = 1 << 4;

const PATINA_O_EXCLUSIVE: u32 = 1 << 5;

const PATINA_O_NOFOLLOW: u32 = 1 << 6;

const PATINA_O_NONBLOCK: u32 = 1 << 7;

const PATINA_O_PATH: u32 = 1 << 8;

const PATINA_O_CLOEXEC: u32 = 1 << 9;

const PATINA_O_OPENED: u32 = 1 << 10;

const PATINA_O_DIRECTORY: u32 = 1 << 11;

const PATINA_O_NOCTTY: u32 = 1 << 12;

// Patina path-resolution flags (see `patina_native.h`).
const PATINA_RESOLVE_NOFOLLOW: u32 = 1 << 0;

const PATINA_RESOLVE_EMPTY_PATH: u32 = 1 << 1;

const PATINA_RESOLVE_BENEATH: u32 = 1 << 2;

const PATINA_RESOLVE_IN_ROOT: u32 = 1 << 3;

const PATINA_RESOLVE_NO_SYMLINKS: u32 = 1 << 4;

const PATINA_RESOLVE_NO_XDEV: u32 = 1 << 5;

const PATINA_RESOLVE_CACHED: u32 = 1 << 6;

const PATINA_RESOLVE_NO_MAGICLINKS: u32 = 1 << 7;

// Kernel `open(2)` flag bits: x86_64 and arm64 disagree on `O_DIRECTORY`,
// `O_NOFOLLOW`, `O_DIRECT` and `O_LARGEFILE`.
const O_ACCMODE: u64 = uapi::O_ACCMODE as u64;

const O_WRONLY: u64 = uapi::O_WRONLY as u64;

const O_RDWR: u64 = uapi::O_RDWR as u64;

const O_CREAT: u64 = uapi::O_CREAT as u64;

const O_EXCL: u64 = uapi::O_EXCL as u64;

const O_TRUNC: u64 = uapi::O_TRUNC as u64;

const O_APPEND: u64 = uapi::O_APPEND as u64;

const O_NONBLOCK: u64 = uapi::O_NONBLOCK as u64;

const O_DIRECTORY: u64 = uapi::O_DIRECTORY as u64;

const O_NOFOLLOW: u64 = uapi::O_NOFOLLOW as u64;

const O_CLOEXEC: u64 = uapi::O_CLOEXEC as u64;

/// A 64-bit kernel forces `O_LARGEFILE` into every `open(2)`-minted
/// description and reports it through `F_GETFL`.
const O_LARGEFILE: u64 = uapi::O_LARGEFILE as u64;

/// `O_LARGEFILE` for the C `fcntl(F_GETFL)`, whose libc spells the macro 0.
#[unsafe(no_mangle)]
pub static PATINA_KERNEL_O_LARGEFILE: c_int = O_LARGEFILE as c_int;

/// `O_DIRECT` on a pipe asks for packet mode, which is not modeled.
const O_DIRECT: u64 = uapi::O_DIRECT as u64;

/// `O_PATH`: a descriptor that resolves paths and answers metadata but cannot
/// read or write. `cap-primitives` walks a path one component at a time with
/// `openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, so this bit is
/// on the hot path of every capability-based filesystem guest.
const O_PATH: u64 = uapi::O_PATH as u64;

const AT_FDCWD: i64 = uapi::AT_FDCWD as i64;

// `futex(2)` op decode (mirrors the libc `syscall()` interposer in
// patina_posix.c so the raw and wrapped paths route identically).
const FUTEX_WAIT: u64 = uapi::FUTEX_WAIT as u64;

const FUTEX_WAKE: u64 = uapi::FUTEX_WAKE as u64;

const FUTEX_WAIT_BITSET: u64 = uapi::FUTEX_WAIT_BITSET as u64;

const FUTEX_WAKE_BITSET: u64 = uapi::FUTEX_WAKE_BITSET as u64;

const FUTEX_REQUEUE: u64 = uapi::FUTEX_REQUEUE as u64;

const FUTEX_CMP_REQUEUE: u64 = uapi::FUTEX_CMP_REQUEUE as u64;

const FUTEX_PRIVATE_FLAG: u64 = uapi::FUTEX_PRIVATE_FLAG as u64;

const FUTEX_CLOCK_REALTIME: u64 = uapi::FUTEX_CLOCK_REALTIME as u64;

const NANOS_PER_SEC: u64 = 1_000_000_000;

// Patina FS entry kinds returned by the metadata / read-dir entries.
const PATINA_ENTRY_DIRECTORY: u32 = 2;

const PATINA_ENTRY_SYMLINK: u32 = 3;

const PATINA_ENTRY_FIFO: u32 = 4;

const PATINA_ENTRY_SOCKET: u32 = 5;

const PATINA_ENTRY_CHAR: u32 = 6;

const PATINA_ENTRY_ANON: u32 = 7;

// getdents64 `d_type` values (linux_dirent64).
const DT_FIFO: u8 = uapi::DT_FIFO as u8;

const DT_DIR: u8 = uapi::DT_DIR as u8;

const DT_REG: u8 = uapi::DT_REG as u8;

const DT_LNK: u8 = uapi::DT_LNK as u8;

const DT_SOCK: u8 = uapi::DT_SOCK as u8;

const DT_CHR: u8 = uapi::DT_CHR as u8;

// File-mode bits for the kernel `struct stat`/`struct statx` (mirrors the C
// `patina_mode_for_kind`).
const S_IFIFO: u32 = uapi::S_IFIFO;

const S_IFDIR: u32 = uapi::S_IFDIR;

const S_IFREG: u32 = uapi::S_IFREG;

const S_IFLNK: u32 = uapi::S_IFLNK;

const S_IFSOCK: u32 = uapi::S_IFSOCK;

const S_IFCHR: u32 = uapi::S_IFCHR;

// `*at` flag bits.
const AT_SYMLINK_NOFOLLOW: u64 = uapi::AT_SYMLINK_NOFOLLOW as u64;

const AT_REMOVEDIR: u64 = uapi::AT_REMOVEDIR as u64;

const AT_SYMLINK_FOLLOW: u64 = uapi::AT_SYMLINK_FOLLOW as u64;

const AT_EMPTY_PATH: u64 = uapi::AT_EMPTY_PATH as u64;

const AT_EACCESS: u64 = uapi::AT_EACCESS as u64;

const AT_NO_AUTOMOUNT: u64 = uapi::AT_NO_AUTOMOUNT as u64;

/// `statx(2)`'s two sync-mode bits (`AT_STATX_FORCE_SYNC|AT_STATX_DONT_SYNC`).
/// They only choose how fresh a network filesystem's answer must be; a virtual
/// filesystem is always exact, so they change nothing.
const AT_STATX_SYNC_TYPE: u64 = uapi::AT_STATX_SYNC_TYPE as u64;

/// The `statx(2)` mask bit reserved for a future `struct statx` expansion.
const STATX__RESERVED: u64 = uapi::STATX__RESERVED as u64;

/// `utimensat(2)` `tv_nsec` sentinels.
const UTIME_NOW: i64 = uapi::UTIME_NOW as i64;
const UTIME_OMIT: i64 = uapi::UTIME_OMIT as i64;

// `fcntl(2)` commands.
const F_DUPFD: u64 = uapi::F_DUPFD as u64;

const F_GETFD: u64 = uapi::F_GETFD as u64;

const F_SETFD: u64 = uapi::F_SETFD as u64;

const F_GETFL: u64 = uapi::F_GETFL as u64;

const F_SETFL: u64 = uapi::F_SETFL as u64;

const F_DUPFD_CLOEXEC: u64 = uapi::F_DUPFD_CLOEXEC as u64;

const F_SETPIPE_SZ: u64 = uapi::F_SETPIPE_SZ as u64;

const F_GETPIPE_SZ: u64 = uapi::F_GETPIPE_SZ as u64;
const F_ADD_SEALS: u64 = uapi::F_ADD_SEALS as u64;
const F_GET_SEALS: u64 = uapi::F_GET_SEALS as u64;
const F_SETOWN: u64 = uapi::F_SETOWN as u64;
const F_SETOWN_EX: u64 = uapi::F_SETOWN_EX as u64;
const F_SETSIG: u64 = uapi::F_SETSIG as u64;
const F_GETOWN: u64 = uapi::F_GETOWN as u64;
const F_GETOWN_EX: u64 = uapi::F_GETOWN_EX as u64;
const F_GETSIG: u64 = uapi::F_GETSIG as u64;

const F_GETLK: u64 = uapi::F_GETLK as u64;

const F_SETLK: u64 = uapi::F_SETLK as u64;

const F_SETLKW: u64 = uapi::F_SETLKW as u64;

const F_OFD_GETLK: u64 = uapi::F_OFD_GETLK as u64;

const F_OFD_SETLK: u64 = uapi::F_OFD_SETLK as u64;

const F_OFD_SETLKW: u64 = uapi::F_OFD_SETLKW as u64;

const FD_CLOEXEC: i64 = uapi::FD_CLOEXEC as i64;

/// Kernel `struct timespec` on 64-bit Linux (`time_t` and `long` are both 8
/// bytes). Read from and written to guest memory during dispatch.
use crate::clocks::Timespec;

/// Kernel `struct timeval` on 64-bit Linux.
use crate::clocks::Timeval;

thread_local! {
    /// Set while this thread is inside [`patina_sud_dispatch`]. A nested SIGSYS
    /// (i.e. a trap taken *while servicing a trap*) can only mean shim/runtime
    /// code executed a raw syscall — the one thing the audit instruction scan
    /// proves it never does. If the invariant were ever violated this flag turns
    /// the recursion into a loud, named abort instead of an unbounded SIGSYS
    /// storm. This is the standalone RED detector for the §4.2 soundness
    /// invariant ("shim never traps").
    static IN_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

/// Only the kernel-frame release may re-enter dispatch as guest code: a raw
/// syscall, or a counter read, from a handler it runs.
pub(crate) fn with_signal_delivery(body: impl FnOnce()) {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            IN_DISPATCH.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(IN_DISPATCH.with(|cell| cell.replace(false)));
    crate::tsc::with_guest_reads(body);
}

/// Run `body` with the reentry guard held. Re-entrant dispatch aborts loudly.
fn with_dispatch_guard<F: FnOnce() -> i64>(nr: i64, body: F) -> i64 {
    if IN_DISPATCH.with(Cell::get) {
        crate::trap_fatal(&format!(
            "SUD re-entered dispatch while servicing syscall {nr}: shim/runtime code executed a raw \
             syscall inside the SIGSYS handler (the instruction scan proves this cannot happen — a \
             reentry means the containment invariant is broken)"
        ));
    }
    IN_DISPATCH.with(|cell| cell.set(true));
    let result = body();
    IN_DISPATCH.with(|cell| cell.set(false));
    result
}

use std::collections::BTreeMap;

use std::sync::Mutex;

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::registry::Syscall;

/// Shape a raw-syscall return from a `patina_*` `int` result: on error the raw
/// caller reads `-errno` from the return register (there is no libc `errno`
/// step), on success the value itself.
fn ret_i32(result: c_int) -> i64 {
    if result < 0 {
        -(crate::environment::patina_errno() as i64)
    } else {
        result as i64
    }
}

/// As [`ret_i32`] for an `intptr_t`-returning entry point (`read`/`write`).
fn ret_isize(result: isize) -> i64 {
    if result < 0 {
        -(crate::environment::patina_errno() as i64)
    } else {
        result as i64
    }
}

#[unsafe(no_mangle)]
/// The SIGSYS dispatch entry point. The C handler passes the decoded syscall
/// number, its six argument registers, and the faulting instruction address
/// (already validated by the C handler to lie within the main executable's
/// text). The returned value is written verbatim into the syscall's return
/// register — raw ABI, so a negative value is `-errno`.
///
/// The exported name doubles as the audit's SUD marker: a binary whose symbol
/// table *defines* `patina_sud_dispatch` carries a dispatch-capable shim, which
/// is condition (a) of the `direct-syscall` audit downgrade (see
/// `patina-target`). It is `#[used]`/`#[no_mangle]` and referenced by the C
/// handler, so it is never dead-stripped.
///
/// # Safety
/// Called only from the C `SIGSYS` handler on the faulting managed thread, with
/// argument registers that are the guest's own — pointers are valid guest
/// addresses for the lifetime of the (synchronous) dispatch.
pub unsafe extern "C" fn patina_sud_dispatch(
    nr: c_long,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    call_addr: usize,
) -> c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let _ = call_addr;
    // `c_long` is `i64` on the LP64 Linux targets this module compiles for, so it
    // matches the `i64` syscall-number table and dispatch signature directly.
    //
    // Thread-provenance invariant (SUD-DESIGN.md §4.2 invariant 1, restated): the
    // trapping thread is a managed task OR the pre-activation main thread —
    // identical thread-semantics to the interposer entries. The main thread holds
    // its task id from the startup constructor on (`MAIN_TASK`) but is only
    // registered with the scheduler lazily (`ensure_active`, on first
    // thread-subsystem use), so a raw syscall before any spawn runs on an
    // inactive runtime, exactly like an interposed call would — the `patina_*`
    // entries handle that today, and dispatch must not be stricter than the
    // boundary it mirrors (a hard managed-task assert here aborted every guest
    // whose first raw syscall preceded its first spawn). No dispatch-side check is
    // needed to hold the invariant: arming strictly follows `set_current_task` in
    // the trampoline, so an armed non-main thread always has a task; a foreign
    // host thread never executes the guest's inline syscall instructions (the C
    // handler already proved `call_addr` is in main-executable text); and shim/std
    // text contains zero raw syscalls (audit-proven), backstopped by the reentry
    // guard below.
    let args = [a0, a1, a2, a3, a4, a5];
    let result = with_dispatch_guard(nr, || {
        crate::thread::signals::refresh_handler_mask();
        dispatch(nr, args)
    });
    deliver();
    result
}

/// Interpret a syscall-argument register as a 32-bit `int` fd/dirfd — exactly as
/// the kernel does. The kernel reads fd/dirfd arguments as `int` (the low 32
/// bits), so a caller may fill the upper 32 register bits either way:
/// hand-written asm sign-extends a negative `AT_FDCWD` (-100 → `..FFFF_FF9C`),
/// but rustix's `linux_raw` backend ZERO-extends it (`raw_fd` does
/// `fd as c_uint as usize` → `0x0000_0000_FFFF_FF9C`). Reading the full 64-bit
/// register as `i64` would then see `AT_FDCWD` as a large positive number and
/// reject it (this exact gap made a rustix-default `openat(CWD, …)` return
/// EINVAL). Truncating to `i32` first recovers the kernel's view regardless of
/// how the upper bits were filled, and leaves every ordinary (small, positive)
/// fd unchanged.
#[inline]
fn arg_fd(reg: u64) -> i64 {
    reg as i32 as i64
}

mod bindings;
mod dispatch;

#[cfg(test)]
mod tests;

use bindings::BINDINGS;
#[cfg(test)]
use dispatch::INDEX_LEN;
use dispatch::{dispatch, row_for};
