//! Syscall-user-dispatch (SUD) dispatch table — Linux only.
//!
//! The C layer (`patina_posix.c`) arms SUD (`prctl(PR_SET_SYSCALL_USER_DISPATCH,
//! …)` with allowed region = glibc's executable segment, NULL selector) and
//! installs a `SIGSYS` handler. When guest code executes a raw `syscall`/`svc`
//! instruction outside glibc's text, the kernel rolls the instruction back and
//! delivers a synchronous, thread-directed `SIGSYS` at the exact faulting IP.
//! The C handler decodes the syscall number and its six argument registers from
//! the `ucontext`, then calls [`patina_sud_dispatch`], which routes the call
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

mod fd_io;
mod fs;
mod mem;
mod net;
mod pidfd;
mod privileged;
mod readiness;
mod sched_identity;
mod signal_process;
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

// The `patina_*` runtime entry points the C interposers call. Declaring them as
// externs (rather than reaching for module paths) routes SUD through the exact
// same symbols — there is no second implementation of any effect. Every one is a
// `#[no_mangle] extern "C"` definition elsewhere in this crate.
unsafe extern "C" {
    fn patina_errno() -> c_int;
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> c_int;
    fn patina_sleep_until_remaining(
        clock_id: u32,
        deadline_nanos: u64,
        remaining: *mut i64,
    ) -> c_int;
    // The one open entry (`openat(2)` shape): resolves `(dirfd, path)` through
    // the runtime's resolver and decides the descriptor's kind from the entry's.
    fn patina_openat(dirfd: c_int, path: *const c_char, flags: u32, mode: u32) -> c_int;
    fn patina_openat2(
        dirfd: c_int,
        path: *const c_char,
        flags: u32,
        mode: u32,
        resolve: u32,
    ) -> c_int;
    fn patina_read(fd: c_int, destination: *mut c_void, length: usize) -> isize;
    fn patina_write(fd: c_int, source: *const c_void, length: usize) -> isize;
    fn patina_pread(fd: c_int, destination: *mut c_void, length: usize, offset: i64) -> isize;
    fn patina_pwrite(fd: c_int, source: *const c_void, length: usize, offset: i64) -> isize;
    fn patina_readv(fd: c_int, vector: *const c_void, count: i64, flags: i32) -> isize;
    fn patina_writev(fd: c_int, vector: *const c_void, count: i64, flags: i32) -> isize;
    fn patina_preadv(
        fd: c_int,
        vector: *const c_void,
        count: i64,
        offset: i64,
        flags: i32,
    ) -> isize;
    fn patina_pwritev(
        fd: c_int,
        vector: *const c_void,
        count: i64,
        offset: i64,
        flags: i32,
    ) -> isize;
    fn patina_close(fd: c_int) -> c_int;
    fn patina_seek(fd: c_int, offset: i64, whence: u32) -> i64;
    fn patina_fsync(fd: c_int) -> c_int;
    fn patina_set_len(fd: c_int, length: u64) -> c_int;
    fn patina_flock(fd: c_int, operation: c_int) -> c_int;
    fn patina_record_lock(fd: c_int, command: u32, lock: *mut PatinaFlock) -> c_int;
    fn patina_dup(fd: c_int) -> c_int;
    fn patina_getrandom(destination: *mut c_void, length: usize, flags: u32) -> isize;
    fn patina_sched_yield() -> c_int;
    fn patina_thread_id() -> c_int;
    fn patina_raw_exit(status: c_int) -> !;
    fn patina_raw_exit_group(status: c_int) -> !;
    fn patina_set_tid_address(address: *mut i32) -> i64;
    // Memory mappings (`crate::mem`): the one model the C mmap/munmap/mremap/
    // msync interposers call, in the raw ABI.
    fn patina_mmap(
        addr: usize,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> i64;
    fn patina_munmap(addr: usize, length: usize) -> i64;
    fn patina_mremap(
        old_addr: usize,
        old_length: usize,
        new_length: usize,
        flags: usize,
        new_addr: usize,
    ) -> i64;
    fn patina_msync(addr: usize, length: usize, flags: c_int) -> i64;
    fn patina_mprotect(addr: usize, length: usize, prot: c_int) -> i64;
    fn patina_mlock(addr: usize, length: usize, flags: u32) -> i64;
    fn patina_munlock(addr: usize, length: usize) -> i64;
    fn patina_mlockall(flags: c_int) -> i64;
    fn patina_munlockall() -> i64;
    fn patina_prlimit(
        pid: c_int,
        resource: u32,
        new: *const crate::limits::Rlimit,
        old: *mut crate::limits::Rlimit,
    ) -> i64;
    // Anonymous files and their seals (`crate::mem`), the C memfd_create and
    // fcntl seal commands' entries.
    fn patina_memfd_create(name: *const c_char, flags: u32) -> c_int;
    fn patina_memfd_secret(flags: u32) -> c_int;
    fn patina_get_seals(fd: c_int) -> c_int;
    fn patina_add_seals(fd: c_int, seals: u32) -> c_int;

    // Filesystem metadata / directory iteration (the same records the C
    // stat/statx/getdents interposers normalize).
    fn patina_metadata_at(
        dirfd: c_int,
        path: *const c_char,
        flags: u32,
        out: *mut PatinaMetadata,
    ) -> c_int;
    fn patina_fd_metadata_full(fd: c_int, out: *mut PatinaMetadata) -> c_int;
    fn patina_statfs(path: *const c_char, out: *mut c_void) -> c_int;
    // Extended attributes: `by` (`xattr::XATTR_BY_*`) names the path, its
    // final symlink followed or not (the `l*` rows), or the descriptor `fd`.
    fn patina_getxattr(
        fd: c_int,
        path: *const c_char,
        by: c_int,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    fn patina_listxattr(
        fd: c_int,
        path: *const c_char,
        by: c_int,
        list: *mut c_void,
        size: usize,
    ) -> isize;
    fn patina_setxattr(
        fd: c_int,
        path: *const c_char,
        by: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn patina_removexattr(fd: c_int, path: *const c_char, by: c_int, name: *const c_char) -> c_int;
    // In-kernel copies.
    fn patina_copy_file_range(
        fd_in: c_int,
        off_in: *mut i64,
        fd_out: c_int,
        off_out: *mut i64,
        len: usize,
        flags: u32,
    ) -> isize;
    fn patina_sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: usize) -> isize;
    fn patina_splice(
        fd_in: c_int,
        off_in: *mut i64,
        fd_out: c_int,
        off_out: *mut i64,
        len: usize,
        flags: u32,
    ) -> isize;
    fn patina_tee(fd_in: c_int, fd_out: c_int, len: usize, flags: u32) -> isize;
    fn patina_vmsplice(fd: c_int, vector: *const c_void, count: i64, flags: u32) -> isize;
    // Page-cache advice and writeback.
    fn patina_fadvise(fd: c_int, offset: i64, length: i64, advice: c_int) -> c_int;
    fn patina_readahead(fd: c_int, offset: i64, count: usize) -> c_int;
    fn patina_sync_file_range(fd: c_int, offset: i64, length: i64, flags: u32) -> c_int;
    fn patina_sync() -> c_int;
    fn patina_syncfs(fd: c_int) -> c_int;
    fn patina_fstatfs(fd: c_int, out: *mut c_void) -> c_int;
    // The one modeled identity, for st_uid/st_gid.
    fn patina_uid() -> u32;
    fn patina_gid() -> u32;
    // Timestamps, ownership and sizes: the same entries the C utimensat/chown/
    // truncate/fallocate families call.
    fn patina_utimensat(
        dirfd: c_int,
        path: *const c_char,
        flags: u32,
        atime_kind: u32,
        atime: PatinaTimestamp,
        mtime_kind: u32,
        mtime: PatinaTimestamp,
    ) -> c_int;
    fn patina_futimens(
        fd: c_int,
        atime_kind: u32,
        atime: PatinaTimestamp,
        mtime_kind: u32,
        mtime: PatinaTimestamp,
    ) -> c_int;
    fn patina_chown(dirfd: c_int, path: *const c_char, flags: u32, uid: u32, gid: u32) -> c_int;
    fn patina_fchown(fd: c_int, uid: u32, gid: u32) -> c_int;
    fn patina_truncate(dirfd: c_int, path: *const c_char, length: i64) -> c_int;
    fn patina_fallocate(fd: c_int, mode: u32, offset: i64, length: i64) -> c_int;
    // Permission bits: the same entries the C chmod/fchmod/fchmodat interposers
    // call, so a raw-syscall guest and a libc guest change one mode model.
    fn patina_chmod(dirfd: c_int, path: *const c_char, mode: u32, flags: u32) -> c_int;
    fn patina_fchmod(fd: c_int, mode: u32) -> c_int;
    fn patina_read_dir(fd: c_int, state_out: *mut *mut c_void) -> c_int;
    // The descriptor table's face: the kind oracle and the per-number /
    // per-description state (`include/patina_native.h`).
    fn patina_fd_kind(fd: c_int) -> c_int;
    fn patina_fd_getfd(fd: c_int) -> c_int;
    fn patina_fd_setfd(fd: c_int, cloexec: c_int) -> c_int;
    fn patina_fd_getfl(fd: c_int) -> c_int;
    fn patina_fd_setfl(fd: c_int, flags: u32) -> c_int;
    fn patina_dupfd(fd: c_int, minimum: c_int, cloexec: c_int) -> c_int;
    fn patina_dup3(oldfd: c_int, newfd: c_int, cloexec: c_int) -> c_int;
    fn patina_close_range(first: u32, last: u32, flags: u32) -> c_int;
    fn patina_ioctl(fd: c_int, request: u64, arg: *mut c_void) -> c_int;
    fn patina_pipe_size(fd: c_int) -> c_int;
    fn patina_pipe_set_size(fd: c_int, size: c_int) -> c_int;
    fn patina_read_dir_next(
        state: *mut c_void,
        name_buf: *mut c_char,
        buf_len: usize,
        kind: *mut u32,
        ino: *mut u64,
    ) -> c_int;
    fn patina_read_dir_free(state: *mut c_void);
    // The namespace operations, each on a `(dirfd, path)` the runtime resolves
    // — the same entries the C interposers of the same names call.
    fn patina_mkdir(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn patina_mknod(dirfd: c_int, path: *const c_char, mode: u32, dev: u32) -> c_int;
    fn patina_unlink(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_rmdir(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_renameat2(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: u32,
    ) -> c_int;
    fn patina_symlink(target: *const c_char, dirfd: c_int, link_path: *const c_char) -> c_int;
    fn patina_link(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        follow: c_int,
    ) -> c_int;
    fn patina_read_link(
        dirfd: c_int,
        path: *const c_char,
        buf: *mut c_char,
        buf_len: usize,
    ) -> isize;
    // The working directory and the umask: the process state the C
    // getcwd/chdir/fchdir/umask interposers read and write.
    fn patina_getcwd(buf: *mut c_char, len: usize) -> isize;
    fn patina_chdir(dirfd: c_int, path: *const c_char) -> c_int;
    fn patina_fchdir(fd: c_int) -> c_int;
    fn patina_umask(mask: u32) -> u32;
    fn patina_pipe(
        read_fd_out: *mut c_int,
        write_fd_out: *mut c_int,
        nonblocking: c_int,
        cloexec: c_int,
    ) -> c_int;

    // Sockets — the exact entries the C socket interposers call.
    fn patina_sock_socket(family: c_int, ty: c_int, protocol: c_int) -> i64;
    fn patina_sock_socketpair(family: c_int, ty: c_int, protocol: c_int, sv: usize) -> i64;
    fn patina_sock_bind(fd: c_int, addr: usize, len: i64) -> i64;
    fn patina_sock_connect(fd: c_int, addr: usize, len: i64) -> i64;
    fn patina_sock_listen(fd: c_int, backlog: c_int) -> i64;
    fn patina_sock_accept(fd: c_int, addr: usize, len_ptr: usize, flags: c_int) -> i64;
    fn patina_sock_name(fd: c_int, addr: usize, len_ptr: usize, peer: c_int) -> i64;
    fn patina_sock_shutdown(fd: c_int, how: c_int) -> i64;
    fn patina_sock_setsockopt(fd: c_int, level: c_int, name: c_int, value: usize, len: i64) -> i64;
    fn patina_sock_getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: usize,
        len_ptr: usize,
    ) -> i64;
    fn patina_sock_sendto(
        fd: c_int,
        buf: usize,
        len: usize,
        flags: c_int,
        addr: usize,
        alen: i64,
    ) -> i64;
    fn patina_sock_recvfrom(
        fd: c_int,
        buf: usize,
        len: usize,
        flags: c_int,
        addr: usize,
        alen_ptr: usize,
    ) -> i64;
    fn patina_sock_sendmsg(fd: c_int, msg: usize, flags: c_int) -> i64;
    fn patina_sock_recvmsg(fd: c_int, msg: usize, flags: c_int) -> i64;
    fn patina_sock_sendmmsg(fd: c_int, vec: usize, vlen: u32, flags: c_int) -> i64;
    fn patina_sock_recvmmsg(fd: c_int, vec: usize, vlen: u32, flags: c_int, timeout: usize) -> i64;

    fn patina_eventfd(initval: u32, flags: c_int) -> c_int;

    // Readiness reactor (Linux epoll frontend over the OS-agnostic core). The SUD
    // rows are a SECOND caller of these exact entries, never a second reactor.
    fn patina_epoll_create1(flags: c_int) -> c_int;
    fn patina_epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *const c_void) -> c_int;
}

// The kernel ABI's own values, from its uapi headers for the target
// architecture (`linux-raw-sys`): errno values shape raw-syscall returns
// (`-errno`), and every flag word below is decoded with them.
const ERANGE: i64 = errno::ERANGE as i64;

const EBADF: i64 = errno::EBADF as i64;

const EACCES: i64 = errno::EACCES as i64;

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

// `access(2)` mode bits.
const X_OK: u64 = uapi::X_OK as u64;

const W_OK: u64 = uapi::W_OK as u64;

const R_OK: u64 = uapi::R_OK as u64;

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

/// Only the kernel-frame release may re-enter dispatch as guest code.
pub(crate) fn with_signal_delivery(body: impl FnOnce()) {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            IN_DISPATCH.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(IN_DISPATCH.with(|cell| cell.replace(false)));
    body();
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

/// Shape a raw-syscall return from a `patina_*` `int` result: on error the raw
/// caller reads `-errno` from the return register (there is no libc `errno`
/// step), on success the value itself.
fn ret_i32(result: c_int) -> i64 {
    if result < 0 {
        // SAFETY: `patina_errno` is a plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

/// As [`ret_i32`] for an `intptr_t`-returning entry point (`read`/`write`).
fn ret_isize(result: isize) -> i64 {
    if result < 0 {
        // SAFETY: as above.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

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
#[unsafe(no_mangle)]
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

/// A routed row's handler: the syscall number and its six argument registers
/// in, the raw return value out (`-errno` on failure). The number is passed so
/// the memory pass-through can hand the host kernel the exact number it trapped.
type Handler = fn(i64, [u64; 6]) -> i64;

/// The handler bound to each routed registry row, by row name. Dispatch is
/// GENERATED from `registry::SYSCALLS` (the [`DISPATCH`] index below is built
/// from the rows for this arch at compile time), so there is no second list of
/// numbers here — only the adapter from registers to the `sys_*` signature.
/// [`build_dispatch`] refuses to compile a `Modeled`/`Passthrough` row without
/// exactly one binding, a `Trap`/`Absent` row with one, or a binding that names
/// no row; `tests::bindings_match_the_registry_rows` reports the same
/// conditions by name.
///
/// fd/dirfd registers go through [`arg_fd`]; `AT_FDCWD` and any negative fd are
/// 32-bit `int`s the kernel reads from the low register bits.
use crate::registry::Syscall;

const BINDINGS: &[(Syscall, Handler)] = &[
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_select, |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], None)
    }),
    (Syscall::N_pselect6, |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], Some(a[5]))
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_signalfd, |_, a| unsafe {
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            0,
        )
    }),
    (Syscall::N_signalfd4, |_, a| unsafe {
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            a[3] as i32,
        )
    }),
    // ---- time ----
    (Syscall::N_clock_gettime, |_, a| {
        sys_clock_gettime(a[0], a[1] as *mut Timespec)
    }),
    (Syscall::N_clock_getres, |_, a| {
        sys_clock_getres(a[0], a[1] as *mut Timespec)
    }),
    (Syscall::N_gettimeofday, |_, a| {
        sys_gettimeofday(a[0] as *mut Timeval, a[1] as *mut [i32; 2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_time, |_, a| sys_time(a[0] as *mut i64)),
    // SAFETY: guest pointers, NULL-checked by the entries.
    (Syscall::N_settimeofday, |_, a| unsafe {
        crate::clocks::settimeofday(a[0] as *const [i64; 2])
    }),
    (Syscall::N_clock_settime, |_, a| unsafe {
        crate::clocks::clock_settime(a[0] as c_int, a[1] as *const Timespec)
    }),
    (Syscall::N_adjtimex, |_, a| unsafe {
        crate::clocks::adjtimex(a[0] as *mut crate::clocks::Timex)
    }),
    (Syscall::N_clock_adjtime, |_, a| unsafe {
        crate::clocks::clock_adjtime(a[0] as c_int, a[1] as *mut crate::clocks::Timex)
    }),
    // ---- the process's timers (`thread::timers`) ----
    (Syscall::N_getitimer, |_, a| unsafe {
        crate::thread::timers::getitimer(a[0] as i32, a[1] as *mut _)
    }),
    (Syscall::N_setitimer, |_, a| unsafe {
        crate::thread::timers::setitimer(a[0] as i32, a[1] as *const _, a[2] as *mut _)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_alarm, |_, a| {
        crate::thread::timers::alarm(a[0] as u32)
    }),
    (Syscall::N_timer_create, |_, a| unsafe {
        crate::thread::timers::timer_create(a[0] as i32, a[1] as *const _, a[2] as *mut i32)
    }),
    (Syscall::N_timer_settime, |_, a| unsafe {
        crate::thread::timers::timer_settime(
            a[0] as i32,
            a[1] as i32,
            a[2] as *const _,
            a[3] as *mut _,
        )
    }),
    (Syscall::N_timer_gettime, |_, a| unsafe {
        crate::thread::timers::timer_gettime(a[0] as i32, a[1] as *mut _)
    }),
    (Syscall::N_timer_getoverrun, |_, a| {
        crate::thread::timers::timer_getoverrun(a[0] as i32)
    }),
    (Syscall::N_timer_delete, |_, a| {
        crate::thread::timers::timer_delete(a[0] as i32)
    }),
    (Syscall::N_timerfd_create, |_, a| {
        crate::thread::timers::timerfd_create(a[0] as i32, a[1] as c_int)
    }),
    (Syscall::N_timerfd_settime, |_, a| {
        crate::thread::timers::timerfd_settime(
            arg_fd(a[0]) as c_int,
            a[1] as i32,
            a[2] as usize,
            a[3] as usize,
        )
    }),
    (Syscall::N_timerfd_gettime, |_, a| {
        crate::thread::timers::timerfd_gettime(arg_fd(a[0]) as c_int, a[1] as usize)
    }),
    (Syscall::N_times, |_, a| unsafe {
        crate::clocks::times(a[0] as *mut [i64; 4])
    }),
    (Syscall::N_getrusage, |_, a| unsafe {
        crate::clocks::getrusage(a[0] as i32, a[1] as *mut crate::clocks::Rusage)
    }),
    // ---- identity: the one unprivileged identity (`crate::identity`) ----
    (Syscall::N_getuid, |_, _| {
        i64::from(crate::identity::credential().uid)
    }),
    (Syscall::N_geteuid, |_, _| {
        i64::from(crate::identity::credential().uid)
    }),
    (Syscall::N_getgid, |_, _| {
        i64::from(crate::identity::credential().gid)
    }),
    (Syscall::N_getegid, |_, _| {
        i64::from(crate::identity::credential().gid)
    }),
    (Syscall::N_getresuid, |_, a| unsafe {
        crate::identity::getres(
            crate::identity::Id::User,
            a[0] as *mut u32,
            a[1] as *mut u32,
            a[2] as *mut u32,
        )
    }),
    (Syscall::N_getresgid, |_, a| unsafe {
        crate::identity::getres(
            crate::identity::Id::Group,
            a[0] as *mut u32,
            a[1] as *mut u32,
            a[2] as *mut u32,
        )
    }),
    (Syscall::N_setuid, |_, a| {
        crate::identity::set(crate::identity::Id::User, a[0] as u32)
    }),
    (Syscall::N_setgid, |_, a| {
        crate::identity::set(crate::identity::Id::Group, a[0] as u32)
    }),
    (Syscall::N_setreuid, |_, a| {
        crate::identity::set_many(crate::identity::Id::User, &[a[0] as u32, a[1] as u32])
    }),
    (Syscall::N_setregid, |_, a| {
        crate::identity::set_many(crate::identity::Id::Group, &[a[0] as u32, a[1] as u32])
    }),
    (Syscall::N_setresuid, |_, a| {
        crate::identity::set_many(
            crate::identity::Id::User,
            &[a[0] as u32, a[1] as u32, a[2] as u32],
        )
    }),
    (Syscall::N_setresgid, |_, a| {
        crate::identity::set_many(
            crate::identity::Id::Group,
            &[a[0] as u32, a[1] as u32, a[2] as u32],
        )
    }),
    (Syscall::N_setfsuid, |_, _| {
        crate::identity::set_fs(crate::identity::Id::User)
    }),
    (Syscall::N_setfsgid, |_, _| {
        crate::identity::set_fs(crate::identity::Id::Group)
    }),
    (Syscall::N_getgroups, |_, a| unsafe {
        crate::identity::getgroups(a[0] as i32, a[1] as *mut u32)
    }),
    (Syscall::N_setgroups, |_, _| crate::identity::setgroups()),
    (Syscall::N_capget, |_, a| unsafe {
        crate::identity::capget(a[0] as *mut _, a[1] as *mut _)
    }),
    (Syscall::N_capset, |_, a| unsafe {
        crate::identity::capset(
            crate::identity::credential(),
            a[0] as *mut _,
            a[1] as *const _,
        )
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_getpgrp, |_, _| crate::identity::getpgrp()),
    (Syscall::N_setpgid, |_, a| {
        crate::identity::setpgid(a[0] as i32, a[1] as i32)
    }),
    (Syscall::N_setsid, |_, _| crate::identity::setsid()),
    // ---- privileged: the virtual credential's capability checks
    // (`privileged`) ----
    (Syscall::N_sethostname, |nr, a| {
        privileged::answer(nr, privileged::set_uts_name, a)
    }),
    (Syscall::N_setdomainname, |nr, a| {
        privileged::answer(nr, privileged::set_uts_name, a)
    }),
    (Syscall::N_mount, |nr, a| {
        privileged::answer(nr, privileged::mount, a)
    }),
    (Syscall::N_umount2, |nr, a| {
        privileged::answer(nr, privileged::umount2, a)
    }),
    (Syscall::N_pivot_root, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_open_tree, |nr, a| {
        privileged::answer(nr, privileged::open_tree, a)
    }),
    (Syscall::N_move_mount, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fsopen, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fsconfig, |nr, a| {
        privileged::answer(nr, privileged::fsconfig, a)
    }),
    (Syscall::N_fsmount, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fspick, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_mount_setattr, |nr, a| {
        privileged::answer(nr, privileged::mount_setattr, a)
    }),
    (Syscall::N_acct, |nr, a| {
        privileged::answer(nr, privileged::acct, a)
    }),
    (Syscall::N_vhangup, |nr, a| {
        privileged::answer(nr, privileged::vhangup, a)
    }),
    (Syscall::N_swapon, |nr, a| {
        privileged::answer(nr, privileged::swapon, a)
    }),
    (Syscall::N_swapoff, |nr, a| {
        privileged::answer(nr, privileged::swapoff, a)
    }),
    (Syscall::N_reboot, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_kexec_load, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_kexec_file_load, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_init_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_finit_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_delete_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_quotactl, |nr, a| {
        privileged::answer(nr, privileged::quotactl, a)
    }),
    (Syscall::N_quotactl_fd, |nr, a| {
        privileged::answer(nr, privileged::quotactl_fd, a)
    }),
    (Syscall::N_chroot, |nr, a| {
        privileged::answer(nr, privileged::chroot, a)
    }),
    (Syscall::N_syslog, |nr, a| {
        privileged::answer(nr, privileged::syslog, a)
    }),
    (Syscall::N_perf_event_open, |nr, a| {
        privileged::answer(nr, privileged::perf_event_open, a)
    }),
    (Syscall::N_bpf, |nr, a| {
        privileged::answer(nr, privileged::bpf, a)
    }),
    (Syscall::N_userfaultfd, |nr, a| {
        privileged::answer(nr, privileged::userfaultfd, a)
    }),
    (Syscall::N_ptrace, |nr, a| {
        privileged::answer(nr, privileged::ptrace, a)
    }),
    (Syscall::N_unshare, |nr, a| {
        privileged::answer(nr, privileged::unshare, a)
    }),
    (Syscall::N_setns, |nr, a| {
        privileged::answer(nr, privileged::setns, a)
    }),
    (Syscall::N_seccomp, |nr, a| {
        privileged::answer(nr, privileged::seccomp, a)
    }),
    (Syscall::N_landlock_create_ruleset, |nr, a| {
        privileged::answer(nr, privileged::landlock_create_ruleset, a)
    }),
    (Syscall::N_landlock_add_rule, |nr, a| {
        privileged::answer(nr, privileged::landlock_add_rule, a)
    }),
    (Syscall::N_landlock_restrict_self, |nr, a| {
        privileged::answer(nr, privileged::landlock_restrict_self, a)
    }),
    (Syscall::N_lsm_list_modules, |nr, a| {
        privileged::answer(nr, privileged::lsm_list_modules, a)
    }),
    (Syscall::N_lsm_get_self_attr, |nr, a| {
        privileged::answer(nr, privileged::lsm_get_self_attr, a)
    }),
    (Syscall::N_lsm_set_self_attr, |nr, a| {
        privileged::answer(nr, privileged::lsm_set_self_attr, a)
    }),
    (Syscall::N_add_key, |nr, a| {
        privileged::answer(nr, privileged::add_key, a)
    }),
    (Syscall::N_request_key, |nr, a| {
        privileged::answer(nr, privileged::request_key, a)
    }),
    (Syscall::N_keyctl, |nr, a| {
        privileged::answer(nr, privileged::keyctl, a)
    }),
    (Syscall::N_statmount, |nr, a| {
        privileged::answer(nr, privileged::statmount, a)
    }),
    (Syscall::N_listmount, |nr, a| {
        privileged::answer(nr, privileged::listmount, a)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_iopl, |nr, a| {
        privileged::answer(nr, privileged::iopl, a)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_ioperm, |nr, a| {
        privileged::answer(nr, privileged::ioperm, a)
    }),
    (Syscall::N_uname, |_, a| unsafe {
        crate::identity::uname(a[0] as *mut _, crate::thread::sched::persona())
    }),
    (Syscall::N_sysinfo, |_, a| unsafe {
        crate::identity::sysinfo(a[0] as *mut _)
    }),
    // ---- scheduling attributes, affinity and persona (`thread::sched`) ----
    (Syscall::N_personality, |_, a| {
        crate::thread::sched::personality(a[0] as u32)
    }),
    (Syscall::N_getpriority, |_, a| {
        crate::thread::sched::getpriority(a[0] as i32, a[1] as i32)
    }),
    (Syscall::N_setpriority, |_, a| {
        crate::thread::sched::setpriority(a[0] as i32, a[1] as i32, a[2] as i32)
    }),
    (Syscall::N_sched_setparam, |_, a| unsafe {
        crate::thread::sched::setscheduler_param(a[0] as i32, None, a[1] as *const i32)
    }),
    (Syscall::N_sched_getparam, |_, a| unsafe {
        crate::thread::sched::getparam(a[0] as i32, a[1] as *mut i32)
    }),
    (Syscall::N_sched_setscheduler, |_, a| unsafe {
        crate::thread::sched::setscheduler_param(a[0] as i32, Some(a[1] as i32), a[2] as *const i32)
    }),
    (Syscall::N_sched_getscheduler, |_, a| {
        crate::thread::sched::getscheduler(a[0] as i32)
    }),
    (Syscall::N_sched_get_priority_max, |_, a| {
        crate::thread::sched::priority_bound(a[0] as i32, true)
    }),
    (Syscall::N_sched_get_priority_min, |_, a| {
        crate::thread::sched::priority_bound(a[0] as i32, false)
    }),
    (Syscall::N_sched_rr_get_interval, |_, a| unsafe {
        crate::thread::sched::rr_interval(a[0] as i32, a[1] as *mut Timespec)
    }),
    (Syscall::N_sched_setattr, |_, a| unsafe {
        crate::thread::sched::setattr(a[0] as i32, a[1] as *mut u8, a[2] as u32)
    }),
    (Syscall::N_sched_getattr, |_, a| unsafe {
        crate::thread::sched::getattr(a[0] as i32, a[1] as *mut u8, a[2] as u32, a[3] as u32)
    }),
    (Syscall::N_sched_setaffinity, |_, a| unsafe {
        crate::thread::sched::setaffinity(a[0] as i32, a[1] as u32, a[2] as *const u8)
    }),
    (Syscall::N_sched_getaffinity, |_, a| unsafe {
        crate::thread::sched::getaffinity(a[0] as i32, a[1] as u32, a[2] as *mut u8)
    }),
    (Syscall::N_getcpu, |_, a| unsafe {
        crate::thread::sched::getcpu(a[0] as *mut u32, a[1] as *mut u32)
    }),
    (Syscall::N_ioprio_set, |_, a| {
        crate::thread::sched::ioprio_set(a[0] as i32, a[1] as i32, a[2] as i32)
    }),
    (Syscall::N_ioprio_get, |_, a| {
        crate::thread::sched::ioprio_get(a[0] as i32, a[1] as i32)
    }),
    (Syscall::N_nanosleep, |_, a| {
        sys_nanosleep(a[0] as *const Timespec, a[1] as *mut Timespec)
    }),
    (Syscall::N_clock_nanosleep, |_, a| {
        sys_clock_nanosleep(a[0], a[1], a[2] as *const Timespec, a[3] as *mut Timespec)
    }),
    // ---- sync / sched / identity / entropy ----
    (Syscall::N_futex, |_, a| sys_futex(a)),
    (Syscall::N_futex_wait, |_, a| {
        crate::thread::futex2::futex_wait(a)
    }),
    (Syscall::N_futex_wake, |_, a| {
        crate::thread::futex2::futex_wake(a)
    }),
    (Syscall::N_futex_requeue, |_, a| {
        crate::thread::futex2::futex_requeue(a)
    }),
    (Syscall::N_futex_waitv, |_, a| {
        crate::thread::futex2::futex_waitv(a)
    }),
    (Syscall::N_getrandom, |_, a| sys_getrandom(a[0], a[1], a[2])),
    // SAFETY: plain runtime entry, no pointers.
    (Syscall::N_sched_yield, |_, _| {
        ret_i32(unsafe { patina_sched_yield() })
    }),
    // SAFETY: as above.
    (Syscall::N_gettid, |_, _| unsafe {
        patina_thread_id() as i64
    }),
    (Syscall::N_set_tid_address, |_, a| unsafe {
        patina_set_tid_address(a[0] as *mut i32)
    }),
    (Syscall::N_exit, |_, a| unsafe {
        patina_raw_exit(a[0] as c_int)
    }),
    (Syscall::N_exit_group, |_, a| unsafe {
        patina_raw_exit_group(a[0] as c_int)
    }),
    // ---- memory: the mapping rows go through the one mapping model (a file
    // mapping is a view of the file's page cache); the rest is process-local
    // and passed through to the host kernel via the glibc `syscall(2)` HOST
    // ALIAS (never the interposed `syscall`).
    (Syscall::N_mmap, |_, a| sys_mmap(a)),
    (Syscall::N_munmap, |_, a| sys_munmap(a)),
    (Syscall::N_mremap, |_, a| sys_mremap(a)),
    (Syscall::N_msync, |_, a| sys_msync(a)),
    (Syscall::N_mprotect, |_, a| sys_mprotect(a)),
    (Syscall::N_pkey_mprotect, |_, a| sys_pkey_mprotect(a)),
    (Syscall::N_pkey_alloc, |_, a| sys_pkey_alloc(a)),
    (Syscall::N_pkey_free, |_, a| sys_pkey_free(a)),
    (Syscall::N_map_shadow_stack, |_, a| sys_map_shadow_stack(a)),
    (Syscall::N_madvise, mem_passthrough),
    (Syscall::N_brk, mem_passthrough),
    (Syscall::N_mincore, mem_passthrough),
    (Syscall::N_mlock, |_, a| unsafe {
        patina_mlock(a[0] as usize, a[1] as usize, 0)
    }),
    (Syscall::N_mlock2, |_, a| unsafe {
        patina_mlock(a[0] as usize, a[1] as usize, a[2] as u32)
    }),
    (Syscall::N_munlock, |_, a| unsafe {
        patina_munlock(a[0] as usize, a[1] as usize)
    }),
    (Syscall::N_mlockall, |_, a| unsafe {
        patina_mlockall(a[0] as c_int)
    }),
    (Syscall::N_munlockall, |_, _| unsafe { patina_munlockall() }),
    // ---- resource limits: the virtual kernel's (`crate::mem`) ----
    (Syscall::N_getrlimit, |_, a| sys_getrlimit(a[0], a[1])),
    (Syscall::N_setrlimit, |_, a| sys_setrlimit(a[0], a[1])),
    (Syscall::N_prlimit64, |_, a| unsafe {
        patina_prlimit(a[0] as c_int, a[1] as u32, a[2] as *const _, a[3] as *mut _)
    }),
    (Syscall::N_remap_file_pages, mem_passthrough),
    (Syscall::N_memfd_create, |_, a| unsafe {
        ret_i32(patina_memfd_create(a[0] as *const c_char, a[1] as u32))
    }),
    (Syscall::N_memfd_secret, |_, a| unsafe {
        ret_i32(patina_memfd_secret(a[0] as u32))
    }),
    // ---- System V IPC: the one-process model (`thread::ipc`) ----
    (Syscall::N_shmget, |_, a| {
        crate::thread::ipc::shmget(a[0] as i32, a[1] as usize, a[2] as i32)
    }),
    (Syscall::N_shmat, |_, a| {
        crate::thread::ipc::shmat(a[0] as i32, a[1] as usize, a[2] as i32)
    }),
    (Syscall::N_shmdt, |_, a| {
        crate::thread::ipc::shmdt(a[0] as usize)
    }),
    (Syscall::N_shmctl, |_, a| unsafe {
        crate::thread::ipc::shmctl(a[0] as i32, a[1] as i32, a[2] as *mut _)
    }),
    (Syscall::N_semget, |_, a| {
        crate::thread::ipc::semget(a[0] as i32, a[1] as i32, a[2] as i32)
    }),
    (Syscall::N_semop, |_, a| unsafe {
        crate::thread::ipc::semtimedop(
            a[0] as i32,
            a[1] as *const _,
            a[2] as usize,
            std::ptr::null(),
        )
    }),
    (Syscall::N_semtimedop, |_, a| unsafe {
        crate::thread::ipc::semtimedop(
            a[0] as i32,
            a[1] as *const _,
            a[2] as usize,
            a[3] as *const _,
        )
    }),
    (Syscall::N_semctl, |_, a| unsafe {
        crate::thread::ipc::semctl(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize)
    }),
    (Syscall::N_msgget, |_, a| {
        crate::thread::ipc::msgget(a[0] as i32, a[1] as i32)
    }),
    (Syscall::N_msgsnd, |_, a| unsafe {
        crate::thread::ipc::msgsnd(a[0] as i32, a[1] as *const u8, a[2] as usize, a[3] as i32)
    }),
    (Syscall::N_msgrcv, |_, a| unsafe {
        crate::thread::ipc::msgrcv(
            a[0] as i32,
            a[1] as *mut u8,
            a[2] as usize,
            a[3] as i64,
            a[4] as i32,
        )
    }),
    (Syscall::N_msgctl, |_, a| unsafe {
        crate::thread::ipc::msgctl(a[0] as i32, a[1] as i32, a[2] as *mut _)
    }),
    // ---- POSIX message queues: the one-process model (`thread::ipc`) ----
    (Syscall::N_mq_open, |_, a| unsafe {
        crate::thread::ipc::mq_open(
            a[0] as *const c_char,
            a[1] as i32,
            a[2] as u32,
            a[3] as *const _,
        )
    }),
    (Syscall::N_mq_unlink, |_, a| unsafe {
        crate::thread::ipc::mq_unlink(a[0] as *const c_char)
    }),
    (Syscall::N_mq_timedsend, |_, a| unsafe {
        crate::thread::ipc::mq_timedsend(
            arg_fd(a[0]) as c_int,
            a[1] as *const u8,
            a[2] as usize,
            a[3] as u32,
            a[4] as *const _,
        )
    }),
    (Syscall::N_mq_timedreceive, |_, a| unsafe {
        crate::thread::ipc::mq_timedreceive(
            arg_fd(a[0]) as c_int,
            a[1] as *mut u8,
            a[2] as usize,
            a[3] as *mut u32,
            a[4] as *const _,
        )
    }),
    (Syscall::N_mq_notify, |_, a| unsafe {
        crate::thread::ipc::mq_notify(arg_fd(a[0]) as c_int, a[1] as *const _)
    }),
    (Syscall::N_mq_getsetattr, |_, a| unsafe {
        crate::thread::ipc::mq_getsetattr(arg_fd(a[0]) as c_int, a[1] as *const _, a[2] as *mut _)
    }),
    // ---- memory policy on the one memory node (`crate::numa`) ----
    (Syscall::N_set_mempolicy, |_, a| unsafe {
        crate::numa::set_mempolicy(a[0] as i32, a[1] as *const u64, a[2])
    }),
    (Syscall::N_get_mempolicy, |_, a| unsafe {
        crate::numa::get_mempolicy(
            a[0] as *mut i32,
            a[1] as *mut u64,
            a[2],
            a[3] as usize,
            a[4],
        )
    }),
    (Syscall::N_mbind, |_, a| unsafe {
        crate::numa::mbind(
            a[0] as usize,
            a[1] as usize,
            a[2] as i32,
            a[3] as *const u64,
            a[4],
            a[5] as u32,
        )
    }),
    (Syscall::N_move_pages, |_, a| unsafe {
        crate::numa::move_pages(
            a[0] as i32,
            a[1] as usize,
            a[2] as *const usize,
            a[3] as *const i32,
            a[4] as *mut i32,
            a[5] as i32,
        )
    }),
    (Syscall::N_migrate_pages, |_, a| unsafe {
        crate::numa::migrate_pages(a[0] as i32, a[1], a[2] as *const u64, a[3] as *const u64)
    }),
    (Syscall::N_set_mempolicy_home_node, |_, a| {
        crate::numa::set_mempolicy_home_node(a[0] as usize, a[1] as usize, a[2], a[3])
    }),
    (Syscall::N_membarrier, |_, a| {
        crate::mem::membarrier(a[0] as c_int, a[1] as u32, a[2] as c_int)
    }),
    // ---- signals / process rows owned by the signals conformance family ----
    // `rt_sigaction` for SIGSYS would replace the dispatch handler: fatal.
    (Syscall::N_rt_sigaction, |_, a| unsafe {
        patina_signal_action(
            a[0] as i32,
            a[1] as *const Action,
            a[2] as *mut Action,
            a[3] as usize,
        )
    }),
    (Syscall::N_rt_sigprocmask, |_, a| unsafe {
        patina_signal_mask(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as *mut u64,
            a[3] as usize,
        )
    }),
    // Both vehicles answer a guest's `rt_sigreturn` before dispatch (the
    // SIGSYS handler and the `syscall(2)` entry resume at the host's own
    // `rt_sigreturn` with the guest's stack pointer, `c/posix/init.c`): it
    // changes control flow, which no return value can.
    (Syscall::N_rt_sigreturn, |nr, _| {
        crate::trap_fatal(&format!(
            "rt_sigreturn (nr {nr}) reached the dispatcher: both vehicles answer it first"
        ))
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_arch_prctl, thread_pointer::sys_arch_prctl),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_modify_ldt, thread_pointer::sys_modify_ldt),
    (Syscall::N_set_robust_list, |_, a| {
        crate::thread::registrations::set_robust_list(a[0] as usize, a[1] as usize)
    }),
    (Syscall::N_pidfd_open, |_, a| {
        pidfd::sys_pidfd_open(a[0], a[1])
    }),
    (Syscall::N_pidfd_getfd, |nr, a| {
        privileged::answer(nr, privileged::pidfd_getfd, a)
    }),
    (Syscall::N_pidfd_send_signal, |_, a| {
        pidfd::sys_pidfd_send_signal(a)
    }),
    (Syscall::N_process_mrelease, |_, a| {
        pidfd::sys_process_mrelease(a[0], a[1])
    }),
    (Syscall::N_process_madvise, |nr, a| {
        privileged::answer(nr, privileged::process_madvise, a)
    }),
    (Syscall::N_process_vm_readv, |nr, a| {
        privileged::answer(nr, privileged::process_vm_readv, a)
    }),
    (Syscall::N_process_vm_writev, |nr, a| {
        privileged::answer(nr, privileged::process_vm_writev, a)
    }),
    (Syscall::N_rseq, |_, a| {
        crate::thread::registrations::rseq(a[0] as usize, a[1] as u32, a[2] as i32, a[3] as u32)
    }),
    (Syscall::N_get_robust_list, |nr, a| {
        privileged::answer(nr, privileged::get_robust_list, a)
    }),
    (Syscall::N_kcmp, |nr, a| {
        privileged::answer(nr, privileged::kcmp, a)
    }),
    // No restart block is ever pending (the registry row says why).
    (Syscall::N_restart_syscall, |_, _| -EINTR),
    (Syscall::N_rt_sigpending, |_, a| unsafe {
        patina_signal_pending(a[0] as *mut u8, a[1] as usize)
    }),
    (Syscall::N_sigaltstack, |_, a| unsafe {
        patina_signal_altstack(a[0] as *const Stack, a[1] as *mut Stack)
    }),
    (Syscall::N_tkill, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: None,
                tid: a[0] as i32,
            },
            a[1] as i32,
            GenerationInfo::Thread,
        )
    }),
    (Syscall::N_rt_sigqueueinfo, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Process { pid: a[0] as i32 },
            a[1] as i32,
            GenerationInfo::Queued(a[2] as *const Info),
        )
    }),
    (Syscall::N_rt_tgsigqueueinfo, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(a[0] as i32),
                tid: a[1] as i32,
            },
            a[2] as i32,
            GenerationInfo::Queued(a[3] as *const Info),
        )
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_pause, |_, _| unsafe {
        patina_signal_wait(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            8,
            WaitMode::Pause,
        )
    }),
    (Syscall::N_rt_sigsuspend, |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            std::ptr::null_mut(),
            std::ptr::null(),
            a[1] as usize,
            WaitMode::Suspend,
        )
    }),
    (Syscall::N_rt_sigtimedwait, |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            a[1] as *mut Info,
            a[2] as *const crate::thread::signals::Timespec,
            a[3] as usize,
            WaitMode::Dequeue,
        )
    }),
    (Syscall::N_kill, |_, a| sys_kill(a[0] as i64, a[1] as i64)),
    (Syscall::N_tgkill, |_, a| {
        sys_tgkill(a[0] as i64, a[1] as i64, a[2] as i64)
    }),
    (Syscall::N_wait4, |_, a| sys_wait4(a[0], a[2])),
    (Syscall::N_waitid, |_, a| sys_waitid(a[0], a[1], a[3])),
    (Syscall::N_getpgid, |_, a| {
        crate::identity::getpgid(a[0] as i32)
    }),
    (Syscall::N_getsid, |_, a| {
        crate::identity::getsid(a[0] as i32)
    }),
    // ---- fd I/O ----
    (Syscall::N_read, |_, a| sys_read(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_write, |_, a| sys_write(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_close, |_, a| sys_close(arg_fd(a[0]))),
    (Syscall::N_lseek, |_, a| {
        sys_lseek(arg_fd(a[0]), a[1] as i64, a[2])
    }),
    (Syscall::N_pread64, |_, a| {
        sys_pread(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    (Syscall::N_pwrite64, |_, a| {
        sys_pwrite(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    (Syscall::N_readv, |_, a| {
        sys_readv(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_writev, |_, a| {
        sys_writev(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_preadv, |_, a| {
        sys_preadv(arg_fd(a[0]), a[1], a[2], a[3] as i64, 0)
    }),
    (Syscall::N_pwritev, |_, a| {
        sys_pwritev(arg_fd(a[0]), a[1], a[2], a[3] as i64, 0)
    }),
    (Syscall::N_preadv2, |_, a| {
        sys_preadv2(arg_fd(a[0]), a[1], a[2], a[3] as i64, a[5])
    }),
    (Syscall::N_pwritev2, |_, a| {
        sys_pwritev2(arg_fd(a[0]), a[1], a[2], a[3] as i64, a[5])
    }),
    (Syscall::N_fsync, |_, a| sys_fsync(arg_fd(a[0]))),
    (Syscall::N_fdatasync, |_, a| sys_fsync(arg_fd(a[0]))),
    (Syscall::N_ftruncate, |_, a| {
        sys_ftruncate(arg_fd(a[0]), a[1] as i64)
    }),
    (Syscall::N_fallocate, |_, a| {
        sys_fallocate(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64)
    }),
    (Syscall::N_flock, |_, a| {
        sys_flock(arg_fd(a[0]), a[1] as i64)
    }),
    (Syscall::N_dup, |_, a| sys_dup(arg_fd(a[0]))),
    (Syscall::N_dup3, |_, a| {
        sys_dup3(arg_fd(a[0]), arg_fd(a[1]), a[2])
    }),
    (Syscall::N_close_range, |_, a| {
        sys_close_range(a[0], a[1], a[2])
    }),
    (Syscall::N_fcntl, |_, a| sys_fcntl(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_ioctl, |_, a| sys_ioctl(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_pipe2, |_, a| sys_pipe2(a[0], a[1])),
    // ---- filesystem ----
    (Syscall::N_openat, |_, a| {
        sys_openat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_openat2, |_, a| {
        sys_openat2(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_fstat, |_, a| sys_fstat(arg_fd(a[0]), a[1])),
    (Syscall::N_newfstatat, |_, a| {
        sys_newfstatat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_statx, |_, a| {
        sys_statx(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_statfs, |_, a| sys_statfs(a[0], a[1])),
    (Syscall::N_name_to_handle_at, |_, a| {
        sys_name_to_handle_at(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    // ---- extended attributes ----
    (Syscall::N_getxattr, |_, a| {
        sys_getxattr(a[0], a[1], a[2], a[3], true)
    }),
    (Syscall::N_lgetxattr, |_, a| {
        sys_getxattr(a[0], a[1], a[2], a[3], false)
    }),
    (Syscall::N_fgetxattr, |_, a| {
        sys_fgetxattr(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_listxattr, |_, a| {
        sys_listxattr(a[0], a[1], a[2], true)
    }),
    (Syscall::N_llistxattr, |_, a| {
        sys_listxattr(a[0], a[1], a[2], false)
    }),
    (Syscall::N_flistxattr, |_, a| {
        sys_flistxattr(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_setxattr, |_, a| {
        sys_setxattr(a[0], a[1], a[2], a[3], a[4], true)
    }),
    (Syscall::N_lsetxattr, |_, a| {
        sys_setxattr(a[0], a[1], a[2], a[3], a[4], false)
    }),
    (Syscall::N_fsetxattr, |_, a| {
        sys_fsetxattr(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_removexattr, |_, a| {
        sys_removexattr(a[0], a[1], true)
    }),
    (Syscall::N_lremovexattr, |_, a| {
        sys_removexattr(a[0], a[1], false)
    }),
    (Syscall::N_fremovexattr, |_, a| {
        sys_fremovexattr(arg_fd(a[0]), a[1])
    }),
    // ---- in-kernel copies ----
    // SAFETY (all five): the pointers are the guest's per each row's contract.
    (Syscall::N_copy_file_range, |_, a| {
        ret_isize(unsafe {
            patina_copy_file_range(
                arg_fd(a[0]) as c_int,
                a[1] as *mut i64,
                arg_fd(a[2]) as c_int,
                a[3] as *mut i64,
                a[4] as usize,
                a[5] as u32,
            )
        })
    }),
    (Syscall::N_sendfile, |_, a| {
        ret_isize(unsafe {
            patina_sendfile(
                arg_fd(a[0]) as c_int,
                arg_fd(a[1]) as c_int,
                a[2] as *mut i64,
                a[3] as usize,
            )
        })
    }),
    (Syscall::N_splice, |_, a| {
        ret_isize(unsafe {
            patina_splice(
                arg_fd(a[0]) as c_int,
                a[1] as *mut i64,
                arg_fd(a[2]) as c_int,
                a[3] as *mut i64,
                a[4] as usize,
                a[5] as u32,
            )
        })
    }),
    (Syscall::N_tee, |_, a| {
        ret_isize(unsafe {
            patina_tee(
                arg_fd(a[0]) as c_int,
                arg_fd(a[1]) as c_int,
                a[2] as usize,
                a[3] as u32,
            )
        })
    }),
    (Syscall::N_vmsplice, |_, a| {
        ret_isize(unsafe {
            patina_vmsplice(
                arg_fd(a[0]) as c_int,
                a[1] as *const c_void,
                a[2] as i64,
                a[3] as u32,
            )
        })
    }),
    // ---- page-cache advice and writeback ----
    // SAFETY (all five): plain runtime entries with no pointers.
    (Syscall::N_sync, |_, _| ret_i32(unsafe { patina_sync() })),
    (Syscall::N_syncfs, |_, a| {
        ret_i32(unsafe { patina_syncfs(arg_fd(a[0]) as c_int) })
    }),
    (Syscall::N_sync_file_range, |_, a| {
        ret_i32(unsafe {
            patina_sync_file_range(arg_fd(a[0]) as c_int, a[1] as i64, a[2] as i64, a[3] as u32)
        })
    }),
    (Syscall::N_readahead, |_, a| {
        ret_i32(unsafe { patina_readahead(arg_fd(a[0]) as c_int, a[1] as i64, a[2] as usize) })
    }),
    (Syscall::N_fadvise64, |_, a| {
        ret_i32(unsafe {
            patina_fadvise(
                arg_fd(a[0]) as c_int,
                a[1] as i64,
                a[2] as i64,
                a[3] as c_int,
            )
        })
    }),
    (Syscall::N_fstatfs, |_, a| sys_fstatfs(arg_fd(a[0]), a[1])),
    (Syscall::N_getdents64, |_, a| {
        sys_getdents64(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_mkdirat, |_, a| {
        sys_mkdirat(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_mknodat, |_, a| {
        sys_mknodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_unlinkat, |_, a| {
        sys_unlinkat(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_symlinkat, |_, a| {
        sys_symlinkat(a[0], arg_fd(a[1]), a[2])
    }),
    (Syscall::N_readlinkat, |_, a| {
        sys_readlinkat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_linkat, |_, a| {
        sys_linkat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    (Syscall::N_renameat, |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], 0)
    }),
    (Syscall::N_renameat2, |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    // `faccessat` carries no flags in the kernel ABI; `faccessat2` adds them.
    // rustix tries `faccessat2` first and falls back to `faccessat` on ENOSYS,
    // so BOTH are routed — a soft deny on `faccessat2` would print its
    // diagnostic on every `..` component a capability-based guest walks.
    (Syscall::N_faccessat, |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_faccessat2, |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // The working directory and the umask: process state the shim keeps, the
    // same state the C getcwd/chdir/fchdir/umask interposers use.
    (Syscall::N_getcwd, |_, a| sys_getcwd(a[0], a[1])),
    (Syscall::N_chdir, |_, a| sys_chdir(a[0])),
    (Syscall::N_fchdir, |_, a| sys_fchdir(arg_fd(a[0]))),
    (Syscall::N_umask, |_, a| sys_umask(a[0])),
    // Same shape for `fchmodat`/`fchmodat2`.
    (Syscall::N_fchmod, |_, a| sys_fchmod(arg_fd(a[0]), a[1])),
    (Syscall::N_fchmodat, |_, a| {
        sys_fchmodat(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_fchmodat2, |_, a| {
        sys_fchmodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // Timestamps, ownership and sizes: the same `patina_*` entries the C
    // utimensat/chown/truncate families call.
    (Syscall::N_utimensat, |_, a| {
        sys_utimensat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_fchownat, |_, a| {
        sys_fchownat(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_fchown, |_, a| {
        sys_fchown(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_truncate, |_, a| sys_truncate(a[0], a[1] as i64)),
    // ---- network: the shared socket entries, argument for argument ----
    (Syscall::N_socket, |_, a| sys_socket(a[0], a[1], a[2])),
    (Syscall::N_socketpair, |_, a| {
        sys_socketpair(a[0], a[1], a[2], a[3])
    }),
    (Syscall::N_bind, |_, a| sys_bind(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_listen, |_, a| sys_listen(arg_fd(a[0]), a[1])),
    (Syscall::N_connect, |_, a| {
        sys_connect(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_accept, |_, a| {
        sys_accept(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_accept4, |_, a| {
        sys_accept(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_sendto, |_, a| {
        sys_sendto(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5])
    }),
    (Syscall::N_recvfrom, |_, a| {
        sys_recvfrom(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5])
    }),
    (Syscall::N_sendmsg, |_, a| {
        sys_sendmsg(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_recvmsg, |_, a| {
        sys_recvmsg(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_sendmmsg, |_, a| {
        sys_sendmmsg(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_recvmmsg, |_, a| {
        sys_recvmmsg(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_shutdown, |_, a| sys_shutdown(arg_fd(a[0]), a[1])),
    (Syscall::N_getsockname, |_, a| {
        sys_name(arg_fd(a[0]), a[1], a[2], false)
    }),
    (Syscall::N_getpeername, |_, a| {
        sys_name(arg_fd(a[0]), a[1], a[2], true)
    }),
    (Syscall::N_setsockopt, |_, a| {
        sys_setsockopt(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_getsockopt, |_, a| {
        sys_getsockopt(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    // ---- readiness ----
    (Syscall::N_epoll_create1, |_, a| sys_epoll_create1(a[0])),
    (Syscall::N_epoll_ctl, |_, a| {
        sys_epoll_ctl(arg_fd(a[0]), a[1] as i64, arg_fd(a[2]), a[3])
    }),
    (Syscall::N_epoll_pwait, |_, a| {
        sys_epoll_pwait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64, a[4], a[5])
    }),
    (Syscall::N_epoll_pwait2, |_, a| {
        sys_epoll_pwait2(arg_fd(a[0]), a[1], a[2] as i64, a[3], a[4], a[5])
    }),
    (Syscall::N_eventfd2, |_, a| sys_eventfd2(a[0], a[1] as i64)),
    (Syscall::N_ppoll, |_, a| {
        sys_ppoll(a[0], a[1], a[2], a[3], a[4])
    }),
    // ---- process: the ONLY prctl option routed is PR_GET_AUXV ----
    (Syscall::N_prctl, |_, a| {
        sys_prctl(a[0], a[1], a[2], a[3], a[4])
    }),
    // ---- x86_64 legacy aliases (route to the SAME modern handler) ----
    // rustix's linux_raw backend and hand-written asm reach for the legacy
    // non-`*at` forms on x86_64; each is exactly its modern form with dirfd =
    // AT_FDCWD (and, for `creat`, synthesized flags). Only the x86_64 table
    // lists these rows, so their identities, and these bindings, exist only
    // there; the ones with a decode of their own bind a handler from
    // `x86_64.rs`.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_open, |_, a| {
        sys_openat(AT_FDCWD, a[0], a[1], a[2])
    }),
    // `creat(path, mode)` is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`: the
    // mode is the SECOND argument here, not the third.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_creat, |_, a| {
        sys_openat(AT_FDCWD, a[0], O_CREAT | O_WRONLY | O_TRUNC, a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_stat, |_, a| {
        sys_newfstatat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_lstat, |_, a| {
        sys_newfstatat(AT_FDCWD, a[0], a[1], AT_SYMLINK_NOFOLLOW)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_unlink, |_, a| sys_unlinkat(AT_FDCWD, a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_rmdir, |_, a| {
        sys_unlinkat(AT_FDCWD, a[0], AT_REMOVEDIR)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_mkdir, |_, a| sys_mkdirat(AT_FDCWD, a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_mknod, |_, a| {
        sys_mknodat(AT_FDCWD, a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_rename, |_, a| {
        sys_renameat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_link, |_, a| {
        sys_linkat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_symlink, |_, a| {
        sys_symlinkat(a[0], AT_FDCWD, a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_readlink, |_, a| {
        sys_readlinkat(AT_FDCWD, a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_access, |_, a| {
        sys_faccessat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_chmod, |_, a| {
        sys_fchmodat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_chown, |_, a| {
        sys_fchownat(AT_FDCWD, a[0], a[1], a[2], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_lchown, |_, a| {
        sys_fchownat(AT_FDCWD, a[0], a[1], a[2], AT_SYMLINK_NOFOLLOW)
    }),
    // The pre-utimensat time rows: whole seconds (`utime`), microseconds
    // (`utimes`, `futimesat`), each decoded onto the one set-times entry.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_utime, |_, a| sys_utime(a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_utimes, |_, a| {
        sys_futimesat(AT_FDCWD, a[0], a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_futimesat, |_, a| {
        sys_futimesat(arg_fd(a[0]), a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_dup2, |_, a| sys_dup2(arg_fd(a[0]), arg_fd(a[1]))),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_ustat, |_, a| sys_ustat(a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_sysfs, |_, a| {
        crate::volume::sysfs(a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_getdents, |_, a| {
        sys_getdents(arg_fd(a[0]), a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_pipe, |_, a| sys_pipe2(a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_eventfd, |_, a| sys_eventfd2(a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_epoll_create, |_, a| sys_epoll_create(a[0])),
    // `epoll_wait` is `epoll_pwait` with no signal mask, in the kernel too.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_epoll_wait, |_, a| {
        sys_epoll_pwait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64, 0, 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_poll, |_, a| {
        sys_poll(a[0], a[1], a[2] as i32 as i64)
    }),
];

/// "No row" / "no binding" sentinel in the dispatch index.
const NONE: u16 = u16::MAX;
/// The dispatch index covers numbers below this bound; the vendored tables top
/// out well under it (x86_64 at 472), and a number at or above it is answered
/// as "not in the vendored table" without consulting the index.
const INDEX_LEN: usize = 1024;

/// The compile-time dispatch index for this arch: number → row, row → binding.
struct Dispatch {
    row_for_nr: [u16; INDEX_LEN],
    binding_for_row: [u16; SYSCALLS.len()],
}

const DISPATCH: Dispatch = build_dispatch();

/// Build [`DISPATCH`] from the registry rows for the host arch. Every check
/// here is a compile error, which is what makes the registry the single source
/// of dispatch: a row cannot claim `Modeled` without a handler, a `Trap` row
/// cannot carry one, and a binding cannot name a row that does not exist.
const fn build_dispatch() -> Dispatch {
    let mut row_for_nr = [NONE; INDEX_LEN];
    let mut binding_for_row = [NONE; SYSCALLS.len()];
    let mut i = 0;
    while i < SYSCALLS.len() {
        let row = &SYSCALLS[i];
        let mut bound = NONE;
        let mut j = 0;
        while j < BINDINGS.len() {
            if BINDINGS[j].0 as usize == row.id as usize {
                if bound != NONE {
                    panic!("a registry row has two handler bindings in sud::BINDINGS");
                }
                bound = j as u16;
            }
            j += 1;
        }
        if row.disposition.is_routed() && bound == NONE {
            panic!("a Modeled/Passthrough registry row has no handler binding in sud::BINDINGS");
        }
        if !row.disposition.may_bind() && bound != NONE {
            panic!("a Trap/Absent registry row has a handler binding in sud::BINDINGS");
        }
        binding_for_row[i] = bound;
        {
            let nr = row.id.number();
            let nr = nr as usize;
            if nr >= INDEX_LEN {
                panic!("a registry row's syscall number exceeds sud::INDEX_LEN");
            }
            if row_for_nr[nr] != NONE {
                panic!("two registry rows share a syscall number on this arch");
            }
            row_for_nr[nr] = i as u16;
        }
        i += 1;
    }
    let mut j = 0;
    while j < BINDINGS.len() {
        let mut found = false;
        let mut i = 0;
        while i < SYSCALLS.len() {
            if SYSCALLS[i].id as usize == BINDINGS[j].0 as usize {
                found = true;
            }
            i += 1;
        }
        if !found {
            panic!("a sud::BINDINGS entry names a syscall that has no registry row");
        }
        j += 1;
    }
    Dispatch {
        row_for_nr,
        binding_for_row,
    }
}

/// The registry row a number resolves to on this arch, if the vendored table
/// lists it.
fn row_for(nr: i64) -> Option<(usize, &'static SyscallRow)> {
    let index = usize::try_from(nr).ok().filter(|nr| *nr < INDEX_LEN)?;
    let row = DISPATCH.row_for_nr[index];
    (row != NONE).then(|| (row as usize, &SYSCALLS[row as usize]))
}

fn dispatch(nr: i64, args: [u64; 6]) -> i64 {
    let Some((index, row)) = row_for(nr) else {
        return not_in_table(nr, args);
    };
    let binding = DISPATCH.binding_for_row[index];
    let bound = (binding != NONE).then(|| BINDINGS[binding as usize].1);
    match (row.disposition, bound) {
        (Disposition::Modeled | Disposition::Passthrough, Some(handler)) => handler(nr, args),
        // A routed row always has a binding: `build_dispatch` refused to compile
        // otherwise. Unreachable by construction, and still a loud abort rather
        // than a silent answer if that ever stopped being true.
        (Disposition::Modeled | Disposition::Passthrough, None) => {
            crate::trap_fatal("SUD dispatch: a routed registry row has no handler binding")
        }
        // A bound handler answers a constant/soft-deny row (it may print the
        // shared deny diagnostic first); an unbound one is answered from the row.
        (Disposition::Constant(_) | Disposition::SoftDeny(_), Some(handler)) => handler(nr, args),
        (Disposition::Constant(value), None) => value,
        (Disposition::SoftDeny(errno), None) => -(errno as i64),
        (Disposition::Trap(class), _) => trap_row(row, class, nr, args),
        (Disposition::Absent, _) => -ENOSYS,
    }
}

/// A number the registry dispositions as a named, deterministic abort. The
/// diagnostic carries the row's name, class, and reasoning, so the guest's
/// stderr says exactly why the number is excluded and what closes it.
fn trap_row(row: &SyscallRow, class: &str, nr: i64, args: [u64; 6]) -> i64 {
    let closes = match row.closes_in {
        Some(arc) => format!(" Closes in the {arc} arc."),
        None => String::new(),
    };
    crate::trap_fatal(&format!(
        "SUD trapped unsupported syscall {} (nr {nr}, class {class}; args {:#x} {:#x} {:#x} {:#x} \
         {:#x} {:#x}): {}{closes} Guest raw syscalls must map to a deterministic route; `cargo \
         patina syscalls` lists every row",
        row.name, args[0], args[1], args[2], args[3], args[4], args[5], row.reasoning
    ));
}

/// A number the vendored table for this arch does not list at all: either
/// newer than the vendored snapshot (refresh the tables and add its row) or
/// garbage in the syscall register. Distinct from a trapped row, which is a
/// deliberate disposition.
fn not_in_table(nr: i64, args: [u64; 6]) -> i64 {
    crate::trap_fatal(&format!(
        "SUD trapped syscall number {nr}, which is not in the vendored Linux {} syscall table \
         (args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); run scripts/refresh-syscalls.py and \
         add a registry row if the kernel has grown a number, or treat this as a corrupt raw \
         syscall",
        Arch::host().name(),
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The by-name twin of the compile-time checks in `build_dispatch`: the same
    /// three conditions, reported with the offending row/binding named. RED:
    /// plant a `("nonesuch", …)` binding, remove the `read` binding, or bind
    /// `fork`, and the message says which.
    #[test]
    fn bindings_match_the_registry_rows() {
        let mut problems = Vec::new();
        for row in SYSCALLS {
            let bound = BINDINGS.iter().filter(|(name, _)| *name == row.id).count();
            if row.disposition.is_routed() && bound == 0 {
                problems.push(format!(
                    "{}: routed row without a handler binding",
                    row.name
                ));
            }
            if !row.disposition.may_bind() && bound > 0 {
                problems.push(format!(
                    "{}: trap/absent row with a handler binding",
                    row.name
                ));
            }
            if bound > 1 {
                problems.push(format!("{}: bound {bound} times", row.name));
            }
        }
        for (name, _) in BINDINGS {
            if !SYSCALLS.iter().any(|row| row.id == *name) {
                problems.push(format!("{name:?}: binding names no registry row"));
            }
        }
        assert!(
            problems.is_empty(),
            "sud::BINDINGS and registry::SYSCALLS disagree:\n  {}",
            problems.join("\n  ")
        );
        // Every number the vendored table lists for this arch resolves to its row.
        for entry in crate::registry::ENTRIES {
            let (_, row) = row_for(entry.nr as i64).unwrap_or_else(|| {
                panic!("{} ({}) has no dispatch index entry", entry.name, entry.nr)
            });
            assert_eq!(row.name, entry.name);
        }
        assert!(row_for(INDEX_LEN as i64).is_none());
        assert!(row_for(-1).is_none());
    }

    #[test]
    fn arg_fd_reads_int_fds_the_way_the_kernel_does() {
        // The kernel reads fd/dirfd as a 32-bit `int` (low register bits). A
        // caller may sign-extend a negative fd (hand asm) OR zero-extend it
        // (rustix's linux_raw `raw_fd` does `fd as c_uint as usize`): both leave
        // the same low 32 bits, and `arg_fd` must recover the same `int`.
        // RED: reading the raw register as `i64` (the pre-fix behavior) makes the
        // zero-extended cases below large positive numbers, so `AT_FDCWD`
        // miscompares and a rustix `openat(CWD, …)` returns EINVAL.
        assert_eq!(arg_fd(0x0000_0000_FFFF_FF9C), AT_FDCWD); // rustix zero-extended AT_FDCWD
        assert_eq!(arg_fd(0xFFFF_FFFF_FFFF_FF9C), AT_FDCWD); // hand-asm sign-extended AT_FDCWD
        assert_eq!(arg_fd(0x0000_0000_FFFF_FFFF), -1); // zero-extended -1
        assert_eq!(arg_fd(0), 0);
        assert_eq!(arg_fd(5), 5);
        assert_eq!(arg_fd(0x4000_0005), 0x4000_0005);
    }

    #[test]
    fn prctl_option_narrows_to_unsigned_int_like_the_kernel() {
        // The kernel reads `option = (unsigned int) arg`, so only the low 32 bits
        // decide the route. rustix passes a clean 32-bit PR_GET_AUXV; hand asm may
        // sign-/zero-extend. RED: comparing the full 64-bit register would make a
        // sign-extended PR_GET_AUXV (or a high-bit-dirty PR_SET_NAME) miscompare —
        // either wrongly denying the auxv route or wrongly accepting an escape.
        assert_eq!(prctl_option(0x4155_5856), PR_GET_AUXV); // exact
        assert_eq!(prctl_option(0xFFFF_FFFF_4155_5856), PR_GET_AUXV); // dirty high bits ignored
        assert_ne!(prctl_option(15), PR_GET_AUXV); // PR_SET_NAME is denied
        assert_eq!(prctl_option(0x1_0000_000F), 15); // truncation: still PR_SET_NAME (denied)
    }

    #[test]
    fn pr_get_auxv_copy_mirrors_the_kernel_semantics() {
        // A stand-in scrubbed auxv (bytes are irrelevant to the copy math; the
        // real region runs through the AT_NULL pair inclusively).
        let saved: Vec<u8> = (0..48u8).collect();

        // Full copy: user buffer >= auxv. Returns the FULL length, copies it all.
        let mut user = vec![0xAAu8; 512];
        assert_eq!(
            pr_get_auxv_copy(&saved, user.as_mut_ptr(), user.len(), 0, 0),
            48
        );
        assert_eq!(&user[..48], &saved[..]);
        assert!(user[48..].iter().all(|&b| b == 0xAA)); // nothing past the auxv touched

        // Truncated copy: a small user buffer gets a prefix, but the return value
        // is STILL the full auxv length (what rustix uses to size its retry). RED:
        // returning the copied count would break rustix's `assert_eq!(len, buf)`.
        let mut small = vec![0u8; 16];
        assert_eq!(
            pr_get_auxv_copy(&saved, small.as_mut_ptr(), small.len(), 0, 0),
            48
        );
        assert_eq!(&small[..], &saved[..16]);

        // Nonzero arg4 or arg5 ⇒ -EINVAL, and NO bytes are copied.
        let mut untouched = vec![0x5Au8; 64];
        assert_eq!(
            pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 1, 0),
            -EINVAL
        );
        assert_eq!(
            pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 0, 1),
            -EINVAL
        );
        assert!(untouched.iter().all(|&b| b == 0x5A));

        // A zero-length user request copies nothing but still reports the length.
        assert_eq!(pr_get_auxv_copy(&saved, std::ptr::null_mut(), 0, 0, 0), 48);
        // A nonzero request with a null buffer faults (mirrors copy_to_user).
        assert_eq!(
            pr_get_auxv_copy(&saved, std::ptr::null_mut(), 8, 0, 0),
            -EFAULT
        );
    }

    #[test]
    fn creat_synthesizes_create_write_truncate_flags() {
        // The legacy `creat(path, mode)` alias routes to openat with a SYNTHESIZED
        // flag word `O_CREAT | O_WRONLY | O_TRUNC` (creat has no flags argument).
        // That must decode to a writable, creating, truncating open — never a
        // read-only one (which would drop the file's contents differently and
        // fail to create). RED: synthesizing the wrong flags (e.g. O_RDONLY=0)
        // would decode to PATINA_O_READ with no create/truncate bit.
        let flags = openat_patina_flags(O_CREAT | O_WRONLY | O_TRUNC);
        assert_eq!(
            flags,
            PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE,
            "creat must be write+create+truncate"
        );
        // And it must NOT be classified read-only (that gates the directory-fd
        // fallback path in sys_openat).
        let read_only = flags & (PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE) == 0;
        assert!(!read_only, "creat is never a read-only open");

        // A bare `open(path, O_RDONLY)` (the read alias) decodes read-only — this
        // pins the contrast the alias relies on.
        assert_eq!(openat_patina_flags(0), PATINA_O_READ);
    }

    #[test]
    fn socketpair_answers_in_kernel_order() {
        use crate::thread::net::abi::{
            AF_INET, AF_UNIX, EPROTONOSUPPORT, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM,
        };
        let mut sv = [-1i32; 2];
        let at = sv.as_mut_ptr() as u64;
        // `__sys_socketpair`: the creation flags first, then both numbers
        // are written to `sv` before any socket exists, then the family.
        assert_eq!(
            sys_socketpair(AF_UNIX as u64, (SOCK_STREAM | 0x1_0000) as u64, 0, at),
            -EINVAL
        );
        assert_eq!(
            sys_socketpair(AF_INET as u64, SOCK_STREAM as u64, 0, 0),
            -EFAULT
        );
        assert_eq!(
            sys_socketpair(
                AF_UNIX as u64,
                (SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC) as u64,
                6,
                at
            ),
            -i64::from(EPROTONOSUPPORT)
        );
    }

    #[test]
    fn ppoll_validates_buffers_and_descriptor_limit_before_waiting() {
        assert_eq!(sys_ppoll(0, 1, 0, 0, 0), -EFAULT);
        assert_eq!(sys_ppoll(0, 1025, 0, 0, 0), -EINVAL);
        assert_eq!(sys_ppoll(0, 0, 0, 1, 4), -EINVAL);
    }

    #[test]
    fn fcntl_and_ioctl_answer_from_the_descriptor_table() {
        // No runtime is installed here: the descriptor table alone answers, and
        // it holds exactly the three standard numbers. A number that names
        // nothing is EBADF for every command (the kernel checks the number
        // before the command), an unknown command on an open number is EINVAL,
        // and FD_CLOEXEC is per number while F_GETFL/F_SETFL are per
        // description (C parity through the SAME entries).
        assert_eq!(sys_fcntl(5, F_GETFD, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_SETFD, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_GETFL, 0), -EBADF);
        assert_eq!(sys_fcntl(5, F_SETFL, 0), -EBADF);
        assert_eq!(sys_fcntl(5, 0x9999, 0), -EBADF);
        assert_eq!(sys_fcntl(2, 0x9999, 0), -EINVAL);
        assert_eq!(sys_fcntl(0, F_GETFL, 0), 0); // O_RDONLY
        assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        assert_eq!(sys_fcntl(2, F_SETFD, FD_CLOEXEC as u64), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
        assert_eq!(sys_fcntl(2, F_SETFD, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        // F_SETFL changes O_APPEND/O_NONBLOCK and nothing else.
        assert_eq!(sys_fcntl(2, F_SETFL, O_NONBLOCK | O_RDWR), 0);
        assert_eq!(sys_fcntl(2, F_GETFL, 0), (O_WRONLY | O_NONBLOCK) as i64);
        assert_eq!(sys_fcntl(2, F_SETFL, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
        // ioctl: FIOCLEX/FIONCLEX are the FD_CLOEXEC bit; an unknown request is
        // a soft -ENOTTY on an open number and -EBADF on a closed one.
        use crate::ioctl::request::{FIOCLEX, FIONCLEX};
        assert_eq!(sys_ioctl(2, FIOCLEX, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
        assert_eq!(sys_ioctl(2, FIONCLEX, 0), 0);
        assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
        assert_eq!(sys_ioctl(2, 0x1234, 0), -(errno::ENOTTY as i64));
        assert_eq!(sys_ioctl(5, 0x1234, 0), -EBADF);
        assert_eq!(sys_ioctl(5, FIOCLEX, 0), -EBADF);
    }

    #[test]
    fn flag_words_the_kernel_refuses_or_ignores() {
        use uapi::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM, LOCK_MAND, LOCK_SH};
        let mut buf = [0u8; 256];
        let buf = buf.as_mut_ptr() as u64;
        let (insecure, nonblock, random) = (
            u64::from(GRND_INSECURE),
            u64::from(GRND_NONBLOCK),
            u64::from(GRND_RANDOM),
        );
        // getrandom: every bit outside NONBLOCK|RANDOM|INSECURE, and INSECURE
        // with RANDOM, are EINVAL before any byte is drawn; every other
        // combination is accepted (no runtime is installed here, so the
        // accepted side is asked of the rule itself), and a null buffer is
        // EFAULT.
        let unknown = 1 << (insecure | nonblock | random).count_ones();
        assert_eq!(sys_getrandom(buf, 16, unknown), -EINVAL);
        assert_eq!(sys_getrandom(buf, 16, insecure | random), -EINVAL);
        for accepted in [
            0,
            nonblock,
            random,
            insecure,
            nonblock | random,
            nonblock | insecure,
        ] {
            assert!(
                crate::getrandom_flags_accepted(accepted as u32),
                "{accepted:#x}"
            );
        }
        assert_eq!(sys_getrandom(0, 16, 0), -EFAULT);
        // newfstatat/statx: a bit vfs_statx does not accept is EINVAL, before
        // the descriptor is looked at; statx also refuses both sync modes at
        // once and the reserved mask bit.
        let path = c"/x".as_ptr() as u64;
        let bad_fd = -1;
        let unknown_at = !STAT_AT_FLAGS & STAT_AT_FLAGS.wrapping_add(1);
        assert_eq!(sys_newfstatat(bad_fd, path, buf, unknown_at), -EINVAL);
        assert_eq!(sys_statx(bad_fd, path, unknown_at, 0, 0), -EINVAL);
        assert_eq!(sys_statx(bad_fd, path, AT_STATX_SYNC_TYPE, 0, 0), -EINVAL);
        assert_eq!(sys_statx(bad_fd, path, 0, STATX__RESERVED, 0), -EINVAL);
        // flock: LOCK_MAND is answered 0 and ignored before anything else is
        // judged (`fs/locks.c`), so a closed descriptor is 0 too.
        let mand = LOCK_MAND as i64 | LOCK_SH as i64;
        assert_eq!(sys_flock(2, mand), 0);
        assert_eq!(sys_flock(5, mand), 0);
    }

    #[test]
    fn open_flags_decode_with_this_architectures_values() {
        // The flag words a guest's libc hands the kernel, in the libc crate's
        // per-target spelling: x86_64 and arm64 disagree on O_DIRECTORY,
        // O_NOFOLLOW and O_DIRECT, so this oracle is independent of the
        // dispatcher's own constants. RED with x86_64's values on arm64: the
        // directory open is refused as unsupported, and pipe2 reads O_DIRECT as
        // O_DIRECTORY.
        let bits = |flags: libc::c_int| flags as u64;
        let directory =
            bits(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        assert_eq!(directory & !OPENAT_SUPPORTED_FLAGS, 0);
        assert_eq!(
            openat_patina_flags(directory),
            PATINA_O_READ | PATINA_O_DIRECTORY | PATINA_O_NOFOLLOW | PATINA_O_CLOEXEC
        );
        assert_ne!(bits(libc::O_DIRECT) & !OPENAT_SUPPORTED_FLAGS, 0);
        // pipe2 refuses packet mode as unmodeled and any other bit as invalid,
        // both before it creates anything.
        let fds: u64 = 0x1000;
        assert_eq!(sys_pipe2(fds, bits(libc::O_DIRECT)), -ENOSYS);
        assert_eq!(sys_pipe2(fds, bits(libc::O_DIRECTORY)), -EINVAL);
    }

    #[test]
    fn openat_flag_decode_ignores_largefile_directory_cloexec_bits() {
        // rustix ORs O_LARGEFILE into every open, and a directory open
        // adds O_DIRECTORY|O_CLOEXEC. The legacy `open`/`creat` aliases and the
        // direct `openat` share ONE decode (`openat_patina_flags`), so they are
        // bit-for-bit identical — the round-6 EBADF was NOT a flag defect (it was
        // the dir-fd fcntl/openat gap). This pins that: the noise bits never
        // perturb the decode. RED: folding O_LARGEFILE into the access-mode
        // compare, or reacting to O_DIRECTORY, would diverge open from openat.
        // O_CLOEXEC is NOT noise: it is the new number's FD_CLOEXEC bit.
        let noise = O_LARGEFILE | O_DIRECTORY;
        assert_eq!(
            openat_patina_flags(O_RDWR | O_CLOEXEC),
            PATINA_O_READ | PATINA_O_WRITE | PATINA_O_CLOEXEC
        );
        // The round-5 flag word.
        assert_eq!(
            openat_patina_flags(O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE),
            PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE
        );
        // A directory open decodes read-only plus the directory requirement;
        // the ONE open entry decides the descriptor's kind from the entry's,
        // so the bit travels rather than routing here.
        assert_eq!(
            openat_patina_flags(O_DIRECTORY | O_LARGEFILE),
            PATINA_O_READ | PATINA_O_DIRECTORY
        );
        // `O_PATH` opens nothing: the access mode and every creating bit are
        // dropped under it, exactly as the kernel ignores them.
        assert_eq!(
            openat_patina_flags(O_PATH | O_RDWR | O_CREAT | O_CLOEXEC),
            PATINA_O_PATH | PATINA_O_CLOEXEC
        );
        // The noise bits are inert atop any base access/creation flag word.
        for base in [
            0,
            O_WRONLY,
            O_RDWR,
            O_CREAT | O_WRONLY | O_TRUNC,
            O_APPEND | O_WRONLY,
        ] {
            assert_eq!(
                openat_patina_flags(base) | PATINA_O_DIRECTORY,
                openat_patina_flags(base | noise)
            );
        }
    }
}
