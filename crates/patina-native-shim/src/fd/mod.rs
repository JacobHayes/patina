//! Descriptor control, duplication, closing, and operation families.

use crate::*;

mod io;
mod locks;
mod seek;
pub(crate) mod value;

pub use io::*;
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) use locks::flock;
pub use locks::*;
pub use seek::*;
#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) use seek::{fsync, seek, set_len};
pub use value::{patina_close, patina_dup, patina_dup2, patina_dup3, patina_dupfd};

// ---------------------------------------------------------------------------
// The descriptor table's C face. `patina_fd_kind` is the ONE kind oracle the C
// interposers and the SUD rows consult when an answer depends on what a number
// names (a socket op on a file is ENOTSOCK, a `*at` dirfd must be a directory,
// mmap of a pipe is ENODEV); everything else about a descriptor — its
// FD_CLOEXEC bit, its status flags, duplication, closing — is answered here so
// the two doors cannot drift.

/// The `PATINA_FD_*` kind of a guest descriptor, or -1 with `EBADF` for a
/// number that names nothing.
#[unsafe(no_mangle)]
pub extern "C" fn patina_fd_kind(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().kind(raw_fd) {
        Some(kind) => {
            set_errno(0);
            kind.wire()
        }
        None => fail(EBADF),
    }
}

#[unsafe(no_mangle)]
/// `RLIMIT_NOFILE` as the table enforces it — the one number `getrlimit`,
/// `sysconf(_SC_OPEN_MAX)` and the `EMFILE` bound must agree on.
pub extern "C" fn patina_fd_limit() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::try_from(fd_limit()).expect("the descriptor limit fits an int")
}

/// The descriptor table's bound now: the soft `RLIMIT_NOFILE`.
pub(crate) fn fd_limit() -> usize {
    fd_table().lock().limit()
}

/// A new soft `RLIMIT_NOFILE` (`src/limits.rs`), which the table enforces
/// from the next allocation on; descriptors above it stay open.
#[cfg(target_os = "linux")]
pub(crate) fn set_fd_limit(limit: u64) {
    fd_table()
        .lock()
        .set_limit(usize::try_from(limit).unwrap_or(usize::MAX));
}

#[unsafe(no_mangle)]
/// `F_GETFD`: 1 when the number carries `FD_CLOEXEC`, 0 when not, -1/`EBADF`.
pub extern "C" fn patina_fd_getfd(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().cloexec(raw_fd) {
        Ok(cloexec) => {
            set_errno(0);
            c_int::from(cloexec)
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `F_SETFD`: set (nonzero) or clear the number's `FD_CLOEXEC` bit.
pub extern "C" fn patina_fd_setfd(raw_fd: c_int, cloexec: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().set_cloexec(raw_fd, cloexec != 0) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `F_GETFL`: the description's status flags in the `PATINA_O_*` vocabulary
/// (access mode, `O_APPEND`, `O_NONBLOCK`, `O_PATH`), or -1/`EBADF`.
pub extern "C" fn patina_fd_getfl(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match resolve_fd(raw_fd) {
        Ok(resolved) => {
            set_errno(0);
            c_int::try_from(resolved.status).unwrap_or_else(|_| fail(EOVERFLOW))
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `F_SETFL`: replace the description's `O_APPEND`/`O_NONBLOCK` with the bits
/// in `flags` (`PATINA_O_*`); every other bit is ignored, as the kernel ignores
/// the access mode and creation flags in an `F_SETFL` argument.
pub extern "C" fn patina_fd_setfl(raw_fd: c_int, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match fd_table().lock().set_status(raw_fd, O_SETFL_MASK, flags) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
/// `ioctl(FIONBIO)` / `SOCK_NONBLOCK` on accept: set or clear `O_NONBLOCK`
/// alone, leaving the other status flags as they are.
pub extern "C" fn patina_fd_set_nonblocking(raw_fd: c_int, nonblocking: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let bits = if nonblocking != 0 { O_NONBLOCK } else { 0 };
    match fd_table().lock().set_status(raw_fd, O_NONBLOCK, bits) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// Per-NUMBER teardown when a slot is vacated (close, dup2/dup3 over it,
/// close_range): the state the two doors key by guest number rather than by
/// description — the SUD `getdents64` snapshot on Linux, the kqueue knotes
/// (which BSD drops when the NUMBER closes, whatever the file's other
/// references) on macOS.
fn retire_number(raw_fd: c_int) {
    #[cfg(target_os = "linux")]
    crate::sud::release_dir_iteration(raw_fd);
    #[cfg(target_os = "macos")]
    thread::kqueue_forget_number(raw_fd);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = raw_fd;
}

#[unsafe(no_mangle)]
/// `close_range(2)`: close every number in `[first, last]`, or with
/// `CLOSE_RANGE_CLOEXEC` mark them close-on-exec instead. `first > last` or an
/// unknown flag is `EINVAL`; the range is clamped to the table.
pub extern "C" fn patina_close_range(first: u32, last: u32, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let closes = first <= last
        && flags & !(fdtable::CLOSE_RANGE_CLOEXEC | fdtable::CLOSE_RANGE_UNSHARE) == 0
        && flags & fdtable::CLOSE_RANGE_CLOEXEC == 0;
    if closes && thread::locks::process_holds_locks() {
        let last = last.min(patina_fd_limit().max(0) as u32);
        for number in first..=last {
            release_posix_locks(number as c_int);
        }
    }
    let closed = match fd_table().lock().close_range(first, last, flags) {
        Ok(closed) => closed,
        Err(errno) => return fail(errno),
    };
    for (number, release) in closed {
        retire_number(number);
        if let Some(release) = release {
            let _ = release_description(release);
        }
    }
    set_errno(0);
    0
}
