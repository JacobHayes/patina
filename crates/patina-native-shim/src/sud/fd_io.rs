//! SUD rows — descriptor I/O: `read`/`write`/`close`/`lseek`, positional and
//! vectored I/O, `fsync`/`ftruncate`/`flock`, `dup*`/`close_range`,
//! `fcntl`/`ioctl`, `pipe2`. Every row is thin marshaling over the SAME
//! universal `patina_*` entry the C interposer calls: the guest number is
//! resolved once, in that entry, against the shim's descriptor table, and the
//! entry dispatches on what it names — so nothing here (and nothing in the C
//! layer) decides by descriptor class, and the two doors cannot drift.

use super::*;

/// Guard the fd against the negative/oversized values that cannot be Patina
/// virtual descriptors, so the cast into `c_int` never wraps.
pub(super) fn fd_out_of_range(fd: i64) -> Option<i64> {
    if fd < 0 || fd > c_int::MAX as i64 {
        Some(-EBADF)
    } else {
        None
    }
}

pub(super) fn sys_read(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
    ret_isize(unsafe { patina_read(fd as c_int, buf as *mut c_void, count as usize) })
}

pub(super) fn sys_write(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the write(2) contract.
    ret_isize(unsafe { patina_write(fd as c_int, buf as *const c_void, count as usize) })
}

pub(super) fn sys_close(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_close(fd as c_int) })
}

pub(super) fn sys_lseek(fd: i64, offset: i64, whence: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // patina_seek returns the new offset or -1; shape it to the raw convention.
    // SAFETY: no pointers.
    let result = unsafe { patina_seek(fd as c_int, offset, whence as u32) };
    if result < 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result
    }
}

// ---- Positional & vectored I/O ----

pub(super) fn sys_pread(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the pread(2) contract.
    ret_isize(unsafe { patina_pread(fd as c_int, buf as *mut c_void, count as usize, offset) })
}

pub(super) fn sys_pwrite(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the pwrite(2) contract.
    ret_isize(unsafe { patina_pwrite(fd as c_int, buf as *const c_void, count as usize, offset) })
}

/// `readv`/`writev` and the `*v2` rows at position -1: the vector, the
/// descriptor and the transfer are all the one Rust entry the C interposers
/// call (`crate::iov`). `flags` are the `RWF_*` word (0 for the plain rows).
pub(super) fn sys_readv(fd: i64, iov: u64, count: u64, flags: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `iov`/`count` describe the guest's vector per the readv(2) contract.
    ret_isize(unsafe {
        patina_readv(
            fd as c_int,
            iov as *const c_void,
            count as i64,
            flags as i32,
        )
    })
}

pub(super) fn sys_writev(fd: i64, iov: u64, count: u64, flags: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `iov`/`count` describe the guest's vector per the writev(2) contract.
    ret_isize(unsafe {
        patina_writev(
            fd as c_int,
            iov as *const c_void,
            count as i64,
            flags as i32,
        )
    })
}

/// `preadv`/`pwritev` at a position. The kernel splits the position across
/// `pos_l`/`pos_h` and joins them as `pos_h << 64 | pos_l` on a 64-bit kernel,
/// so the low register is the whole position.
pub(super) fn sys_preadv(fd: i64, iov: u64, count: u64, offset: i64, flags: u64) -> i64 {
    // SAFETY: as `sys_readv`.
    ret_isize(unsafe {
        patina_preadv(
            fd as c_int,
            iov as *const c_void,
            count as i64,
            offset,
            flags as i32,
        )
    })
}

pub(super) fn sys_pwritev(fd: i64, iov: u64, count: u64, offset: i64, flags: u64) -> i64 {
    // SAFETY: as `sys_writev`.
    ret_isize(unsafe {
        patina_pwritev(
            fd as c_int,
            iov as *const c_void,
            count as i64,
            offset,
            flags as i32,
        )
    })
}

/// `preadv2`/`pwritev2`: position -1 is the cursor (`readv`/`writev` with the
/// flags); any other position is the positional row.
pub(super) fn sys_preadv2(fd: i64, iov: u64, count: u64, offset: i64, flags: u64) -> i64 {
    if offset == -1 {
        sys_readv(fd, iov, count, flags)
    } else {
        sys_preadv(fd, iov, count, offset, flags)
    }
}

pub(super) fn sys_pwritev2(fd: i64, iov: u64, count: u64, offset: i64, flags: u64) -> i64 {
    if offset == -1 {
        sys_writev(fd, iov, count, flags)
    } else {
        sys_pwritev(fd, iov, count, offset, flags)
    }
}

pub(super) fn sys_fsync(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // A directory fd IS an ordinary deterministic-filesystem fd, so `fsync` on it
    // is the crash model's namespace-durability barrier with no special case.
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_fsync(fd as c_int) })
}

pub(super) fn sys_ftruncate(fd: i64, length: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    if length < 0 {
        return -EINVAL;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_set_len(fd as c_int, length as u64) })
}

pub(super) fn sys_flock(fd: i64, operation: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_flock(fd as c_int, operation as c_int) })
}

// ---- Duplication and closing ----

pub(super) fn sys_dup(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_dup(fd as c_int) })
}

/// `dup3(2)`: the kernel refuses a flag other than `O_CLOEXEC` before it looks
/// at either descriptor. `newfd` is passed through unclamped so a number outside
/// the table is the entry's `EBADF`, not a wrapped one.
pub(super) fn sys_dup3(oldfd: i64, newfd: i64, flags: u64) -> i64 {
    if flags & !O_CLOEXEC != 0 {
        return -EINVAL;
    }
    if let Some(err) = fd_out_of_range(oldfd) {
        return err;
    }
    let newfd = c_int::try_from(newfd).unwrap_or(-1);
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_dup3(oldfd as c_int, newfd, c_int::from(flags & O_CLOEXEC != 0)) })
}

/// `close_range(2)`: the kernel reads `first`/`last` as unsigned ints.
pub(super) fn sys_close_range(first: u64, last: u64, flags: u64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_close_range(first as u32, last as u32, flags as u32) })
}

// ---- fcntl / ioctl ----

/// The kernel's file-status flags <-> the shim's `PATINA_O_*` status vocabulary,
/// for `F_GETFL`/`F_SETFL` (the C `patina_getfl_to_posix`/`patina_setfl_from_posix`
/// pair, in the Linux spelling).
fn getfl_to_kernel(status: u32) -> i64 {
    let readable = status & PATINA_O_READ != 0;
    let writable = status & PATINA_O_WRITE != 0;
    let mut flags = if readable && writable {
        O_RDWR
    } else if writable {
        O_WRONLY
    } else {
        0
    };
    if status & PATINA_O_APPEND != 0 {
        flags |= O_APPEND;
    }
    if status & PATINA_O_NONBLOCK != 0 {
        flags |= O_NONBLOCK;
    }
    if status & PATINA_O_PATH != 0 {
        flags |= O_PATH;
    }
    if status & PATINA_O_DIRECTORY != 0 {
        flags |= O_DIRECTORY;
    }
    // A 64-bit kernel forces O_LARGEFILE into every open(2)-minted description
    // (fs/open.c build_open_how); the shim's table remembers which those are.
    if status & PATINA_O_OPENED != 0 {
        flags |= O_LARGEFILE;
    }
    flags as i64
}

fn setfl_from_kernel(flags: u64) -> u32 {
    let mut status = 0;
    if flags & O_APPEND != 0 {
        status |= PATINA_O_APPEND;
    }
    if flags & O_NONBLOCK != 0 {
        status |= PATINA_O_NONBLOCK;
    }
    status
}

pub(super) fn sys_fcntl(fd: i64, command: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    match command {
        F_GETFD => {
            // SAFETY: no pointers.
            let cloexec = unsafe { patina_fd_getfd(cfd) };
            if cloexec < 0 {
                return ret_i32(cloexec);
            }
            if cloexec != 0 { FD_CLOEXEC } else { 0 }
        }
        // SAFETY: no pointers.
        F_SETFD => {
            ret_i32(unsafe { patina_fd_setfd(cfd, c_int::from(arg & FD_CLOEXEC as u64 != 0)) })
        }
        F_GETFL => {
            // SAFETY: no pointers.
            let status = unsafe { patina_fd_getfl(cfd) };
            if status < 0 {
                return ret_i32(status);
            }
            getfl_to_kernel(status as u32)
        }
        // SAFETY: no pointers.
        F_SETFL => ret_i32(unsafe { patina_fd_setfl(cfd, setfl_from_kernel(arg)) }),
        // SAFETY: no pointers.
        F_DUPFD => ret_i32(unsafe { patina_dupfd(cfd, arg as c_int, 0) }),
        // SAFETY: no pointers.
        F_DUPFD_CLOEXEC => ret_i32(unsafe { patina_dupfd(cfd, arg as c_int, 1) }),
        // SAFETY: no pointers.
        F_ADD_SEALS => ret_i32(unsafe { patina_add_seals(cfd, arg as u32) }),
        // SAFETY: no pointers.
        F_GET_SEALS => ret_i32(unsafe { patina_get_seals(cfd) }),
        // SAFETY: no pointers.
        F_GETPIPE_SZ => ret_i32(unsafe { patina_pipe_size(cfd) }),
        // SAFETY: no pointers.
        F_SETPIPE_SZ => ret_i32(unsafe { patina_pipe_set_size(cfd, arg as c_int) }),
        // POSIX record locks and their OFD variants: the one entry the C fcntl
        // calls too, reading the guest's kernel-layout `struct flock`.
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            // SAFETY: `arg` is the guest's `struct flock` (or null) per the
            // fcntl(2) contract; the entry refuses a null one EFAULT.
            ret_i32(unsafe { patina_record_lock(cfd, command as u32, arg as *mut PatinaFlock) })
        }
        // An unknown command on an open descriptor is EINVAL; on a closed one
        // the kernel answers EBADF first (C parity).
        _ => {
            if fd_kind(fd).is_none() {
                -EBADF
            } else {
                -EINVAL
            }
        }
    }
}

/// `ioctl(2)`: the one entry the C `ioctl` calls too (`crate::ioctl`).
pub(super) fn sys_ioctl(fd: i64, request: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // The kernel reads the request as an `unsigned int`.
    // SAFETY: `arg` is the guest's argument for the request.
    ret_i32(unsafe { patina_ioctl(fd as c_int, u64::from(request as u32), arg as *mut c_void) })
}

/// `pipe2(2)`: `O_NONBLOCK` and `O_CLOEXEC` are honored at creation, `O_DIRECT`
/// (packet mode) is not modeled (a soft `ENOSYS`, as the C `pipe2` answers), and
/// any other flag is `EINVAL` — byte-identical to the C interposer.
pub(super) fn sys_pipe2(fds_out: u64, flags: u64) -> i64 {
    if fds_out == 0 {
        return -EFAULT;
    }
    let remaining = flags & !(O_NONBLOCK | O_CLOEXEC);
    if remaining & O_DIRECT != 0 {
        return -ENOSYS;
    }
    if remaining != 0 {
        return -EINVAL;
    }
    let nonblocking = (flags & O_NONBLOCK != 0) as c_int;
    let cloexec = (flags & O_CLOEXEC != 0) as c_int;
    let mut read_fd: c_int = 0;
    let mut write_fd: c_int = 0;
    // SAFETY: local writable storage for the pair.
    let rc = unsafe { patina_pipe(&mut read_fd, &mut write_fd, nonblocking, cloexec) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    // SAFETY: `fds_out` is the guest's `int[2]`.
    unsafe {
        let out = fds_out as *mut c_int;
        out.write(read_fd);
        out.add(1).write(write_fd);
    }
    0
}
