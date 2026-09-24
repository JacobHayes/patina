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

// `lseek(2)` whence values.
pub(super) const SEEK_SET: u64 = 0;

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

/// Kernel `struct iovec` on 64-bit Linux.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Iovec {
    iov_base: u64,
    iov_len: usize,
}

/// Iterate the guest iovec array, applying `op` to each (base, len). Mirrors the
/// C `writev`/`readv`: stop at the first short/failed transfer, returning the
/// running total (or `-errno` if the very first transfer failed).
pub(super) fn iovec_loop(iov: u64, count: i64, mut op: impl FnMut(u64, u64) -> i64) -> i64 {
    if count < 0 || (count > 0 && iov == 0) {
        return -EINVAL;
    }
    let mut total: i64 = 0;
    for index in 0..count as usize {
        // SAFETY: `iov` is the guest's iovec array of `count` entries.
        let vector = unsafe { (iov as *const Iovec).add(index).read() };
        let moved = op(vector.iov_base, vector.iov_len as u64);
        if moved < 0 {
            return if total > 0 { total } else { moved };
        }
        total += moved;
        if (moved as u64) < vector.iov_len as u64 {
            break;
        }
    }
    total
}

pub(super) fn sys_readv(fd: i64, iov: u64, count: i64) -> i64 {
    iovec_loop(iov, count, |base, len| sys_read(fd, base, len))
}

pub(super) fn sys_writev(fd: i64, iov: u64, count: i64) -> i64 {
    iovec_loop(iov, count, |base, len| sys_write(fd, base, len))
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
        F_GETPIPE_SZ => ret_i32(unsafe { patina_pipe_size(cfd) }),
        // SAFETY: no pointers.
        F_SETPIPE_SZ => ret_i32(unsafe { patina_pipe_set_size(cfd, arg as c_int) }),
        // POSIX record locks and their OFD variants: mirror the C fcntl lock arm
        // EXACTLY (patina_posix.c). One process per run, so process-scoped
        // record locks never conflict with themselves: F_SETLK/F_SETLKW succeed
        // on an open descriptor and F_GETLK reports the range unlocked. A
        // whole-file OFD lock routes to the per-description flock table; a
        // byte-range OFD lock and F_OFD_GETLK are a soft -ENOSYS.
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            if arg == 0 {
                return -EINVAL;
            }
            // Table check only, as in C: a record lock does no I/O and must not
            // consult the (fault-eligible) filesystem descriptor lookup. The
            // kernel's fcntl_setlk then checks the lock type against the
            // description's access mode (a read lock needs a readable
            // description, a write lock a writable one: EBADF).
            // SAFETY: no pointers.
            let status = unsafe { patina_fd_getfl(cfd) };
            if status < 0 {
                return -EBADF;
            }
            let status = status as u32;
            let lock_ptr = arg as *mut KernelFlock;
            // SAFETY: `arg` is the guest's `struct flock` per the fcntl(2) contract.
            let lock = unsafe { lock_ptr.read() };
            if lock.l_type != F_RDLCK && lock.l_type != F_WRLCK && lock.l_type != F_UNLCK {
                return -EINVAL;
            }
            if command != F_GETLK
                && command != F_OFD_GETLK
                && ((lock.l_type == F_RDLCK && status & PATINA_O_READ == 0)
                    || (lock.l_type == F_WRLCK && status & PATINA_O_WRITE == 0))
            {
                return -EBADF;
            }
            match command {
                F_GETLK => {
                    // SAFETY: same guest struct, writable per the F_GETLK contract.
                    unsafe { (*lock_ptr).l_type = F_UNLCK };
                    0
                }
                F_SETLK | F_SETLKW => 0,
                F_OFD_GETLK => -ENOSYS,
                _ => {
                    if !(lock.l_whence as u64 == SEEK_SET && lock.l_start == 0 && lock.l_len == 0) {
                        return -ENOSYS;
                    }
                    let mut op = match lock.l_type {
                        F_RDLCK => LOCK_SH,
                        F_WRLCK => LOCK_EX,
                        _ => LOCK_UN,
                    };
                    if command == F_OFD_SETLK {
                        op |= LOCK_NB;
                    }
                    // SAFETY: no pointers.
                    ret_i32(unsafe { patina_flock(cfd, op) })
                }
            }
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

pub(super) fn sys_ioctl(fd: i64, request: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // Mirror the C ioctl interposer EXACTLY: FIONBIO flips O_NONBLOCK on the
    // description, FIOCLEX/FIONCLEX the number's FD_CLOEXEC bit; everything
    // else is a SOFT -ENOTTY on an open descriptor (NOT fatal, NOT a fabricated
    // FIONREAD=0, which C does not model) and -EBADF on a closed one.
    match request {
        FIONBIO => {
            // SAFETY: `arg` points to an `int` on/off flag when non-null.
            let on = if arg != 0 {
                (unsafe { (arg as *const c_int).read() }) != 0
            } else {
                false
            };
            // SAFETY: no pointers.
            ret_i32(unsafe { patina_fd_set_nonblocking(cfd, c_int::from(on)) })
        }
        // SAFETY: no pointers.
        FIOCLEX => ret_i32(unsafe { patina_fd_setfd(cfd, 1) }),
        // SAFETY: no pointers.
        FIONCLEX => ret_i32(unsafe { patina_fd_setfd(cfd, 0) }),
        _ => {
            if fd_kind(fd).is_none() {
                -EBADF
            } else {
                -ENOTTY
            }
        }
    }
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
