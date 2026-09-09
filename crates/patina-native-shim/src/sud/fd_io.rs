//! SUD rows — descriptor I/O: `read`/`write`/`close`/`lseek`, positional and
//! vectored I/O, `fsync`/`ftruncate`/`flock`, `dup*`, `fcntl`/`ioctl`, `pipe2`.
//! Every row routes by descriptor class to the exact entry the C interposer uses.

use super::*;

/// Route a raw `read(2)` by fd class, exactly as the C `read` interposer does: a
/// virtual socket/pipe/eventfd descriptor (fd >= [`PATINA_SOCKET_FD_BASE`]) goes
/// to the network/pipe/eventfd entries, everything else to the deterministic
/// filesystem. Keeping this decode identical to the C path is what makes a raw
/// `read` on a rustix-default socket record the same op-stream as an interposed
/// one.
pub(super) fn sys_read(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    let dst = buf as *mut c_void;
    let len = count as usize;
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
        return unsafe {
            let kind = patina_net_kind(cfd);
            if kind == 3 {
                ret_isize(patina_net_stream_recv(cfd, dst, len))
            } else if kind == 0 {
                ret_isize(patina_net_recv(cfd, dst, len))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_isize(patina_pipe_read(cfd, dst, len))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_isize(patina_eventfd_read(cfd, dst, len))
            } else if kind < 0 {
                -EBADF
            } else {
                -ENOTCONN
            }
        };
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
    ret_isize(unsafe { patina_read(cfd, dst, len) })
}

/// Route a raw `write(2)` by fd class, mirroring the C `write` interposer:
/// captured stdout/stderr (fd 1/2), then virtual socket/pipe/eventfd classes,
/// then the deterministic filesystem.
pub(super) fn sys_write(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    let src = buf as *const c_void;
    let len = count as usize;
    if fd == 1 || fd == 2 {
        // SAFETY: `buf`/`count` describe a guest buffer per the write(2) contract.
        return ret_isize(unsafe { patina_stdio_write(cfd, src, len) });
    }
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: as above.
        return unsafe {
            let kind = patina_net_kind(cfd);
            if kind == 3 {
                ret_isize(patina_net_stream_send(cfd, src, len))
            } else if kind == 0 {
                ret_isize(patina_net_send(cfd, src, len))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_isize(patina_pipe_write(cfd, src, len))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_isize(patina_eventfd_write(cfd, src, len))
            } else if kind < 0 {
                -EBADF
            } else {
                -ENOTCONN
            }
        };
    }
    // SAFETY: as above.
    ret_isize(unsafe { patina_write(cfd, src, len) })
}

/// Route a raw `close(2)` by fd class, mirroring the C `close` interposer.
pub(super) fn sys_close(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // A directory fd goes through the SAME entry the C `close` interposer uses,
    // which releases the fd→path binding, this layer's iteration snapshot, and
    // the underlying filesystem fd together.
    if is_dir_fd(fd) {
        // SAFETY: no pointers.
        return ret_i32(unsafe { patina_dirclose(cfd) });
    }
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: no dereferenced pointers.
        return unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                ret_i32(patina_epoll_close(cfd))
            } else if patina_eventfd_is(cfd) != 0 {
                ret_i32(patina_eventfd_close(cfd))
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_i32(patina_pipe_close(cfd))
            } else {
                ret_i32(patina_net_close(cfd))
            }
        };
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_close(cfd) })
}

// `lseek(2)` whence values.
pub(super) const SEEK_SET: u64 = 0;

pub(super) fn sys_lseek(fd: i64, offset: i64, whence: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // A directory fd: `lseek(fd, 0, SEEK_SET)` is rustix `Dir::rewind` — drop the
    // current snapshot so the next `getdents64` takes a fresh one from the start.
    // It does NOT route to `patina_seek`: the driver refuses to seek a directory
    // handle (a directory has no byte offset), and the libc path never lseeks one
    // either — `rewinddir` re-snapshots exactly like this. Any other seek on a
    // directory fd is meaningless (ESPIPE, matching a directory stream).
    if is_dir_fd(fd) {
        if whence == SEEK_SET && offset == 0 {
            release_dir_iteration(fd as c_int);
            return 0;
        }
        return -ESPIPE;
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

/// Guard the fd against the negative/oversized values that cannot be Patina
/// virtual descriptors, so the cast into `c_int` never wraps.
pub(super) fn fd_out_of_range(fd: i64) -> Option<i64> {
    if fd < 0 || fd > c_int::MAX as i64 {
        Some(-EINVAL)
    } else {
        None
    }
}

// ---- Positional & vectored I/O ----

pub(super) fn sys_pread(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // Virtual sockets have no offset addressing (ESPIPE), mirroring the C pread.
    if fd >= PATINA_SOCKET_FD_BASE {
        return -ESPIPE;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the pread(2) contract.
    ret_isize(unsafe { patina_pread(fd as c_int, buf as *mut c_void, count as usize, offset) })
}

pub(super) fn sys_pwrite(fd: i64, buf: u64, count: u64, offset: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    if fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE {
        return -ESPIPE;
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
    // Advisory locks on virtual sockets are not modeled (C denies them, with a
    // recorded diagnostic).
    if fd >= PATINA_SOCKET_FD_BASE {
        return sud_deny(
            "patina: advisory locks on virtual sockets are not modeled; failing closed\n",
        );
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_flock(fd as c_int, operation as c_int) })
}

pub(super) fn sys_dup(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // Mirror the C `dup` interposer class-by-class, including the byte-identical
    // deny diagnostics: captured stdio and virtual eventfd/socket dups fail closed
    // with their own messages; epoll and pipe endpoints alias into a shared handle.
    if (0..=2).contains(&fd) {
        return sud_deny(
            "patina: duplicating a captured stdio descriptor is not modeled; failing closed\n",
        );
    }
    if is_dir_fd(fd) {
        return dup_dir_fd(fd);
    }
    let cfd = fd as c_int;
    if fd >= PATINA_SOCKET_FD_BASE {
        // SAFETY: no dereferenced pointers.
        return unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                ret_i32(patina_epoll_dup(cfd))
            } else if patina_eventfd_is(cfd) != 0 {
                sud_deny(
                    "patina: duplicating a virtual eventfd descriptor is not modeled; failing closed\n",
                )
            } else if patina_pipe_is_endpoint(cfd) != 0 {
                ret_i32(patina_pipe_dup(cfd))
            } else {
                sud_deny(
                    "patina: duplicating a virtual socket descriptor is not modeled; failing closed\n",
                )
            }
        };
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_dup(cfd) })
}

pub(super) fn sys_dup3(oldfd: i64, newfd: i64, _flags: i64) -> i64 {
    // dup3 to a chosen descriptor number is not modeled; equal fds are EINVAL
    // (POSIX dup3), everything else fails closed — mirrors the C dup3 interposer,
    // including the byte-identical deny diagnostic.
    if oldfd == newfd {
        return -EINVAL;
    }
    sud_deny("patina: dup3 to a chosen descriptor number is not modeled; failing closed\n")
}

/// Legacy `dup2(2)` (x86_64-only syscall). It differs from `dup3` in EXACTLY the
/// equal-fd case: `dup2(fd, fd)` validates `fd` and returns it unchanged (no
/// close, no CLOEXEC), whereas `dup3(fd, fd, …)` is `-EINVAL`. A distinct-target
/// `dup2` is `dup3(old, new, 0)` — dup-to-a-chosen-number, which this model does
/// not support, so it fails closed identically. Mirrors the C `dup2` interposer's
/// validity checks so the raw and wrapped paths route identically.
pub(super) fn sys_dup2(oldfd: i64, newfd: i64) -> i64 {
    if oldfd != newfd {
        // Not the no-op case: a chosen-number dup is unmodeled. Emit the dup2
        // (NOT dup3) deny line so a raw dup2 records the same bytes a libc dup2
        // does — the two messages differ only by the "2"/"3", so delegating to
        // sys_dup3 here would print the wrong one.
        return sud_deny(
            "patina: dup2 to a chosen descriptor number is not modeled; failing closed\n",
        );
    }
    // Equal fds: return `fd` iff it is a currently-valid descriptor, else EBADF.
    if fd_out_of_range(oldfd).is_some() {
        return -EBADF;
    }
    if (0..=2).contains(&oldfd) {
        return newfd; // captured stdio is always valid
    }
    let cfd = oldfd as c_int;
    if oldfd >= PATINA_SOCKET_FD_BASE {
        // Mirror the C dup2 validity EXACTLY (patina_posix.c:1110): a virtual fd is
        // valid iff it is a net socket (net_is_nonblocking >= 0) OR a pipe/socketpair
        // endpoint. epoll and eventfd fds are NOT accepted — C reports EBADF for
        // them, so this must too.
        // SAFETY: no dereferenced pointers.
        let valid =
            unsafe { patina_net_is_nonblocking(cfd) >= 0 || patina_pipe_is_endpoint(cfd) != 0 };
        return if valid { newfd } else { -EBADF };
    }
    // A regular fd: validate through the SAME metadata entry the C dup2 uses.
    let (mut kind, mut length, mut ino, mut atime, mut mtime) = (0u32, 0u64, 0u64, 0u64, 0u64);
    let (mut nlink, mut mode) = (0u32, 0u32);
    // SAFETY: every out-param is local writable storage.
    let rc = unsafe {
        patina_fd_metadata_full(
            cfd,
            &mut kind,
            &mut length,
            &mut ino,
            &mut nlink,
            &mut atime,
            &mut mtime,
            &mut mode,
        )
    };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    newfd
}

pub(super) fn sys_fcntl(fd: i64, command: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    if fd >= PATINA_SOCKET_FD_BASE {
        // Virtual epoll descriptors.
        // SAFETY: no dereferenced pointers below unless noted.
        unsafe {
            if patina_epoll_is_epoll(cfd) != 0 {
                return match command {
                    F_DUPFD | F_DUPFD_CLOEXEC => ret_i32(patina_epoll_dup(cfd)),
                    F_GETFD => FD_CLOEXEC,
                    F_SETFD | F_SETFL | F_GETFL => 0,
                    _ => -EINVAL,
                };
            }
            if patina_pipe_is_endpoint(cfd) != 0 {
                return match command {
                    F_GETFL => {
                        let nb = patina_pipe_is_nonblocking(cfd);
                        if nb < 0 {
                            -EBADF
                        } else if nb != 0 {
                            O_NONBLOCK as i64
                        } else {
                            0
                        }
                    }
                    F_SETFL => ret_i32(patina_pipe_set_nonblocking(
                        cfd,
                        ((arg & O_NONBLOCK) != 0) as c_int,
                    )),
                    F_GETFD => FD_CLOEXEC,
                    F_SETFD => 0,
                    F_DUPFD | F_DUPFD_CLOEXEC => ret_i32(patina_pipe_dup(cfd)),
                    _ => -EINVAL,
                };
            }
            // Virtual sockets: report/adjust the blocking flag; cloexec is a no-op.
            return match command {
                F_GETFL => {
                    let nb = patina_net_is_nonblocking(cfd);
                    if nb < 0 {
                        -EBADF
                    } else if nb != 0 {
                        O_NONBLOCK as i64
                    } else {
                        0
                    }
                }
                F_SETFL => ret_i32(patina_net_set_nonblocking(
                    cfd,
                    ((arg & O_NONBLOCK) != 0) as c_int,
                )),
                F_GETFD => FD_CLOEXEC,
                F_SETFD => 0,
                // Duplicating a virtual socket descriptor is not modeled.
                F_DUPFD | F_DUPFD_CLOEXEC => sud_deny(
                    "patina: duplicating a virtual socket descriptor is not modeled; failing closed\n",
                ),
                _ => -EINVAL,
            };
        }
    }
    // A directory fd must be recognized BEFORE the regular-fd tail, whose F_GETFL
    // is a soft ENOSYS — which is exactly what breaks rustix `Dir::read_from`,
    // whose first act is `fcntl(dir_fd, F_GETFL)`. The directory was opened
    // read-only, so F_GETFL reports O_RDONLY (O_DIRECTORY/O_CLOEXEC/O_PATH are
    // not file-status flags), the CLOEXEC/flag setters are no-ops, and F_DUPFD
    // yields a fresh handle to the same directory. Mirrors the C fcntl dir rows.
    if is_dir_fd(fd) {
        return match command {
            F_GETFL => 0, // O_RDONLY
            F_GETFD => FD_CLOEXEC,
            F_SETFD | F_SETFL => 0,
            F_DUPFD | F_DUPFD_CLOEXEC => dup_dir_fd(fd),
            _ => -EINVAL,
        };
    }
    // Regular fds (and captured stdio): mirror the C fcntl regular-fd tail EXACTLY
    // (patina_posix.c). Only F_GETFD/F_SETFD/F_DUPFD are modeled; F_GETFL, F_SETFL,
    // and every unknown command fall through to a SOFT -ENOSYS (NOT 0, NOT fatal),
    // just as C's final `errno = ENOSYS; return -1` does.
    match command {
        F_GETFD => FD_CLOEXEC,
        F_SETFD => 0,
        F_DUPFD | F_DUPFD_CLOEXEC => {
            if (0..=2).contains(&fd) {
                return sud_deny(
                    "patina: duplicating a captured stdio descriptor is not modeled; failing closed\n",
                );
            }
            // SAFETY: no pointers.
            let dup = unsafe { patina_dup(cfd) };
            if dup < 0 {
                // SAFETY: plain thread-local read.
                return -(unsafe { patina_errno() } as i64);
            }
            // The deterministic counter is monotonic; a requested minimum above
            // it cannot be honored without modeling sparse placement.
            if (dup as u64) < arg {
                // SAFETY: no pointers.
                unsafe { patina_close(dup) };
                return sud_deny(
                    "patina: F_DUPFD minimum above the deterministic descriptor counter is not modeled; failing closed\n",
                );
            }
            dup as i64
        }
        // POSIX record locks and their OFD variants: mirror the C fcntl lock arm
        // EXACTLY (patina_posix.c). One process per run, so process-scoped
        // record locks never conflict with themselves: F_SETLK/F_SETLKW succeed
        // on an open regular fd and F_GETLK reports the range unlocked. A
        // whole-file OFD lock routes to the per-inode flock table; a byte-range
        // OFD lock and F_OFD_GETLK are a soft -ENOSYS.
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            if arg == 0 {
                return -EINVAL;
            }
            // Range check only, as in C: a record lock does no I/O and must not
            // consult the (fault-eligible) filesystem descriptor lookup.
            if fd < 3 {
                return -EBADF;
            }
            let lock_ptr = arg as *mut KernelFlock;
            // SAFETY: `arg` is the guest's `struct flock` per the fcntl(2) contract.
            let lock = unsafe { lock_ptr.read() };
            if lock.l_type != F_RDLCK && lock.l_type != F_WRLCK && lock.l_type != F_UNLCK {
                return -EINVAL;
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
        // F_GETFL / F_SETFL / any unknown command: soft ENOSYS (C parity).
        _ => -ENOSYS,
    }
}

pub(super) fn sys_ioctl(fd: i64, request: u64, arg: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    let cfd = fd as c_int;
    // Mirror the C ioctl interposer EXACTLY: FIONBIO toggles nonblocking on a
    // VIRTUAL socket only; FIOCLEX/FIONCLEX are no-ops; everything else — an
    // unknown request, or FIONBIO on a non-virtual fd — is a SOFT -ENOTTY (NOT
    // fatal, NOT a fabricated FIONREAD=0, which C does not model).
    match request {
        FIONBIO if fd >= PATINA_SOCKET_FD_BASE => {
            // SAFETY: `arg` points to an `int` on/off flag when non-null.
            let on = if arg != 0 {
                (unsafe { (arg as *const c_int).read() }) != 0
            } else {
                false
            };
            ret_i32(unsafe { patina_net_set_nonblocking(cfd, on as c_int) })
        }
        FIOCLEX | FIONCLEX => 0,
        _ => -ENOTTY,
    }
}

pub(super) fn sys_pipe2(fds_out: u64, flags: u64) -> i64 {
    if fds_out == 0 {
        return -EFAULT;
    }
    let nonblocking = (flags & O_NONBLOCK != 0) as c_int;
    let mut read_fd: c_int = 0;
    let mut write_fd: c_int = 0;
    // SAFETY: local writable storage for the pair.
    let rc = unsafe { patina_pipe(&mut read_fd, &mut write_fd, nonblocking) };
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
