/*
 * Descriptor I/O: read/write and their positional/vectored forms, close/dup,
 * lseek/fsync/ftruncate/flock, fcntl/ioctl, isatty, and pipes.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * isatty: whether a descriptor is a terminal is a nondeterministic property of
 * how the run was launched (pipe vs file vs tty), and programs branch on it —
 * search tools, for instance, derive heading/color/line-number defaults from it. A
 * fully interposed guest must never observe host terminal state, so report a
 * deterministic "not a terminal" for every descriptor: captured guest stdio is
 * never a tty under the runtime. Interposing here (rather than allow-listing the
 * import) makes guest output provably independent of host tty state instead of
 * merely "neutral given the flags". This is a strong definition, so the guest's
 * isatty reference binds here and the libc symbol drops off the import table.
 */
int isatty(int fd) {
    (void)fd;
    errno = ENOTTY;
    return 0;
}

static int patina_fcntl_record_lock(int fd, int command, struct flock *lock);

int fcntl(int fd, int command, ...) {
#ifdef __APPLE__
    /* Virtual kqueue descriptors. F_DUPFD/F_DUPFD_CLOEXEC clone into a second fd
     * sharing the SAME registry (tokio's IO driver clones its selector through
     * F_DUPFD_CLOEXEC); the requested minimum is honored implicitly because the
     * deterministic fd counter always allocates above it. cloexec and the
     * blocking flag are no-ops on a kqueue. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_kqueue_is_kq(fd)) {
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return fail_int(patina_kqueue_dup(fd));
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_SETFL) return 0;
        if (command == F_GETFL) return 0;
        errno = EINVAL;
        return -1;
    }
#endif
#ifdef __linux__
    /* Virtual epoll descriptors: the Linux mirror of the kqueue branch above.
     * F_DUPFD/F_DUPFD_CLOEXEC clone into a second fd sharing the SAME registry
     * (mio clones its selector this way); the requested minimum is honored
     * implicitly because the deterministic fd counter always allocates above
     * it. cloexec and the blocking flag are no-ops on an epoll fd. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_epoll_is_epoll(fd)) {
        if (command == F_DUPFD || command == F_DUPFD_CLOEXEC)
            return fail_int(patina_epoll_dup(fd));
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_SETFL) return 0;
        if (command == F_GETFL) return 0;
        errno = EINVAL;
        return -1;
    }
#endif
    /* Virtual pipe/socketpair endpoints: same blocking-flag surface as sockets,
     * routed to the pipe table (cloexec is a no-op). F_DUPFD/F_DUPFD_CLOEXEC
     * alias the endpoint's channel side(s) refcounted (std's try_clone — tokio's
     * signal driver clones a socketpair end this way); as with kqueue fds the
     * requested minimum is honored implicitly because the deterministic fd
     * counter always allocates above it. */
    if (fd >= PATINA_SOCKET_FD_BASE && patina_pipe_is_endpoint(fd)) {
        if (command == F_GETFL) {
            int nonblocking = patina_pipe_is_nonblocking(fd);
            if (nonblocking < 0) {
                errno = EBADF;
                return -1;
            }
            return nonblocking ? O_NONBLOCK : 0;
        }
        if (command == F_SETFL) {
            va_list ap;
            va_start(ap, command);
            int flags = va_arg(ap, int);
            va_end(ap);
            return patina_pipe_set_nonblocking(fd, (flags & O_NONBLOCK) ? 1 : 0);
        }
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return fail_int(patina_pipe_dup(fd));
        errno = EINVAL;
        return -1;
    }
    /* Virtual sockets: report/adjust the blocking flag; cloexec is a no-op. */
    if (fd >= PATINA_SOCKET_FD_BASE) {
        if (command == F_GETFL) {
            int nonblocking = patina_net_is_nonblocking(fd);
            if (nonblocking < 0) {
                errno = EBADF;
                return -1;
            }
            return nonblocking ? O_NONBLOCK : 0;
        }
        if (command == F_SETFL) {
            va_list ap;
            va_start(ap, command);
            int flags = va_arg(ap, int);
            va_end(ap);
            return patina_net_set_nonblocking(fd, (flags & O_NONBLOCK) ? 1 : 0);
        }
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD) return 0;
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return patina_posix_deny("patina: duplicating a virtual socket descriptor is not modeled; failing closed\n");
        errno = EINVAL;
        return -1;
    }
    /* Virtual directory descriptors. A directory handle was opened read-only, so
     * F_GETFL reports O_RDONLY (O_DIRECTORY/O_CLOEXEC/O_PATH are not file-status
     * flags); the flag setters are no-ops and F_DUPFD yields a fresh handle to
     * the same directory. rustix's `Dir::read_from` does exactly
     * fcntl(dirfd, F_GETFL) -> openat(dirfd, ".", flags) before iterating, so a
     * dir fd that fell through to the regular-fd tail's ENOSYS could not be
     * listed at all. Mirrors the SUD dispatcher's dir-fd fcntl rows. */
    if (patina_dir_is_dirfd(fd)) {
        if (command == F_GETFL) return 0; /* O_RDONLY */
        if (command == F_GETFD) return FD_CLOEXEC;
        if (command == F_SETFD || command == F_SETFL) return 0;
        if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || command == F_DUPFD_CLOEXEC
#endif
        )
            return patina_dup_dirfd(fd);
        errno = EINVAL;
        return -1;
    }
    /* POSIX record locks (F_GETLK/F_SETLK/F_SETLKW) and the Linux open-file-
     * description variants (F_OFD_*): see patina_fcntl_record_lock below. */
    if (command == F_GETLK || command == F_SETLK || command == F_SETLKW
#ifdef F_OFD_SETLK
        || command == F_OFD_GETLK || command == F_OFD_SETLK || command == F_OFD_SETLKW
#endif
    ) {
        va_list ap;
        va_start(ap, command);
        struct flock *lock = va_arg(ap, struct flock *);
        va_end(ap);
        return patina_fcntl_record_lock(fd, command, lock);
    }
#ifdef __APPLE__
    /* Rust std maps File::sync_all to F_FULLFSYNC on Darwin. */
    if (command == F_FULLFSYNC) return fail_int(patina_fsync(fd));
#endif
    if (command == F_GETFD) return FD_CLOEXEC;
    if (command == F_SETFD) return 0;
    if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
        || command == F_DUPFD_CLOEXEC
#endif
    ) {
        if (fd >= 0 && fd <= 2)
            return patina_posix_deny("patina: duplicating a captured stdio descriptor is not modeled; failing closed\n");
        va_list ap;
        va_start(ap, command);
        int minimum = va_arg(ap, int);
        va_end(ap);
        int duplicate = patina_dup(fd);
        if (duplicate < 0) {
            errno = patina_errno();
            return -1;
        }
        if (duplicate < minimum) {
            /* Deterministic numbering is monotonic from 3; a minimum above the
             * counter cannot be honored without modeling sparse fd placement. */
            patina_close(duplicate);
            return patina_posix_deny("patina: F_DUPFD minimum above the deterministic descriptor counter is not modeled; failing closed\n");
        }
        return duplicate; /* CLOEXEC is a no-op: no exec under the runtime. */
    }
    errno = ENOSYS;
    return -1;
}

#ifdef __linux__
/*
 * glibc's LFS alias of fcntl. Anything compiled with _FILE_OFFSET_BITS=64 —
 * which is every bundled C library that touches files, SQLite's unix VFS
 * included — emits `fcntl64`, so leaving it uninterposed sent record locks
 * (F_SETLK on the virtual database/WAL descriptors) to the HOST fcntl, which
 * fails EBADF and surfaces as SQLITE_IOERR_LOCK. The variadic argument is
 * forwarded as an opaque pointer-sized value the way glibc's own wrapper does:
 * `fcntl` re-reads it as whichever type the command defines.
 */
int fcntl64(int fd, int command, ...) {
    va_list ap;
    va_start(ap, command);
    void *argument = va_arg(ap, void *);
    va_end(ap);
    return fcntl(fd, command, argument);
}

#endif

ssize_t read(int fd, void *destination, size_t length) {
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) return fail_size(patina_net_stream_recv(fd, destination, length));
        if (kind == 0) return fail_size(patina_net_recv(fd, destination, length));
        if (patina_pipe_is_endpoint(fd)) return fail_size(patina_pipe_read(fd, destination, length));
#ifdef __linux__
        if (patina_eventfd_is(fd)) return fail_size(patina_eventfd_read(fd, destination, length));
#endif
        errno = kind < 0 ? EBADF : ENOTCONN;
        return -1;
    }
    return fail_size(patina_read(fd, destination, length));
}

ssize_t write(int fd, const void *source, size_t length) {
    if (fd == 1 || fd == 2) return fail_size(patina_stdio_write(fd, source, length));
    if (fd >= PATINA_SOCKET_FD_BASE) {
        int kind = patina_net_kind(fd);
        if (kind == 3) return fail_size(patina_net_stream_send(fd, source, length));
        if (kind == 0) return fail_size(patina_net_send(fd, source, length));
        if (patina_pipe_is_endpoint(fd)) return fail_size(patina_pipe_write(fd, source, length));
#ifdef __linux__
        if (patina_eventfd_is(fd)) return fail_size(patina_eventfd_write(fd, source, length));
#endif
        errno = kind < 0 ? EBADF : ENOTCONN;
        return -1;
    }
    return fail_size(patina_write(fd, source, length));
}

/* Positional I/O. Database-style file backends do ALL of their I/O through
 * pread/pwrite (read_exact_at/write_all_at), never seek+read/write, so these
 * must reach the deterministic filesystem or that I/O would bypass the crash
 * model entirely. They route to patina_p{read,write}, which the runtime
 * services as ONE positional operation (atomic w.r.t. the scheduler and cursor-
 * independent), NOT a caller-side seek+read that could interleave under
 * concurrency. Virtual sockets have no offset addressing, so a positional call
 * on a socket fd is ESPIPE, matching the kernel. */
ssize_t pread(int fd, void *destination, size_t length, off_t offset) {
    if (fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}

ssize_t pwrite(int fd, const void *source, size_t length, off_t offset) {
    if (fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#ifdef __linux__
/* Large-file positional I/O variants. glibc std lowers positional reads/writes
 * on 64-bit off_t Linux to the *64 symbols (database file backends use them), so
 * they must reach the same deterministic positional I/O as pread/pwrite rather
 * than be denied. off64_t is always 64-bit, so the full offset is preserved. */
ssize_t pread64(int fd, void *destination, size_t length, off64_t offset) {
    if (fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}
ssize_t pwrite64(int fd, const void *source, size_t length, off64_t offset) {
    if (fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#endif

/* Whole-file advisory lock (a single-opener database takes one via File::try_lock on open).
 * Routed to the runtime's per-inode lock table (patina_flock): a lone opener
 * always acquires, but two independent opens of the same file contend exactly
 * as a real flock would (LOCK_EX|LOCK_NB on the second → EWOULDBLOCK, i.e.
 * a database's already-open error). See the "Advisory file lock" row in
 * crates/patina-target/ESCAPE-CLASSES.md. Virtual sockets have no advisory-lock
 * model, so a flock on one fails closed. */
int flock(int fd, int operation) {
    if (fd >= PATINA_SOCKET_FD_BASE)
        return patina_posix_deny("patina: advisory locks on virtual sockets are not modeled; failing closed\n");
    return fail_int(patina_flock(fd, operation));
}

int close(int fd) {
    /* A virtual directory descriptor is released here as well as by closedir, so
     * a guest that close()s the raw fd (rather than the DIR) still frees it.
     * Directory fds are ordinary deterministic-FS fds now (small numbers), so
     * check the directory table before the socket-space dispatch. */
    if (patina_dir_is_dirfd(fd)) return fail_int(patina_dirclose(fd));
    if (fd >= PATINA_SOCKET_FD_BASE) {
#ifdef __APPLE__
        if (patina_kqueue_is_kq(fd)) return fail_int(patina_kqueue_close(fd));
#endif
#ifdef __linux__
        if (patina_epoll_is_epoll(fd)) return fail_int(patina_epoll_close(fd));
        if (patina_eventfd_is(fd)) return fail_int(patina_eventfd_close(fd));
#endif
        if (patina_pipe_is_endpoint(fd)) return fail_int(patina_pipe_close(fd));
        return fail_int(patina_net_close(fd));
    }
    return fail_int(patina_close(fd));
}

int dup(int fd) {
    if (fd >= 0 && fd <= 2)
        return patina_posix_deny("patina: duplicating a captured stdio descriptor is not modeled; failing closed\n");
    if (fd >= PATINA_SOCKET_FD_BASE) {
#ifdef __APPLE__
        /* A kqueue fd duplicates into a second fd sharing the SAME registry
         * (tokio's IO driver clones its selector this way). */
        if (patina_kqueue_is_kq(fd)) return fail_int(patina_kqueue_dup(fd));
#endif
#ifdef __linux__
        /* Same registry-aliasing dup for an epoll fd (mio's selector clone). */
        if (patina_epoll_is_epoll(fd)) return fail_int(patina_epoll_dup(fd));
        if (patina_eventfd_is(fd))
            return patina_posix_deny("patina: duplicating a virtual eventfd descriptor is not modeled; failing closed\n");
#endif
        /* A pipe/socketpair endpoint duplicates into a refcounted alias of the
         * same channel side(s); virtual sockets still fail closed. */
        if (patina_pipe_is_endpoint(fd)) return fail_int(patina_pipe_dup(fd));
        return patina_posix_deny("patina: duplicating a virtual socket descriptor is not modeled; failing closed\n");
    }
    if (patina_dir_is_dirfd(fd)) return patina_dup_dirfd(fd);
    return fail_int(patina_dup(fd));
}

int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) {
        /* POSIX: equal descriptors validate oldfd and return newfd unchanged. */
        if (oldfd >= 0 && oldfd <= 2) return newfd;
        if (oldfd >= PATINA_SOCKET_FD_BASE) {
            if (patina_net_is_nonblocking(oldfd) < 0 && patina_pipe_is_endpoint(oldfd) == 0) {
                errno = EBADF;
                return -1;
            }
            return newfd;
        }
        uint32_t kind;
        uint64_t length, ino_v, atime_v, mtime_v;
        uint32_t nlink_v, mode_v;
        if (patina_fd_metadata_full(oldfd, &kind, &length, &ino_v, &nlink_v, &atime_v, &mtime_v,
                                    &mode_v) != 0) {
            errno = patina_errno();
            return -1;
        }
        return newfd;
    }
    return patina_posix_deny("patina: dup2 to a chosen descriptor number is not modeled; failing closed\n");
}

#ifdef __linux__
int dup3(int oldfd, int newfd, int flags) {
    (void)oldfd;
    (void)flags;
    if (oldfd == newfd) { errno = EINVAL; return -1; } /* POSIX dup3 */
    return patina_posix_deny("patina: dup3 to a chosen descriptor number is not modeled; failing closed\n");
}

#endif

ssize_t writev(int fd, const struct iovec *vectors, int count) {
    if (count < 0 || (count > 0 && vectors == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t written = write(fd, vectors[index].iov_base, vectors[index].iov_len);
        if (written < 0) return total > 0 ? total : -1;
        total += written;
        if ((size_t)written < vectors[index].iov_len) break;
    }
    return total;
}

/* Positional vectored I/O. Database file backends batch a transaction's WAL
 * frames with ONE pwritev (turso's UnixFile::pwritev is the live example), so
 * these must reach the same deterministic positional I/O as pread/pwrite rather
 * than be denied. Each vector is one positional runtime op at an advancing
 * offset; like writev/readv, stop at the first short or failed transfer and
 * return the running total (a short transfer here is how an injected short
 * write surfaces to a vectored caller). Sockets have no offset: ESPIPE. */
ssize_t preadv(int fd, const struct iovec *vectors, int count, off_t offset) {
    if (count < 0 || (count > 0 && vectors == NULL)) { errno = EINVAL; return -1; }
    if (fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t consumed = fail_size(patina_pread(
            fd, vectors[index].iov_base, vectors[index].iov_len, (int64_t)offset + (int64_t)total));
        if (consumed < 0) return total > 0 ? total : -1;
        total += consumed;
        if ((size_t)consumed < vectors[index].iov_len) break;
    }
    return total;
}

ssize_t pwritev(int fd, const struct iovec *vectors, int count, off_t offset) {
    if (count < 0 || (count > 0 && vectors == NULL)) { errno = EINVAL; return -1; }
    if (fd == 1 || fd == 2 || fd >= PATINA_SOCKET_FD_BASE) { errno = ESPIPE; return -1; }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t written = fail_size(patina_pwrite(
            fd, vectors[index].iov_base, vectors[index].iov_len, (int64_t)offset + (int64_t)total));
        if (written < 0) return total > 0 ? total : -1;
        total += written;
        if ((size_t)written < vectors[index].iov_len) break;
    }
    return total;
}

#ifdef __linux__
/* Large-file variants, the same way pread64/pwrite64 mirror pread/pwrite. */
ssize_t preadv64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    return preadv(fd, vectors, count, (off_t)offset);
}
ssize_t pwritev64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    return pwritev(fd, vectors, count, (off_t)offset);
}

#endif

ssize_t readv(int fd, const struct iovec *vectors, int count) {
    if (count < 0 || (count > 0 && vectors == NULL)) {
        errno = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int index = 0; index < count; ++index) {
        ssize_t consumed = read(fd, vectors[index].iov_base, vectors[index].iov_len);
        if (consumed < 0) return total > 0 ? total : -1;
        total += consumed;
        if ((size_t)consumed < vectors[index].iov_len) break;
    }
    return total;
}

off_t lseek(int fd, off_t offset, int whence) {
    uint32_t patina_whence;
    switch (whence) {
        case SEEK_SET: patina_whence = PATINA_SEEK_START; break;
        case SEEK_CUR: patina_whence = PATINA_SEEK_CURRENT; break;
        case SEEK_END: patina_whence = PATINA_SEEK_END; break;
        default: errno = EINVAL; return (off_t)-1;
    }
    int64_t result = patina_seek(fd, (int64_t)offset, patina_whence);
    if (result < 0) errno = patina_errno();
    return (off_t)result;
}

int fsync(int fd) {
    return fail_int(patina_fsync(fd));
}

#ifdef __linux__
/* fdatasync: databases call it to make committed data durable. The deterministic
 * crash-model FS makes the file durable through the same sync path (it draws no
 * data-vs-metadata distinction), so route it to patina_fsync — a durability
 * guarantee at least as strong as fdatasync's, and deterministic. */
int fdatasync(int fd) {
    return fail_int(patina_fsync(fd));
}

#endif

int ftruncate(int fd, off_t length) {
    if (length < 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_set_len(fd, (uint64_t)length));
}

#ifdef __linux__
off64_t lseek64(int fd, off64_t offset, int whence) {
    return (off64_t)lseek(fd, (off_t)offset, whence);
}

int ftruncate64(int fd, off64_t length) {
    return ftruncate(fd, (off_t)length);
}

#endif

/* POSIX record locks (F_GETLK/F_SETLK/F_SETLKW) and the Linux open-file-
 * description variants (F_OFD_*). A run is ONE process, and process-scoped
 * record locks never conflict with locks the same process already holds
 * (POSIX: they are merged, and any close releases them all), so on an open
 * regular fd F_SETLK/F_SETLKW succeed and F_GETLK reports the range as
 * unlocked — exactly what the lone opener sees on the host. Storage engines
 * take such a whole-file lock on every open (turso via rustix fcntl_lock is
 * the live example); left unmodeled, the lock reports ENOSYS and the engine
 * aborts at unlock. OFD locks DO conflict across descriptions inside one
 * process: a whole-file OFD lock routes to the per-inode flock table
 * (shared/exclusive/unlock; non-blocking for F_OFD_SETLK); a byte-range OFD
 * lock and F_OFD_GETLK stay a soft ENOSYS rather than a fabricated answer. */
static int patina_fcntl_record_lock(int fd, int command, struct flock *lock) {
    if (lock == NULL) { errno = EINVAL; return -1; }
    /* Descriptor validity is a RANGE check only (virtual sockets and pipes are
     * rejected above; captured stdio by the range): a record lock is pure
     * bookkeeping that does no I/O, so it must not consult the filesystem
     * driver, whose descriptor lookup is fault-eligible (an injected EIO on
     * fcntl(F_UNLCK) would be a fabricated failure mode — real fcntl locks
     * cannot fail that way). */
    if (fd < 3) { errno = EBADF; return -1; }
    if (lock->l_type != F_RDLCK && lock->l_type != F_WRLCK && lock->l_type != F_UNLCK) {
        errno = EINVAL;
        return -1;
    }
    if (command == F_GETLK) { lock->l_type = F_UNLCK; return 0; }
    if (command == F_SETLK || command == F_SETLKW) return 0;
#ifdef F_OFD_SETLK
    if (command == F_OFD_GETLK) { errno = ENOSYS; return -1; }
    if (!(lock->l_whence == SEEK_SET && lock->l_start == 0 && lock->l_len == 0)) {
        errno = ENOSYS;
        return -1;
    }
    int op = lock->l_type == F_RDLCK ? LOCK_SH : lock->l_type == F_WRLCK ? LOCK_EX : LOCK_UN;
    if (command == F_OFD_SETLK) op |= LOCK_NB;
    return fail_int(patina_flock(fd, op));
#else
    errno = ENOSYS;
    return -1;
#endif
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
#ifdef FIONBIO
    if (request == (unsigned long)FIONBIO && fd >= PATINA_SOCKET_FD_BASE) {
        int on = arg != NULL ? *(int *)arg : 0;
        return patina_net_set_nonblocking(fd, on ? 1 : 0);
    }
#endif
#ifdef FIOCLEX
    if (request == (unsigned long)FIOCLEX) return 0;
#endif
#ifdef FIONCLEX
    if (request == (unsigned long)FIONCLEX) return 0;
#endif
    (void)fd;
    errno = ENOTTY;
    return -1;
}

/*
 * In-process pipe / socketpair (class g, in-process slice). Both endpoints stay
 * inside this one guest process — the common case is an async runtime's own
 * IO-driver / signal self-pipe wakeup — so there is NO cross-address-space
 * escape: they are modeled as deterministic in-memory byte channels wired to the
 * scheduler's wakeup path (see the "in-process pipe / socketpair" section in the
 * Rust shim). Descriptors come from the shared virtual-fd space above, so the
 * interposed read/write/close/fcntl route them to the pipe class via
 * patina_pipe_is_endpoint. eventfd (Linux) is likewise in-process — a single
 * 64-bit counter inside this guest, mio's Waker vehicle — and is interposed as
 * a deterministic counter (see the eventfd section in the Rust shim and the
 * Linux reactor block below). The truly cross-process class-g members
 * (shm_open, the mach_msg / mach_port / mq families) stay refused.
 */
int pipe(int fildes[2]) {
    if (fildes == NULL) {
        errno = EFAULT;
        return -1;
    }
    return fail_int(patina_pipe(&fildes[0], &fildes[1], 0));
}

#ifdef __linux__
/*
 * pipe2 is the Linux flag-taking pipe (macOS has no such symbol). Same
 * deterministic in-process channel as pipe() above, honoring O_NONBLOCK at
 * creation; O_CLOEXEC is accepted-and-ignored (no exec under the runtime),
 * O_DIRECT (packet-mode pipes) is not modeled and fails ENOSYS, and any other
 * flag fails EINVAL.
 */
int pipe2(int pipefd[2], int flags) {
    if (pipefd == NULL) {
        errno = EFAULT;
        return -1;
    }
    int nonblocking = (flags & O_NONBLOCK) ? 1 : 0;
    int remaining = flags & ~O_NONBLOCK;
#ifdef O_CLOEXEC
    remaining &= ~O_CLOEXEC;
#endif
#ifdef O_DIRECT
    if (remaining & O_DIRECT) {
        errno = ENOSYS;
        return -1;
    }
    remaining &= ~O_DIRECT;
#endif
    if (remaining != 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_pipe(&pipefd[0], &pipefd[1], nonblocking));
}
#endif
