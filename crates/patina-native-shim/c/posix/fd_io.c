/*
 * Descriptor I/O: read/write and their positional/vectored forms, close/dup,
 * lseek/fsync/ftruncate/flock, fcntl/ioctl, isatty, pipes, and close_range.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 *
 * Every interposer here is thin marshaling over a universal `patina_*` entry:
 * the guest descriptor number is resolved ONCE, in Rust, against the shim's
 * descriptor table, and the entry dispatches on what the number names. Nothing
 * in this file asks what kind of descriptor it holds -- the SUD rows call the
 * same entries, which is what keeps the libc door and the raw-syscall door
 * byte-identical. The only kind question left to C is the one the platform
 * vocabulary forces: which `fcntl` commands carry a pointer.
 */

/*
 * isatty: whether a descriptor is a terminal is a nondeterministic property of
 * how the run was launched (pipe vs file vs tty), and programs branch on it —
 * search tools, for instance, derive heading/color/line-number defaults from it. A
 * fully interposed guest must never observe host terminal state, so report a
 * deterministic "not a terminal" for every open descriptor: captured guest stdio
 * is never a tty under the runtime, and standard input is a stream at EOF. A
 * number that names nothing is EBADF, as the kernel answers. Interposing here
 * (rather than allow-listing the import) makes guest output provably
 * independent of host tty state instead of merely "neutral given the flags".
 * This is a strong definition, so the guest's isatty reference binds here and
 * the libc symbol drops off the import table.
 */
int isatty(int fd) {
    if (patina_fd_kind(fd) < 0) {
        errno = EBADF;
        return 0;
    }
    errno = ENOTTY;
    return 0;
}

/* The platform's file-status flags <-> the shim's PATINA_O_* status vocabulary,
 * for F_GETFL/F_SETFL. Only the bits the kernel reports through F_GETFL are
 * translated: the access mode, O_APPEND, O_NONBLOCK, and O_PATH. */
static int patina_getfl_to_posix(uint32_t status) {
    int flags;
    int readable = (status & PATINA_O_READ) != 0;
    int writable = (status & PATINA_O_WRITE) != 0;
    if (readable && writable) flags = O_RDWR;
    else if (writable) flags = O_WRONLY;
    else flags = O_RDONLY;
    if (status & PATINA_O_APPEND) flags |= O_APPEND;
    if (status & PATINA_O_NONBLOCK) flags |= O_NONBLOCK;
#ifdef O_PATH
    if (status & PATINA_O_PATH) flags |= O_PATH;
#endif
#ifdef __linux__
    /* A 64-bit kernel forces O_LARGEFILE into every open(2)-minted description
     * (fs/open.c build_open_how) and F_GETFL reports it; the shim's table
     * remembers which those are. glibc defines the O_LARGEFILE macro as 0 on
     * 64-bit targets, so the bit is the kernel's, for this architecture. */
    if (status & PATINA_O_OPENED) flags |= PATINA_KERNEL_O_LARGEFILE;
#endif
    return flags;
}

static uint32_t patina_setfl_from_posix(int flags) {
    uint32_t status = 0;
    if (flags & O_APPEND) status |= PATINA_O_APPEND;
    if (flags & O_NONBLOCK) status |= PATINA_O_NONBLOCK;
    return status;
}

static int patina_fcntl_record_lock(int fd, int command, struct flock *lock);

int fcntl(int fd, int command, ...) {
    /* POSIX record locks (F_GETLK/F_SETLK/F_SETLKW) and the Linux open-file-
     * description variants (F_OFD_*) carry a pointer: see
     * patina_fcntl_record_lock below. Every other modeled command carries an int
     * (or nothing), so the variadic argument is read exactly once, by type. */
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
    va_list ap;
    va_start(ap, command);
    int argument = va_arg(ap, int);
    va_end(ap);
    switch (command) {
        case F_GETFD: {
            int cloexec = patina_fd_getfd(fd);
            if (cloexec < 0) return fail_int(cloexec);
            return cloexec ? FD_CLOEXEC : 0;
        }
        case F_SETFD:
            return fail_int(patina_fd_setfd(fd, (argument & FD_CLOEXEC) != 0));
        case F_GETFL: {
            int status = patina_fd_getfl(fd);
            if (status < 0) return fail_int(status);
            return patina_getfl_to_posix((uint32_t)status);
        }
        case F_SETFL:
            return fail_int(patina_fd_setfl(fd, patina_setfl_from_posix(argument)));
        case F_DUPFD:
            return fail_int(patina_dupfd(fd, argument, 0));
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC:
            return fail_int(patina_dupfd(fd, argument, 1));
#endif
#ifdef F_GETPIPE_SZ
        case F_GETPIPE_SZ:
            return fail_int(patina_pipe_size(fd));
        case F_SETPIPE_SZ:
            return fail_int(patina_pipe_set_size(fd, argument));
#endif
#ifdef F_ADD_SEALS
        case F_ADD_SEALS:
            return fail_int(patina_add_seals(fd, (uint32_t)argument));
        case F_GET_SEALS:
            return fail_int(patina_get_seals(fd));
#endif
#ifdef __APPLE__
        /* Rust std maps File::sync_all to F_FULLFSYNC on Darwin. */
        case F_FULLFSYNC:
            return fail_int(patina_fsync(fd));
#endif
        default:
            break;
    }
    /* An unknown command on an open descriptor is EINVAL; on a closed one the
     * kernel answers EBADF first. */
    if (patina_fd_kind(fd) < 0) {
        errno = EBADF;
        return -1;
    }
    errno = EINVAL;
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
    return fail_size(patina_read(fd, destination, length));
}

ssize_t write(int fd, const void *source, size_t length) {
    return fail_size(patina_write(fd, source, length));
}

/* Positional I/O. Database-style file backends do ALL of their I/O through
 * pread/pwrite (read_exact_at/write_all_at), never seek+read/write, so these
 * must reach the deterministic filesystem or that I/O would bypass the crash
 * model entirely. They route to patina_p{read,write}, which the runtime
 * services as ONE positional operation (atomic w.r.t. the scheduler and cursor-
 * independent), NOT a caller-side seek+read that could interleave under
 * concurrency. A description without offset addressing (a pipe, a socket, the
 * captured streams) is ESPIPE, matching the kernel. */
ssize_t pread(int fd, void *destination, size_t length, off_t offset) {
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}

ssize_t pwrite(int fd, const void *source, size_t length, off_t offset) {
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#ifdef __linux__
/* Large-file positional I/O variants. glibc std lowers positional reads/writes
 * on 64-bit off_t Linux to the *64 symbols (database file backends use them), so
 * they must reach the same deterministic positional I/O as pread/pwrite rather
 * than be denied. off64_t is always 64-bit, so the full offset is preserved. */
ssize_t pread64(int fd, void *destination, size_t length, off64_t offset) {
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}
ssize_t pwrite64(int fd, const void *source, size_t length, off64_t offset) {
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#endif

/* Whole-file advisory lock (a single-opener database takes one via File::try_lock on open).
 * Routed to the runtime's per-description lock table (patina_flock): a lone
 * opener always acquires, but two independent opens of the same file contend
 * exactly as a real flock would (LOCK_EX|LOCK_NB on the second → EWOULDBLOCK,
 * i.e. a database's already-open error), and a dup of the holder can release
 * it. See the "Advisory file lock" row in crates/patina-target/ESCAPE-CLASSES.md. */
int flock(int fd, int operation) {
    return fail_int(patina_flock(fd, operation));
}

int close(int fd) {
    return fail_int(patina_close(fd));
}

int dup(int fd) {
    return fail_int(patina_dup(fd));
}

int dup2(int oldfd, int newfd) {
    return fail_int(patina_dup2(oldfd, newfd));
}

#ifdef __linux__
int dup3(int oldfd, int newfd, int flags) {
    if ((flags & ~O_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_dup3(oldfd, newfd, (flags & O_CLOEXEC) != 0));
}

/* close_range(2), glibc 2.34+. The flags are the kernel's: CLOSE_RANGE_UNSHARE
 * (a no-op with one process) and CLOSE_RANGE_CLOEXEC. Unknown flags and
 * first > last are EINVAL; the range is clamped to the descriptor table. */
int close_range(unsigned int first, unsigned int last, int flags) {
    return fail_int(patina_close_range(first, last, (uint32_t)flags));
}

#endif

/* Vectored I/O: thin marshaling over the one Rust implementation the SUD rows
 * call too (the iovec import, the access-mode and position refusals, the
 * segment-by-segment transfer). Database file backends batch a transaction's
 * WAL frames with ONE pwritev (turso's UnixFile::pwritev is the live example),
 * so these reach the same deterministic positional I/O as pread/pwrite. */
ssize_t writev(int fd, const struct iovec *vectors, int count) {
    return fail_size(patina_writev(fd, vectors, count, 0));
}

ssize_t readv(int fd, const struct iovec *vectors, int count) {
    return fail_size(patina_readv(fd, vectors, count, 0));
}

ssize_t preadv(int fd, const struct iovec *vectors, int count, off_t offset) {
    return fail_size(patina_preadv(fd, vectors, count, (int64_t)offset, 0));
}

ssize_t pwritev(int fd, const struct iovec *vectors, int count, off_t offset) {
    return fail_size(patina_pwritev(fd, vectors, count, (int64_t)offset, 0));
}

#ifdef __linux__
/* Large-file variants, the same way pread64/pwrite64 mirror pread/pwrite. */
ssize_t preadv64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    return fail_size(patina_preadv(fd, vectors, count, (int64_t)offset, 0));
}
ssize_t pwritev64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    return fail_size(patina_pwritev(fd, vectors, count, (int64_t)offset, 0));
}

#endif

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
 * descriptor F_SETLK/F_SETLKW succeed and F_GETLK reports the range as
 * unlocked — exactly what the lone opener sees on the host. Storage engines
 * take such a whole-file lock on every open (turso via rustix fcntl_lock is
 * the live example); left unmodeled, the lock reports ENOSYS and the engine
 * aborts at unlock. OFD locks DO conflict across descriptions inside one
 * process: a whole-file OFD lock routes to the per-description flock table
 * (shared/exclusive/unlock; non-blocking for F_OFD_SETLK); a byte-range OFD
 * lock and F_OFD_GETLK stay a soft ENOSYS rather than a fabricated answer. */
static int patina_fcntl_record_lock(int fd, int command, struct flock *lock) {
    if (lock == NULL) { errno = EINVAL; return -1; }
    /* Descriptor validity is a TABLE check only: a record lock is pure
     * bookkeeping that does no I/O, so it must not consult the filesystem
     * driver, whose descriptor lookup is fault-eligible (an injected EIO on
     * fcntl(F_UNLCK) would be a fabricated failure mode — real fcntl locks
     * cannot fail that way). The kernel's fcntl_setlk then checks the lock
     * type against the description's access mode: a read lock needs a readable
     * description and a write lock a writable one, else EBADF. */
    int status = patina_fd_getfl(fd);
    if (status < 0) { errno = EBADF; return -1; }
    if (lock->l_type != F_RDLCK && lock->l_type != F_WRLCK && lock->l_type != F_UNLCK) {
        errno = EINVAL;
        return -1;
    }
    if (command != F_GETLK
#ifdef F_OFD_GETLK
        && command != F_OFD_GETLK
#endif
    ) {
        if ((lock->l_type == F_RDLCK && !(status & PATINA_O_READ)) ||
            (lock->l_type == F_WRLCK && !(status & PATINA_O_WRITE))) {
            errno = EBADF;
            return -1;
        }
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

/* ioctl: the generic descriptor requests (FIOCLEX/FIONCLEX/FIONBIO/FIONREAD)
 * are answered by the one Rust entry the SUD row calls too; anything else is
 * ENOTTY there. */
int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return fail_int(patina_ioctl(fd, (uint64_t)request, arg));
}

/*
 * In-process pipe / socketpair (class g, in-process slice). Both endpoints stay
 * inside this one guest process — the common case is an async runtime's own
 * IO-driver / signal self-pipe wakeup — so there is NO cross-address-space
 * escape: they are modeled as deterministic in-memory byte channels wired to the
 * scheduler's wakeup path (see the "in-process pipe / socketpair" section in the
 * Rust shim). The two numbers come from the descriptor table like every other,
 * so the interposed read/write/close/fcntl reach the pipe class through the
 * universal entries. eventfd (Linux) is likewise in-process — a single 64-bit
 * counter inside this guest, mio's Waker vehicle — and is interposed as a
 * deterministic counter (see the eventfd section in the Rust shim and the Linux
 * reactor block below). The truly cross-process class-g members (shm_open, the
 * mach_msg / mach_port / mq families) stay refused.
 */
int pipe(int fildes[2]) {
    if (fildes == NULL) {
        errno = EFAULT;
        return -1;
    }
    return fail_int(patina_pipe(&fildes[0], &fildes[1], 0, 0));
}

#ifdef __linux__
/*
 * pipe2 is the Linux flag-taking pipe (macOS has no such symbol). Same
 * deterministic in-process channel as pipe() above, honoring O_NONBLOCK and
 * O_CLOEXEC at creation; O_DIRECT (packet-mode pipes) is not modeled and fails
 * ENOSYS, and any other flag fails EINVAL.
 */
int pipe2(int pipefd[2], int flags) {
    if (pipefd == NULL) {
        errno = EFAULT;
        return -1;
    }
    int nonblocking = (flags & O_NONBLOCK) ? 1 : 0;
    int cloexec = (flags & O_CLOEXEC) ? 1 : 0;
    int remaining = flags & ~(O_NONBLOCK | O_CLOEXEC);
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
    return fail_int(patina_pipe(&pipefd[0], &pipefd[1], nonblocking, cloexec));
}
#endif
