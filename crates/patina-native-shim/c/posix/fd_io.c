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
 * byte-identical. Rust owns fcntl decoding and its platform flag/struct-flock translations.
 */

/*
 * isatty: whether a descriptor is a terminal is a nondeterministic property of
 * how the run was launched (pipe vs file vs tty), and programs branch on it —
 * search tools, for instance, derive heading/color/line-number defaults from it. A
 * fully interposed guest must never observe host terminal state: captured guest
 * stdio is never a tty under the runtime, and standard input is a stream at EOF.
 * On Linux it is glibc's (termios/isatty.c): a TCGETS through the ioctl row's
 * entry succeeds exactly for the virtual machine's own terminals, its
 * pseudoterminals, and anything else answers that row's errno (ENOTTY, EBADF,
 * EINVAL from the entropy device, EIO from a hung-up slave). Darwin has no
 * modeled terminal: "not a terminal" for every open descriptor, EBADF for a
 * number that names nothing. Interposing here (rather than allow-listing the
 * import) makes guest output provably independent of host tty state instead of
 * merely "neutral given the flags". This is a strong definition, so the guest's
 * isatty reference binds here and the libc symbol drops off the import table.
 */
#ifdef __linux__
struct patina_kernel_termios {
    tcflag_t c_iflag, c_oflag, c_cflag, c_lflag;
    cc_t c_line;
    cc_t c_cc[19];
};

/* The one TCGETS both isatty and the stdio buffering choice ask, so the
 * shim never calls the interposable isatty itself. */
static int patina_isatty(int fd) {
    struct patina_kernel_termios kernel;
    return fail_int(patina_ioctl(fd, TCGETS, &kernel)) == 0;
}

int isatty(int fd) {
    return patina_isatty(fd);
}
#else
int isatty(int fd) {
    if (patina_fd_kind(fd) < 0) {
        errno = EBADF;
        return 0;
    }
    errno = ENOTTY;
    return 0;
}
#endif

ssize_t read(int fd, void *destination, size_t length) {
    PATINA_CANCEL_POINT("read");
    return fail_size(patina_read(fd, destination, length));
}

ssize_t write(int fd, const void *source, size_t length) {
    PATINA_CANCEL_POINT("write");
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
    PATINA_CANCEL_POINT("pread");
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}

ssize_t pwrite(int fd, const void *source, size_t length, off_t offset) {
    PATINA_CANCEL_POINT("pwrite");
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

#ifdef __linux__
/* Large-file positional I/O variants. glibc std lowers positional reads/writes
 * on 64-bit off_t Linux to the *64 symbols (database file backends use them), so
 * they must reach the same deterministic positional I/O as pread/pwrite rather
 * than be denied. off64_t is always 64-bit, so the full offset is preserved. */
ssize_t pread64(int fd, void *destination, size_t length, off64_t offset) {
    PATINA_CANCEL_POINT("pread64");
    return fail_size(patina_pread(fd, destination, length, (int64_t)offset));
}
ssize_t pwrite64(int fd, const void *source, size_t length, off64_t offset) {
    PATINA_CANCEL_POINT("pwrite64");
    return fail_size(patina_pwrite(fd, source, length, (int64_t)offset));
}

/* glibc's exported internal names for read and write, which older objects
 * import, and its `_FORTIFY_SOURCE` reads (debug/read_chk.c, pread_chk.c,
 * pread64_chk.c): the plain call once the buffer the compiler knew holds the
 * length asked for (`__chk_fail` otherwise, before any syscall). */
ssize_t __read(int fd, void *destination, size_t length) {
    return fail_size(patina_read(fd, destination, length));
}

ssize_t __write(int fd, const void *source, size_t length) {
    return fail_size(patina_write(fd, source, length));
}

static ssize_t patina_read_chk(int fd, void *destination, size_t length, size_t buflen) {
    if (length > buflen) patina_chk_fail();
    return fail_size(patina_read(fd, destination, length));
}

static ssize_t patina_pread_chk(int fd, void *destination, size_t length, int64_t offset,
                                size_t buflen) {
    if (length > buflen) patina_chk_fail();
    return fail_size(patina_pread(fd, destination, length, offset));
}

ssize_t __read_chk(int fd, void *destination, size_t length, size_t buflen) {
    PATINA_CANCEL_POINT("__read_chk");
    return patina_read_chk(fd, destination, length, buflen);
}

ssize_t __pread_chk(int fd, void *destination, size_t length, off_t offset, size_t buflen) {
    PATINA_CANCEL_POINT("__pread_chk");
    return patina_pread_chk(fd, destination, length, (int64_t)offset, buflen);
}

ssize_t __pread64_chk(int fd, void *destination, size_t length, off64_t offset, size_t buflen) {
    PATINA_CANCEL_POINT("__pread64_chk");
    return patina_pread_chk(fd, destination, length, (int64_t)offset, buflen);
}

/* In-kernel copies: glibc's copy_file_range and sendfile are the bare
 * syscalls, so the wrappers are the rows' one model (src/transfer.rs) with
 * errno set. Rust's std reaches copy_file_range for `fs::copy`/`io::copy`
 * between files. off_t is off64_t on a 64-bit target. */
ssize_t copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t length,
                        unsigned int flags) {
    PATINA_CANCEL_POINT("copy_file_range");
    return fail_size(patina_copy_file_range(fd_in, (int64_t *)off_in, fd_out, (int64_t *)off_out,
                                            length, (uint32_t)flags));
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    return fail_size(patina_sendfile(out_fd, in_fd, (int64_t *)offset, count));
}

/* The LFS spelling `<sys/sendfile.h>` binds under _FILE_OFFSET_BITS=64. */
ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count) {
    return fail_size(patina_sendfile(out_fd, in_fd, (int64_t *)offset, count));
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
    PATINA_CANCEL_POINT("close");
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
    PATINA_CANCEL_POINT("writev");
    return fail_size(patina_writev(fd, vectors, count, 0));
}

ssize_t readv(int fd, const struct iovec *vectors, int count) {
    PATINA_CANCEL_POINT("readv");
    return fail_size(patina_readv(fd, vectors, count, 0));
}

ssize_t preadv(int fd, const struct iovec *vectors, int count, off_t offset) {
    PATINA_CANCEL_POINT("preadv");
    return fail_size(patina_preadv(fd, vectors, count, (int64_t)offset, 0));
}

ssize_t pwritev(int fd, const struct iovec *vectors, int count, off_t offset) {
    PATINA_CANCEL_POINT("pwritev");
    return fail_size(patina_pwritev(fd, vectors, count, (int64_t)offset, 0));
}

#ifdef __linux__
/* Large-file variants, the same way pread64/pwrite64 mirror pread/pwrite. */
ssize_t preadv64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    PATINA_CANCEL_POINT("preadv64");
    return fail_size(patina_preadv(fd, vectors, count, (int64_t)offset, 0));
}
ssize_t pwritev64(int fd, const struct iovec *vectors, int count, off64_t offset) {
    PATINA_CANCEL_POINT("pwritev64");
    return fail_size(patina_pwritev(fd, vectors, count, (int64_t)offset, 0));
}

#endif

off_t lseek(int fd, off_t offset, int whence) {
    uint32_t patina_whence;
    switch (whence) {
        case SEEK_SET: patina_whence = PATINA_SEEK_START; break;
        case SEEK_CUR: patina_whence = PATINA_SEEK_CURRENT; break;
        case SEEK_END: patina_whence = PATINA_SEEK_END; break;
#ifdef SEEK_DATA
        case SEEK_DATA: patina_whence = PATINA_SEEK_DATA; break;
        case SEEK_HOLE: patina_whence = PATINA_SEEK_HOLE; break;
#endif
        default: errno = EINVAL; return (off_t)-1;
    }
    int64_t result = patina_seek(fd, (int64_t)offset, patina_whence);
    if (result < 0) errno = patina_errno();
    return (off_t)result;
}

int fsync(int fd) {
    PATINA_CANCEL_POINT("fsync");
    return fail_int(patina_fsync(fd));
}

#ifdef __linux__
/* fdatasync: databases call it to make committed data durable. The deterministic
 * crash-model FS makes the file durable through the same sync path (it draws no
 * data-vs-metadata distinction), so route it to patina_fsync — a durability
 * guarantee at least as strong as fdatasync's, and deterministic. */
int fdatasync(int fd) {
    PATINA_CANCEL_POINT("fdatasync");
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

#ifdef __linux__
/* glibc's tcgetattr (sysdeps/unix/sysv/linux/tcgetattr.c): TCGETS into the
 * kernel's termios through the same entry the ioctl row takes, then the user
 * struct: the flags and line discipline copied, the kernel's 19 control
 * characters followed by _POSIX_VDISABLE, and both speeds the baud bits of
 * c_cflag. A descriptor that is not a terminal answers the ioctl row's errno
 * and nothing is written. */

int tcgetattr(int fd, struct termios *termios_p) {
    struct patina_kernel_termios kernel;
    if (fail_int(patina_ioctl(fd, TCGETS, &kernel)) != 0) return -1;
    termios_p->c_iflag = kernel.c_iflag;
    termios_p->c_oflag = kernel.c_oflag;
    termios_p->c_cflag = kernel.c_cflag;
    termios_p->c_lflag = kernel.c_lflag;
    termios_p->c_line = kernel.c_line;
    termios_p->c_ispeed = termios_p->c_ospeed = kernel.c_cflag & (CBAUD | CBAUDEX);
    memcpy(termios_p->c_cc, kernel.c_cc, sizeof kernel.c_cc);
    memset(termios_p->c_cc + sizeof kernel.c_cc, _POSIX_VDISABLE,
           sizeof termios_p->c_cc - sizeof kernel.c_cc);
    return 0;
}

/*
 * glibc 2.39's pseudoterminal and terminal-settings functions (Linux), over
 * the same entries the rows take: `/dev/ptmx` through the open entry, the
 * tty requests through `patina_ioctl`. The pairs are the virtual machine's
 * (`src/thread/pty.rs`), so none of this reaches the host's terminals.
 */

/* glibc's private IBAUD0 input-speed bit in c_iflag (termios/speed.c), which
 * tcsetattr strips before the kernel sees the flags. */
#define PATINA_IBAUD0 020000000000u

/* The ioctl's error number, set as errno and answered. */
static int patina_ioctl_error(void) {
    int error = patina_errno();
    errno = error;
    return error;
}

/* glibc's tcsetattr (sysdeps/unix/sysv/linux/tcsetattr.c) as Ubuntu builds
 * 2.39, with Debian's local-tcsetaddr.diff. The settings are read first (a
 * failure is only remembered, in errno); the action picks
 * TCSETS/TCSETSW/TCSETSF (EINVAL for any other), and the user struct becomes
 * the kernel's: the flags less IBAUD0, the line discipline and the first 19
 * control characters. When both requests succeeded the settings are read
 * again (a failure answers 0, errno as it was): if the input flags (IBAUD0
 * aside), the output, control and local flags and the line discipline all
 * read back as they were, and the driver refused the parity or receiver
 * asked for, or a character size other than CS5 (a pty keeps CS8|CREAD
 * without parity), the answer is -1 EINVAL, though the kernel applied the
 * rest. */
static int patina_tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    struct patina_kernel_termios old;
    int old_result = fail_int(patina_ioctl(fd, TCGETS, &old));
    unsigned long command;
    switch (optional_actions) {
        case TCSANOW: command = TCSETS; break;
        case TCSADRAIN: command = TCSETSW; break;
        case TCSAFLUSH: command = TCSETSF; break;
        default: errno = EINVAL; return -1;
    }
    struct patina_kernel_termios kernel;
    kernel.c_iflag = termios_p->c_iflag & ~PATINA_IBAUD0;
    kernel.c_oflag = termios_p->c_oflag;
    kernel.c_cflag = termios_p->c_cflag;
    kernel.c_lflag = termios_p->c_lflag;
    kernel.c_line = termios_p->c_line;
    memcpy(kernel.c_cc, termios_p->c_cc, sizeof kernel.c_cc);
    int result = fail_int(patina_ioctl(fd, command, &kernel));
    if (result != 0 || old_result != 0) return result;
    int saved = errno;
    if (fail_int(patina_ioctl(fd, TCGETS, &kernel)) != 0) {
        errno = saved;
        return 0;
    }
    int unchanged = old.c_oflag == kernel.c_oflag && old.c_lflag == kernel.c_lflag &&
                    old.c_line == kernel.c_line && old.c_cflag == kernel.c_cflag &&
                    (old.c_iflag | PATINA_IBAUD0) == (kernel.c_iflag | PATINA_IBAUD0);
    tcflag_t asked = termios_p->c_cflag;
    int refused = (asked & (PARENB | CREAD)) != (kernel.c_cflag & (PARENB | CREAD)) ||
                  ((asked & CSIZE) != 0 && (asked & CSIZE) != (kernel.c_cflag & CSIZE));
    if (unchanged && refused) {
        errno = EINVAL;
        return -1;
    }
    errno = saved;
    return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    return patina_tcsetattr(fd, optional_actions, termios_p);
}

/* glibc's tcflush: TCFLSH with the queue selector. */
int tcflush(int fd, int queue_selector) {
    return fail_int(patina_ioctl(fd, TCFLSH, (void *)(intptr_t)queue_selector));
}

/* glibc's tcdrain: TCSBRK with a nonzero argument (wait, send no break), a
 * cancellation point. */
int tcdrain(int fd) {
    PATINA_CANCEL_POINT("tcdrain");
    return fail_int(patina_ioctl(fd, TCSBRK, (void *)1));
}

/* glibc's posix_openpt: an open of /dev/ptmx with the caller's flags. */
int posix_openpt(int flags) {
    return patina_openat_impl(AT_FDCWD, "/dev/ptmx", flags, 0);
}

/* A master request (TIOCGPTN, TIOCSPTLCK) that grantpt/unlockpt make: 0, or
 * -1 with errno, ENOTTY spelled as POSIX's EINVAL. */
static int patina_master_request(int fd, unsigned long request, void *arg) {
    if (patina_ioctl(fd, request, arg) == 0) return 0;
    int error = patina_errno();
    errno = error == ENOTTY ? EINVAL : error;
    return -1;
}

/* glibc's grantpt (sysdeps/unix/sysv/linux/grantpt.c): devpts made the node
 * with its owner, group and mode already, so it only checks that the
 * descriptor is a master. */
int grantpt(int fd) {
    unsigned int index;
    return patina_master_request(fd, TIOCGPTN, &index);
}

/* glibc's unlockpt: TIOCSPTLCK with 0. */
int unlockpt(int fd) {
    int unlock = 0;
    return patina_master_request(fd, TIOCSPTLCK, &unlock);
}

/* glibc's ptsname_r: the pair's index (TIOCGPTN; its error number answered),
 * then "/dev/pts/<index>" if the buffer has room for it and its terminator
 * (ERANGE otherwise), errno left as it was. */
static int patina_ptsname_into(int fd, char *buf, size_t buflen) {
    int saved = errno;
    unsigned int index;
    if (patina_ioctl(fd, TIOCGPTN, &index) != 0) return patina_ioctl_error();
    char digits[10];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + index % 10);
        index /= 10;
    } while (index != 0);
    const size_t prefix = sizeof "/dev/pts/" - 1;
    if (buflen < prefix + count + 1) {
        errno = ERANGE;
        return ERANGE;
    }
    memcpy(buf, "/dev/pts/", prefix);
    for (size_t i = 0; i < count; i++) buf[prefix + i] = digits[count - 1 - i];
    buf[prefix + count] = '\0';
    errno = saved;
    return 0;
}

int ptsname_r(int fd, char *buf, size_t buflen) {
    return patina_ptsname_into(fd, buf, buflen);
}

/* glibc's ptsname: ptsname_r into a static buffer, NULL on failure. */
char *ptsname(int fd) {
    static char name[sizeof "/dev/pts/" + 20];
    return patina_ptsname_into(fd, name, sizeof name) == 0 ? name : NULL;
}

/* glibc's ttyname_r (sysdeps/unix/sysv/linux/ttyname_r.c): EINVAL for no
 * buffer, ERANGE for one shorter than "/dev/pts/", the isatty errno for a
 * descriptor that is no terminal; then the name /proc/self/fd reads for it
 * (the virtual machine's: /dev/ptmx for a master, /dev/pts/<index> for a
 * slave). A buffer with room for the name but not its terminator gets it
 * back truncated, which does not stat to the terminal, and glibc's scan of
 * the devices finds no room either: ENODEV. */
static int patina_ttyname_into(int fd, char *buf, size_t buflen) {
    if (buf == NULL) {
        errno = EINVAL;
        return EINVAL;
    }
    if (buflen < sizeof "/dev/pts/") {
        errno = ERANGE;
        return ERANGE;
    }
    struct patina_kernel_termios kernel;
    if (patina_ioctl(fd, TCGETS, &kernel) != 0) return patina_ioctl_error();
    char name[sizeof "/dev/pts/" + 20];
    intptr_t length = patina_pty_name(fd, name, sizeof name);
    if (length < 0) return patina_ioctl_error();
    if ((size_t)length >= buflen) {
        errno = ENODEV;
        return ENODEV;
    }
    memcpy(buf, name, (size_t)length + 1);
    return 0;
}

int ttyname_r(int fd, char *buf, size_t buflen) {
    return patina_ttyname_into(fd, buf, buflen);
}

/* The fortified forms glibc's _FORTIFY_SOURCE calls when the length is not
 * a constant (debug/ptsname_r_chk.c, debug/ttyname_r_chk.c): a length past
 * the buffer's object aborts (`__chk_fail`) before anything else. */
int __ptsname_r_chk(int fd, char *buf, size_t buflen, size_t nreal) {
    if (buflen > nreal) patina_chk_fail();
    return patina_ptsname_into(fd, buf, buflen);
}

int __ttyname_r_chk(int fd, char *buf, size_t buflen, size_t nreal) {
    if (buflen > nreal) patina_chk_fail();
    return patina_ttyname_into(fd, buf, buflen);
}

/* glibc's ttyname: ttyname_r into a static buffer, NULL on failure. */
char *ttyname(int fd) {
    static char name[4096];
    return patina_ttyname_into(fd, name, sizeof name) == 0 ? name : NULL;
}

/* glibc's openpty (login/openpty.c): a master (posix_openpt(O_RDWR)), grantpt,
 * unlockpt, the slave through TIOCGPTPEER (O_RDWR|O_NOCTTY; by name if that
 * fails), the settings (TCSAFLUSH) and window size when given, errors on those
 * ignored, and the slave's name when asked. On failure both descriptors are
 * closed, -1 answered and the out-parameters left as they were. */
int openpty(int *amaster, int *aslave, char *name, const struct termios *termp,
            const struct winsize *winp) {
    char path[sizeof "/dev/pts/" + 20];
    int master = patina_openat_impl(AT_FDCWD, "/dev/ptmx", O_RDWR, 0);
    if (master == -1) return -1;
    int slave = -1;
    unsigned int index;
    int unlock = 0;
    if (patina_master_request(master, TIOCGPTN, &index) != 0) goto fail;
    if (patina_master_request(master, TIOCSPTLCK, &unlock) != 0) goto fail;
    slave = fail_int(patina_ioctl(master, TIOCGPTPEER, (void *)(intptr_t)(O_RDWR | O_NOCTTY)));
    if (slave == -1) {
        if (patina_ptsname_into(master, path, sizeof path) != 0) goto fail;
        slave = patina_openat_impl(AT_FDCWD, path, O_RDWR | O_NOCTTY, 0);
        if (slave == -1) goto fail;
    }
    if (termp != NULL) (void)patina_tcsetattr(slave, TCSAFLUSH, termp);
    if (winp != NULL) (void)patina_ioctl(slave, TIOCSWINSZ, (void *)winp);
    if (name != NULL) {
        if (patina_ptsname_into(master, path, sizeof path) != 0) goto fail;
        memcpy(name, path, strlen(path) + 1);
    }
    *amaster = master;
    *aslave = slave;
    return 0;
fail:
    (void)patina_close(master);
    if (slave != -1) (void)patina_close(slave);
    return -1;
}
#endif

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
