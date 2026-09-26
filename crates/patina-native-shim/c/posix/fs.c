/*
 * Filesystem: the working directory and umask, directory iteration, open/openat
 * and the directory descriptors, metadata (stat/statx/statfs), permissions, and
 * the namespace operations (mkdir/unlink/link/rename/...).
 *
 * Every path here is a (dirfd, path) pair handed to the runtime, whose ONE
 * resolver (`patina_resolve_path` and the entries built on it) applies the
 * working directory, `..`, symlink walking, ENAMETOOLONG/ENOTDIR/ELOOP and the
 * trailing-slash rule identically for this door and the raw-syscall one. This
 * slice only translates the libc spelling: AT_FDCWD onto PATINA_AT_FDCWD, flag
 * words onto the PATINA_O_ and PATINA_RESOLVE_ vocabularies, and struct stat
 * onto the metadata.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * getcwd(3): glibc semantics over the runtime's working directory. A NULL
 * buffer allocates with the guest allocator (size 0: exactly the length, the
 * GNU extension std relies on; otherwise `size` bytes); a non-NULL buffer of
 * size 0 is EINVAL; a buffer too small is ERANGE. The directory's current name
 * is read once into a PATH_MAX buffer so both conventions cost one lookup.
 */
char *getcwd(char *destination, size_t length) {
    if (destination != NULL && length == 0) {
        errno = EINVAL;
        return NULL;
    }
    char current[PATH_MAX];
    intptr_t needed = patina_getcwd(current, sizeof current);
    if (needed < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (destination == NULL) {
        size_t allocate = length == 0 ? (size_t)needed + 1 : length;
        if (allocate < (size_t)needed + 1) {
            errno = ERANGE;
            return NULL;
        }
        char *owned = malloc(allocate);
        if (owned == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        memcpy(owned, current, (size_t)needed + 1);
        return owned;
    }
    if (length < (size_t)needed + 1) {
        errno = ERANGE;
        return NULL;
    }
    memcpy(destination, current, (size_t)needed + 1);
    return destination;
}

int chdir(const char *path) {
    return fail_int(patina_chdir(PATINA_AT_FDCWD, path));
}

int fchdir(int fd) {
    return fail_int(patina_fchdir(fd));
}

mode_t umask(mode_t mask) {
    return (mode_t)patina_umask((uint32_t)mask);
}

char *realpath(const char *restrict path, char *restrict destination) {
    char resolved[PATH_MAX];
    uint32_t kind = 0;
    intptr_t length = patina_resolve_path(PATINA_AT_FDCWD, path, 0, resolved, sizeof resolved, &kind);
    if (length < 0) {
        errno = patina_errno();
        return NULL;
    }
    /* realpath names an EXISTING entry: a resolvable spelling whose final
     * component is missing is ENOENT, as glibc answers. */
    if (kind == 0) {
        errno = ENOENT;
        return NULL;
    }
    // `resolved` now holds the NUL-terminated canonical path. When the caller
    // provides no buffer, malloc the result with the guest allocator so the
    // guest's own free(3) reclaims it (the opendir/closedir ownership model).
    if (destination == NULL) {
        char *owned = malloc((size_t)length + 1);
        if (owned == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        memcpy(owned, resolved, (size_t)length + 1);
        return owned;
    }
    memcpy(destination, resolved, (size_t)length + 1);
    return destination;
}

#ifdef __linux__
/*
 * The directory stream as glibc 2.39 builds it (sysdeps/unix/sysv/linux/
 * opendir.c, readdir64.c, readdir64_r.c, rewinddir.c, telldir.c, seekdir.c,
 * closedir.c): a DIR is its descriptor and a buffer of getdents64 records. Nothing is read at open; a read
 * refills the buffer through the dispatcher's getdents64 row, so the stream
 * reads the directory through its descriptor, shares the descriptor's position
 * with a raw getdents64 and lseek, and fails as they fail.
 */
enum { PATINA_DIR_ALLOCATION = 32768 };

struct patina_dir {
    int fd;
    /* Bytes of records in `data`, and the offset of the next one. */
    size_t size;
    size_t offset;
    /* The last record's d_off: the position telldir answers. */
    off_t filepos;
    _Alignas(struct dirent64) unsigned char data[PATINA_DIR_ALLOCATION];
};

/* On a 64-bit glibc `struct dirent` IS `struct dirent64` (readdir aliases
 * readdir64), and both are the kernel's linux_dirent64 record. */
_Static_assert(sizeof(struct dirent) == sizeof(struct dirent64) &&
                   offsetof(struct dirent, d_name) == offsetof(struct dirent64, d_name),
               "struct dirent is struct dirent64 on a 64-bit glibc");

static DIR *patina_alloc_dir(int fd) {
    struct patina_dir *directory = malloc(sizeof *directory);
    if (directory == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    directory->fd = fd;
    directory->size = 0;
    directory->offset = 0;
    directory->filepos = 0;
    return (DIR *)(void *)directory;
}

/* glibc's opendir: O_RDONLY|O_NDELAY|O_DIRECTORY|O_CLOEXEC, nothing read. */
DIR *opendir(const char *path) {
    int fd = patina_openat(PATINA_AT_FDCWD, path,
                           PATINA_O_READ | PATINA_O_NONBLOCK | PATINA_O_DIRECTORY |
                               PATINA_O_CLOEXEC,
                           0);
    if (fd < 0) {
        errno = patina_errno();
        return NULL;
    }
    DIR *directory = patina_alloc_dir(fd);
    if (directory == NULL) patina_close(fd);
    return directory;
}

/* glibc's fdopendir: fstat (ENOTDIR for anything but a directory), F_GETFL (an
 * O_PATH descriptor opened nothing: EBADF), then FD_CLOEXEC on the adopted
 * descriptor (__alloc_dir), which closedir closes. */
DIR *fdopendir(int fd) {
    struct patina_metadata values;
    if (patina_fd_metadata_full(fd, &values) < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (values.kind != PATINA_ENTRY_DIRECTORY) {
        errno = ENOTDIR;
        return NULL;
    }
    int status = patina_fd_getfl(fd);
    if (status < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (status & PATINA_O_PATH) {
        errno = EBADF;
        return NULL;
    }
    if (patina_fd_setfd(fd, 1) < 0) {
        errno = patina_errno();
        return NULL;
    }
    return patina_alloc_dir(fd);
}

/* The next record, refilling the buffer when it is spent: NULL with *error 0
 * at the end of the directory (getdents64's 0, or the ENOENT of a removed
 * directory POSIX treats as the end), or NULL with the read's errno. */
static struct dirent64 *patina_dir_next(struct patina_dir *directory, int *error) {
    *error = 0;
    if (directory->offset >= directory->size) {
        long bytes = patina_sud_dispatch(SYS_getdents64, (unsigned long)directory->fd,
                                         (uintptr_t)directory->data, sizeof directory->data,
                                         0, 0, 0, 0);
        if (bytes <= 0) {
            if (bytes < 0 && bytes != -ENOENT) *error = (int)-bytes;
            return NULL;
        }
        directory->size = (size_t)bytes;
        directory->offset = 0;
    }
    struct dirent64 *entry = (struct dirent64 *)(void *)&directory->data[directory->offset];
    directory->offset += entry->d_reclen;
    directory->filepos = entry->d_off;
    return entry;
}

/* glibc declares the DIR/dirent parameters nonnull (NULL is caller UB, and
 * -Wnonnull-compare rejects defensive checks), so these trust the contract.
 * At the end a read answers NULL and leaves errno alone. */
struct dirent64 *readdir64(DIR *dirp) {
    int error;
    struct dirent64 *entry = patina_dir_next((struct patina_dir *)(void *)dirp, &error);
    if (error != 0) errno = error;
    return entry;
}

struct dirent *readdir(DIR *dirp) {
    return (struct dirent *)(void *)readdir64(dirp);
}

/* readdir_r and readdir64_r (one function in glibc) copy the record into the
 * caller's entry and return the read's error number (0 and a NULL result at
 * the end). */
static int patina_readdir_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result) {
    int error;
    struct dirent64 *next = patina_dir_next((struct patina_dir *)(void *)dirp, &error);
    if (next == NULL) {
        *result = NULL;
        if (error != 0) errno = error;
        return error;
    }
    memcpy(entry, next, next->d_reclen);
    *result = entry;
    return 0;
}

int readdir_r(DIR *restrict dirp, struct dirent *restrict entry,
              struct dirent **restrict result) {
    return patina_readdir_r(dirp, (struct dirent64 *)(void *)entry,
                            (struct dirent64 **)(void *)result);
}

int readdir64_r(DIR *restrict dirp, struct dirent64 *restrict entry,
                struct dirent64 **restrict result) {
    return patina_readdir_r(dirp, entry, result);
}

/*
 * glibc's getdents64 is the syscall with the length clamped to INT_MAX (the
 * kernel's length checks use an int). This one forwards into the dispatcher's
 * getdents64 row, so the libc wrapper, readdir and a raw getdents64 read one
 * per-descriptor iteration.
 */
ssize_t getdents64(int fd, void *buffer, size_t length) {
    if (length > INT_MAX) length = INT_MAX;
    return dispatch_result(patina_sud_dispatch(SYS_getdents64, (unsigned long)fd,
                                               (uintptr_t)buffer, length, 0, 0, 0, 0));
}

/* closedir answers close's result on the stream's descriptor; a NULL stream
 * is EINVAL, glibc's own check (the empty asm keeps the test the header's
 * nonnull declaration would let the compiler drop). */
int closedir(DIR *dirp) {
    __asm__("" : "+r"(dirp));
    if (dirp == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = ((struct patina_dir *)(void *)dirp)->fd;
    free(dirp);
    return fail_int(patina_close(fd));
}

/* rewinddir seeks the descriptor back to the start and drops the buffer;
 * seekdir seeks it to a position telldir answered. */
static void patina_dir_seek(DIR *dirp, long position) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    (void)patina_seek(directory->fd, position, SEEK_SET);
    directory->size = 0;
    directory->offset = 0;
    directory->filepos = position;
}

void rewinddir(DIR *dirp) {
    patina_dir_seek(dirp, 0);
}

void seekdir(DIR *dirp, long position) {
    patina_dir_seek(dirp, position);
}

long telldir(DIR *dirp) {
    return (long)((struct patina_dir *)(void *)dirp)->filepos;
}

int dirfd(DIR *dirp) {
    return ((struct patina_dir *)(void *)dirp)->fd;
}

#else
/* Darwin's directory stream: a snapshot of the listing, taken at open. */
struct patina_dir {
    void *state;
    /* Every DIR owns a virtual directory descriptor, which closedir releases:
     * opendir mints one (as a real opendir does, which is what makes dirfd()
     * meaningful on it), fdopendir takes ownership of the caller's (POSIX). The
     * snapshot is read THROUGH it, so iteration is a read of the descriptor and
     * not a second lookup of a name. */
    int owned_fd;
    struct dirent entry;
};

static unsigned char patina_dirent_type(uint32_t kind) {
    switch (kind) {
        case PATINA_ENTRY_DIRECTORY: return DT_DIR;
        case PATINA_ENTRY_SYMLINK: return DT_LNK;
        case PATINA_ENTRY_FIFO: return DT_FIFO;
        case PATINA_ENTRY_SOCKET: return DT_SOCK;
        case PATINA_ENTRY_CHAR: return DT_CHR;
        case PATINA_ENTRY_FILE:
        default: return DT_REG;
    }
}

static void patina_fill_dirent_common(struct dirent *entry, uint64_t ino, uint32_t kind) {
    entry->d_ino = (ino_t)ino;
    entry->d_reclen = (unsigned short)sizeof *entry;
    entry->d_namlen = (uint8_t)strlen(entry->d_name);
    entry->d_type = patina_dirent_type(kind);
}

/*
 * opendir: open the directory, THEN read it through that descriptor -- what a
 * real opendir does (open(path, O_RDONLY|O_DIRECTORY) followed by getdents). It
 * costs the `r` the driver charges at open, dirfd() on the result is a real
 * descriptor, and a rename under the iteration cannot redirect it.
 */
DIR *opendir(const char *path) {
    /* glibc opens the directory O_CLOEXEC, and so does this. */
    int fd = patina_openat(PATINA_AT_FDCWD, path,
                           PATINA_O_READ | PATINA_O_DIRECTORY | PATINA_O_CLOEXEC, 0);
    if (fd < 0) {
        errno = patina_errno();
        return NULL;
    }
    void *state = NULL;
    if (patina_read_dir(fd, &state) != 0) {
        int saved = patina_errno();
        patina_close(fd);
        errno = saved;
        return NULL;
    }
    struct patina_dir *directory = calloc(1, sizeof *directory);
    if (directory == NULL) {
        patina_read_dir_free(state);
        patina_close(fd);
        errno = ENOMEM;
        return NULL;
    }
    directory->state = state;
    directory->owned_fd = fd;
    return (DIR *)(void *)directory;
}

/*
 * fdopendir: build the same DIR opendir builds, but from the directory a virtual
 * dir fd is bound to, and TRANSFER the fd's ownership into the DIR (POSIX: the
 * descriptor is closed by closedir, not the caller). std's remove_dir_all opens
 * each directory with openat(..., O_DIRECTORY) and hands the fd here, then reads
 * entries and removes children through unlinkat(dirfd, ...). The entry snapshot
 * is taken now, exactly like opendir, so iteration is stable across the removals.
 */
DIR *fdopendir(int fd) {
    void *state = NULL;
    if (patina_read_dir(fd, &state) != 0) {
        errno = patina_errno();
        return NULL;
    }
    struct patina_dir *directory = calloc(1, sizeof *directory);
    if (directory == NULL) {
        patina_read_dir_free(state);
        errno = ENOMEM;
        return NULL;
    }
    directory->state = state;
    directory->owned_fd = fd;
    return (DIR *)(void *)directory;
}

/* glibc declares the DIR/dirent parameters nonnull (NULL is caller UB, and
 * -Wnonnull-compare rejects defensive checks), so these trust the contract. */
struct dirent *readdir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    uint32_t kind = 0;
    uint64_t ino = 0;
    int result = patina_read_dir_next(directory->state, directory->entry.d_name,
                                      sizeof directory->entry.d_name, &kind, &ino);
    if (result < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (result == 0) return NULL;
    patina_fill_dirent_common(&directory->entry, ino, kind);
    return &directory->entry;
}

int readdir_r(DIR *restrict dirp, struct dirent *restrict entry,
              struct dirent **restrict result) {
    errno = 0;
    struct dirent *next = readdir(dirp);
    if (next == NULL) {
        *result = NULL;
        return errno;
    }
    memcpy(entry, next, sizeof *entry);
    *result = entry;
    return 0;
}

int closedir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    patina_read_dir_free(directory->state);
    /* POSIX: closedir releases the descriptor the DIR owns -- the one opendir
     * minted or the one fdopendir took ownership of. */
    patina_close(directory->owned_fd);
    free(directory);
    return 0;
}

void rewinddir(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    void *state = NULL;
    if (patina_read_dir(directory->owned_fd, &state) != 0) {
        errno = patina_errno();
        return;
    }
    patina_read_dir_free(directory->state);
    directory->state = state;
}

int dirfd(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    return directory->owned_fd;
}

#endif

/*
 * symlinkat/readlinkat and their AT_FDCWD spellings. symlinkat resolves only
 * the LINK side: a symlink's target is a string the filesystem stores verbatim,
 * never a path this call resolves -- which is why the syscall takes one dirfd
 * and not two. The raw-syscall rows were modeled from the start; without these
 * a libc-backend guest that works through a directory descriptor (cap-std with
 * the libc backend, or any std program on a platform without
 * syscall-user-dispatch) had no path to them at all and failed closed at the
 * audit.
 */
int symlink(const char *target, const char *link_path) {
    return fail_int(patina_symlink(target, PATINA_AT_FDCWD, link_path));
}

int symlinkat(const char *target, int dirfd, const char *link_path) {
    return fail_int(patina_symlink(target, patina_at(dirfd), link_path));
}

ssize_t readlink(const char *restrict path, char *restrict destination, size_t length) {
    return fail_size(patina_read_link(PATINA_AT_FDCWD, path, destination, length));
}

ssize_t readlinkat(int dirfd, const char *restrict path, char *restrict destination,
                   size_t length) {
    return fail_size(patina_read_link(patina_at(dirfd), path, destination, length));
}

#ifdef __linux__
/* glibc's `_FORTIFY_SOURCE` readlinks (debug/readlink_chk.c,
 * readlinkat_chk.c): the plain call once the buffer the compiler knew holds
 * the length asked for (`__chk_fail` otherwise, before any syscall). */
static ssize_t patina_readlink_chk(const char *path, char *destination, size_t length,
                                   size_t buflen) {
    if (length > buflen) patina_chk_fail();
    return fail_size(patina_read_link(PATINA_AT_FDCWD, path, destination, length));
}

static ssize_t patina_readlinkat_chk(int dirfd, const char *path, char *destination,
                                     size_t length, size_t buflen) {
    if (length > buflen) patina_chk_fail();
    return fail_size(patina_read_link(patina_at(dirfd), path, destination, length));
}

ssize_t __readlink_chk(const char *path, char *destination, size_t length, size_t buflen) {
    return patina_readlink_chk(path, destination, length, buflen);
}

ssize_t __readlinkat_chk(int dirfd, const char *path, char *destination, size_t length,
                         size_t buflen) {
    return patina_readlinkat_chk(dirfd, path, destination, length, buflen);
}
#endif

/*
 * link/linkat: create a hard link. std::fs::hard_link lowers to
 * linkat(AT_FDCWD, original, AT_FDCWD, link, 0) on Linux and macOS.
 * AT_SYMLINK_FOLLOW is the only defined flag: when set, `from`'s trailing
 * symlink is resolved before linking, so the link targets the resolved file
 * rather than duplicating the symlink -- the runtime's link duplicates a
 * symlink entry as-is, which is precisely the no-AT_SYMLINK_FOLLOW behavior.
 * Any other flag bit is EINVAL rather than silently ignored.
 */
int link(const char *from, const char *to) {
    return fail_int(patina_link(PATINA_AT_FDCWD, from, PATINA_AT_FDCWD, to, 0));
}

int linkat(int fromfd, const char *from, int tofd, const char *to, int flags) {
    if ((flags & ~AT_SYMLINK_FOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_link(patina_at(fromfd), from, patina_at(tofd), to,
                                (flags & AT_SYMLINK_FOLLOW) != 0));
}

/*
 * open/openat/creat and the LFS aliases: decode the libc flag word onto the
 * runtime's PATINA_O_* vocabulary and hand the (dirfd, path) pair to the one
 * openat entry, which resolves it, decides the descriptor's kind from the
 * entry's, and applies the umask to a creating mode. A flag outside the modeled
 * set fails closed (ENOSYS) rather than being silently dropped.
 *
 * `mode` is the caller's creation mode -- open(2)'s third argument. POSIX says
 * the kernel reads it only when the flags can create the entry, and the
 * variadic argument is UNDEFINED otherwise, so every caller here passes 0
 * unless it saw O_CREAT and read a real `mode_t`. An open of an EXISTING file
 * must not touch that file's mode, which is the driver's rule, not a rule this
 * layer can enforce -- so the honest thing to hand it is the caller's request
 * and nothing invented.
 */
static int patina_openat_impl(int dirfd, const char *path, int flags, mode_t mode) {
    patina_note_boundary_symbol("open");
    int supported = O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | O_EXCL;
#ifdef O_CLOEXEC
    supported |= O_CLOEXEC;
#endif
#ifdef O_LARGEFILE
    supported |= O_LARGEFILE;
#endif
#ifdef O_NOFOLLOW
    supported |= O_NOFOLLOW;
#endif
#ifdef O_DIRECTORY
    supported |= O_DIRECTORY;
#endif
#ifdef O_PATH
    supported |= O_PATH;
#endif
    /* O_NONBLOCK changes the open of exactly one modeled kind -- a FIFO, where
     * it turns the rendezvous with the opposite end into an immediate answer.
     * On a regular file or a directory it is the no-op it is on every Unix, and
     * callers add it defensively there. */
#ifdef O_NONBLOCK
    supported |= O_NONBLOCK;
#endif
    if ((flags & ~supported) != 0) {
        errno = ENOSYS;
        return -1;
    }
    uint32_t patina_flags = 0;
    int path_only = 0;
#ifdef O_PATH
    /* O_PATH ignores the access mode entirely -- it opens nothing, so there is
     * nothing to ask for. */
    if (flags & O_PATH) {
        path_only = 1;
        patina_flags |= PATINA_O_PATH;
    }
#endif
    if (!path_only) {
        switch (flags & O_ACCMODE) {
            case O_RDONLY: patina_flags |= PATINA_O_READ; break;
            case O_WRONLY: patina_flags |= PATINA_O_WRITE; break;
            case O_RDWR: patina_flags |= PATINA_O_READ | PATINA_O_WRITE; break;
            default: errno = EINVAL; return -1;
        }
        if (flags & O_CREAT) patina_flags |= PATINA_O_CREATE;
        if (flags & O_TRUNC) patina_flags |= PATINA_O_TRUNCATE;
        if (flags & O_APPEND) patina_flags |= PATINA_O_APPEND;
        if (flags & O_EXCL) patina_flags |= PATINA_O_EXCLUSIVE;
    }
#ifdef O_NOFOLLOW
    if (flags & O_NOFOLLOW) patina_flags |= PATINA_O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    if (flags & O_NONBLOCK) patina_flags |= PATINA_O_NONBLOCK;
#endif
#ifdef O_CLOEXEC
    if (flags & O_CLOEXEC) patina_flags |= PATINA_O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY) patina_flags |= PATINA_O_DIRECTORY;
#endif
    return fail_int(patina_openat(patina_at(dirfd), path, patina_flags, (uint32_t)(mode & 07777)));
}

/*
 * Read open(2)'s variadic creation mode. Only ever called when the flags say
 * the kernel would read it: a variadic argument that was never passed is
 * undefined behavior to fetch, so the O_CREAT test guards every call site.
 */
static mode_t patina_open_mode(va_list *ap) {
    return (mode_t)va_arg(*ap, unsigned int);
}

static int patina_openat_variadic(int dirfd, const char *path, int flags, va_list *ap) {
    mode_t mode = 0;
    if (flags & O_CREAT) mode = patina_open_mode(ap);
    return patina_openat_impl(dirfd, path, flags, mode);
}

int open(const char *path, int flags, ...) {
    PATINA_CANCEL_POINT("open");
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(AT_FDCWD, path, flags, &ap);
    va_end(ap);
    return result;
}

/*
 * openat: the dirfd-relative spelling. rustix's libc backend lowers its `fs`
 * calls onto these on both platforms, so they are strong defs in the common
 * section rather than Apple-only.
 */
int openat(int dirfd, const char *path, int flags, ...) {
    PATINA_CANCEL_POINT("openat");
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(dirfd, path, flags, &ap);
    va_end(ap);
    return result;
}

/*
 * `creat(path, mode)` is exactly `open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)`, so
 * route it through the deterministic filesystem like `open`, mode and all. A raw
 * host `creat` would write the real filesystem; interposing keeps it in the
 * deterministic FS. Being a strong def it also drops off the guest import table.
 */
int creat(const char *path, mode_t mode) {
    PATINA_CANCEL_POINT("creat");
    return patina_openat_impl(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

#ifdef __linux__
int open64(const char *path, int flags, ...) {
    PATINA_CANCEL_POINT("open64");
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(AT_FDCWD, path, flags, &ap);
    va_end(ap);
    return result;
}

/* glibc's LFS alias of openat (rustix's libc backend lowers its fs calls onto
 * the *64 names on 64-bit Linux). */
int openat64(int dirfd, const char *path, int flags, ...) {
    PATINA_CANCEL_POINT("openat64");
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(dirfd, path, flags, &ap);
    va_end(ap);
    return result;
}

/* glibc's exported internal names for open, which older objects import. */
int __open(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(AT_FDCWD, path, flags, &ap);
    va_end(ap);
    return result;
}

int __open64(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(AT_FDCWD, path, flags, &ap);
    va_end(ap);
    return result;
}

/* glibc's `_FORTIFY_SOURCE` opens (io/open_2.c, open64_2.c, openat_2.c,
 * openat64_2.c): the compiler saw the call pass no mode, so a flag word that
 * needs one (`O_CREAT`, or all of `O_TMPFILE`) is `__fortify_fail`, naming the
 * call, before any syscall; otherwise the plain open. */
static int patina_open_needs_mode(int flags) {
    return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE;
}

static int patina_open_2(const char *path, int flags) {
    if (patina_open_needs_mode(flags))
        patina_fortify_fail("invalid open call: O_CREAT or O_TMPFILE without mode");
    return patina_openat_impl(AT_FDCWD, path, flags, 0);
}

static int patina_open64_2(const char *path, int flags) {
    if (patina_open_needs_mode(flags))
        patina_fortify_fail("invalid open64 call: O_CREAT or O_TMPFILE without mode");
    return patina_openat_impl(AT_FDCWD, path, flags, 0);
}

static int patina_openat_2(int dirfd, const char *path, int flags) {
    if (patina_open_needs_mode(flags))
        patina_fortify_fail("invalid openat call: O_CREAT or O_TMPFILE without mode");
    return patina_openat_impl(dirfd, path, flags, 0);
}

static int patina_openat64_2(int dirfd, const char *path, int flags) {
    if (patina_open_needs_mode(flags))
        patina_fortify_fail("invalid openat64 call: O_CREAT or O_TMPFILE without mode");
    return patina_openat_impl(dirfd, path, flags, 0);
}

int __open_2(const char *path, int flags) {
    PATINA_CANCEL_POINT("__open_2");
    return patina_open_2(path, flags);
}
int __open64_2(const char *path, int flags) {
    PATINA_CANCEL_POINT("__open64_2");
    return patina_open64_2(path, flags);
}
int __openat_2(int dirfd, const char *path, int flags) {
    PATINA_CANCEL_POINT("__openat_2");
    return patina_openat_2(dirfd, path, flags);
}
int __openat64_2(int dirfd, const char *path, int flags) {
    PATINA_CANCEL_POINT("__openat64_2");
    return patina_openat64_2(dirfd, path, flags);
}

#endif

/*
 * st_mode is the entry's file-type bits ORed with its permission bits. The two
 * arrive separately from the deterministic filesystem (`kind` and `mode`)
 * because they are separate facts there: the kind is structural, the mode is
 * mutable state chmod changes.
 */
static mode_t patina_stat_mode(const struct patina_metadata *values) {
    mode_t type;
    switch (values->kind) {
        case PATINA_ENTRY_DIRECTORY: type = S_IFDIR; break;
        case PATINA_ENTRY_SYMLINK: type = S_IFLNK; break;
        case PATINA_ENTRY_FIFO: type = S_IFIFO; break;
        case PATINA_ENTRY_SOCKET: type = S_IFSOCK; break;
        case PATINA_ENTRY_CHAR: type = S_IFCHR; break;
        case PATINA_ENTRY_FILE:
        default: type = S_IFREG; break;
    }
    return type | (mode_t)(values->mode & 07777);
}

/* The device a PATINA_FS_* filesystem reports (st_dev, stx_dev_*). */
static void patina_fs_device(uint32_t fs, unsigned *major, unsigned *minor) {
    switch (fs) {
        case PATINA_FS_PIPEFS:
            *major = 0;
            *minor = PATINA_PIPEFS_DEV_MINOR;
            break;
        case PATINA_FS_SOCKFS:
            *major = 0;
            *minor = PATINA_SOCKFS_DEV_MINOR;
            break;
        case PATINA_FS_VOLUME:
        default:
            *major = PATINA_VOLUME_DEV_MAJOR;
            *minor = PATINA_VOLUME_DEV_MINOR;
            break;
    }
}

/* The libc's own dev_t encoding of (major, minor), spelled out rather than
 * through glibc's makedev, which is an out-of-line import (gnu_dev_makedev). */
static dev_t patina_st_dev(const struct patina_metadata *values) {
    unsigned major, minor;
    patina_fs_device(values->fs, &major, &minor);
#ifdef __APPLE__
    return (dev_t)((major << 24) | minor);
#else
    uint64_t major64 = major, minor64 = minor;
    return (dev_t)(((major64 & 0xfffff000u) << 32) | ((major64 & 0xfffu) << 8) |
                   ((minor64 & 0xffffff00u) << 12) | (minor64 & 0xffu));
#endif
}

static void patina_split_nanos(uint64_t nanos, time_t *seconds, long *subseconds) {
    *seconds = (time_t)(nanos / UINT64_C(1000000000));
    *subseconds = (long)(nanos % UINT64_C(1000000000));
}

/* The virtual volume's block geometry, the same 4 KiB the statfs profile
 * reports: st_blksize, and st_blocks in the 512-byte units stat(2) counts. */
#define PATINA_STAT_BLOCK_SIZE UINT64_C(4096)
static uint64_t patina_stat_blocks(uint64_t length) {
    return ((length + PATINA_STAT_BLOCK_SIZE - 1) / PATINA_STAT_BLOCK_SIZE) *
           (PATINA_STAT_BLOCK_SIZE / 512);
}

/*
 * The by-path metadata read every stat-family interposer shares: (dirfd, path)
 * resolved by the runtime with `resolve_flags` (PATINA_RESOLVE_NOFOLLOW for the
 * lstat spellings). Sets errno on failure.
 */
static int patina_metadata_values(int dirfd, const char *path, uint32_t resolve_flags,
                                  struct patina_metadata *values) {
    int result = patina_metadata_at(dirfd, path, resolve_flags, values);
    if (result < 0) errno = patina_errno();
    return result;
}

static int patina_fd_metadata_values(int fd, struct patina_metadata *values) {
    int result = patina_fd_metadata_full(fd, values);
    if (result < 0) errno = patina_errno();
    return result;
}

/*
 * struct stat from a metadata record: the kind and permission bits as st_mode,
 * the owner from the one modeled identity, all three POSIX timestamps from the
 * record's own (ctime is the inode change time, never a copy of mtime), and
 * the virtual volume's block geometry.
 */
static int fill_stat(int result, const struct patina_metadata *values, struct stat *status) {
    if (result < 0) return -1;
    /* The kernel's copy-out to a NULL buffer faults. */
    if (status == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_stat_mode(values);
    status->st_dev = patina_st_dev(values);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino_t)values->ino;
    status->st_size = (off_t)values->length;
    status->st_uid = (uid_t)patina_uid();
    status->st_gid = (gid_t)patina_gid();
    status->st_blksize = (blksize_t)PATINA_STAT_BLOCK_SIZE;
    status->st_blocks = (blkcnt_t)patina_stat_blocks(values->length);
#ifdef __APPLE__
    patina_split_nanos(values->atime_nanos, &status->st_atimespec.tv_sec,
                       &status->st_atimespec.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtimespec.tv_sec,
                       &status->st_mtimespec.tv_nsec);
    patina_split_nanos(values->ctime_nanos, &status->st_ctimespec.tv_sec,
                       &status->st_ctimespec.tv_nsec);
    patina_split_nanos(values->btime_nanos, &status->st_birthtimespec.tv_sec,
                       &status->st_birthtimespec.tv_nsec);
#else
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->ctime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
#endif
    return 0;
}

/* Portability shims for the *at* flag bits Linux defines and other platforms do
 * not: defined as 0 so a platform without the bit can never match it. */
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0
#endif
#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0
#endif

/* The errno for an *at flag outside the modeled set. On Linux each modeled set
 * is every bit the kernel accepts, so the rest are the kernel's EINVAL. Darwin
 * defines bits that are not modeled (AT_SYMLINK_NOFOLLOW_ANY, AT_REALDEV,
 * AT_FDONLY, AT_REMOVEDIR_DATALESS), and those fail closed. */
#ifdef __linux__
#define PATINA_AT_FLAG_REFUSAL EINVAL
#else
#define PATINA_AT_FLAG_REFUSAL ENOSYS
#endif

/*
 * Resolve the addressing forms the *at* metadata entries accept onto the same
 * virtual metadata the `stat` family answers from, so one helper serves
 * `fstatat`, `fstatat64` and `statx`:
 *
 *   AT_EMPTY_PATH with an empty path on a descriptor -> the DESCRIPTOR's own
 *   metadata (Rust's `File::metadata()` on Linux is exactly
 *   `statx(fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, ...)`, so refusing it
 *   refused the most common metadata call in the ecosystem);
 *   AT_EMPTY_PATH with an empty path on AT_FDCWD -> the working directory;
 *   everything else -> the resolved path, with AT_SYMLINK_NOFOLLOW naming a
 *   trailing symlink itself.
 *
 * The flags are the ones the Linux kernel's vfs_statx accepts for both calls
 * (fs/stat.c). The AT_STATX_SYNC_* bits only choose how fresh a network
 * filesystem's answer must be; a virtual filesystem is always exact, so they
 * change nothing.
 */
#define PATINA_STAT_AT_FLAGS \
    (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE)

static int patina_stat_at_values(int directory, const char *path, int flags,
                                 struct patina_metadata *values) {
    if ((flags & ~PATINA_STAT_AT_FLAGS) != 0) {
        errno = PATINA_AT_FLAG_REFUSAL;
        return -1;
    }
    uint32_t resolve_flags = 0;
    if ((flags & AT_SYMLINK_NOFOLLOW) != 0) resolve_flags |= PATINA_RESOLVE_NOFOLLOW;
    if ((flags & AT_EMPTY_PATH) != 0) {
        resolve_flags |= PATINA_RESOLVE_EMPTY_PATH;
        if (directory != AT_FDCWD && (path == NULL || path[0] == '\0')) {
            return patina_fd_metadata_values(directory, values);
        }
    }
    return patina_metadata_values(patina_at(directory), path, resolve_flags, values);
}

/*
 * Existence and permission probe. The guest is one non-root identity (what
 * patina_uid reports) owning every modeled entry, so the answer reads the OWNER
 * triad of the entry's modeled permission bits — X_OK included: the bit is a
 * mode fact the kernel answers from, and whether anything can actually execute
 * is the process family's business (exec itself stays a trap).
 */
static int patina_access_impl(int dirfd, const char *path, int mode) {
    struct patina_metadata values;
    if (patina_metadata_values(dirfd, path, 0, &values) < 0) return -1;
    unsigned owner = (values.mode >> 6) & 07;
    unsigned wanted = 0;
    if ((mode & R_OK) != 0) wanted |= 04;
    if ((mode & W_OK) != 0) wanted |= 02;
    if ((mode & X_OK) != 0) wanted |= 01;
    if ((owner & wanted) != wanted) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

/*
 * chmod/fchmod/fchmodat. The deterministic filesystem owns the mode, so these
 * are real interposers rather than a host escape: patina_chmod applies the
 * trailing-symlink rule (without NOFOLLOW the link's TARGET changes, with it a
 * link is EOPNOTSUPP, exactly as Linux answers) and patina_fchmod names the
 * node a descriptor already holds. The variadic-free signatures match POSIX, so
 * all three drop off a shim-linked guest's import table.
 */
int chmod(const char *path, mode_t mode) {
    return fail_int(patina_chmod(PATINA_AT_FDCWD, path, (uint32_t)mode, 0));
}

int fchmod(int fd, mode_t mode) {
    return fail_int(patina_fchmod(fd, (uint32_t)mode));
}

int fchmodat(int directory, const char *path, mode_t mode, int flags) {
    if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t resolve_flags = (flags & AT_SYMLINK_NOFOLLOW) != 0 ? PATINA_RESOLVE_NOFOLLOW : 0;
    if ((flags & AT_EMPTY_PATH) != 0) resolve_flags |= PATINA_RESOLVE_EMPTY_PATH;
    return fail_int(patina_chmod(patina_at(directory), path, (uint32_t)mode, resolve_flags));
}

/*
 * mkfifo/mkfifoat, and the mknod pair that glibc's mkfifo is sometimes a thin
 * wrapper over. The type decision, the refusals and their order are the one
 * Rust entry the SUD mknodat row calls too.
 */
int mkfifo(const char *path, mode_t mode) {
    return fail_int(patina_mkfifo(PATINA_AT_FDCWD, path, (uint32_t)mode));
}

int mkfifoat(int directory, const char *path, mode_t mode) {
    return fail_int(patina_mkfifo(patina_at(directory), path, (uint32_t)mode));
}

/* glibc's __mknodat: the kernel takes a 32-bit device word, so a dev_t that
 * does not fit is EINVAL before the call. */
static int patina_mknod_impl(int dirfd, const char *path, mode_t mode, dev_t device) {
    uint32_t kernel_device = (uint32_t)device;
    if ((dev_t)kernel_device != device) {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_mknod(dirfd, path, (uint32_t)mode, kernel_device));
}

int mknod(const char *path, mode_t mode, dev_t device) {
    return patina_mknod_impl(PATINA_AT_FDCWD, path, mode, device);
}

int mknodat(int directory, const char *path, mode_t mode, dev_t device) {
    return patina_mknod_impl(patina_at(directory), path, mode, device);
}

int access(const char *path, int mode) {
    return patina_access_impl(PATINA_AT_FDCWD, path, mode);
}

int faccessat(int directory, const char *path, int mode, int flags) {
    /* AT_EACCESS only chooses effective vs real ids, which are the same single
     * identity here; AT_SYMLINK_NOFOLLOW would probe the link itself, which the
     * virtual filesystem does not distinguish for permissions. */
    int allowed = 0;
#ifdef AT_EACCESS
    allowed |= AT_EACCESS;
#endif
    allowed |= AT_SYMLINK_NOFOLLOW;
    if ((flags & ~allowed) != 0) {
        errno = EINVAL;
        return -1;
    }
    return patina_access_impl(patina_at(directory), path, mode);
}

int stat(const char *path, struct stat *status) {
    struct patina_metadata values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values);
    return fill_stat(result, &values, status);
}

int lstat(const char *path, struct stat *status) {
    struct patina_metadata values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, PATINA_RESOLVE_NOFOLLOW, &values);
    return fill_stat(result, &values, status);
}

int fstat(int fd, struct stat *status) {
    struct patina_metadata values;
    int result = patina_fd_metadata_values(fd, &values);
    return fill_stat(result, &values, status);
}

int fstatat(int directory, const char *restrict path, struct stat *restrict status, int flags) {
    struct patina_metadata values;
    int result = patina_stat_at_values(directory, path, flags, &values);
    return fill_stat(result, &values, status);
}

#ifdef __linux__
/* Filesystem-level metadata (statfs/fstatfs): the one description the SUD
 * rows answer too. glibc's `struct statfs` and `struct statfs64` are the
 * kernel's 64-bit layout on every 64-bit target, so the entry fills the
 * caller's struct directly. Storage engines probe this to decide whether a
 * path's filesystem supports their multi-process coordination (turso's
 * shared-WAL probe on every open is the live example). */
int statfs(const char *path, struct statfs *out) {
    return fail_int(patina_statfs(path, out));
}
int statfs64(const char *path, struct statfs64 *out) {
    return fail_int(patina_statfs(path, out));
}
int fstatfs(int fd, struct statfs *out) {
    return fail_int(patina_fstatfs(fd, out));
}
int fstatfs64(int fd, struct statfs64 *out) {
    return fail_int(patina_fstatfs(fd, out));
}

/* glibc's POSIX spelling of the same description, statvfs/fstatvfs and the
 * LFS statvfs64/fstatvfs64 (sysdeps/unix/sysv/linux/statvfs.c, fstatvfs.c,
 * internal_statvfs.c): statfs(2), then glibc's conversion. `f_frsize` falls
 * back to `f_bsize`; `f_fsid` packs statfs's two words, the second high;
 * `f_favail` is `f_ffree`; `f_flag` is the mount flags statfs reports with
 * `ST_VALID` cleared; `f_type` (new in glibc 2.39) is statfs's. `struct statvfs` and `struct statvfs64` share one layout
 * on a 64-bit target, as `struct statfs` and `struct statfs64` do. */
/* statfs(2)'s "f_flags is valid" bit (linux/statfs.h has no userspace name). */
#define PATINA_ST_VALID 0x0020

static int patina_statvfs_from(int result, const struct statfs *fs, struct statvfs *out) {
    if (result < 0) return fail_int(result);
    memset(out, 0, sizeof *out);
    out->f_bsize = (unsigned long)fs->f_bsize;
    out->f_frsize = (unsigned long)(fs->f_frsize != 0 ? fs->f_frsize : fs->f_bsize);
    out->f_blocks = fs->f_blocks;
    out->f_bfree = fs->f_bfree;
    out->f_bavail = fs->f_bavail;
    out->f_files = fs->f_files;
    out->f_ffree = fs->f_ffree;
    out->f_favail = fs->f_ffree;
    out->f_fsid = ((unsigned long)(unsigned int)fs->f_fsid.__val[1] << 32) |
                  (unsigned long)(unsigned int)fs->f_fsid.__val[0];
    out->f_flag = (unsigned long)(fs->f_flags ^ PATINA_ST_VALID);
    out->f_namemax = (unsigned long)fs->f_namelen;
    out->f_type = (unsigned int)fs->f_type;
    return 0;
}

static int patina_statvfs_path(const char *path, struct statvfs *out) {
    struct statfs fs;
    return patina_statvfs_from(patina_statfs(path, &fs), &fs, out);
}

static int patina_statvfs_fd(int fd, struct statvfs *out) {
    struct statfs fs;
    return patina_statvfs_from(patina_fstatfs(fd, &fs), &fs, out);
}

_Static_assert(sizeof(struct statvfs) == sizeof(struct statvfs64),
               "statvfs64 is statvfs on a 64-bit target");

int statvfs(const char *path, struct statvfs *out) {
    return patina_statvfs_path(path, out);
}
int statvfs64(const char *path, struct statvfs64 *out) {
    return patina_statvfs_path(path, (struct statvfs *)out);
}
int fstatvfs(int fd, struct statvfs *out) {
    return patina_statvfs_fd(fd, out);
}
int fstatvfs64(int fd, struct statvfs64 *out) {
    return patina_statvfs_fd(fd, (struct statvfs *)out);
}

/* Extended attributes: glibc's twelve wrappers are the bare syscalls, so each
 * is the rows' one model (src/xattr.rs) with errno set — by path (a trailing
 * symlink followed), by link (`l*`: not followed) and by descriptor (`f*`).
 * The model judges a NULL path in the kernel's order. */
int setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
    return fail_int(patina_setxattr(-1, path, PATINA_XATTR_BY_PATH, name, value, size, flags));
}
int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
    return fail_int(patina_setxattr(-1, path, PATINA_XATTR_BY_LINK, name, value, size, flags));
}
int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
    return fail_int(patina_setxattr(fd, NULL, PATINA_XATTR_BY_FD, name, value, size, flags));
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
    return fail_size(patina_getxattr(-1, path, PATINA_XATTR_BY_PATH, name, value, size));
}
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) {
    return fail_size(patina_getxattr(-1, path, PATINA_XATTR_BY_LINK, name, value, size));
}
ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) {
    return fail_size(patina_getxattr(fd, NULL, PATINA_XATTR_BY_FD, name, value, size));
}

ssize_t listxattr(const char *path, char *list, size_t size) {
    return fail_size(patina_listxattr(-1, path, PATINA_XATTR_BY_PATH, list, size));
}
ssize_t llistxattr(const char *path, char *list, size_t size) {
    return fail_size(patina_listxattr(-1, path, PATINA_XATTR_BY_LINK, list, size));
}
ssize_t flistxattr(int fd, char *list, size_t size) {
    return fail_size(patina_listxattr(fd, NULL, PATINA_XATTR_BY_FD, list, size));
}

int removexattr(const char *path, const char *name) {
    return fail_int(patina_removexattr(-1, path, PATINA_XATTR_BY_PATH, name));
}
int lremovexattr(const char *path, const char *name) {
    return fail_int(patina_removexattr(-1, path, PATINA_XATTR_BY_LINK, name));
}
int fremovexattr(int fd, const char *name) {
    return fail_int(patina_removexattr(fd, NULL, PATINA_XATTR_BY_FD, name));
}

static int fill_stat64(int result, const struct patina_metadata *values, struct stat64 *status) {
    if (result < 0) return -1;
    /* The kernel's copy-out to a NULL buffer faults. */
    if (status == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_stat_mode(values);
    status->st_dev = patina_st_dev(values);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino64_t)values->ino;
    status->st_size = (off64_t)values->length;
    status->st_uid = (uid_t)patina_uid();
    status->st_gid = (gid_t)patina_gid();
    status->st_blksize = (blksize_t)PATINA_STAT_BLOCK_SIZE;
    status->st_blocks = (blkcnt64_t)patina_stat_blocks(values->length);
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->ctime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
    return 0;
}

int stat64(const char *path, struct stat64 *status) {
    struct patina_metadata values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values);
    return fill_stat64(result, &values, status);
}

int lstat64(const char *path, struct stat64 *status) {
    struct patina_metadata values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, PATINA_RESOLVE_NOFOLLOW, &values);
    return fill_stat64(result, &values, status);
}

int fstat64(int fd, struct stat64 *status) {
    struct patina_metadata values;
    int result = patina_fd_metadata_values(fd, &values);
    return fill_stat64(result, &values, status);
}

int fstatat64(int directory, const char *restrict path, struct stat64 *restrict status, int flags) {
    struct patina_metadata values;
    int result = patina_stat_at_values(directory, path, flags, &values);
    return fill_stat64(result, &values, status);
}

/* The one virtual volume's mount id, as statx reports it (STATX_MNT_ID is
 * always filled, like the kernel's vfs_statx). One mount, one id. */
#define PATINA_STATX_MNT_ID UINT64_C(1)

static void patina_statx_time(struct statx_timestamp *out, uint64_t nanos) {
    out->tv_sec = (int64_t)(nanos / UINT64_C(1000000000));
    out->tv_nsec = (uint32_t)(nanos % UINT64_C(1000000000));
}

/*
 * statx: BASIC_STATS except BLOCKS (no allocation extent model), plus MNT_ID,
 * as the kernel's vfs_statx fills them whatever was asked; STATX_BTIME is
 * filled — and reported — only when requested, as ext4/xfs do.
 */
int statx(int directory, const char *restrict path, int flags, unsigned int mask,
          struct statx *restrict status) {
    /* do_statx refuses both sync modes at once and the reserved mask bit. */
    if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE || (mask & STATX__RESERVED) != 0) {
        errno = EINVAL;
        return -1;
    }
    struct patina_metadata values;
    int result = patina_stat_at_values(directory, path, flags, &values);
    if (result < 0) return -1;
    memset(status, 0, sizeof *status);
    status->stx_mask = (STATX_BASIC_STATS & ~STATX_BLOCKS) | STATX_MNT_ID;
    status->stx_blksize = (uint32_t)PATINA_STAT_BLOCK_SIZE;
    status->stx_mode = (uint16_t)patina_stat_mode(&values);
    status->stx_nlink = values.nlink;
    status->stx_uid = patina_uid();
    status->stx_gid = patina_gid();
    status->stx_ino = values.ino;
    status->stx_size = values.length;
    status->stx_blocks = 0; /* Allocation extents are not modeled. */
    patina_statx_time(&status->stx_atime, values.atime_nanos);
    patina_statx_time(&status->stx_mtime, values.mtime_nanos);
    patina_statx_time(&status->stx_ctime, values.ctime_nanos);
    if ((mask & STATX_BTIME) != 0) {
        status->stx_mask |= STATX_BTIME;
        patina_statx_time(&status->stx_btime, values.btime_nanos);
    }
    status->stx_mnt_id = PATINA_STATX_MNT_ID;
    unsigned major, minor;
    patina_fs_device(values.fs, &major, &minor);
    status->stx_dev_major = major;
    status->stx_dev_minor = minor;
    return 0;
}

#endif

/*
 * The utimensat family. Every spelling lowers onto the two PATINA_TIME_*
 * arguments patina_utimensat/patina_futimens take, decoded here exactly as the
 * kernel decodes them: UTIME_NOW/UTIME_OMIT in tv_nsec (utimensat/futimens), a
 * NULL times pointer meaning now/now, a tv_nsec outside [0, 999999999] EINVAL,
 * a tv_usec outside [0, 999999] EINVAL (utimes/futimes/lutimes/futimesat),
 * whole seconds for utime(3). glibc's own wrappers would issue utimensat from
 * inside libc text, past the dispatcher, so each is a strong definition here.
 */
/* The timestamp ABI is unsigned nanoseconds. Never wrap a guest time. */
static int patina_checked_time(int64_t seconds, uint64_t fraction, uint64_t *nanos) {
    if (seconds < 0 || (uint64_t)seconds > (UINT64_MAX - fraction) / UINT64_C(1000000000)) {
        errno = EINVAL;
        return -1;
    }
    *nanos = (uint64_t)seconds * UINT64_C(1000000000) + fraction;
    return 0;
}

static int patina_time_argument(const struct timespec *time, uint32_t *kind, uint64_t *nanos) {
    if (time == NULL) {
        *kind = PATINA_TIME_NOW;
        *nanos = 0;
        return 0;
    }
#ifdef UTIME_NOW
    if (time->tv_nsec == UTIME_NOW) {
        *kind = PATINA_TIME_NOW;
        *nanos = 0;
        return 0;
    }
    if (time->tv_nsec == UTIME_OMIT) {
        *kind = PATINA_TIME_OMIT;
        *nanos = 0;
        return 0;
    }
#endif
    if (time->tv_nsec < 0 || time->tv_nsec > 999999999L || time->tv_sec < 0) {
        errno = EINVAL;
        return -1;
    }
    *kind = PATINA_TIME_SET;
    return patina_checked_time(time->tv_sec, (uint64_t)time->tv_nsec, nanos);
}

static int patina_timeval_argument(const struct timeval *time, uint32_t *kind, uint64_t *nanos) {
    if (time == NULL) {
        *kind = PATINA_TIME_NOW;
        *nanos = 0;
        return 0;
    }
    if (time->tv_usec < 0 || time->tv_usec > 999999L || time->tv_sec < 0) {
        errno = EINVAL;
        return -1;
    }
    *kind = PATINA_TIME_SET;
    return patina_checked_time(time->tv_sec, (uint64_t)time->tv_usec * UINT64_C(1000), nanos);
}

static int patina_utimensat_impl(int dirfd, const char *path, const struct timespec times[2],
                                 uint32_t resolve_flags) {
    uint32_t atime_kind, mtime_kind;
    uint64_t atime_nanos, mtime_nanos;
    if (patina_time_argument(times == NULL ? NULL : &times[0], &atime_kind, &atime_nanos) < 0)
        return -1;
    if (patina_time_argument(times == NULL ? NULL : &times[1], &mtime_kind, &mtime_nanos) < 0)
        return -1;
    return fail_int(patina_utimensat(dirfd, path, resolve_flags, atime_kind, atime_nanos,
                                     mtime_kind, mtime_nanos));
}

static int patina_futimens_impl(int fd, const struct timespec times[2]) {
    uint32_t atime_kind, mtime_kind;
    uint64_t atime_nanos, mtime_nanos;
    if (patina_time_argument(times == NULL ? NULL : &times[0], &atime_kind, &atime_nanos) < 0)
        return -1;
    if (patina_time_argument(times == NULL ? NULL : &times[1], &mtime_kind, &mtime_nanos) < 0)
        return -1;
    return fail_int(patina_futimens(fd, atime_kind, atime_nanos, mtime_kind, mtime_nanos));
}

static int patina_utimes_impl(int dirfd, const char *path, const struct timeval times[2],
                              uint32_t resolve_flags) {
    uint32_t atime_kind, mtime_kind;
    uint64_t atime_nanos, mtime_nanos;
    if (patina_timeval_argument(times == NULL ? NULL : &times[0], &atime_kind, &atime_nanos) < 0)
        return -1;
    if (patina_timeval_argument(times == NULL ? NULL : &times[1], &mtime_kind, &mtime_nanos) < 0)
        return -1;
    return fail_int(patina_utimensat(dirfd, path, resolve_flags, atime_kind, atime_nanos,
                                     mtime_kind, mtime_nanos));
}

int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags) {
    /* The kernel accepts utimensat(fd, NULL, …) as the descriptor shape, but
     * glibc's wrapper — whose contract this symbol IS — refuses a null path
     * with EINVAL and spells the descriptor shape as futimens(3). glibc
     * declares the parameter nonnull, so the null test goes through a local
     * the compiler cannot fold. */
    const char *volatile spelled = path;
    if (spelled == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (times != NULL && times[0].tv_nsec == UTIME_OMIT && times[1].tv_nsec == UTIME_OMIT)
        return patina_utimensat_impl(patina_at(dirfd), path, times, 0);
    if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t resolve_flags = (flags & AT_SYMLINK_NOFOLLOW) != 0 ? PATINA_RESOLVE_NOFOLLOW : 0;
    if (flags & AT_EMPTY_PATH) resolve_flags |= PATINA_RESOLVE_EMPTY_PATH;
    return patina_utimensat_impl(patina_at(dirfd), path, times, resolve_flags);
}

int futimens(int fd, const struct timespec times[2]) {
    return patina_futimens_impl(fd, times);
}

int utimes(const char *path, const struct timeval times[2]) {
    return patina_utimes_impl(PATINA_AT_FDCWD, path, times, 0);
}

int lutimes(const char *path, const struct timeval times[2]) {
    return patina_utimes_impl(PATINA_AT_FDCWD, path, times, PATINA_RESOLVE_NOFOLLOW);
}

int futimes(int fd, const struct timeval times[2]) {
    uint32_t atime_kind, mtime_kind;
    uint64_t atime_nanos, mtime_nanos;
    if (patina_timeval_argument(times == NULL ? NULL : &times[0], &atime_kind, &atime_nanos) < 0)
        return -1;
    if (patina_timeval_argument(times == NULL ? NULL : &times[1], &mtime_kind, &mtime_nanos) < 0)
        return -1;
    return fail_int(patina_futimens(fd, atime_kind, atime_nanos, mtime_kind, mtime_nanos));
}

int utime(const char *path, const struct utimbuf *times) {
    if (times == NULL) return patina_utimensat_impl(PATINA_AT_FDCWD, path, NULL, 0);
    uint64_t atime, mtime;
    if (patina_checked_time(times->actime, 0, &atime) < 0 ||
        patina_checked_time(times->modtime, 0, &mtime) < 0) return -1;
    return fail_int(patina_utimensat(PATINA_AT_FDCWD, path, 0, PATINA_TIME_SET,
                                     atime, PATINA_TIME_SET, mtime));
}

#ifdef __linux__
int futimesat(int dirfd, const char *path, const struct timeval times[2]) {
    /* A NULL path names the directory descriptor itself (the pre-utimensat
     * kernel contract glibc still honors). */
    if (path == NULL) return futimes(dirfd, times);
    return patina_utimes_impl(patina_at(dirfd), path, times, 0);
}
#endif

/*
 * The chown family: a comparison against the one modeled identity, with the
 * kernel's setuid/setgid kill and ctime move on success (through the one mode
 * entry), EPERM otherwise. fchownat honors AT_SYMLINK_NOFOLLOW and
 * AT_EMPTY_PATH; any other flag is EINVAL.
 */
int chown(const char *path, uid_t owner, gid_t group) {
    return fail_int(patina_chown(PATINA_AT_FDCWD, path, 0, (uint32_t)owner, (uint32_t)group));
}

int lchown(const char *path, uid_t owner, gid_t group) {
    return fail_int(patina_chown(PATINA_AT_FDCWD, path, PATINA_RESOLVE_NOFOLLOW, (uint32_t)owner,
                                 (uint32_t)group));
}

int fchown(int fd, uid_t owner, gid_t group) {
    return fail_int(patina_fchown(fd, (uint32_t)owner, (uint32_t)group));
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags) {
    if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t resolve_flags = 0;
    if ((flags & AT_SYMLINK_NOFOLLOW) != 0) resolve_flags |= PATINA_RESOLVE_NOFOLLOW;
    if ((flags & AT_EMPTY_PATH) != 0) resolve_flags |= PATINA_RESOLVE_EMPTY_PATH;
    return fail_int(patina_chown(patina_at(dirfd), path, resolve_flags, (uint32_t)owner,
                                 (uint32_t)group));
}

/*
 * truncate/fallocate: sizes by name and by descriptor over the deterministic
 * filesystem. posix_fallocate is glibc's spelling of fallocate(fd, 0, …) that
 * returns the errno value instead of -1 — and would otherwise issue the syscall
 * from inside libc text, past the dispatcher.
 */
int truncate(const char *path, off_t length) {
    return fail_int(patina_truncate(PATINA_AT_FDCWD, path, (int64_t)length));
}

#ifdef __linux__
int truncate64(const char *path, off64_t length) {
    return fail_int(patina_truncate(PATINA_AT_FDCWD, path, (int64_t)length));
}

int fallocate(int fd, int mode, off_t offset, off_t length) {
    PATINA_CANCEL_POINT("fallocate");
    return fail_int(patina_fallocate(fd, (uint32_t)mode, (int64_t)offset, (int64_t)length));
}

int fallocate64(int fd, int mode, off64_t offset, off64_t length) {
    PATINA_CANCEL_POINT("fallocate64");
    return fail_int(patina_fallocate(fd, (uint32_t)mode, (int64_t)offset, (int64_t)length));
}

int posix_fallocate(int fd, off_t offset, off_t length) {
    if (patina_fallocate(fd, 0, (int64_t)offset, (int64_t)length) < 0) return patina_errno();
    return 0;
}

int posix_fallocate64(int fd, off64_t offset, off64_t length) {
    if (patina_fallocate(fd, 0, (int64_t)offset, (int64_t)length) < 0) return patina_errno();
    return 0;
}

/* posix_fadvise/posix_fadvise64: glibc's fadvise64(2) wrappers
 * (sysdeps/unix/sysv/linux/posix_fadvise64.c), which return the error number
 * rather than setting errno — errno is left as it was. The advice is a hint,
 * so the one model (patina_fadvise) only judges it. */
static int patina_posix_fadvise(int fd, int64_t offset, int64_t length, int advice) {
    if (patina_fadvise(fd, offset, length, advice) < 0) return patina_errno();
    return 0;
}

int posix_fadvise(int fd, off_t offset, off_t length, int advice) {
    return patina_posix_fadvise(fd, (int64_t)offset, (int64_t)length, advice);
}

int posix_fadvise64(int fd, off64_t offset, off64_t length, int advice) {
    return patina_posix_fadvise(fd, (int64_t)offset, (int64_t)length, advice);
}
#endif

/*
 * mkdir/mkdirat. The creation mode crosses the boundary; the runtime applies
 * the process umask, exactly as the kernel does.
 *
 * mkdirat is here because cap-std and every other dirfd-relative caller reaches
 * for it, and a libc-backend rustix lowers `Dir::create_dir` straight onto it --
 * without this def the symbol is an uninterposed import the pre-run audit
 * refuses.
 */
int mkdir(const char *path, mode_t mode) {
    return fail_int(patina_mkdir(PATINA_AT_FDCWD, path, (uint32_t)(mode & 07777)));
}

int mkdirat(int directory, const char *path, mode_t mode) {
    return fail_int(patina_mkdir(patina_at(directory), path, (uint32_t)(mode & 07777)));
}

int unlink(const char *path) {
    return fail_int(patina_unlink(PATINA_AT_FDCWD, path));
}

int rmdir(const char *path) {
    return fail_int(patina_rmdir(PATINA_AT_FDCWD, path));
}

int rename(const char *from, const char *to) {
    return fail_int(patina_renameat2(PATINA_AT_FDCWD, from, PATINA_AT_FDCWD, to, 0));
}

/*
 * *at removal/rename. unlinkat routes to rmdir when AT_REMOVEDIR is set,
 * otherwise unlink (AT_REMOVEDIR is the only flag Linux defines). renameat resolves both dirfds
 * (cap-std's `Dir::rename` is dir-fd-relative on both sides).
 */
int unlinkat(int dirfd, const char *path, int flags) {
    if ((flags & ~AT_REMOVEDIR) != 0) {
        errno = PATINA_AT_FLAG_REFUSAL;
        return -1;
    }
    if (flags & AT_REMOVEDIR) return fail_int(patina_rmdir(patina_at(dirfd), path));
    return fail_int(patina_unlink(patina_at(dirfd), path));
}

int renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
    return fail_int(
        patina_renameat2(patina_at(olddirfd), old_path, patina_at(newdirfd), new_path, 0));
}

#ifdef __linux__
/*
 * glibc exports renameat2 (the flags-carrying rename): the flags —
 * RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT — are the kernel's, and
 * the one rename entry judges them as do_renameat2 does.
 */
int renameat2(int olddirfd, const char *old_path, int newdirfd, const char *new_path,
              unsigned int flags) {
    return fail_int(
        patina_renameat2(patina_at(olddirfd), old_path, patina_at(newdirfd), new_path, flags));
}
#endif
