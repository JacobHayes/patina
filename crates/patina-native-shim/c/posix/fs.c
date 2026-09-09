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

struct patina_dir {
    void *state;
    uint64_t index;
    /* Every DIR owns a virtual directory descriptor, which closedir releases:
     * opendir mints one (as a real opendir does, which is what makes dirfd()
     * meaningful on it), fdopendir takes ownership of the caller's (POSIX). The
     * snapshot is read THROUGH it, so iteration is a read of the descriptor and
     * not a second lookup of a name. */
    int owned_fd;
    struct dirent entry;
#ifdef __linux__
    struct dirent64 entry64;
#endif
};

static unsigned char patina_dirent_type(uint32_t kind) {
    switch (kind) {
        case PATINA_ENTRY_DIRECTORY: return DT_DIR;
        case PATINA_ENTRY_SYMLINK: return DT_LNK;
        case PATINA_ENTRY_FIFO: return DT_FIFO;
        case PATINA_ENTRY_FILE:
        default: return DT_REG;
    }
}

static void patina_fill_dirent_common(struct dirent *entry, uint64_t index, uint32_t kind) {
    /* Deterministic synthetic inode: one-based snapshot index in driver order. */
    entry->d_ino = (ino_t)(index + 1);
    entry->d_reclen = (unsigned short)sizeof *entry;
#ifdef __APPLE__
    entry->d_namlen = (uint8_t)strlen(entry->d_name);
#endif
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
    int result = patina_read_dir_next(directory->state, directory->entry.d_name,
                                      sizeof directory->entry.d_name, &kind);
    if (result < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (result == 0) return NULL;
    patina_fill_dirent_common(&directory->entry, directory->index, kind);
    directory->index += 1;
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

#ifdef __linux__
struct dirent64 *readdir64(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    uint32_t kind = 0;
    int result = patina_read_dir_next(directory->state, directory->entry64.d_name,
                                      sizeof directory->entry64.d_name, &kind);
    if (result < 0) {
        errno = patina_errno();
        return NULL;
    }
    if (result == 0) return NULL;
    /* Deterministic synthetic inode: one-based snapshot index in driver order. */
    directory->entry64.d_ino = (ino64_t)(directory->index + 1);
    directory->entry64.d_reclen = (unsigned short)sizeof directory->entry64;
    directory->entry64.d_type = patina_dirent_type(kind);
    directory->index += 1;
    return &directory->entry64;
}

#endif

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
    directory->index = 0;
}

int dirfd(DIR *dirp) {
    struct patina_dir *directory = (struct patina_dir *)(void *)dirp;
    return directory->owned_fd;
}

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
    return patina_openat_impl(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

#ifdef __linux__
int open64(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(AT_FDCWD, path, flags, &ap);
    va_end(ap);
    return result;
}

/* glibc's LFS alias of openat (rustix's libc backend lowers its fs calls onto
 * the *64 names on 64-bit Linux). */
int openat64(int dirfd, const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_openat_variadic(dirfd, path, flags, &ap);
    va_end(ap);
    return result;
}

#endif

struct patina_stat_values {
    uint32_t kind;
    uint64_t length;
    uint64_t ino;
    uint32_t nlink;
    uint64_t atime_nanos;
    uint64_t mtime_nanos;
    uint32_t mode;
};

/*
 * st_mode is the entry's file-type bits ORed with its permission bits. The two
 * arrive separately from the deterministic filesystem (`kind` and `mode`)
 * because they are separate facts there: the kind is structural, the mode is
 * mutable state chmod changes.
 */
static mode_t patina_stat_mode(const struct patina_stat_values *values) {
    mode_t type;
    switch (values->kind) {
        case PATINA_ENTRY_DIRECTORY: type = S_IFDIR; break;
        case PATINA_ENTRY_SYMLINK: type = S_IFLNK; break;
        case PATINA_ENTRY_FIFO: type = S_IFIFO; break;
        case PATINA_ENTRY_FILE:
        default: type = S_IFREG; break;
    }
    return type | (mode_t)(values->mode & 07777);
}

static void patina_split_nanos(uint64_t nanos, time_t *seconds, long *subseconds) {
    *seconds = (time_t)(nanos / UINT64_C(1000000000));
    *subseconds = (long)(nanos % UINT64_C(1000000000));
}

/*
 * The by-path metadata read every stat-family interposer shares: (dirfd, path)
 * resolved by the runtime with `resolve_flags` (PATINA_RESOLVE_NOFOLLOW for the
 * lstat spellings). Sets errno on failure.
 */
static int patina_metadata_values(int dirfd, const char *path, uint32_t resolve_flags,
                                  struct patina_stat_values *values) {
    int result = patina_metadata_at(dirfd, path, resolve_flags, &values->kind, &values->length,
                                    &values->ino, &values->nlink, &values->atime_nanos,
                                    &values->mtime_nanos, &values->mode);
    if (result < 0) errno = patina_errno();
    return result;
}

static int patina_fd_metadata_values(int fd, struct patina_stat_values *values) {
    int result = patina_fd_metadata_full(fd, &values->kind, &values->length, &values->ino,
                                         &values->nlink, &values->atime_nanos,
                                         &values->mtime_nanos, &values->mode);
    if (result < 0) errno = patina_errno();
    return result;
}

static int fill_stat(int result, const struct patina_stat_values *values, struct stat *status) {
    if (result < 0) return -1;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_stat_mode(values);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino_t)values->ino;
    status->st_size = (off_t)values->length;
#ifdef __APPLE__
    patina_split_nanos(values->atime_nanos, &status->st_atimespec.tv_sec,
                       &status->st_atimespec.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtimespec.tv_sec,
                       &status->st_mtimespec.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctimespec.tv_sec,
                       &status->st_ctimespec.tv_nsec);
#else
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
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
 * Flags outside `allowed` still fail closed.
 */
static int patina_stat_at_values(int directory, const char *path, int flags, int allowed,
                                 struct patina_stat_values *values) {
    if ((flags & ~allowed) != 0) {
        errno = ENOSYS;
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

#define PATINA_STAT_AT_FLAGS (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT)

/*
 * Existence and permission probe. The guest is one non-root identity (uid 1000,
 * what getuid reports) owning every modeled entry, so the answer reads the
 * OWNER triad of the entry's modeled permission bits. X_OK on a regular file is
 * refused whatever its mode: nothing here can be executed, so reporting a file
 * as runnable would be a fabricated answer, not a permission one.
 */
static int patina_access_impl(int dirfd, const char *path, int mode) {
    struct patina_stat_values values;
    if (patina_metadata_values(dirfd, path, 0, &values) < 0) return -1;
    if ((mode & X_OK) != 0 && values.kind != PATINA_ENTRY_DIRECTORY) {
        errno = EACCES;
        return -1;
    }
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
    if ((flags & ~AT_SYMLINK_NOFOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint32_t resolve_flags = (flags & AT_SYMLINK_NOFOLLOW) != 0 ? PATINA_RESOLVE_NOFOLLOW : 0;
    return fail_int(patina_chmod(patina_at(directory), path, (uint32_t)mode, resolve_flags));
}

/*
 * mkfifo/mkfifoat, and the mknod pair that glibc's mkfifo is sometimes a thin
 * wrapper over. A FIFO is the one special file the deterministic filesystem
 * models, so these are real interposers rather than a host escape.
 *
 * mknod's other types are NOT modeled and must not look modeled: a device node
 * is a host escape by construction, and the single non-root identity this
 * runtime models could not create one on a real kernel either, so S_IFCHR /
 * S_IFBLK answer the EPERM an unprivileged process gets. Every remaining type
 * (regular file, socket, directory, or an unknown bit pattern) is a loud named
 * deny.
 */
int mkfifo(const char *path, mode_t mode) {
    return fail_int(patina_mkfifo(PATINA_AT_FDCWD, path, (uint32_t)mode));
}

int mkfifoat(int directory, const char *path, mode_t mode) {
    return fail_int(patina_mkfifo(patina_at(directory), path, (uint32_t)mode));
}

static int patina_mknod_impl(int dirfd, const char *path, mode_t mode, dev_t device) {
    mode_t type = mode & S_IFMT;
    if (type == S_IFIFO) {
        /* A FIFO has no device number; a caller passing one is confused about
         * what it is creating, and honoring it would be inventing a field. */
        if (device != 0) {
            errno = EINVAL;
            return -1;
        }
        return fail_int(patina_mkfifo(dirfd, path, (uint32_t)(mode & 07777)));
    }
    if (type == S_IFCHR || type == S_IFBLK) {
        errno = EPERM;
        return -1;
    }
    return patina_posix_deny(PATINA_DENY_MKNOD_TYPE);
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
        errno = ENOSYS;
        return -1;
    }
    return patina_access_impl(patina_at(directory), path, mode);
}

int stat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values);
    return fill_stat(result, &values, status);
}

int lstat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, PATINA_RESOLVE_NOFOLLOW, &values);
    return fill_stat(result, &values, status);
}

int fstat(int fd, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    return fill_stat(result, &values, status);
}

int fstatat(int directory, const char *restrict path, struct stat *restrict status, int flags) {
    struct patina_stat_values values;
    int result = patina_stat_at_values(directory, path, flags, PATINA_STAT_AT_FLAGS, &values);
    return fill_stat(result, &values, status);
}

#ifdef __linux__
/* Filesystem-level metadata (statfs/fstatfs). The virtual filesystem answers as
 * ONE ext4-like volume (EXT4_SUPER_MAGIC, 4 KiB blocks, 255-byte names) for any
 * path or descriptor that resolves; a missing path is ENOENT exactly as stat().
 * Storage engines probe this to decide whether a path's filesystem supports
 * their multi-process coordination (turso's shared-WAL probe on every open is
 * the live example); left unmodeled, the call reaches the HOST with a virtual
 * path and the engine refuses to open at all. The profile is a constant, so it
 * is the same on record and replay and on every host. */
static void patina_fill_statfs_profile(struct statfs *out) {
    memset(out, 0, sizeof *out);
    out->f_type = 0xEF53; /* EXT4_SUPER_MAGIC */
    out->f_bsize = 4096;
    out->f_frsize = 4096;
    out->f_blocks = 1u << 20;
    out->f_bfree = 1u << 19;
    out->f_bavail = 1u << 19;
    out->f_files = 1u << 20;
    out->f_ffree = 1u << 19;
    out->f_namelen = 255;
}
static void patina_fill_statfs64_profile(struct statfs64 *out) {
    memset(out, 0, sizeof *out);
    out->f_type = 0xEF53; /* EXT4_SUPER_MAGIC */
    out->f_bsize = 4096;
    out->f_frsize = 4096;
    out->f_blocks = 1u << 20;
    out->f_bfree = 1u << 19;
    out->f_bavail = 1u << 19;
    out->f_files = 1u << 20;
    out->f_ffree = 1u << 19;
    out->f_namelen = 255;
}
int statfs(const char *path, struct statfs *out) {
    struct patina_stat_values values;
    if (patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values) < 0) return -1;
    patina_fill_statfs_profile(out);
    return 0;
}
int statfs64(const char *path, struct statfs64 *out) {
    struct patina_stat_values values;
    if (patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values) < 0) return -1;
    patina_fill_statfs64_profile(out);
    return 0;
}
int fstatfs(int fd, struct statfs *out) {
    struct patina_stat_values values;
    if (patina_fd_metadata_values(fd, &values) < 0) return -1;
    patina_fill_statfs_profile(out);
    return 0;
}
int fstatfs64(int fd, struct statfs64 *out) {
    struct patina_stat_values values;
    if (patina_fd_metadata_values(fd, &values) < 0) return -1;
    patina_fill_statfs64_profile(out);
    return 0;
}

static int fill_stat64(int result, const struct patina_stat_values *values, struct stat64 *status) {
    if (result < 0) return -1;
    if (status == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(status, 0, sizeof *status);
    status->st_mode = patina_stat_mode(values);
    status->st_nlink = (nlink_t)values->nlink;
    status->st_ino = (ino64_t)values->ino;
    status->st_size = (off64_t)values->length;
    patina_split_nanos(values->atime_nanos, &status->st_atim.tv_sec, &status->st_atim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_mtim.tv_sec, &status->st_mtim.tv_nsec);
    patina_split_nanos(values->mtime_nanos, &status->st_ctim.tv_sec, &status->st_ctim.tv_nsec);
    return 0;
}

int stat64(const char *path, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, 0, &values);
    return fill_stat64(result, &values, status);
}

int lstat64(const char *path, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_metadata_values(PATINA_AT_FDCWD, path, PATINA_RESOLVE_NOFOLLOW, &values);
    return fill_stat64(result, &values, status);
}

int fstat64(int fd, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    return fill_stat64(result, &values, status);
}

int fstatat64(int directory, const char *restrict path, struct stat64 *restrict status, int flags) {
    struct patina_stat_values values;
    int result = patina_stat_at_values(directory, path, flags, PATINA_STAT_AT_FLAGS, &values);
    return fill_stat64(result, &values, status);
}

int statx(int directory, const char *restrict path, int flags, unsigned int mask,
          struct statx *restrict status) {
    (void)mask;
    /* The three STATX_SYNC bits only choose how fresh a network filesystem's
     * answer must be; a virtual filesystem is always exact, so they are accepted
     * and ignored rather than failing closed. */
    struct patina_stat_values values;
    int result = patina_stat_at_values(
        directory, path, flags,
        PATINA_STAT_AT_FLAGS | AT_STATX_SYNC_AS_STAT | AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC,
        &values);
    if (result < 0) return -1;
    memset(status, 0, sizeof *status);
    status->stx_mask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_INO | STATX_SIZE |
                       STATX_ATIME | STATX_MTIME | STATX_CTIME;
    status->stx_mode = (uint16_t)patina_stat_mode(&values);
    status->stx_nlink = values.nlink;
    status->stx_ino = values.ino;
    status->stx_size = values.length;
    status->stx_atime.tv_sec = (int64_t)(values.atime_nanos / UINT64_C(1000000000));
    status->stx_atime.tv_nsec = (uint32_t)(values.atime_nanos % UINT64_C(1000000000));
    status->stx_mtime.tv_sec = (int64_t)(values.mtime_nanos / UINT64_C(1000000000));
    status->stx_mtime.tv_nsec = (uint32_t)(values.mtime_nanos % UINT64_C(1000000000));
    status->stx_ctime = status->stx_mtime;
    return 0;
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
    return fail_int(patina_rename(PATINA_AT_FDCWD, from, PATINA_AT_FDCWD, to));
}

/*
 * *at removal/rename. unlinkat routes to rmdir when AT_REMOVEDIR is set,
 * otherwise unlink; unknown flags fail closed. renameat resolves both dirfds
 * (cap-std's `Dir::rename` is dir-fd-relative on both sides); renameat2 models
 * only flags==0 and otherwise fails closed, then routes through renameat.
 */
int unlinkat(int dirfd, const char *path, int flags) {
    if ((flags & ~AT_REMOVEDIR) != 0) {
        errno = ENOSYS;
        return -1;
    }
    if (flags & AT_REMOVEDIR) return fail_int(patina_rmdir(patina_at(dirfd), path));
    return fail_int(patina_unlink(patina_at(dirfd), path));
}

int renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
    return fail_int(patina_rename(patina_at(olddirfd), old_path, patina_at(newdirfd), new_path));
}

#ifdef __linux__
/*
 * glibc exports renameat2 (the flags-carrying rename). Only the plain
 * flags==0 case maps onto the deterministic rename; RENAME_EXCHANGE/NOREPLACE
 * are not modeled and fail closed.
 */
int renameat2(int olddirfd, const char *old_path, int newdirfd, const char *new_path,
              unsigned int flags) {
    if (flags != 0) {
        errno = ENOSYS;
        return -1;
    }
    return renameat(olddirfd, old_path, newdirfd, new_path);
}
#endif
