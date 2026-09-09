/*
 * Filesystem: directory iteration, open/openat and the shared directory
 * descriptor table, metadata (stat/statx/statfs), permissions, and the
 * namespace operations (mkdir/unlink/link/rename/...).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

char *getcwd(char *destination, size_t length) {
    if (destination == NULL || length < 2) {
        errno = destination == NULL ? ENOSYS : ERANGE;
        return NULL;
    }
    destination[0] = '/';
    destination[1] = '\0';
    return destination;
}

char *realpath(const char *restrict path, char *restrict destination) {
    char resolved[PATH_MAX];
    intptr_t length = patina_canonicalize(path, resolved, sizeof resolved);
    if (length < 0) {
        errno = patina_errno();
        return NULL;
    }
    if ((size_t)length >= PATH_MAX) {
        errno = ENAMETOOLONG;
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
    int fd = patina_diropen(path, 1, 0);
    if (fd < 0) {
        errno = patina_errno();
        return NULL;
    }
    void *state = NULL;
    if (patina_read_dir(fd, &state) != 0) {
        int saved = patina_errno();
        patina_dirclose(fd);
        errno = saved;
        return NULL;
    }
    struct patina_dir *directory = calloc(1, sizeof *directory);
    if (directory == NULL) {
        patina_read_dir_free(state);
        patina_dirclose(fd);
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
    patina_dirclose(directory->owned_fd);
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

int symlink(const char *target, const char *link_path) {
    return fail_int(patina_symlink(target, link_path));
}

int link(const char *from, const char *to) {
    return fail_int(patina_link(from, to));
}

ssize_t readlink(const char *restrict path, char *restrict destination, size_t length) {
    return fail_size(patina_read_link(path, destination, length));
}

static int patina_open_directory(const char *path, int flags);

/*
 * `mode` is the caller's creation mode -- open(2)'s third argument. POSIX says
 * the kernel reads it only when the flags can create the entry, and the
 * variadic argument is UNDEFINED otherwise, so every caller here passes 0
 * unless it saw O_CREAT and read a real `mode_t`. An open of an EXISTING file
 * must not touch that file's mode, which is the driver's rule, not a rule this
 * layer can enforce -- so the honest thing to hand it is the caller's request
 * and nothing invented.
 */
static int patina_posix_open(const char *path, int flags, mode_t mode) {
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
    /* O_PATH names a descriptor that resolves paths and answers metadata but
     * cannot read, write or iterate. cap-std's `Dir` walks a path a component at
     * a time with openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW), which is
     * why it is modeled; a directory handle is the interesting one, but the
     * kernel gives an O_PATH descriptor for any kind, so a file or a FIFO gets
     * an ordinary path-only fd. Only a symlink is refused: the deterministic
     * filesystem has no descriptor for a link entry, so O_PATH|O_NOFOLLOW on one
     * -- the single spelling that names the link ITSELF -- is a named deny
     * rather than a descriptor silently bound to the target instead. Without
     * O_NOFOLLOW the link resolves, exactly as every other open does. */
#ifdef O_PATH
    if ((flags & O_PATH) != 0 && (flags & O_DIRECTORY) == 0) {
        uint32_t probe_kind = 0;
        uint64_t probe_length = 0;
        if (patina_metadata(path, &probe_kind, &probe_length) != 0) {
            errno = patina_errno();
            return -1;
        }
        if (probe_kind == PATINA_ENTRY_SYMLINK) {
#ifdef O_NOFOLLOW
            if (flags & O_NOFOLLOW) return patina_posix_deny(PATINA_DENY_O_PATH_SYMLINK);
#endif
            char canonical[PATH_MAX];
            intptr_t canonical_len = patina_canonicalize(path, canonical, sizeof canonical);
            if (canonical_len < 0) {
                errno = patina_errno();
                return -1;
            }
            if ((size_t)canonical_len >= sizeof canonical) {
                errno = ENAMETOOLONG;
                return -1;
            }
            if (patina_metadata(canonical, &probe_kind, &probe_length) != 0) {
                errno = patina_errno();
                return -1;
            }
            if (probe_kind == PATINA_ENTRY_DIRECTORY) {
                return patina_open_directory(canonical, flags);
            }
            return fail_int(patina_open(canonical, PATINA_O_PATH, 0));
        }
        if (probe_kind == PATINA_ENTRY_DIRECTORY) {
            return patina_open_directory(path, flags);
        }
        return fail_int(patina_open(path, PATINA_O_PATH, 0));
    }
#endif
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY) return patina_open_directory(path, flags);
#endif
    uint32_t patina_flags = 0;
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
#ifdef O_NOFOLLOW
    if (flags & O_NOFOLLOW) patina_flags |= PATINA_O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    if (flags & O_NONBLOCK) patina_flags |= PATINA_O_NONBLOCK;
#endif
    return fail_int(patina_open(path, patina_flags, (uint32_t)(mode & 07777)));
}

/*
 * Read open(2)'s variadic creation mode. Only ever called when the flags say
 * the kernel would read it: a variadic argument that was never passed is
 * undefined behavior to fetch, so the O_CREAT test guards every call site.
 */
static mode_t patina_open_mode(va_list *ap) {
    return (mode_t)va_arg(*ap, unsigned int);
}

static int patina_open_variadic(const char *path, int flags, va_list *ap) {
    mode_t mode = 0;
    if (flags & O_CREAT) mode = patina_open_mode(ap);
    return patina_posix_open(path, flags, mode);
}

int open(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_open_variadic(path, flags, &ap);
    va_end(ap);
    return result;
}

/*
 * Duplicate a virtual directory descriptor. POSIX `dup` SHARES the open file
 * description, so patina_dirdup duplicates the descriptor itself and registers
 * the copy with the *at resolver -- it re-resolves no name (a rename cannot
 * detach the copy) and re-charges no permission (a chmod between the open and
 * the dup cannot refuse it), which reopening the path would do both of.
 * (dup2/dup3 to a CHOSEN number stay fail-closed for every fd class alike.)
 * Mirrors the SUD dispatcher's dir-fd dup rows.
 */
static int patina_dup_dirfd(int fd) {
    return fail_int(patina_dirdup(fd));
}

/*
 * Resolve `path` for the *at family against a directory descriptor. Called only
 * when `dirfd != AT_FDCWD`. The descriptor must be a virtual directory descriptor
 * (issued by openat(..., O_DIRECTORY)); a real/unknown kernel descriptor the
 * deterministic filesystem never issued fails closed with ENOSYS (matching the
 * rest of the *at family) rather than silently escaping to the host -- even for
 * an absolute path, so an arbitrary bogus fd is never honored. Given a valid
 * descriptor, an absolute `path` ignores it (POSIX) and a relative `path` is
 * joined onto its bound directory path.
 */
static int patina_resolve_at(int dirfd, const char *path, char *out, size_t out_len) {
    if (!patina_dir_is_dirfd(dirfd)) {
        errno = ENOSYS;
        return -1;
    }
    if (path[0] == '/') {
        size_t path_len = strlen(path);
        if (path_len + 1 > out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, path, path_len + 1);
        return 0;
    }
    char base[PATH_MAX];
    intptr_t base_len = patina_dirpath(dirfd, base, sizeof base);
    if (base_len < 0) {
        errno = patina_errno();
        return -1;
    }
    if ((size_t)base_len >= sizeof base) {
        errno = ENAMETOOLONG;
        return -1;
    }
    size_t path_len = strlen(path);
    int separator = ((size_t)base_len > 0 && base[base_len - 1] == '/') ? 0 : 1;
    if ((size_t)base_len + (size_t)separator + path_len + 1 > out_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, base, (size_t)base_len);
    size_t offset = (size_t)base_len;
    if (separator) out[offset++] = '/';
    memcpy(out + offset, path, path_len + 1);
    return 0;
}

/*
 * open/openat(..., O_DIRECTORY|O_PATH): decode the flags and hand the directory
 * open to patina_diropen, which owns the validation (entry kind, O_NOFOLLOW ->
 * ELOOP on a symlink, trailing-symlink resolution, ENOTDIR) for BOTH this
 * interposer and the SUD dispatcher. Only a read-only open can name a directory;
 * a write/create/truncate/append/exclusive one is EISDIR. The fd is a real
 * deterministic-FS fd, so fstat reports a directory and fsync is the
 * parent-directory durability barrier.
 */
static int patina_open_directory(const char *path, int flags) {
    int path_only = 0;
#ifdef O_PATH
    /* O_PATH ignores the access mode entirely -- it opens nothing, so there is
     * nothing to ask for -- while a plain directory open must be read-only. */
    if (flags & O_PATH) path_only = 1;
#endif
    if (!path_only && ((flags & O_ACCMODE) != O_RDONLY ||
                       (flags & (O_CREAT | O_TRUNC | O_APPEND | O_EXCL)) != 0)) {
        errno = EISDIR;
        return -1;
    }
    int follow = 1;
#ifdef O_NOFOLLOW
    if (flags & O_NOFOLLOW) follow = 0;
#endif
    return fail_int(patina_diropen(path, follow, path_only));
}

/*
 * openat over the path-based deterministic filesystem. AT_FDCWD is a plain path;
 * a virtual directory descriptor (from a prior openat(..., O_DIRECTORY)) joins
 * its bound path with a relative `path` -- the resolution std's remove_dir_all
 * needs to recurse and remove children. O_DIRECTORY yields a virtual directory
 * descriptor; everything else routes to the ordinary file open. A real kernel
 * dirfd the deterministic filesystem never issued still fails closed (ENOSYS,
 * matching the rest of the *at family).
 * The variadic mode is dropped just as `open` drops it. rustix's libc backend
 * lowers its `fs` calls onto these on both platforms, so they are strong defs in
 * the common section rather than Apple-only.
 */
static int patina_openat_impl(int dirfd, const char *path, int flags, mode_t mode) {
    char resolved[PATH_MAX];
    const char *effective = path;
    if (dirfd != AT_FDCWD) {
        if (patina_resolve_at(dirfd, path, resolved, sizeof resolved) != 0) return -1;
        effective = resolved;
    }
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY) {
        return patina_open_directory(effective, flags);
    }
#endif
    return patina_posix_open(effective, flags, mode);
}

static int patina_openat_variadic(int dirfd, const char *path, int flags, va_list *ap) {
    mode_t mode = 0;
    if (flags & O_CREAT) mode = patina_open_mode(ap);
    return patina_openat_impl(dirfd, path, flags, mode);
}

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
    return patina_posix_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

#ifdef __linux__
int open64(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    int result = patina_open_variadic(path, flags, &ap);
    va_end(ap);
    return result;
}

/* glibc's LFS alias of openat (rustix's libc backend lowers its fs calls onto
 * the *64 names on 64-bit Linux). Shares openat's directory-descriptor handling. */
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

static int patina_metadata_values(const char *path, struct patina_stat_values *values) {
    return patina_metadata_full(path, &values->kind, &values->length, &values->ino,
                                &values->nlink, &values->atime_nanos, &values->mtime_nanos,
                                &values->mode);
}

static int patina_fd_metadata_values(int fd, struct patina_stat_values *values) {
    return patina_fd_metadata_full(fd, &values->kind, &values->length, &values->ino,
                                   &values->nlink, &values->atime_nanos, &values->mtime_nanos,
                                   &values->mode);
}

static int patina_resolve_symlink_target(const char *link_path, const char *target,
                                         char *resolved, size_t resolved_len) {
    if (target[0] == '/') {
        size_t target_len = strlen(target);
        if (target_len >= resolved_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(resolved, target, target_len + 1);
        return 0;
    }
    const char *slash = strrchr(link_path, '/');
    size_t parent_len = 0;
    if (slash != NULL) parent_len = slash == link_path ? 1 : (size_t)(slash - link_path);
    size_t target_len = strlen(target);
    size_t separator = parent_len == 0 || (parent_len == 1 && link_path[0] == '/') ? 0 : 1;
    if (parent_len + separator + target_len + 1 > resolved_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (parent_len == 0) {
        memcpy(resolved, target, target_len + 1);
    } else {
        memcpy(resolved, link_path, parent_len);
        size_t offset = parent_len;
        if (separator) resolved[offset++] = '/';
        memcpy(resolved + offset, target, target_len + 1);
    }
    return 0;
}

static int patina_stat_metadata(const char *path, int follow_terminal_symlink,
                                struct patina_stat_values *values) {
    int result = patina_metadata_values(path, values);
    if (result < 0) {
        errno = patina_errno();
        return -1;
    }
    if (!follow_terminal_symlink || values->kind != PATINA_ENTRY_SYMLINK) return 0;

    char target[PATH_MAX];
    ssize_t target_len = readlink(path, target, sizeof target - 1);
    if (target_len < 0) return -1;
    target[target_len] = '\0';
    char resolved[PATH_MAX];
    if (patina_resolve_symlink_target(path, target, resolved, sizeof resolved) != 0) return -1;
    result = patina_metadata_values(resolved, values);
    if (result < 0) {
        errno = patina_errno();
        return -1;
    }
    if (values->kind == PATINA_ENTRY_SYMLINK) {
        errno = ELOOP;
        return -1;
    }
    return 0;
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
 * Resolve the three addressing forms the *at* metadata entries accept onto the
 * same virtual metadata the `stat` family answers from, so one helper serves
 * `fstatat`, `fstatat64` and `statx`:
 *
 *   AT_EMPTY_PATH with an empty path -> the DESCRIPTOR's own metadata
 *   AT_FDCWD                         -> the path, verbatim
 *   a virtual directory descriptor   -> the descriptor's path joined with `path`
 *
 * The first form is why this exists: Rust's `File::metadata()` on Linux is
 * `statx(fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, ...)`, so refusing a
 * non-AT_FDCWD dirfd outright refused the most common metadata call in the
 * ecosystem — and refused it with ENOSYS, which std surfaces verbatim as
 * `ErrorKind::Unsupported` instead of falling back to `fstat`. Flags outside
 * `allowed` still fail closed.
 */
static int patina_stat_at_values(int directory, const char *path, int flags, int allowed,
                                 struct patina_stat_values *values) {
    if ((flags & ~allowed) != 0) {
        errno = ENOSYS;
        return -1;
    }
    if ((flags & AT_EMPTY_PATH) != 0 && (path == NULL || path[0] == '\0')) {
        /* AT_FDCWD with an empty path names the working directory, which is not
         * a modeled virtual entry. */
        if (directory == AT_FDCWD) {
            errno = ENOSYS;
            return -1;
        }
        if (patina_fd_metadata_values(directory, values) < 0) {
            errno = patina_errno();
            return -1;
        }
        return 0;
    }
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    if (directory == AT_FDCWD) {
        return patina_stat_metadata(path, follow, values);
    }
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return patina_stat_metadata(resolved, follow, values);
}

#define PATINA_STAT_AT_FLAGS (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT)

/*
 * Existence and permission probe. The guest is one non-root identity (uid 1000,
 * what getuid reports) owning every modeled entry, so the answer reads the
 * OWNER triad of the entry's modeled permission bits. X_OK on a regular file is
 * refused whatever its mode: nothing here can be executed, so reporting a file
 * as runnable would be a fabricated answer, not a permission one.
 */
static int patina_access_impl(const char *path, int mode) {
    struct patina_stat_values values;
    if (patina_stat_metadata(path, 1, &values) < 0) return -1;
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
 * trailing-symlink rule (follow != 0 changes the link's TARGET, follow == 0 is
 * EOPNOTSUPP on a link, exactly as Linux answers) and patina_fchmod names the
 * node a descriptor already holds. The variadic-free signatures match POSIX, so
 * all three drop off a shim-linked guest's import table.
 */
int chmod(const char *path, mode_t mode) {
    return fail_int(patina_chmod(path, (uint32_t)mode, 1));
}

int fchmod(int fd, mode_t mode) {
    return fail_int(patina_fchmod(fd, (uint32_t)mode));
}

int fchmodat(int directory, const char *path, mode_t mode, int flags) {
    if ((flags & ~AT_SYMLINK_NOFOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }
    int follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    if (directory == AT_FDCWD) return fail_int(patina_chmod(path, (uint32_t)mode, follow));
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return fail_int(patina_chmod(resolved, (uint32_t)mode, follow));
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
    return fail_int(patina_mkfifo(path, (uint32_t)mode));
}

int mkfifoat(int directory, const char *path, mode_t mode) {
    if (directory == AT_FDCWD) return fail_int(patina_mkfifo(path, (uint32_t)mode));
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return fail_int(patina_mkfifo(resolved, (uint32_t)mode));
}

static int patina_mknod_impl(const char *path, mode_t mode, dev_t device) {
    mode_t type = mode & S_IFMT;
    if (type == S_IFIFO) {
        /* A FIFO has no device number; a caller passing one is confused about
         * what it is creating, and honoring it would be inventing a field. */
        if (device != 0) {
            errno = EINVAL;
            return -1;
        }
        return fail_int(patina_mkfifo(path, (uint32_t)(mode & 07777)));
    }
    if (type == S_IFCHR || type == S_IFBLK) {
        errno = EPERM;
        return -1;
    }
    return patina_posix_deny(PATINA_DENY_MKNOD_TYPE);
}

int mknod(const char *path, mode_t mode, dev_t device) {
    return patina_mknod_impl(path, mode, device);
}

int mknodat(int directory, const char *path, mode_t mode, dev_t device) {
    if (directory == AT_FDCWD) return patina_mknod_impl(path, mode, device);
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return patina_mknod_impl(resolved, mode, device);
}

int access(const char *path, int mode) { return patina_access_impl(path, mode); }

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
    if (directory == AT_FDCWD) return patina_access_impl(path, mode);
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return patina_access_impl(resolved, mode);
}

int stat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 1, &values);
    return fill_stat(result, &values, status);
}

int lstat(const char *path, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 0, &values);
    return fill_stat(result, &values, status);
}

int fstat(int fd, struct stat *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    if (result < 0) errno = patina_errno();
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
    if (patina_stat_metadata(path, 1, &values) < 0) return -1;
    patina_fill_statfs_profile(out);
    return 0;
}
int statfs64(const char *path, struct statfs64 *out) {
    struct patina_stat_values values;
    if (patina_stat_metadata(path, 1, &values) < 0) return -1;
    patina_fill_statfs64_profile(out);
    return 0;
}
int fstatfs(int fd, struct statfs *out) {
    struct patina_stat_values values;
    if (patina_fd_metadata_values(fd, &values) < 0) { errno = patina_errno(); return -1; }
    patina_fill_statfs_profile(out);
    return 0;
}
int fstatfs64(int fd, struct statfs64 *out) {
    struct patina_stat_values values;
    if (patina_fd_metadata_values(fd, &values) < 0) { errno = patina_errno(); return -1; }
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
    int result = patina_stat_metadata(path, 1, &values);
    return fill_stat64(result, &values, status);
}

int lstat64(const char *path, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_stat_metadata(path, 0, &values);
    return fill_stat64(result, &values, status);
}

int fstat64(int fd, struct stat64 *status) {
    struct patina_stat_values values;
    int result = patina_fd_metadata_values(fd, &values);
    if (result < 0) errno = patina_errno();
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
 * mkdir/mkdirat. The creation mode crosses the boundary; the driver applies the
 * modeled umask, exactly as the kernel applies the process umask.
 *
 * mkdirat is here because cap-std and every other dirfd-relative caller reaches
 * for it, and a libc-backend rustix lowers `Dir::create_dir` straight onto it --
 * without this def the symbol is an uninterposed import the pre-run audit
 * refuses.
 */
int mkdir(const char *path, mode_t mode) {
    return fail_int(patina_mkdir(path, (uint32_t)(mode & 07777)));
}

int mkdirat(int directory, const char *path, mode_t mode) {
    if (directory == AT_FDCWD) return mkdir(path, mode);
    char resolved[PATH_MAX];
    if (patina_resolve_at(directory, path, resolved, sizeof resolved) != 0) return -1;
    return fail_int(patina_mkdir(resolved, (uint32_t)(mode & 07777)));
}

int unlink(const char *path) {
    return fail_int(patina_unlink(path));
}

int rmdir(const char *path) {
    return fail_int(patina_rmdir(path));
}

int rename(const char *from, const char *to) {
    return fail_int(patina_rename(from, to));
}

/*
 * *at removal/rename over the path-based deterministic filesystem. AT_FDCWD is a
 * plain path; a virtual directory descriptor joins its bound path with a relative
 * `path` (std's remove_dir_all removes children with unlinkat(dirfd, name, ...)).
 * unlinkat routes to rmdir when AT_REMOVEDIR is set, otherwise unlink; unknown
 * flags fail closed. renameat resolves both dirfds the same way (cap-std's
 * `Dir::rename` is dir-fd-relative on both sides); renameat2 models only flags==0
 * and otherwise fails closed, then routes through renameat.
 */
int unlinkat(int dirfd, const char *path, int flags) {
    if ((flags & ~AT_REMOVEDIR) != 0) {
        errno = ENOSYS;
        return -1;
    }
    char resolved[PATH_MAX];
    const char *effective = path;
    if (dirfd != AT_FDCWD) {
        if (patina_resolve_at(dirfd, path, resolved, sizeof resolved) != 0) return -1;
        effective = resolved;
    }
    if (flags & AT_REMOVEDIR) return fail_int(patina_rmdir(effective));
    return fail_int(patina_unlink(effective));
}

/*
 * symlinkat/readlinkat: the dirfd-relative spellings of symlink and readlink.
 * The raw-syscall rows were modeled from the start; without these a libc-backend
 * guest that works through a directory descriptor (cap-std with the libc
 * backend, or any std program on a platform without syscall-user-dispatch) had
 * no path to them at all and failed closed at the audit.
 *
 * symlinkat resolves only the LINK side: a symlink's target is a string the
 * filesystem stores verbatim, never a path this call resolves -- which is why
 * the syscall takes one dirfd and not two.
 */
int symlinkat(const char *target, int dirfd, const char *link_path) {
    if (dirfd == AT_FDCWD) return symlink(target, link_path);
    char resolved[PATH_MAX];
    if (patina_resolve_at(dirfd, link_path, resolved, sizeof resolved) != 0) return -1;
    return fail_int(patina_symlink(target, resolved));
}

ssize_t readlinkat(int dirfd, const char *restrict path, char *restrict destination,
                   size_t length) {
    if (dirfd == AT_FDCWD) return readlink(path, destination, length);
    char resolved[PATH_MAX];
    if (patina_resolve_at(dirfd, path, resolved, sizeof resolved) != 0) return -1;
    return fail_size(patina_read_link(resolved, destination, length));
}

/*
 * link/linkat: create a hard link. std::fs::hard_link lowers to
 * linkat(AT_FDCWD, original, AT_FDCWD, link, 0) on Linux and macOS. AT_FDCWD and
 * absolute paths pass straight through; a virtual directory descriptor resolves
 * its bound path for symmetry with the openat/unlinkat family. AT_SYMLINK_FOLLOW
 * is the only defined flag: when set, `from` is canonicalized (its trailing
 * symlink resolved) before linking, so the link targets the resolved file rather
 * than duplicating the symlink -- the driver's link duplicates a symlink entry
 * as-is, which is precisely the no-AT_SYMLINK_FOLLOW behavior. Any other flag bit
 * is EINVAL rather than silently ignored.
 */
int linkat(int fromfd, const char *from, int tofd, const char *to, int flags) {
    if ((flags & ~AT_SYMLINK_FOLLOW) != 0) {
        errno = EINVAL;
        return -1;
    }
    char from_resolved[PATH_MAX];
    char to_resolved[PATH_MAX];
    const char *from_effective = from;
    const char *to_effective = to;
    if (fromfd != AT_FDCWD) {
        if (patina_resolve_at(fromfd, from, from_resolved, sizeof from_resolved) != 0) return -1;
        from_effective = from_resolved;
    }
    if (tofd != AT_FDCWD) {
        if (patina_resolve_at(tofd, to, to_resolved, sizeof to_resolved) != 0) return -1;
        to_effective = to_resolved;
    }
    if (flags & AT_SYMLINK_FOLLOW) {
        char canonical[PATH_MAX];
        intptr_t canonical_len = patina_canonicalize(from_effective, canonical, sizeof canonical);
        if (canonical_len < 0) {
            errno = patina_errno();
            return -1;
        }
        if ((size_t)canonical_len >= sizeof canonical) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return fail_int(patina_link(canonical, to_effective));
    }
    return fail_int(patina_link(from_effective, to_effective));
}

int renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
    char old_resolved[PATH_MAX];
    char new_resolved[PATH_MAX];
    const char *old_effective = old_path;
    const char *new_effective = new_path;
    if (olddirfd != AT_FDCWD) {
        if (patina_resolve_at(olddirfd, old_path, old_resolved, sizeof old_resolved) != 0) return -1;
        old_effective = old_resolved;
    }
    if (newdirfd != AT_FDCWD) {
        if (patina_resolve_at(newdirfd, new_path, new_resolved, sizeof new_resolved) != 0) return -1;
        new_effective = new_resolved;
    }
    return fail_int(patina_rename(old_effective, new_effective));
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
