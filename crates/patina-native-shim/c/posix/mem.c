/*
 * Memory: mmap/mmap64, munmap, mremap, mprotect, msync, the mlock family and
 * memfd_create — the C spellings of the one model in `src/mem/`
 * (`patina_mmap` & co.), which the SUD rows of the same names call too.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
/* ==========================================================================
 * MEMORY MAPPINGS
 *
 * An anonymous mapping is host address space; a mapping of a virtual descriptor
 * is a view of the file's page cache, coherent with read/write through every
 * descriptor on the file (src/mem.rs). The model answers in the raw syscall ABI;
 * these wrappers only fold a -errno into errno and the libc failure value.
 *
 * The allocator reaches these on every arena growth, possibly before any init
 * hook the shim owns has run: the model's anonymous path touches no runtime
 * state and reaches the host kernel through the glibc syscall(2) host alias,
 * resolved on first use.
 * ========================================================================== */

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

/* The raw ABI's failure range: -4095..-1. */
static int patina_mem_failed(int64_t result) {
    if (result < 0 && result >= -4095) {
        errno = (int)-result;
        return 1;
    }
    return 0;
}

static void *patina_mem_address(int64_t result) {
    return patina_mem_failed(result) ? MAP_FAILED : (void *)(uintptr_t)result;
}

void *mmap(void *hint, size_t length, int protection, int flags, int fd, off_t offset) {
    return patina_mem_address(
        patina_mmap((uintptr_t)hint, length, protection, flags, fd, (int64_t)offset));
}

/* glibc's LFS alias. Anything compiled with _FILE_OFFSET_BITS=64 — SQLite's
 * unix VFS included — emits `mmap64`. */
void *mmap64(void *hint, size_t length, int protection, int flags, int fd, off64_t offset) {
    return patina_mem_address(
        patina_mmap((uintptr_t)hint, length, protection, flags, fd, (int64_t)offset));
}

int munmap(void *address, size_t length) {
    return patina_mem_failed(patina_munmap((uintptr_t)address, length)) ? -1 : 0;
}

int msync(void *address, size_t length, int flags) {
    return patina_mem_failed(patina_msync((uintptr_t)address, length, flags)) ? -1 : 0;
}

int mprotect(void *address, size_t length, int protection) {
    return patina_mem_failed(patina_mprotect((uintptr_t)address, length, protection)) ? -1 : 0;
}

int mlock(const void *address, size_t length) {
    return patina_mem_failed(patina_mlock((uintptr_t)address, length, 0)) ? -1 : 0;
}

int mlock2(const void *address, size_t length, unsigned int flags) {
    return patina_mem_failed(patina_mlock((uintptr_t)address, length, flags)) ? -1 : 0;
}

int munlock(const void *address, size_t length) {
    return patina_mem_failed(patina_munlock((uintptr_t)address, length)) ? -1 : 0;
}

int mlockall(int flags) {
    return patina_mem_failed(patina_mlockall(flags)) ? -1 : 0;
}

int munlockall(void) {
    return patina_mem_failed(patina_munlockall()) ? -1 : 0;
}

int memfd_create(const char *name, unsigned int flags) {
    return fail_int(patina_memfd_create(name, flags));
}

/* glibc reads the fifth argument only when a flag names a new address. */
void *mremap(void *address, size_t old_length, size_t new_length, int flags, ...) {
    void *new_address = NULL;
    if ((flags & (MREMAP_FIXED | MREMAP_DONTUNMAP)) != 0) {
        va_list ap;
        va_start(ap, flags);
        new_address = va_arg(ap, void *);
        va_end(ap);
    }
    return patina_mem_address(patina_mremap((uintptr_t)address, old_length, new_length,
                                            (uintptr_t)(unsigned)flags,
                                            (uintptr_t)new_address));
}
#endif
