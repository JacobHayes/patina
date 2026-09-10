/*
 * Memory mappings: mmap/mmap64, munmap, msync, mremap over the host VM aliases,
 * with virtual-descriptor mappings populated from and flushed to the model.
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
 * MEMORY MAPPINGS: mmap/mmap64, munmap, msync, mremap
 *
 * A mapping of a VIRTUAL descriptor is the one boundary operation that hands
 * the guest raw memory instead of a return value, and leaving it uninterposed
 * was silently host-dependent in the worst way: patina's descriptors are
 * integers handed out by the deterministic runtime, they mean nothing to the
 * kernel, so `mmap(..., fd, ...)` on one reached the HOST mmap and failed
 * EBADF. That is exactly how SQLite's unix VFS failed here — `unixShmMap` maps
 * the WAL-index (`-shm`) file with `MAP_SHARED|PROT_READ|PROT_WRITE` and
 * reports `SQLITE_IOERR_SHMMAP` when the map fails, so every WAL-mode database
 * was unusable under patina even though every other file operation was modeled.
 *
 * The model, in one sentence: a file-backed mapping is a page-aligned PRIVATE
 * copy of the file range, populated through `patina_pread` at map time and (for
 * a writable `MAP_SHARED` mapping) flushed back through `patina_pwrite` on
 * `msync` and on the final `munmap`. That is exact for `MAP_PRIVATE` — POSIX
 * leaves it unspecified whether post-map changes to the file are visible in a
 * private mapping — and it is exact for a `MAP_SHARED` mapping as long as the
 * mapped range has exactly ONE live mapping in the process, because there is
 * then no second view for a page cache to keep coherent. Repeated maps of the
 * IDENTICAL (inode, offset, length, protection) range therefore share a single
 * backing region behind a reference count rather than getting private copies,
 * which keeps that invariant true instead of merely assumed; a map that
 * OVERLAPS a live shared mapping without matching it exactly is the case the
 * model cannot represent, so it fails closed rather than diverging silently.
 * SQLite keeps one shm mapping per file per process (`unixShmNode`), so the
 * exact-match path is the only one it ever needs.
 *
 * Anonymous mappings (`MAP_ANONYMOUS`, fd -1) carry no boundary effect at all —
 * they are process-local address space, the same class as `malloc` — so they
 * are forwarded to the host allocator path unchanged, and are deliberately NOT
 * recorded or noted as a boundary: the allocator calls this on every arena
 * growth, and putting a scheduling point there would make the guest's memory
 * allocation pattern part of the simulated schedule.
 *
 * The host primitives are reached through `__real_dlsym(RTLD_NEXT, ...)`, the
 * `-Wl,--wrap=dlsym` alias, exactly like the SUD section's prctl/open/read/close
 * vehicles: naming `mmap` as an undefined external would collide with the strong
 * definition below (host-alias doctrine), and it keeps the vehicle names off the
 * guest's import table. That vehicle is Linux-only, so this whole section is —
 * on Darwin `mmap` stays uninterposed and a file-backed map of a virtual
 * descriptor still fails EBADF there, loudly, which is the pre-existing state.
 * ========================================================================== */

extern void *__real_dlsym(void *handle, const char *symbol);

/* Host vehicles, resolved lazily on first use (the `patina_real_sigaction`
 * convention). Lazy rather than eager because the anonymous path can run during
 * allocator bootstrap, before any init hook the shim owns has executed; glibc's
 * own internal mmap calls bind to its hidden alias and never reach here, so
 * resolving through dlsym cannot recurse back into this interposer. */
enum {
    PATINA_HOST_MMAP = 0,
    PATINA_HOST_MUNMAP = 1,
    PATINA_HOST_MPROTECT = 2,
    PATINA_HOST_MREMAP = 3,
    PATINA_HOST_VM_SLOTS = 4,
};
static void *patina_host_vm_table[PATINA_HOST_VM_SLOTS];

static void *patina_host_vm(int slot, const char *name) {
    void *resolved = __atomic_load_n(&patina_host_vm_table[slot], __ATOMIC_ACQUIRE);
    if (resolved == NULL) {
        resolved = __real_dlsym(RTLD_NEXT, name);
        __atomic_store_n(&patina_host_vm_table[slot], resolved, __ATOMIC_RELEASE);
    }
    return resolved;
}

typedef void *(*patina_host_mmap_fn)(void *, size_t, int, int, int, off_t);
typedef int (*patina_host_munmap_fn)(void *, size_t);
typedef int (*patina_host_mprotect_fn)(void *, size_t, int);
typedef void *(*patina_host_mremap_fn)(void *, size_t, size_t, int, void *);

/* Portability shims for mapping flags a given <sys/mman.h> may predate. Defined
 * as 0 so a flag the platform does not know can never match a caller's bits. */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0
#endif
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif
#ifndef MAP_FILE
#define MAP_FILE 0
#endif
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

/* patina pins `sysconf(_SC_PAGESIZE)` to 4096, so that is the page size the
 * guest computes its offsets and region sizes against and the one this layer
 * validates against. It is NOT used to round the host reservation: every host
 * call below is given the same byte length the guest asked for, so the kernel
 * rounds map and unmap identically whatever its own page size is. */
#define PATINA_MAP_PAGE_SIZE ((size_t)4096)

/*
 * One live file-backed mapping. `address` doubles as the slot's occupancy flag
 * and is published LAST (and retired FIRST), so a slot is only ever visible to
 * another thread fully initialized. Table mutations are confined to critical
 * sections containing no boundary call, which the cooperative single-runnable-
 * task scheduler makes atomic; the atomics on `address`/`references` make the
 * table correct even without that guarantee.
 */
#define PATINA_MAPPING_SLOTS 64

struct patina_mapping {
    void *address;       /* backing region base; NULL means the slot is free */
    size_t length;       /* bytes of the mapping, as the caller asked for them */
    int64_t desc;        /* the retained open file description the region mirrors */
    int64_t offset;      /* byte offset of the region within that file */
    uint64_t inode;      /* deterministic-fs inode: the identity a second map keys on */
    int protection;      /* PROT_* the caller asked for */
    int shared;          /* MAP_SHARED (as opposed to MAP_PRIVATE) */
    int writeback;       /* shared AND writable: msync/munmap flush to the file */
    unsigned references; /* live maps sharing this region */
};

static struct patina_mapping patina_mappings[PATINA_MAPPING_SLOTS];

/* mmap reports failure as MAP_FAILED, not -1, so the deny helper needs its own
 * return convention; the diagnostic and the ENOSYS errno are the shared ones. */
static void *patina_mmap_deny(const char *message) {
    patina_posix_deny(message);
    return MAP_FAILED;
}

/* Does [start, start+length) intersect the live mapping in `entry`? Callers use
 * this for the fail-closed overlap checks; a zero-length query never overlaps,
 * matching the kernel's rejection of zero-length ranges. */
static int patina_mapping_overlaps(const struct patina_mapping *entry, const void *start,
                                   size_t length) {
    if (length == 0) return 0;
    uintptr_t query_low = (uintptr_t)start;
    uintptr_t query_high = query_low + length;
    uintptr_t entry_low = (uintptr_t)entry->address;
    uintptr_t entry_high = entry_low + entry->length;
    return query_low < entry_high && entry_low < query_high;
}

/* Scan for a live mapping that overlaps [start, start+length). Returns the slot
 * or NULL. Contains no boundary call on purpose (see the table comment). */
static struct patina_mapping *patina_mapping_find(const void *start, size_t length) {
    for (int slot = 0; slot < PATINA_MAPPING_SLOTS; slot++) {
        struct patina_mapping *entry = &patina_mappings[slot];
        if (__atomic_load_n(&entry->address, __ATOMIC_ACQUIRE) == NULL) continue;
        if (patina_mapping_overlaps(entry, start, length)) return entry;
    }
    return NULL;
}

/*
 * Copy the file range [offset, offset+length) of `fd` into `destination`.
 * A short read means the mapping runs past end-of-file; the tail is left as the
 * zero pages the anonymous reservation already provides, which is what a real
 * mapping shows for the partial page at EOF. (Touching a page entirely beyond
 * EOF raises SIGBUS on a real kernel; there is no page-fault vehicle here to
 * reproduce that, so the honest approximation is the zero page.)
 */
static int patina_mapping_populate(int fd, void *destination, size_t length, int64_t offset) {
    size_t done = 0;
    while (done < length) {
        intptr_t got = patina_pread(fd, (char *)destination + done, length - done,
                                    offset + (int64_t)done);
        if (got < 0) {
            errno = patina_errno();
            return -1;
        }
        if (got == 0) break;
        done += (size_t)got;
    }
    return 0;
}

/*
 * Flush [start, start+length) of a writable shared mapping back to its file.
 * This is where a MAP_SHARED store becomes a deterministic-filesystem write —
 * without it, everything the guest wrote through the mapping would be invisible
 * to the crash model and to any later read of the file.
 */
static int patina_mapping_flush(const struct patina_mapping *entry, const char *start,
                                size_t length) {
    size_t skip = (size_t)((uintptr_t)start - (uintptr_t)entry->address);
    size_t done = 0;
    while (done < length) {
        /* Through the RETAINED description, not a guest number: the guest may
         * have closed (or reused) its number since the map, and the kernel's
         * mapping keeps the file alive regardless. */
        intptr_t wrote = patina_desc_pwrite(entry->desc, start + done, length - done,
                                            entry->offset + (int64_t)(skip + done));
        if (wrote < 0) {
            errno = patina_errno();
            return -1;
        }
        if (wrote == 0) {
            /* A zero-length write on a virtual descriptor means the runtime
             * cannot accept the data at all; looping would spin forever, so
             * report the same I/O error a truncated writeback deserves. */
            errno = EIO;
            return -1;
        }
        done += (size_t)wrote;
    }
    return 0;
}

static void *patina_mmap_impl(void *hint, size_t length, int protection, int flags, int fd,
                              int64_t offset) {
    /* Anonymous address space: process-local, no boundary effect, straight to
     * the host. The descriptor is forced to -1 because Linux ignores it for an
     * anonymous map and a virtual descriptor number must never reach the
     * kernel. MAP_FIXED is honored here (allocators carve reservations with it)
     * but must not be allowed to silently replace a modeled file mapping. */
    if ((flags & MAP_ANONYMOUS) != 0 || fd < 0) {
        if ((flags & MAP_FIXED) != 0 && patina_mapping_find(hint, length) != NULL) {
            return patina_mmap_deny(
                "patina: MAP_FIXED over a live file-backed mapping is not modeled; failing closed\n");
        }
        patina_host_mmap_fn host = (patina_host_mmap_fn)patina_host_vm(PATINA_HOST_MMAP, "mmap");
        if (host == NULL) {
            errno = ENOSYS;
            return MAP_FAILED;
        }
        return host(hint, length, protection, flags, -1, (off_t)offset);
    }

    patina_note_boundary_symbol("mmap");

    /* Everything below models a mapping of a VIRTUAL descriptor. Flags outside
     * the modeled set fail closed: MAP_FIXED would have to replace part of an
     * existing mapping, MAP_GROWSDOWN/MAP_STACK/MAP_HUGETLB/MAP_LOCKED all ask
     * for kernel VM behavior the copy model has no counterpart for.
     * MAP_NORESERVE and MAP_POPULATE are pure hints about when the kernel
     * commits pages, and this layer commits every page up front, so they are
     * accepted and ignored. MAP_FILE is the historical zero-valued no-op. */
    const int modeled_flags = MAP_SHARED | MAP_SHARED_VALIDATE | MAP_PRIVATE | MAP_FILE |
                              MAP_NORESERVE | MAP_POPULATE;
    if ((flags & ~modeled_flags) != 0) {
        return patina_mmap_deny(
            "patina: this mmap flag combination on a virtual descriptor is not modeled; failing closed\n");
    }
    int shared = (flags & (MAP_SHARED | MAP_SHARED_VALIDATE)) != 0;
    if (shared == ((flags & MAP_PRIVATE) != 0)) {
        /* Exactly one of MAP_SHARED/MAP_PRIVATE is required by the API. */
        errno = EINVAL;
        return MAP_FAILED;
    }
    if (length == 0 || ((uint64_t)offset % PATINA_MAP_PAGE_SIZE) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    /* Without MAP_FIXED an address hint is only advice, and honoring it would
     * make the returned address depend on the host's address-space layout, so
     * the model always picks its own address — which is exactly the latitude
     * the kernel also has. */
    (void)hint;
    {
        int kind = patina_fd_kind(fd);
        if (kind < 0) {
            errno = EBADF;
            return MAP_FAILED;
        }
        if (kind != PATINA_FD_FILE) {
            /* Sockets, pipes, directories, the streams and the entropy device
             * have no byte-addressable contents. */
            errno = ENODEV;
            return MAP_FAILED;
        }
    }

    /* The inode is the identity a second mapping of the same bytes is matched
     * on: two descriptors open on one file must share one backing region, or
     * stores through one would be invisible to the other. Taken before the
     * table scan so the scan itself contains no boundary call. */
    struct patina_metadata metadata;
    if (patina_fd_metadata_full(fd, &metadata) < 0) {
        errno = patina_errno();
        return MAP_FAILED;
    }
    uint64_t inode = metadata.ino;
    if (metadata.kind != PATINA_ENTRY_FILE) {
        errno = ENODEV;
        return MAP_FAILED;
    }

    /* Reserve the backing region from the host as anonymous, always writable so
     * it can be populated, then drop it to the requested protection. The region
     * is invisible to any other thread until it is published in the table
     * below, which is why the populating read is safe to do before the scan
     * even though it is a boundary (and may therefore yield). */
    patina_host_mmap_fn host_mmap = (patina_host_mmap_fn)patina_host_vm(PATINA_HOST_MMAP, "mmap");
    patina_host_munmap_fn host_munmap =
        (patina_host_munmap_fn)patina_host_vm(PATINA_HOST_MUNMAP, "munmap");
    if (host_mmap == NULL || host_munmap == NULL) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    void *region = host_mmap(NULL, length, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return MAP_FAILED;
    if (patina_mapping_populate(fd, region, length, offset) != 0) {
        int saved = errno;
        host_munmap(region, length);
        errno = saved;
        return MAP_FAILED;
    }
    /* The mapping holds the file's DESCRIPTION, as the kernel's does: the
     * writeback at munmap/msync must not depend on the guest keeping its
     * number open. Released when the region retires. */
    int64_t desc = patina_fd_retain(fd);
    if (desc < 0) {
        int saved = patina_errno();
        host_munmap(region, length);
        errno = saved;
        return MAP_FAILED;
    }
    if ((protection & PROT_WRITE) == 0) {
        patina_host_mprotect_fn host_mprotect =
            (patina_host_mprotect_fn)patina_host_vm(PATINA_HOST_MPROTECT, "mprotect");
        if (host_mprotect == NULL || host_mprotect(region, length, protection) != 0) {
            int saved = host_mprotect == NULL ? ENOSYS : errno;
            host_munmap(region, length);
            errno = saved;
            return MAP_FAILED;
        }
    }

    /* Publish. From here to the return there is no boundary call, so the scan,
     * the reference-count bump and the slot claim are one atomic step under the
     * cooperative scheduler. */
    struct patina_mapping *free_slot = NULL;
    for (int slot = 0; slot < PATINA_MAPPING_SLOTS; slot++) {
        struct patina_mapping *entry = &patina_mappings[slot];
        if (__atomic_load_n(&entry->address, __ATOMIC_ACQUIRE) == NULL) {
            if (free_slot == NULL) free_slot = entry;
            continue;
        }
        if (entry->inode != inode) continue;
        if (entry->offset == offset && entry->length == length && entry->shared == shared &&
            entry->protection == protection) {
            /* The identical range, already mapped: hand back the one backing
             * region so both mappings genuinely share their bytes. The region
             * already holds its own description reference. */
            __atomic_fetch_add(&entry->references, 1, __ATOMIC_ACQ_REL);
            host_munmap(region, length);
            (void)patina_desc_release(desc);
            return entry->address;
        }
        if (!shared && !entry->shared) continue; /* two private copies never alias */
        if ((uint64_t)offset < (uint64_t)entry->offset + entry->length &&
            (uint64_t)entry->offset < (uint64_t)offset + length) {
            host_munmap(region, length);
            (void)patina_desc_release(desc);
            return patina_mmap_deny(
                "patina: a second, differently-shaped shared mapping of a file range that is already mapped is not modeled (there is no page cache to keep the two views coherent); failing closed\n");
        }
    }
    if (free_slot == NULL) {
        host_munmap(region, length);
        (void)patina_desc_release(desc);
        return patina_mmap_deny(
            "patina: more live file-backed mappings than the shim's mapping table holds; failing closed\n");
    }
    free_slot->length = length;
    free_slot->desc = desc;
    free_slot->offset = offset;
    free_slot->inode = inode;
    free_slot->protection = protection;
    free_slot->shared = shared;
    free_slot->writeback = shared && (protection & PROT_WRITE) != 0;
    free_slot->references = 1;
    __atomic_store_n(&free_slot->address, region, __ATOMIC_RELEASE);
    return region;
}

void *mmap(void *hint, size_t length, int protection, int flags, int fd, off_t offset) {
    return patina_mmap_impl(hint, length, protection, flags, fd, (int64_t)offset);
}

/* glibc's LFS alias. Anything compiled with _FILE_OFFSET_BITS=64 — SQLite's
 * unix VFS included — emits `mmap64`, so leaving it out would send exactly the
 * calls this section exists for straight back to the host. */
void *mmap64(void *hint, size_t length, int protection, int flags, int fd, off64_t offset) {
    return patina_mmap_impl(hint, length, protection, flags, fd, (int64_t)offset);
}

int munmap(void *address, size_t length) {
    struct patina_mapping *entry = patina_mapping_find(address, length);
    if (entry == NULL) {
        /* Not a modeled mapping: anonymous address space, straight to the host. */
        patina_host_munmap_fn host =
            (patina_host_munmap_fn)patina_host_vm(PATINA_HOST_MUNMAP, "munmap");
        if (host == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return host(address, length);
    }
    patina_note_boundary_symbol("munmap");
    if (address != entry->address || length != entry->length) {
        /* Unmapping part of a modeled mapping would split one file window into
         * two, which the table has no shape for. The kernel allows it; the
         * model says so out loud instead of leaking a half-tracked region. */
        return patina_posix_deny(
            "patina: unmapping part of a file-backed mapping is not modeled; failing closed\n");
    }
    if (__atomic_sub_fetch(&entry->references, 1, __ATOMIC_ACQ_REL) > 0) {
        /* Another map of the identical range is still using this region, so the
         * bytes must stay live and unflushed for it. */
        return 0;
    }
    /* Retire the slot BEFORE the flush so no new mapping can attach to a region
     * that is about to be freed. A map of the same range racing this window
     * would read the file before the flush lands — the kernel is equally racy
     * when a mapping is torn down concurrently with one being created, and
     * SQLite (the only caller here) tears its single shm mapping down under the
     * shm mutex. */
    struct patina_mapping retired = *entry;
    __atomic_store_n(&entry->address, NULL, __ATOMIC_RELEASE);
    int result = 0;
    if (retired.writeback &&
        patina_mapping_flush(&retired, (const char *)retired.address, retired.length) != 0) {
        result = -1;
    }
    /* The region's description reference goes with it: if the guest already
     * closed its number, this is where the file's last reference (and its
     * recorded close) lands. */
    if (patina_desc_release(retired.desc) != 0 && result == 0) {
        errno = patina_errno();
        result = -1;
    }
    int saved = errno;
    patina_host_munmap_fn host = (patina_host_munmap_fn)patina_host_vm(PATINA_HOST_MUNMAP, "munmap");
    if (host == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (host(retired.address, retired.length) != 0) return -1;
    if (result != 0) errno = saved;
    return result;
}

int msync(void *address, size_t length, int flags) {
    struct patina_mapping *entry = patina_mapping_find(address, length);
    if (entry == NULL) {
        /* An msync outside a modeled mapping is either an anonymous region (for
         * which it means nothing) or a mapping this layer never saw. Neither
         * has a durability model here, so it fails closed rather than returning
         * a success the caller would read as "the file is on stable storage". */
        return patina_posix_deny(
            "patina: msync of a region that is not a modeled file-backed mapping is not modeled; failing closed\n");
    }
    patina_note_boundary_symbol("msync");
    if ((flags & MS_INVALIDATE) != 0) {
        /* MS_INVALIDATE asks for OTHER views of the file to be dropped so they
         * re-read it. The model has exactly one view per range by construction,
         * so there is nothing to invalidate — but honoring it silently would
         * hide a caller that genuinely expects a second view to exist. */
        return patina_posix_deny(
            "patina: msync MS_INVALIDATE is not modeled (a mapped range has exactly one view); failing closed\n");
    }
    if ((uintptr_t)address < (uintptr_t)entry->address ||
        (uintptr_t)address + length > (uintptr_t)entry->address + entry->length) {
        return patina_posix_deny(
            "patina: msync of a range spanning outside its mapping is not modeled; failing closed\n");
    }
    /* A private or read-only mapping has nothing to push back to the file, and
     * MS_SYNC/MS_ASYNC differ only in whether the caller waits — this layer's
     * writes are already synchronous into the deterministic filesystem, so both
     * are the same flush. */
    if (!entry->writeback) return 0;
    return patina_mapping_flush(entry, (const char *)address, length);
}

/*
 * mremap on a modeled mapping would move or resize a region whose identity the
 * table keys on, and growing one would have to invent file bytes that the map
 * did not cover; neither is modeled, so it fails closed. Everything else is
 * anonymous address space (glibc's large-block realloc reaches it) and is
 * forwarded. It is interposed rather than left to the host precisely so the
 * modeled case is caught: the backing regions ARE real host mappings, so an
 * unwatched host mremap would succeed and leave the table pointing at freed
 * address space.
 */
void *mremap(void *address, size_t old_length, size_t new_length, int flags, ...) {
    void *new_address = NULL;
    if ((flags & MREMAP_FIXED) != 0) {
        va_list ap;
        va_start(ap, flags);
        new_address = va_arg(ap, void *);
        va_end(ap);
    }
    if (patina_mapping_find(address, old_length) != NULL ||
        (new_address != NULL && patina_mapping_find(new_address, new_length) != NULL)) {
        return patina_mmap_deny(
            "patina: mremap of a file-backed mapping is not modeled; failing closed\n");
    }
    patina_host_mremap_fn host = (patina_host_mremap_fn)patina_host_vm(PATINA_HOST_MREMAP, "mremap");
    if (host == NULL) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    return host(address, old_length, new_length, flags, new_address);
}
#endif
