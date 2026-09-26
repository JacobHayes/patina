/*
 * Entropy: the seeded getentropy/getrandom implementations (`dlsym` hands
 * them out too: c/posix/dlsym.c).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * Deterministic entropy implementations behind BOTH the public interposers and
 * the `dlsym` routing table (c/posix/dlsym.c).
 *
 * These have internal linkage on purpose. `__wrap_dlsym` hands their addresses
 * to a caller that will hold and call them later, and the host-alias doctrine
 * says a pointer the shim gives out must name a shim-owned entry that can never
 * be rebound to a public, interposable symbol. Routing the public `getentropy`/
 * `getrandom` interposers through the same statics keeps the static-link path
 * and the dynamic-lookup path bit-for-bit the same code over the same
 * `patina_entropy` stream.
 */

/* glibc's getentropy (misc/getentropy.c): a request past 256 bytes is EIO
 * before anything is drawn; otherwise getrandom's answer, EFAULT for a buffer
 * it cannot write. */
static int patina_deterministic_getentropy(void *destination, size_t length) {
    if (length > 256) {
        errno = EIO;
        return -1;
    }
    if (patina_entropy(destination, length) != 0) {
        errno = patina_errno();
        return -1;
    }
    return 0;
}

static ssize_t patina_deterministic_getrandom(void *destination, size_t length,
                                              unsigned int flags) {
    return fail_size(patina_getrandom(destination, length, flags));
}

int getentropy(void *destination, size_t length) {
    return patina_deterministic_getentropy(destination, length);
}

#ifdef __APPLE__
/* Rust std sources RandomState entropy from CommonCrypto on macOS. */
int32_t CCRandomGenerateBytes(void *destination, size_t length) {
    if (patina_entropy(destination, length) != 0) __builtin_trap();
    return 0; /* kCCSuccess */
}

#endif

#ifdef __linux__
ssize_t getrandom(void *destination, size_t length, unsigned int flags) {
    return patina_deterministic_getrandom(destination, length, flags);
}

#endif
