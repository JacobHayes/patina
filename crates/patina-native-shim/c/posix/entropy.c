/*
 * Entropy: the seeded getentropy/getrandom implementations and the `dlsym`
 * routing table that hands them out.
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
 * the `dlsym` routing table below.
 *
 * These have internal linkage on purpose. `__wrap_dlsym` hands their addresses
 * to a caller that will hold and call them later, and the host-alias doctrine
 * says a pointer the shim gives out must name a shim-owned entry that can never
 * be rebound to a public, interposable symbol. Routing the public `getentropy`/
 * `getrandom` interposers through the same statics keeps the static-link path
 * and the dynamic-lookup path bit-for-bit the same code over the same
 * `patina_entropy` stream.
 */

static int patina_deterministic_getentropy(void *destination, size_t length) {
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

/*
 * The `dlsym` entropy routing table: the complete set of names dynamic symbol
 * lookup may resolve, and the shim's own deterministic implementation of each.
 * `__wrap_dlsym` (Linux, below) is its only caller; it is a distinct symbol so
 * the table can be probed on both platforms, including macOS where the linker
 * offers no `--wrap`.
 *
 * Why an allowlist rather than a flat NULL: returning NULL is not fail-closed
 * for a name the shim ALREADY defines deterministically — it pushes the caller
 * onto a fallback path that is *less* modeled. The `getrandom` crate's Linux
 * backend resolves `getrandom` through `dlsym(RTLD_DEFAULT, ...)`, and on NULL
 * falls back to its `use_file` path, which opens and `poll()`s `/dev/random`
 * (unmodeled: ENOENT, then ENOSYS) instead of drawing seeded bytes. The
 * allowlist is therefore exactly the entropy symbols this file already defines:
 * it routes a caller to the code the static linker would have bound it to and
 * cannot widen what the guest can reach. Everything else — std's optional
 * `__pthread_get_minstack` probe, `dlopen`, any host effect symbol — still
 * resolves to NULL, so `dlsym` stays neutered by default.
 *
 * Entropy names the shim does NOT model (`arc4random*`, `SecRandomCopyBytes`)
 * are deliberately absent: there is no deterministic implementation to route
 * to, and the symbol audit denies them statically.
 *
 * Membership is structural — every entropy symbol this file defines — rather
 * than demand-driven. Only `getrandom` has a measured consumer today (the
 * `getrandom` crate, ≥0.3, on non-musl Linux; 0.2 issues the raw syscall
 * instead, which the `syscall` interposer already covers, and `std` reaches its
 * own `getrandom` through weak linkage, not `dlsym`). `getentropy` is here
 * because the closure rule is what makes the table auditable: a name the shim
 * defines is safe to hand out by construction, and the cost of omitting one is
 * not a refusal but a silent demotion to a less-modeled fallback — the exact
 * failure this table exists to prevent.
 */
void *patina_dlsym_entropy(const char *symbol) {
    if (symbol == NULL) return NULL;
    if (strcmp(symbol, "getrandom") == 0) {
        return (void *)(uintptr_t)&patina_deterministic_getrandom;
    }
    if (strcmp(symbol, "getentropy") == 0) {
        return (void *)(uintptr_t)&patina_deterministic_getentropy;
    }
    return NULL;
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

/*
 * Rust std probes for optional glibc symbols (e.g. __pthread_get_minstack) via
 * dlsym when spawning threads, and the `getrandom` crate resolves `getrandom`
 * the same way. Interpose it so dynamic symbol lookup can never return a HOST
 * symbol: the only non-NULL answers come from `patina_dlsym_entropy` above —
 * the shim's own deterministic entropy implementations, the code the static
 * linker would have bound the caller to anyway. Every other name resolves to
 * NULL and std falls back to its defaults. dlopen/dlclose/dladdr are not
 * provided, so an unmanaged binary importing them is still audit-rejected.
 *
 * The interposer is `__wrap_dlsym`: `cargo patina native-build` links
 * `-Wl,--wrap=dlsym`, so every guest/std reference to `dlsym` binds here while
 * the shim's own host-alias table reaches the real glibc resolver through the
 * distinct `__real_dlsym` (see the shim's Linux `hostapi` module). That table is
 * in turn how the shim reaches every real host vehicle — including the genuine
 * `pthread_create` behind the strong-def thread interposer above — so `dlsym`
 * stays neutered for guest code without denying the shim its one sanctioned
 * resolution primitive. `dlsym` is the only symbol wrapped at link time;
 * `pthread_create` deliberately is not (that would clash with libgcc's own
 * `__wrap_pthread_create` on x86).
 */
void *__wrap_dlsym(void *handle, const char *symbol) {
    (void)handle;
    return patina_dlsym_entropy(symbol);
}
#endif
