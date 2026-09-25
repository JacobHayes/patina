/*
 * dlsym: the routing table dynamic symbol lookup answers from, and the
 * `__wrap_dlsym` interposer over it.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 * It comes last: the table names internal-linkage implementations from the
 * slices before it.
 */

/*
 * The `dlsym` routing table: the complete set of names dynamic symbol lookup
 * may resolve, and the shim's own implementation of each. `__wrap_dlsym`
 * (Linux, below) is its only caller; it is a distinct symbol so the table can
 * be probed on both platforms, including macOS where the linker offers no
 * `--wrap`.
 *
 * Why an allowlist rather than a flat NULL: returning NULL is not fail-closed
 * for a name the shim ALREADY defines — it pushes the caller onto a fallback
 * path that is *less* modeled. The `getrandom` crate's Linux backend resolves
 * `getrandom` through `dlsym(RTLD_DEFAULT, ...)`, and on NULL falls back to
 * its `use_file` path, which opens and `poll()`s `/dev/random` (unmodeled:
 * ENOENT, then ENOSYS) instead of drawing seeded bytes. The table routes a
 * caller to the code the static linker would have bound it to and cannot widen
 * what the guest can reach. Everything else — std's optional
 * `__pthread_get_minstack` probe, `dlopen`, any host effect symbol — still
 * resolves to NULL, so `dlsym` stays neutered by default.
 *
 * Every entry is an internal-linkage implementation: the host-alias doctrine
 * says a pointer the shim gives out must name a shim-owned entry that can
 * never be rebound to a public, interposable symbol. The public definitions
 * call the same statics, so static and dynamic binding run the same code.
 *
 * Membership is structural: the entropy calls, the `_FORTIFY_SOURCE` file,
 * receive and poll spellings, and getifaddrs/freeifaddrs — shim definitions a
 * program may reach through `dlsym` as well as by linking (a name the shim
 * defines is safe to hand out by construction; omitting one silently
 * demotes its caller to a less-modeled fallback). Names the shim does NOT
 * model (`arc4random*`, `SecRandomCopyBytes`) are absent: there is nothing
 * deterministic to route to, and the symbol audit denies them statically.
 */
void *patina_dlsym_route(const char *symbol) {
    if (symbol == NULL) return NULL;
    static const struct {
        const char *name;
        void *entry;
    } routes[] = {
        {"getentropy", (void *)(uintptr_t)&patina_deterministic_getentropy},
        {"getrandom", (void *)(uintptr_t)&patina_deterministic_getrandom},
#ifdef __linux__
        {"__open_2", (void *)(uintptr_t)&patina_open_2},
        {"__open64_2", (void *)(uintptr_t)&patina_open64_2},
        {"__openat_2", (void *)(uintptr_t)&patina_openat_2},
        {"__openat64_2", (void *)(uintptr_t)&patina_openat64_2},
        {"__read_chk", (void *)(uintptr_t)&patina_read_chk},
        {"__pread_chk", (void *)(uintptr_t)&patina_pread_chk},
        {"__pread64_chk", (void *)(uintptr_t)&patina_pread_chk},
        {"__readlink_chk", (void *)(uintptr_t)&patina_readlink_chk},
        {"__readlinkat_chk", (void *)(uintptr_t)&patina_readlinkat_chk},
        {"__recv_chk", (void *)(uintptr_t)&patina_recv_chk},
        {"__recvfrom_chk", (void *)(uintptr_t)&patina_recvfrom_chk},
        {"__poll_chk", (void *)(uintptr_t)&patina_poll_chk},
        {"__ppoll_chk", (void *)(uintptr_t)&patina_ppoll_chk},
        {"getifaddrs", (void *)(uintptr_t)&patina_getifaddrs},
        {"freeifaddrs", (void *)(uintptr_t)&patina_freeifaddrs},
#endif
    };
    for (size_t at = 0; at < sizeof routes / sizeof routes[0]; ++at) {
        if (strcmp(symbol, routes[at].name) == 0) return routes[at].entry;
    }
    return NULL;
}

#ifdef __linux__
/*
 * Rust std probes for optional glibc symbols (e.g. __pthread_get_minstack) via
 * dlsym when spawning threads, and the `getrandom` crate resolves `getrandom`
 * the same way. Interpose it so dynamic symbol lookup can never return a HOST
 * symbol: the only non-NULL answers come from `patina_dlsym_route` above.
 * dlopen/dlclose/dladdr are not provided, so an unmanaged binary importing
 * them is still audit-rejected.
 *
 * The interposer is `__wrap_dlsym`: `cargo patina native-build` links
 * `-Wl,--wrap=dlsym`, so every guest/std reference to `dlsym` binds here while
 * the shim's own host-alias table reaches the real glibc resolver through the
 * distinct `__real_dlsym` (see the shim's Linux `hostapi` module). That table is
 * in turn how the shim reaches every real host vehicle — including the genuine
 * `pthread_create` behind the strong-def thread interposer — so `dlsym`
 * stays neutered for guest code without denying the shim its one sanctioned
 * resolution primitive. `dlsym` is the only symbol wrapped at link time;
 * `pthread_create` deliberately is not (that would clash with libgcc's own
 * `__wrap_pthread_create` on x86).
 */
void *__wrap_dlsym(void *handle, const char *symbol) {
    (void)handle;
    return patina_dlsym_route(symbol);
}
#endif
