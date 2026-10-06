/*
 * dlsym: the routing table dynamic symbol lookup answers from, the
 * `__wrap_dlsym` interposer over it, and `dlerror`.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 * It comes last: the table names the definitions of every slice before it.
 */

/*
 * The `dlsym` routing table: the names dynamic symbol lookup resolves, and the
 * shim's own definition of each. `__wrap_dlsym` (Linux, below) is its caller;
 * `patina_dlsym_route` is a distinct symbol so the table can be probed on both
 * platforms, including macOS where the linker offers no `--wrap`.
 *
 * On Linux the table is every name the shim defines as a libc contract — each
 * registry row that is `Modeled` or `Partial` on Linux (`build_support.rs`
 * generates the routing macros from that inventory) — so a
 * program that resolves a function dynamically gets exactly the code the
 * static linker would have bound it to: `dlsym(RTLD_DEFAULT, "getpid")` is the
 * address `&getpid` has in the program, as under glibc. `dlsym` itself is the
 * guest's `__wrap_dlsym`. Everything else answers NULL: a name only the host
 * defines (`gnu_get_libc_version`, std's optional `__pthread_get_minstack`
 * probe), a deny-trapped escape (`fork`, the spawn family), and the shim's
 * control plane. Returning NULL is not fail-closed for a name the shim
 * defines — it pushes the caller onto a less-modeled fallback (the `getrandom`
 * crate's `/dev/random` poll) — and a host name is never an answer.
 *
 * The pointers handed out are hidden aliases of the definitions, never
 * references to the public names: the host-alias doctrine forbids giving out
 * a pointer that could be rebound to a public, interposable symbol, and a
 * reference to `getpid` in an object linked into a shared library would bind
 * at load time to whichever `getpid` the global scope finds first — glibc's,
 * if the shim's lost. A hidden alias is resolved when the shim is linked, to
 * the shim's own code, so the answer equals the public definition's address
 * in the program and can never become a host entry. macOS has no aliases (and
 * a guest's `dlsym` is not interposed there), so its table stays the entropy
 * pair, through their internal-linkage implementations.
 */
#ifdef __linux__


/* Names whose definition is an assembly entry (`syscall`, init.c): the entry
 * defines its hidden `patina_route_` alias itself, since a C alias cannot
 * name an assembly symbol. */

#define PATINA_ROUTE_ALIAS(name) \
    extern __typeof__(name) patina_route_##name \
        __attribute__((alias(#name), visibility("hidden")));
#define PATINA_ROUTE_ENTRY(name) {#name, (void *)(uintptr_t)&patina_route_##name},

/* An alias need not repeat its target's optimization hints (leaf, nothrow)
 * or its deprecation (readdir_r, siginterrupt): it is only ever an address. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmissing-attributes"
#endif
PATINA_ROUTED(PATINA_ROUTE_ALIAS)
#ifdef __x86_64__
PATINA_ROUTED_X86_64(PATINA_ROUTE_ALIAS)
#endif
extern __typeof__(open) __open;
extern __typeof__(open64) __open64;
#define PATINA_ROUTE_EXTERN(name) extern __typeof__(name) patina_route_##name __attribute__((visibility("hidden")));
PATINA_ROUTED_ASM(PATINA_ROUTE_EXTERN)
#undef PATINA_ROUTE_EXTERN
void *__wrap_dlsym(void *handle, const char *symbol);
extern __typeof__(__wrap_dlsym) patina_route_dlsym
    __attribute__((alias("__wrap_dlsym"), visibility("hidden")));
#pragma GCC diagnostic pop

void *patina_dlsym_route(const char *symbol) {
    if (symbol == NULL) return NULL;
    static const struct {
        const char *name;
        void *entry;
    } routes[] = {
        PATINA_ROUTED(PATINA_ROUTE_ENTRY)
        PATINA_ROUTED_ASM(PATINA_ROUTE_ENTRY)
#ifdef __x86_64__
        PATINA_ROUTED_X86_64(PATINA_ROUTE_ENTRY)
#endif
        {"dlsym", (void *)(uintptr_t)&patina_route_dlsym},
    };
    for (size_t at = 0; at < sizeof routes / sizeof routes[0]; ++at) {
        if (strcmp(symbol, routes[at].name) == 0) return routes[at].entry;
    }
    return NULL;
}
#else
void *patina_dlsym_route(const char *symbol) {
    if (symbol == NULL) return NULL;
    if (strcmp(symbol, "getentropy") == 0)
        return (void *)(uintptr_t)&patina_deterministic_getentropy;
    if (strcmp(symbol, "getrandom") == 0)
        return (void *)(uintptr_t)&patina_deterministic_getrandom;
    return NULL;
}
#endif

#ifdef __linux__
/*
 * Rust std probes for an optional glibc symbol (__pthread_get_minstack) via
 * dlsym, and the `getrandom` crate resolves `getrandom` the same way. (std's
 * other ELF probes, `statx`, `copy_file_range` and `getrandom`, are weak
 * references the static link already binds to the shim's definitions; they
 * never reach dlsym.)
 * Interpose it so dynamic symbol lookup can never return a HOST symbol: the
 * only non-NULL answers come from `patina_dlsym_route` above, whatever the
 * handle (`RTLD_DEFAULT`, `RTLD_NEXT`: the shim's definition is the next one
 * the executable would bind as well). dlopen/dlclose/dladdr are not provided,
 * so an unmanaged binary importing them is still audit-rejected.
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
 *
 * `dlerror` is glibc's, per thread: a failed lookup leaves a message naming
 * the program and the symbol (glibc's "PROGRAM: undefined symbol: NAME"),
 * saying why patina found none, which the next `dlerror` answers once; a
 * successful lookup clears it.
 */
static __thread char patina_dlerror_message[512];
static __thread int patina_dlerror_pending;

static void patina_dlerror_set(const char *symbol) {
    const char *parts[] = {
        patina_program_path != NULL ? patina_program_path : "",
        ": undefined symbol: ",
        symbol != NULL ? symbol : "(null)",
        " (patina: dynamic lookup answers only the names the shim defines)",
    };
    size_t at = 0;
    for (size_t part = 0; part < sizeof parts / sizeof parts[0]; ++part) {
        size_t length = strlen(parts[part]);
        size_t room = sizeof patina_dlerror_message - 1 - at;
        if (length > room) length = room;
        memcpy(patina_dlerror_message + at, parts[part], length);
        at += length;
    }
    patina_dlerror_message[at] = '\0';
}

void *__wrap_dlsym(void *handle, const char *symbol) {
    (void)handle;
    void *entry = patina_dlsym_route(symbol);
    patina_dlerror_pending = entry == NULL;
    if (entry == NULL) patina_dlerror_set(symbol);
    return entry;
}

char *dlerror(void) {
    if (!patina_dlerror_pending) return NULL;
    patina_dlerror_pending = 0;
    return patina_dlerror_message;
}
#endif
