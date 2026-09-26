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
 * registry row that is `Modeled` or `Partial` on Linux (a drift test holds the
 * two lists together, `dlsym_routes_are_the_registry_definitions`) — so a
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
#define PATINA_ROUTED(X) \
    X(__assert_fail) \
    X(__clock_gettime) \
    X(__gettimeofday) \
    X(__libc_current_sigrtmax) \
    X(__open) \
    X(__open64) \
    X(__open64_2) \
    X(__open_2) \
    X(__openat64_2) \
    X(__openat_2) \
    X(__poll_chk) \
    X(__ppoll_chk) \
    X(__pread64_chk) \
    X(__pread_chk) \
    X(__read) \
    X(__read_chk) \
    X(__readlink_chk) \
    X(__readlinkat_chk) \
    X(__recv_chk) \
    X(__recvfrom_chk) \
    X(__res_init) \
    X(__write) \
    X(abort) \
    X(accept) \
    X(accept4) \
    X(access) \
    X(acct) \
    X(bind) \
    X(chdir) \
    X(chmod) \
    X(chown) \
    X(chroot) \
    X(clearenv) \
    X(clock_getres) \
    X(clock_gettime) \
    X(clock_nanosleep) \
    X(close) \
    X(close_range) \
    X(closedir) \
    X(connect) \
    X(copy_file_range) \
    X(creat) \
    X(delete_module) \
    X(dirfd) \
    X(dlerror) \
    X(dup) \
    X(dup2) \
    X(dup3) \
    X(endpwent) \
    X(epoll_create1) \
    X(epoll_ctl) \
    X(epoll_pwait) \
    X(epoll_wait) \
    X(eventfd) \
    X(exit) \
    X(faccessat) \
    X(fallocate) \
    X(fallocate64) \
    X(fchdir) \
    X(fchmod) \
    X(fchmodat) \
    X(fchown) \
    X(fchownat) \
    X(fcntl) \
    X(fcntl64) \
    X(fdatasync) \
    X(fdopendir) \
    X(fflush) \
    X(fgetxattr) \
    X(flistxattr) \
    X(flock) \
    X(fprintf) \
    X(fputc) \
    X(fputs) \
    X(freeaddrinfo) \
    X(freeifaddrs) \
    X(fremovexattr) \
    X(fsconfig) \
    X(fsetxattr) \
    X(fsmount) \
    X(fsopen) \
    X(fspick) \
    X(fstat) \
    X(fstat64) \
    X(fstatat) \
    X(fstatat64) \
    X(fstatfs) \
    X(fstatfs64) \
    X(fstatvfs) \
    X(fstatvfs64) \
    X(fsync) \
    X(ftruncate) \
    X(ftruncate64) \
    X(futimens) \
    X(futimes) \
    X(futimesat) \
    X(fwrite) \
    X(getaddrinfo) \
    X(getcwd) \
    X(getdents64) \
    X(getegid) \
    X(getentropy) \
    X(getenv) \
    X(geteuid) \
    X(getgid) \
    X(gethostname) \
    X(getifaddrs) \
    X(getpeername) \
    X(getpid) \
    X(getppid) \
    X(getpwent) \
    X(getpwuid_r) \
    X(getrandom) \
    X(getrlimit) \
    X(getrlimit64) \
    X(getrusage) \
    X(getsockname) \
    X(getsockopt) \
    X(gettid) \
    X(gettimeofday) \
    X(getuid) \
    X(getxattr) \
    X(if_nametoindex) \
    X(init_module) \
    X(ioctl) \
    X(isatty) \
    X(kill) \
    X(killpg) \
    X(lchown) \
    X(lgetxattr) \
    X(link) \
    X(linkat) \
    X(listen) \
    X(listxattr) \
    X(llistxattr) \
    X(localtime_r) \
    X(lremovexattr) \
    X(lseek) \
    X(lseek64) \
    X(lsetxattr) \
    X(lstat) \
    X(lstat64) \
    X(lutimes) \
    X(memfd_create) \
    X(mkdir) \
    X(mkdirat) \
    X(mkfifo) \
    X(mkfifoat) \
    X(mknod) \
    X(mknodat) \
    X(mlock) \
    X(mlock2) \
    X(mlockall) \
    X(mmap) \
    X(mmap64) \
    X(mount) \
    X(mount_setattr) \
    X(move_mount) \
    X(mprotect) \
    X(mremap) \
    X(msync) \
    X(munlock) \
    X(munlockall) \
    X(munmap) \
    X(nanosleep) \
    X(open) \
    X(open64) \
    X(open_tree) \
    X(openat) \
    X(openat64) \
    X(opendir) \
    X(pause) \
    X(pipe) \
    X(pipe2) \
    X(pivot_root) \
    X(poll) \
    X(posix_fadvise) \
    X(posix_fadvise64) \
    X(posix_fallocate) \
    X(posix_fallocate64) \
    X(ppoll) \
    X(prctl) \
    X(pread) \
    X(pread64) \
    X(preadv) \
    X(preadv64) \
    X(printf) \
    X(pselect) \
    X(psignal) \
    X(pthread_atfork) \
    X(pthread_cancel) \
    X(pthread_cond_broadcast) \
    X(pthread_cond_destroy) \
    X(pthread_cond_init) \
    X(pthread_cond_signal) \
    X(pthread_cond_timedwait) \
    X(pthread_cond_wait) \
    X(pthread_create) \
    X(pthread_detach) \
    X(pthread_exit) \
    X(pthread_getname_np) \
    X(pthread_join) \
    X(pthread_kill) \
    X(pthread_mutex_destroy) \
    X(pthread_mutex_init) \
    X(pthread_mutex_lock) \
    X(pthread_mutex_trylock) \
    X(pthread_mutex_unlock) \
    X(pthread_once) \
    X(pthread_rwlock_destroy) \
    X(pthread_rwlock_init) \
    X(pthread_rwlock_rdlock) \
    X(pthread_rwlock_tryrdlock) \
    X(pthread_rwlock_trywrlock) \
    X(pthread_rwlock_unlock) \
    X(pthread_rwlock_wrlock) \
    X(pthread_setname_np) \
    X(pthread_sigmask) \
    X(ptrace) \
    X(putchar) \
    X(putenv) \
    X(puts) \
    X(pwrite) \
    X(pwrite64) \
    X(pwritev) \
    X(pwritev64) \
    X(quotactl) \
    X(raise) \
    X(read) \
    X(readdir) \
    X(readdir64) \
    X(readdir_r) \
    X(readlink) \
    X(readlinkat) \
    X(readv) \
    X(realpath) \
    X(reboot) \
    X(recv) \
    X(recvfrom) \
    X(recvmmsg) \
    X(recvmsg) \
    X(removexattr) \
    X(rename) \
    X(renameat) \
    X(renameat2) \
    X(res_init) \
    X(rewinddir) \
    X(rmdir) \
    X(sched_getaffinity) \
    X(sched_getcpu) \
    X(sched_setaffinity) \
    X(sched_yield) \
    X(secure_getenv) \
    X(select) \
    X(send) \
    X(sendfile) \
    X(sendfile64) \
    X(sendmmsg) \
    X(sendmsg) \
    X(sendto) \
    X(setenv) \
    X(setgid) \
    X(setgroups) \
    X(setns) \
    X(setpgid) \
    X(setpwent) \
    X(setrlimit) \
    X(setrlimit64) \
    X(setsid) \
    X(setsockopt) \
    X(setuid) \
    X(setxattr) \
    X(shutdown) \
    X(sigaction) \
    X(sigaltstack) \
    X(siginterrupt) \
    X(signal) \
    X(signalfd) \
    X(sigpending) \
    X(sigprocmask) \
    X(sigqueue) \
    X(sigsuspend) \
    X(sigtimedwait) \
    X(sigwait) \
    X(sigwaitinfo) \
    X(sleep) \
    X(socket) \
    X(socketpair) \
    X(stat) \
    X(stat64) \
    X(statfs) \
    X(statfs64) \
    X(statvfs) \
    X(statvfs64) \
    X(statx) \
    X(strsignal) \
    X(swapoff) \
    X(swapon) \
    X(symlink) \
    X(symlinkat) \
    X(sysconf) \
    X(sysinfo) \
    X(tcgetattr) \
    X(tgkill) \
    X(time) \
    X(tkill) \
    X(truncate) \
    X(truncate64) \
    X(umask) \
    X(umount2) \
    X(uname) \
    X(unlink) \
    X(unlinkat) \
    X(unsetenv) \
    X(unshare) \
    X(utime) \
    X(utimensat) \
    X(utimes) \
    X(vfprintf) \
    X(vhangup) \
    X(waitid) \
    X(waitpid) \
    X(write) \
    X(writev)

#define PATINA_ROUTED_X86_64(X) \
    X(ioperm) \
    X(iopl)

/* Names whose definition is an assembly entry (`syscall`, init.c): the entry
 * defines its hidden `patina_route_` alias itself, since a C alias cannot
 * name an assembly symbol. */
#define PATINA_ROUTED_ASM(X) \
    X(syscall)

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
extern long patina_route_syscall(long number, ...) __attribute__((visibility("hidden")));
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
