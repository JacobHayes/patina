/*
 * Scheduling and identity: pids/uids, uname, sched_*, sysconf/sysinfo,
 * rlimits, rusage, prctl, hostname, and the passwd lookup.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

pid_t getpid(void) {
    return (pid_t)patina_pid();
}

pid_t getppid(void) {
    return (pid_t)patina_ppid();
}

#ifdef __linux__
pid_t gettid(void) {
    return (pid_t)patina_thread_id();
}

int __res_init(void) {
    errno = ENOSYS;
    return -1;
}

int res_init(void) {
    return __res_init();
}

#endif

#if defined(__APPLE__)
int pthread_threadid_np(pthread_t thread, uint64_t *thread_id) {
    if (thread_id == NULL) return EINVAL;
    if (thread != NULL && !pthread_equal(thread, pthread_self())) return ENOTSUP;
    *thread_id = (uint64_t)patina_thread_id();
    return 0;
}

#endif

/* The virtual kernel's self-description, from the one Rust model: the SUD
 * `uname` row on Linux, the Darwin model (src/darwin_identity.rs) on macOS.
 * uname and gethostname below both read it here, never through the public
 * uname. */
#ifdef __linux__
static int virtual_uname(struct utsname *name) {
    return signal_result(patina_sud_dispatch(SYS_uname, (uintptr_t)name, 0, 0, 0, 0, 0, 0));
}
#else
_Static_assert(sizeof(struct utsname) == 5 * 256,
               "Darwin struct utsname: five 256-byte fields (src/darwin_identity.rs)");
static int virtual_uname(struct utsname *name) {
    return fail_int(patina_uname(name));
}
#endif

int uname(struct utsname *name) {
    return virtual_uname(name);
}

/*
 * sched_yield / std::thread::yield_now. std's mpsc/mpmc backoff spins through
 * yield_now before it parks, so route the yield to a deterministic scheduling
 * point rather than yielding the host scheduler outside the runtime.
 */
int sched_yield(void) {
    return patina_sched_yield();
}

#ifdef __linux__
/* Live CPU id → a fixed 0. `sched_getcpu` is host-scheduling nondeterminism
 * (which core happens to run this thread); pinning it to a constant makes an
 * allocator's per-CPU arena selection deterministic, like the pid/uname
 * constants. Distinct from `__sched_cpucount` (the pure `CPU_COUNT` popcount over
 * caller memory), which is allowlisted rather than interposed. */
int sched_getcpu(void) {
    return 0;
}

/* The virtual machine's one CPU (the SUD `sched_setaffinity` row): a mask
 * naming it changes nothing, one naming no CPU the machine has is EINVAL. */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
    return signal_result(patina_sud_dispatch(SYS_sched_setaffinity, (uint64_t)pid,
        (uint64_t)cpusetsize, (uintptr_t)mask, 0, 0, 0, 0));
}

#endif

/*
 * Deterministic process-state values (getuid/geteuid/... below). The process
 * class itself — spawning, exec, reaping, credential and session changes — is a
 * deterministic-runtime non-goal, handled by the deny-traps just below.
 */
uid_t getuid(void) { return (uid_t)patina_uid(); }
uid_t geteuid(void) { return (uid_t)patina_uid(); }
gid_t getgid(void) { return (gid_t)patina_gid(); }
gid_t getegid(void) { return (gid_t)patina_gid(); }

long sysconf(int name) {
#ifdef _SC_PAGESIZE
    if (name == _SC_PAGESIZE) return 4096;
#endif
#ifdef _SC_PAGE_SIZE
    if (name == _SC_PAGE_SIZE) return 4096;
#endif
#ifdef _SC_NPROCESSORS_ONLN
    if (name == _SC_NPROCESSORS_ONLN) return 1;
#endif
#ifdef _SC_NPROCESSORS_CONF
    if (name == _SC_NPROCESSORS_CONF) return 1;
#endif
#ifdef _SC_CLK_TCK
    if (name == _SC_CLK_TCK) return 100;
#endif
#ifdef _SC_OPEN_MAX
    if (name == _SC_OPEN_MAX) return patina_fd_limit();
#endif
#ifdef _SC_NGROUPS_MAX
    /* The kernel's NGROUPS_MAX, the bound setgroups(2) enforces. */
    if (name == _SC_NGROUPS_MAX) return 65536;
#endif
    errno = EINVAL;
    return -1;
}

/*
 * ==========================================================================
 * Deterministic time / host-query / stdio surface.
 *
 * Real crates (mimalloc, the `time`/`chrono` crates, sysinfo, aws-lc-rs, zstd)
 * link a libc surface that reads host wall-clock timezone data, host
 * CPU/memory/hardware inventory, and libc `FILE*` stdio. Left as host imports
 * these taint the run's determinism claim and the pre-run gate refuses them.
 * Each is interposed with a strong definition that returns a value that is a
 * pure function of the virtual clock / a fixed world-model constant, so the
 * guest audits clean, the symbol drops off the import table, and the same seed
 * yields the same bytes regardless of the host. The world-model constants match
 * the ones the shim already exposes elsewhere (one CPU — sched_getcpu/
 * sched_getaffinity/sysconf(_SC_NPROCESSORS_*); a 4096-byte page —
 * sysconf(_SC_PAGESIZE)).
 * ==========================================================================
 */

/* Fixed physical-memory world-model constant of the Darwin interposers
 * (8 GiB; the Linux virtual machine's is src/limits.rs MACHINE_MEMORY).
 * mimalloc's arena sizing reads it; a fixed nonzero constant keeps its
 * heuristics deterministic regardless of the host's real RAM. */
#define PATINA_PHYSICAL_MEMORY_BYTES (UINT64_C(8) * 1024 * 1024 * 1024)

/*
 * getrusage(): the virtual CPU time — the virtual time the process's tasks
 * computed through while holding the baton — never the host's accounting, all
 * of it user time. RUSAGE_CHILDREN is zero (no child is ever waited for), and
 * so is every counter the runtime does not model: ru_maxrss (guest memory
 * reaches the host allocator, so a peak-RSS figure would be host state, not a
 * function of the seed), faults, blocks and context switches.
 *
 * The first-argument type follows the platform's own prototype: glibc types it as
 * `__rusage_who_t` (an enum under _GNU_SOURCE), Darwin as plain `int`.
 */
#ifdef __linux__
/* The virtual CPU time from the one Rust model (the SUD `getrusage` row). */
int getrusage(__rusage_who_t who, struct rusage *usage) {
    return signal_result(patina_sud_dispatch(SYS_getrusage, (uint64_t)(int64_t)who,
        (uintptr_t)usage, 0, 0, 0, 0, 0));
}
#else
int getrusage(int who, struct rusage *usage) {
    if (usage == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(usage, 0, sizeof *usage);
    if (who == RUSAGE_SELF) {
        uint64_t nanos = 0;
        if (patina_cpu_time_nanos(&nanos) == 0) {
            patina_timeval_from_nanos(nanos, &usage->ru_utime);
        }
    }
    return 0;
}
#endif

#ifdef __linux__
/* sysinfo(2): the virtual machine, from the one Rust model (the SUD row). */
int sysinfo(struct sysinfo *info) {
    return signal_result(patina_sud_dispatch(SYS_sysinfo, (uintptr_t)info, 0, 0, 0, 0, 0, 0));
}

int prctl(int option, ...) {
    va_list ap;
    va_start(ap, option);
    unsigned long arg2 = va_arg(ap, unsigned long);
    unsigned long arg3 = va_arg(ap, unsigned long);
    unsigned long arg4 = va_arg(ap, unsigned long);
    unsigned long arg5 = va_arg(ap, unsigned long);
    va_end(ap);

    return signal_result(patina_sud_dispatch(SYS_prctl, (uint64_t)option,
        arg2, arg3, arg4, arg5, 0, 0));
}

/*
 * getrlimit/setrlimit (the sysinfo crate reads limits): the virtual kernel's
 * limits (patina_prlimit, which the SUD getrlimit/setrlimit/prlimit64 rows
 * call too; src/limits.rs), never the host's ulimits: 16 resources from the
 * kernel's INIT_RLIMITS, changed by the unprivileged rule.
 */
static int patina_limit_result(int64_t result) {
    if (result < 0) {
        errno = (int)-result;
        return -1;
    }
    return 0;
}

/* glibc issues prlimit64(0, resource, NULL, rlim) for getrlimit and
 * prlimit64(0, resource, rlim, NULL) for setrlimit, so a NULL limit asks for
 * nothing and sets nothing: 0 once the resource is known. The plain and the
 * LFS spellings are one function in glibc on a 64-bit target (rlim_t is
 * rlim64_t), as here. */
static int patina_getrlimit(__rlimit_resource_t resource, struct rlimit64 *rlim) {
    struct patina_rlimit limit;
    int64_t result = patina_prlimit(0, (uint32_t)resource, NULL, rlim == NULL ? NULL : &limit);
    if (result == 0 && rlim != NULL) {
        rlim->rlim_cur = (rlim64_t)limit.cur;
        rlim->rlim_max = (rlim64_t)limit.max;
    }
    return patina_limit_result(result);
}

static int patina_setrlimit(__rlimit_resource_t resource, const struct rlimit64 *rlim) {
    if (rlim == NULL) return patina_limit_result(patina_prlimit(0, (uint32_t)resource, NULL, NULL));
    struct patina_rlimit limit = {(uint64_t)rlim->rlim_cur, (uint64_t)rlim->rlim_max};
    return patina_limit_result(patina_prlimit(0, (uint32_t)resource, &limit, NULL));
}

_Static_assert(sizeof(struct rlimit) == sizeof(struct rlimit64),
               "rlim_t is rlim64_t on a 64-bit target");

int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim) {
    return patina_getrlimit(resource, (struct rlimit64 *)rlim);
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    return patina_setrlimit(resource, (const struct rlimit64 *)rlim);
}

int getrlimit64(__rlimit_resource_t resource, struct rlimit64 *rlim) {
    return patina_getrlimit(resource, rlim);
}

int setrlimit64(__rlimit_resource_t resource, const struct rlimit64 *rlim) {
    return patina_setrlimit(resource, rlim);
}

/*
 * std::thread::available_parallelism reads the CPU affinity mask: the virtual
 * machine's one CPU, from the SUD `sched_getaffinity` row, in glibc's shape
 * (the kernel answers the bytes it wrote; the wrapper zeroes the rest of the
 * caller's set and answers 0).
 */
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
    int written = signal_result(patina_sud_dispatch(SYS_sched_getaffinity, (uint64_t)pid,
        (uint64_t)(cpusetsize > INT_MAX ? INT_MAX : cpusetsize), (uintptr_t)mask, 0, 0, 0, 0));
    if (written < 0) return -1;
    memset((char *)mask + written, 0, cpusetsize - (size_t)written);
    return 0;
}

#endif

/*
 * Host-state queries → fixed deterministic values (isatty/confstr precedent).
 * These read real host identity/paths; a fully interposed guest must see a
 * constant instead so its output cannot depend on where, or as whom, it ran.
 * Being strong definitions, the guest references bind here and the libc symbols
 * drop off the import table.
 */
#ifdef __linux__
/* glibc's gethostname: uname's node name, ENAMETOOLONG (with the prefix that
 * fits copied) when it does not fit with its NUL. */
int gethostname(char *name, size_t len) {
    struct utsname buf;
    if (virtual_uname(&buf) != 0) return -1;
    size_t node_len = strlen(buf.nodename) + 1;
    memcpy(name, buf.nodename, len < node_len ? len : node_len);
    if (node_len > len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}
#else
/* Darwin's gethostname: uname's node name (the kernel's `kern.hostname`
 * holds the same name), truncated to fit with its NUL as xnu's string
 * sysctl truncates; a zero-length buffer receives nothing and succeeds, as
 * the host's does. `name` is declared nonnull (passing NULL is caller UB). */
int gethostname(char *name, size_t len) {
    struct utsname buf;
    if (virtual_uname(&buf) != 0) return -1;
    if (len == 0) return 0;
    size_t copied = strlen(buf.nodename); /* length without the NUL */
    if (copied >= len) copied = len - 1;
    memcpy(name, buf.nodename, copied);
    name[copied] = '\0';
    return 0;
}
#endif
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
    (void)uid;
    (void)pwd;
    (void)buf;
    (void)buflen;
    /* Deterministic "no such user": the guest environment is emptied, so std's
     * home-directory lookup cleanly Nones and no host user identity leaks.
     * `result` is declared nonnull by glibc (a NULL compare is a
     * -Werror=nonnull-compare error under gcc), so the contract is trusted. */
    *result = NULL;
    return 0;
}
