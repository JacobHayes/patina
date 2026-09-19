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
    return (pid_t)1;
}

pid_t getppid(void) {
    return (pid_t)2;
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

int uname(struct utsname *name) {
    (void)name;
    errno = ENOSYS;
    return -1;
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

/* CPU affinity is inert under the single-baton scheduler — exactly one managed
 * thread runs at a time regardless — so setting it is a deterministic no-op
 * success rather than a real host scheduling effect. */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
    (void)pid;
    (void)cpusetsize;
    (void)mask;
    return 0;
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
    if (name == _SC_NGROUPS_MAX) return 16;
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

/* Fixed physical-memory world-model constant (8 GiB). mimalloc's arena sizing
 * and sysinfo's total-memory probe read it; neither value is guest-observable
 * output, but a fixed nonzero constant keeps their heuristics deterministic
 * regardless of the host's real RAM. */
#define PATINA_PHYSICAL_MEMORY_BYTES (UINT64_C(8) * 1024 * 1024 * 1024)

/*
 * getrusage(): per-process resource accounting is host state (real CPU time,
 * peak RSS, page faults) that varies run to run. Report a value that is a pure
 * function of the deterministic virtual clock instead: ru_utime is the modeled
 * CPU time (elapsed virtual monotonic time via patina_cpu_time_nanos — see its
 * ABI note for why the monotonic clock is the process's summed run-slice total),
 * all attributed to user time (ru_stime = 0, by the split convention above). A
 * guest that branches on its own CPU usage (mimalloc's process-info probe reads
 * ru_utime/ru_stime) then sees a deterministic, monotonically advancing counter
 * instead of live host counters, identical across same-seed runs. Both platforms.
 *
 * Only RUSAGE_SELF carries the modeled CPU time. RUSAGE_CHILDREN stays zeroed
 * (the runtime models no child processes), and on Linux RUSAGE_THREAD stays
 * zeroed too: per-thread run-slices are not separately accumulated (the model is
 * a single process-wide CPU timeline), so a truthful deterministic zero is
 * reported rather than mislabeling the whole-process timeline as one thread's.
 *
 * ru_maxrss stays 0: the shim models no deterministic memory high-water. Guest
 * allocations reach the host allocator / an anonymous-mmap passthrough (Linux
 * SUD; macOS has no mmap interposer at all), so any peak-RSS figure would reflect
 * host allocator/version/platform state — not simulation state — and could not be
 * made a pure function of the seed. A deterministic 0 (mimalloc reads it as
 * peak_rss) is preferable to a non-reproducible number.
 *
 * The first-argument type follows the platform's own prototype: glibc types it as
 * `__rusage_who_t` (an enum under _GNU_SOURCE), Darwin as plain `int`.
 */
#ifdef __linux__
int getrusage(__rusage_who_t who, struct rusage *usage) {
#else
int getrusage(int who, struct rusage *usage) {
#endif
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

#ifdef __linux__
/*
 * sysinfo(2): Linux host memory/uptime/load summary (mimalloc's physical-memory
 * probe on Linux). Report a fixed deterministic struct — uptime from the virtual
 * monotonic clock, total memory = the 8 GiB world-model constant with a 1-byte
 * mem_unit, one process — so a guest reading it sees the same values regardless
 * of the host. freeram stays a fixed half of totalram rather than
 * `totalram - high-water`: the shim models no deterministic memory high-water
 * (see getrusage's ru_maxrss), so there is no seed-stable figure to subtract, and
 * a fixed fraction keeps the value a pure function of the world model.
 */
int sysinfo(struct sysinfo *info) {
    if (info == NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(info, 0, sizeof *info);
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &nanos) == 0) {
        info->uptime = (long)(nanos / UINT64_C(1000000000));
    }
    info->mem_unit = 1;
    info->totalram = (unsigned long)PATINA_PHYSICAL_MEMORY_BYTES;
    info->freeram = (unsigned long)(PATINA_PHYSICAL_MEMORY_BYTES / 2);
    info->procs = 1;
    return 0;
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
 * getrlimit/setrlimit (the sysinfo crate reads limits). getrlimit reports a
 * fixed generous limit — RLIM_INFINITY, except RLIMIT_NOFILE which reports the
 * descriptor table's own bound (patina_fd_limit: the number EMFILE enforces
 * and sysconf(_SC_OPEN_MAX) reports) — as a deterministic constant independent
 * of the host's real ulimits. setrlimit
 * refuses with EPERM: a truthful "cannot mutate host resource limits" rather
 * than a lying success (a guest cannot change limits the runtime does not model).
 */
int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim) {
    /* `rlim` is declared nonnull by glibc (a NULL compare is -Werror under gcc). */
    rlim_t value = RLIM_INFINITY;
#ifdef RLIMIT_NOFILE
    if (resource == RLIMIT_NOFILE) {
        value = (rlim_t)patina_fd_limit();
    }
#endif
    rlim->rlim_cur = value;
    rlim->rlim_max = value;
    return 0;
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    (void)resource;
    (void)rlim;
    errno = EPERM;
    return -1;
}

/*
 * std::thread::available_parallelism reads the CPU affinity mask. Return a fixed
 * single-CPU set so the guest sees a deterministic core count regardless of the
 * host; the deterministic scheduler runs one baton at a time anyway, and every
 * testbed forces stable output ordering, so the value never
 * perturbs results. This is interposed (not trapped) because it IS reached at
 * startup, unlike the inert spawn surface above.
 */
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
    (void)pid;
    if (mask == NULL || cpusetsize == 0) {
        errno = EINVAL;
        return -1;
    }
    memset(mask, 0, cpusetsize);
    /* CPU 0 present, all others absent: a deterministic one-core affinity. */
    ((unsigned char *)mask)[0] = 1;
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
int gethostname(char *name, size_t len) {
    static const char host[] = "patina";
    /* `name` is declared nonnull by glibc (comparing it to NULL is a
     * -Werror=nonnull-compare error under gcc, and passing NULL is caller UB),
     * so only the buffer length is validated here — the readdir/dirent
     * nonnull-parameter precedent above. */
    if (len == 0) {
        errno = EINVAL;
        return -1;
    }
    size_t copied = sizeof host - 1; /* length without the NUL */
    if (copied >= len) copied = len - 1;
    memcpy(name, host, copied);
    name[copied] = '\0';
    return 0;
}
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
