/*
 * Darwin-only surface: Mach/dispatch/os_unfair_lock vehicles, sysctl/task_info
 * host queries, and the CoreFoundation/Security/IOKit deny-traps and models.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __APPLE__
uint64_t mach_absolute_time(void) {
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &nanos) != 0) __builtin_trap();
    return nanos;
}

kern_return_t mach_timebase_info(mach_timebase_info_t info) {
    if (info == NULL) return KERN_INVALID_ARGUMENT;
    info->numer = 1;
    info->denom = 1;
    return KERN_SUCCESS;
}

kern_return_t mach_wait_until(uint64_t deadline) {
    if (patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) != 0) __builtin_trap();
    return KERN_SUCCESS;
}

/*
 * clock_gettime_nsec_np returns the clock value directly in nanoseconds (a
 * Darwin extension rustix's time module reaches for). Route it through the same
 * virtual clock as clock_gettime with the same clock-id mapping. The real API
 * returns 0 on an unrecognized clock id and sets errno EINVAL, so mirror that
 * failure return rather than inventing a sentinel.
 */
uint64_t clock_gettime_nsec_np(clockid_t clock_id) {
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC || clock_id == CLOCK_MONOTONIC_RAW ||
             clock_id == CLOCK_UPTIME_RAW)
        patina_clock = PATINA_CLOCK_MONOTONIC;
    else {
        errno = EINVAL;
        return 0;
    }
    uint64_t nanos = 0;
    if (patina_clock_now(patina_clock, &nanos) != 0) {
        errno = patina_errno();
        return 0;
    }
    return nanos;
}

/*
 * os_unfair_lock (parking_lot_core's Darwin word lock). A bare u32 with no init
 * call, so the deterministic mutex table lazily registers it on first use. The
 * real primitive is non-recursive and traps on a recursive lock by the owner or
 * an unlock by a non-owner; the routed implementation aborts loudly on the same
 * misuse rather than succeeding silently. trylock yields 1 on acquisition and 0
 * when the lock is already held (by anyone), matching the real single-cmpxchg.
 */
void os_unfair_lock_lock(os_unfair_lock_t lock) {
    patina_os_unfair_lock_lock((void *)lock);
}

bool os_unfair_lock_trylock(os_unfair_lock_t lock) {
    return patina_os_unfair_lock_trylock((void *)lock) != 0;
}

void os_unfair_lock_unlock(os_unfair_lock_t lock) {
    patina_os_unfair_lock_unlock((void *)lock);
}

/*
 * issetugid(): "was this process started setuid/setgid?" Interposed to a fixed
 * deterministic 0 (never running as a set-id binary under Patina), so guest code
 * that gates on it (allocators reading environment/config — tikv-jemallocator's
 * malloc-conf lookup calls it) behaves identically regardless of the host's real
 * id state. A pure boolean of fixed process identity, no boundary effect; being
 * a strong def it also drops off the guest import table.
 */
int issetugid(void) {
    return 0;
}

/*
 * libdispatch semaphores. Rust std's Darwin thread Parker blocks on a
 * libdispatch semaphore, so std::thread::park / park_timeout and everything
 * layered on them (mpsc/mpmc recv and recv_timeout, blocking channel and Once
 * paths) reach dispatch_semaphore_wait. Interpose the whole surface and route
 * it through the deterministic scheduler + virtual clock; without this the
 * Parker blocks a real host thread and reads host time outside the runtime.
 *
 * These are strong definitions, so std's references bind here at link time and
 * the real libdispatch symbols drop off the import table entirely. The shim's
 * own execution baton deliberately uses a distinct Mach semaphore, so it never
 * recurses into these interposers.
 */
uint64_t dispatch_time(uint64_t when, int64_t delta) {
    return patina_dispatch_time(when, delta);
}

void *dispatch_semaphore_create(intptr_t value) {
    return patina_dispatch_semaphore_create(value);
}

intptr_t dispatch_semaphore_wait(void *sem, uint64_t timeout) {
    return patina_dispatch_semaphore_wait(sem, timeout);
}

intptr_t dispatch_semaphore_signal(void *sem) {
    return patina_dispatch_semaphore_signal(sem);
}

void dispatch_release(void *object) {
    patina_dispatch_release(object);
}

/*
 * confstr reads host configuration strings (temp/cache directory, default PATH),
 * which are host-specific and nondeterministic. std::env::temp_dir queries
 * _CS_DARWIN_USER_TEMP_DIR; return a fixed deterministic path routed through the
 * deterministic filesystem, and report "no value" for everything else so callers
 * fall back to their own deterministic defaults.
 */
size_t confstr(int name, char *buf, size_t len) {
    const char *value = NULL;
    if (name == _CS_DARWIN_USER_TEMP_DIR) value = "/tmp/";
    if (value == NULL) {
        if (buf != NULL && len > 0) buf[0] = '\0';
        return 0;
    }
    size_t needed = strlen(value) + 1;
    if (buf != NULL && len > 0) {
        size_t copy = needed < len ? needed : len;
        memcpy(buf, value, copy);
        buf[copy - 1] = '\0';
    }
    return needed;
}

/*
 * __assert_rtn (Darwin `assert` failure hook, reached by aws-lc). It only fires
 * when an assertion has already failed, so aborting is the correct deterministic
 * outcome; route the diagnostic to the captured stderr sink first (flush + abort
 * like patina_process_trap) so it reaches the operator. NOT allowlisted — a
 * genuine assertion failure must be a loud, reproducible abort, not a host
 * passthrough.
 */
__attribute__((noreturn)) void __assert_rtn(const char *function, const char *file, int line,
                                            const char *expression) {
    char message[512];
    int needed = snprintf(message, sizeof message,
                          "patina: assertion failed: (%s), function %s, file %s, line %d.\n",
                          expression ? expression : "", function ? function : "",
                          file ? file : "", line);
    if (needed > 0) {
        size_t length = (size_t)needed < sizeof message ? (size_t)needed : sizeof message - 1;
        (void)patina_stdio_write(2, message, length);
    }
    patina_flush_captured_stdio();
    abort();
}

/* Deterministic sysctl emit: copy a fixed value into the caller's oldp per the
 * BSD length protocol (report the size when oldp is NULL; ENOMEM on a short
 * buffer). Shared by the mib `sysctl` and the name-keyed `sysctlbyname`. */
static int patina_sysctl_emit(const void *value, size_t value_len, void *oldp, size_t *oldlenp) {
    if (oldp != NULL) {
        if (oldlenp == NULL) {
            errno = EINVAL;
            return -1;
        }
        if (*oldlenp < value_len) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(oldp, value, value_len);
        *oldlenp = value_len;
    } else if (oldlenp != NULL) {
        *oldlenp = value_len;
    }
    return 0;
}

static int patina_sysctl_emit_int(int value, void *oldp, size_t *oldlenp) {
    return patina_sysctl_emit(&value, sizeof value, oldp, oldlenp);
}

static int patina_sysctl_emit_int64(int64_t value, void *oldp, size_t *oldlenp) {
    return patina_sysctl_emit(&value, sizeof value, oldp, oldlenp);
}

/*
 * sysctl (mib form) / sysctlbyname (name form): host hardware/kernel state reads
 * (mimalloc's physical-memory probe, sysinfo's totals, aws-lc's CPU-feature
 * detection). Serve the small set of keys real crates query as fixed
 * world-model constants: physical memory = 8 GiB, CPU count = 1, page size =
 * 4096 (matching sysconf), and EVERY optional CPU feature (`hw.optional.*`)
 * reported ABSENT (0) so crypto libraries fall back to portable, deterministic
 * code paths. Writes (newp) are refused (EPERM — a guest may not mutate kernel
 * state), and any unmodeled key fails ENOENT per the sysctl convention, so an
 * unhandled query is a deterministic miss rather than a host read.
 */
int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (newp != NULL || newlen != 0) {
        errno = EPERM;
        return -1;
    }
    if (name == NULL || namelen < 2) {
        errno = ENOENT;
        return -1;
    }
    if (name[0] == CTL_HW) {
        switch (name[1]) {
#ifdef HW_MEMSIZE
        case HW_MEMSIZE:
            return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
#endif
#ifdef HW_PHYSMEM64
        case HW_PHYSMEM64:
            return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
#endif
#ifdef HW_NCPU
        case HW_NCPU:
            return patina_sysctl_emit_int(1, oldp, oldlenp);
#endif
#ifdef HW_AVAILCPU
        case HW_AVAILCPU:
            return patina_sysctl_emit_int(1, oldp, oldlenp);
#endif
#ifdef HW_PAGESIZE
        case HW_PAGESIZE:
            return patina_sysctl_emit_int(4096, oldp, oldlenp);
#endif
        default:
            break;
        }
    }
    errno = ENOENT;
    return -1;
}

int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (newp != NULL || newlen != 0) {
        errno = EPERM;
        return -1;
    }
    if (name == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        return patina_sysctl_emit_int64((int64_t)PATINA_PHYSICAL_MEMORY_BYTES, oldp, oldlenp);
    }
    if (strcmp(name, "hw.pagesize") == 0) {
        return patina_sysctl_emit_int(4096, oldp, oldlenp);
    }
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.logicalcpu_max") == 0 || strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu_max") == 0 || strcmp(name, "hw.activecpu") == 0) {
        return patina_sysctl_emit_int(1, oldp, oldlenp);
    }
    /* Optional CPU-feature flags → absent (0): safe and deterministic, crypto
     * libraries take the portable path. */
    if (strncmp(name, "hw.optional.", 12) == 0) {
        return patina_sysctl_emit_int(0, oldp, oldlenp);
    }
    errno = ENOENT;
    return -1;
}

/* Split a nanosecond count into a Mach `time_value_t` (seconds + microseconds),
 * the CPU-time carrier in the task_info flavors. Same all-as-user convention as
 * getrusage: the caller fills user_time from this and leaves system_time zeroed. */
static void patina_time_value_from_nanos(uint64_t nanos, time_value_t *out) {
    out->seconds = (integer_t)(nanos / UINT64_C(1000000000));
    out->microseconds = (integer_t)((nanos % UINT64_C(1000000000)) / 1000);
}

/*
 * task_info: Mach per-task introspection. Real consumers (verified against
 * mimalloc's `_mi_prim_process_info`) read `resident_size` from MACH_TASK_BASIC_INFO
 * (falling back to TASK_BASIC_INFO) for current RSS. Memory sizes stay 0 for the
 * same reason getrusage's ru_maxrss does — no deterministic memory high-water is
 * modeled (see getrusage) — but the CPU-time fields the basic flavors carry are
 * filled from the SAME deterministic model as getrusage's ru_utime
 * (patina_cpu_time_nanos), all as user_time, so a guest branching on task-level
 * CPU time sees the same monotonically advancing, seed-stable counter. Every other
 * word stays zeroed and the call reports KERN_SUCCESS. The task port argument
 * (mach_task_self) is ignored. */
kern_return_t task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out,
                        mach_msg_type_number_t *task_info_count) {
    (void)target_task;
    if (task_info_out == NULL || task_info_count == NULL) {
        return KERN_SUCCESS;
    }
    mach_msg_type_number_t count = *task_info_count;
    memset(task_info_out, 0, (size_t)count * sizeof(natural_t));
    uint64_t nanos = 0;
    (void)patina_cpu_time_nanos(&nanos);
    switch (flavor) {
#ifdef MACH_TASK_BASIC_INFO
    case MACH_TASK_BASIC_INFO:
        if (count >= MACH_TASK_BASIC_INFO_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((mach_task_basic_info_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_BASIC_INFO_64
    case TASK_BASIC_INFO_64:
        if (count >= TASK_BASIC_INFO_64_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_basic_info_64_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_BASIC_INFO_32
    case TASK_BASIC_INFO_32:
        if (count >= TASK_BASIC_INFO_32_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_basic_info_32_t)task_info_out)->user_time);
        }
        break;
#endif
#ifdef TASK_THREAD_TIMES_INFO
    case TASK_THREAD_TIMES_INFO:
        if (count >= TASK_THREAD_TIMES_INFO_COUNT) {
            patina_time_value_from_nanos(
                nanos, &((task_thread_times_info_t)task_info_out)->user_time);
        }
        break;
#endif
    default:
        break;
    }
    return KERN_SUCCESS;
}

/*
 * _NSGetExecutablePath hands back the host executable's real path (std's
 * current_exe() reads it). Fail so current_exe() is a deterministic Err rather
 * than leaking the host path. A future guest that needs current_exe() -> Ok
 * should get a FIXED VIRTUAL path written here, never the host's real one.
 * (One leading underscore in source: the asm symbol is `__NSGetExecutablePath`,
 * matching the guest import — two underscores here would define the wrong name.)
 */
int _NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    (void)buf;
    (void)bufsize;
    return -1;
}

#endif

/*
 * Dormant-path deny-traps: the helpers of the native-trust-root
 * (rustls-native-certs) and host-inventory (sysinfo / chrono-timezone) surfaces
 * that the honest deterministic models below leave unreachable by construction.
 *
 * These generalize the process-spawn deny-trap doctrine above (ESCAPE-CLASSES.md
 * row e, "Why symbol-reachability, not static call-graph"). A large native
 * binary commonly LINKS an optional TLS-trust-root loader or a host-inventory
 * crate whose call sites are statically wired but runtime-flag dormant — the
 * scenario never reaches them — yet a reachability audit cannot clear a
 * statically-wired path, so the pre-run gate would refuse the whole binary. A
 * strong shim definition binds the guest reference at link (the symbol drops off
 * the import table, so the gate passes when the path is dormant) and fails LOUD +
 * reproducibly at FIRST CALL, naming the symbol, if a scenario genuinely reaches
 * it. Merely linking the surface is inert; only a real call trips the trap.
 *
 * Scope is exactly the enumerated dormant surface. The LIVE-path members these
 * families also expose — `sysctl`/`sysctlbyname`/`getrusage`/`task_info`, the
 * stdio surface, `localtime_r` — are deliberately NOT trapped here (a tier-3
 * interposer change owns those): a strong def would silently swallow a path a
 * normal startup actually reaches, so they stay refused pre-run.
 */
/* Apple-only: every remaining caller is a PATINA_FRAMEWORK_TRAP /
 * PATINA_INTROSPECTION_TRAP macro in the __APPLE__ region below — the
 * cross-platform members (`kill`, `if_nametoindex`) are deterministic models now,
 * and an unguarded unused static is -Werror=unused-function on Linux. */

#ifdef __APPLE__
__attribute__((noreturn)) static void patina_native_trap(const char *klass,
                                                         const char *symbol) {
    static const char prefix[] = "patina: ";
    write(2, prefix, sizeof prefix - 1);
    write(2, klass, strlen(klass));
    static const char mid[] = " reached under patina: ";
    write(2, mid, sizeof mid - 1);
    write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; not interposed by the deterministic runtime; failing closed\n";
    write(2, suffix, sizeof suffix - 1);
    /* abort() skips the atexit shutdown flush (patina_process_trap precedent), so
     * push the captured guest output and this diagnostic to the real descriptors
     * before terminating. */
    patina_flush_captured_stdio();
    abort();
}

/*
 * macOS CoreFoundation / Security framework and Mach/BSD/IOKit host-introspection
 * surface. A runtime abort is not "support": wherever the API contract admits an
 * honest deterministic result, the entry point below returns it, so a program
 * that EXERCISES the path (rustls-native-certs' trust-root loader, sysinfo's
 * host/CPU/process inventory, iana-time-zone/chrono's local timezone) runs
 * deterministically — like a locked-down host with an empty inventory — instead
 * of aborting. Once each ENTRY point returns honest emptiness, a set of helpers
 * becomes unreachable by construction; those stay deny-traps, each annotated
 * with why the honest entry points can never reach it. Every def here (honest or
 * trap) binds its guest reference by NAME and shadows the framework/Mach symbol
 * at link (the symbol drops off the import table); the traps additionally keep
 * the arity-free `void name(void)` shape, safe because they are never called.
 */

/* Synthetic CoreFoundation tokens handed back by the honest entry points so a
 * consumer runs against a valid non-NULL object without any real CF object
 * existing. Each is a distinct address (so an identity compare, though none is
 * performed today, still distinguishes them); their bytes are never read. */
static const char patina_cf_empty_array = 0;
static const char patina_cf_system_timezone = 0;
static const char patina_cf_timezone_name = 0;
static const char patina_cf_utc_name[] = "UTC";
/* The guest's fixed virtual executable path (proc_pidpath for pid 1). */
static const char patina_proc_pid1_path[] = "/patina/guest";

/* --- rustls-native-certs / security-framework trust-root surface ---
 *
 * Verified against rustls-native-certs 0.8.4 + security-framework 3.7.0 +
 * core-foundation 0.10.1. TrustSettings::iter() calls
 * SecTrustSettingsCopyCertificates and maps errSecNoTrustSettings to an EMPTY
 * certificate iterator (via CFArray::from_CFTypes(&[])), so load_native_certs()
 * returns zero certs and zero errors deterministically for every domain — a host
 * with no per-domain trust settings. Return that status for all domains; the out
 * parameter is left untouched (security-framework ignores it on this status).
 */
int SecTrustSettingsCopyCertificates(unsigned int domain, void **out) {
    (void)domain;
    (void)out;
    return -25263; /* errSecNoTrustSettings */
}

/* --- CoreFoundation helpers the honest entry points make reachable ---
 *
 * The empty trust-root path builds an empty CFArray (from_CFTypes(&[]) ->
 * CFArrayCreate/CFArrayGetCount/CFRelease), and the UTC timezone path below
 * releases its synthetic timezone. Exactly those helpers are honest; the rest
 * stay traps. `wrap_under_create_rule` asserts non-NULL, so CFArrayCreate and
 * CFTimeZoneCopySystem must return non-NULL synthetic tokens (defined with the
 * data symbols below). No real CF object is ever created: their bytes are never
 * read, so CFArrayGetCount reports 0 and CFRelease is a no-op (also for NULL).
 */
const void *CFArrayCreate(const void *allocator, const void *const *values,
                          long num_values, const void *callbacks) {
    (void)allocator;
    (void)values;
    (void)num_values;
    (void)callbacks;
    return &patina_cf_empty_array;
}
long CFArrayGetCount(const void *array) {
    (void)array;
    return 0;
}
void CFRelease(const void *cf) { (void)cf; }

/* --- iana-time-zone 0.1.65 / chrono::Local timezone surface ---
 *
 * The runtime models a single fixed timezone, UTC (see localtime_r above:
 * tm_gmtoff 0, tm_zone "UTC"), so report UTC here for a consistent world.
 * tz_darwin.rs flow: CFTimeZoneResetSystem() (cache invalidate; a no-op here) ->
 * a non-NULL CFTimeZoneCopySystem() -> CFTimeZoneGetName() -> as_utf8()
 * (CFStringGetCStringPtr, UTF-8) yields "UTC". Returning the C string directly
 * keeps the fallback conversion (CFStringGetLength/CFStringGetBytes) unreachable.
 * get_timezone() therefore returns Ok("UTC"); chrono::Local resolves the same
 * fixed UTC offset it gets from the localtime_r interposer, deterministically.
 */
void CFTimeZoneResetSystem(void) {}
const void *CFTimeZoneCopySystem(void) { return &patina_cf_system_timezone; }
const void *CFTimeZoneGetName(const void *tz) {
    (void)tz;
    return &patina_cf_timezone_name;
}
const char *CFStringGetCStringPtr(const void *string, unsigned int encoding) {
    (void)string;
    (void)encoding;
    return patina_cf_utc_name;
}

/* --- IOKit CPU-frequency surface (sysinfo get_cpu_frequency, macos/cpu.rs) ---
 *
 * Return NULL from IOServiceMatching: sysinfo reads a NULL matching dictionary as
 * "AppleARMIODevice not found" and reports CPU frequency 0 (unknown) — honest,
 * since the deterministic world does not model CPU frequency. This keeps the
 * whole IOServiceGetMatchingServices / IOIteratorNext / IOObjectRelease /
 * IORegistryEntry* / CFData chain unreachable (they stay traps below).
 */
void *IOServiceMatching(const char *name) {
    (void)name;
    return NULL;
}

/* --- deny-traps unreachable once the entry points above return honest emptiness.
 * `void name(void)` is safe because none is ever called (justification each). */
#define PATINA_FRAMEWORK_TRAP(name)                                            \
    void name(void) { patina_native_trap("macos-framework", #name); }
#define PATINA_INTROSPECTION_TRAP(name)                                        \
    void name(void) { patina_native_trap("host-introspection", #name); }

/* Trust-root empty path: the cert iterator is empty, so no certificate is ever
 * indexed, DER-encoded, or trust-queried, and no os_error is formatted. */
PATINA_FRAMEWORK_TRAP(CFArrayGetValueAtIndex)     /* empty array: never indexed */
PATINA_FRAMEWORK_TRAP(SecCertificateCopyData)     /* no cert to DER-encode */
PATINA_FRAMEWORK_TRAP(SecTrustSettingsCopyTrustSettings) /* no cert to query */
PATINA_FRAMEWORK_TRAP(SecCopyErrorMessageString)  /* errSecNoTrustSettings != error path */
/* Per-cert trust-settings inspection (CFDictionary/CFNumber/CFString compares)
 * only runs once a cert is yielded — never on the empty path. */
PATINA_FRAMEWORK_TRAP(CFDictionaryGetValueIfPresent)
PATINA_FRAMEWORK_TRAP(CFEqual)
PATINA_FRAMEWORK_TRAP(CFNumberGetValue)
PATINA_FRAMEWORK_TRAP(CFGetTypeID)
/* CFString builders and the get-rule retain: security-framework's cert/policy
 * name construction and iana's to_utf8 fallback are all downstream of a yielded
 * cert or a NULL CFStringGetCStringPtr — neither occurs. */
PATINA_FRAMEWORK_TRAP(CFRetain)
PATINA_FRAMEWORK_TRAP(CFStringCreateWithBytesNoCopy)
PATINA_FRAMEWORK_TRAP(CFStringCreateWithCStringNoCopy)
PATINA_FRAMEWORK_TRAP(CFStringGetBytes)
PATINA_FRAMEWORK_TRAP(CFStringGetLength)
/* CFData accessors belong to the IOKit CPU-frequency property read, dead once
 * IOServiceMatching returns NULL. */
PATINA_FRAMEWORK_TRAP(CFDataGetBytePtr)
PATINA_FRAMEWORK_TRAP(CFDataGetLength)
PATINA_FRAMEWORK_TRAP(CFDataGetBytes)
PATINA_FRAMEWORK_TRAP(CFDataGetTypeID)

/* The IOKit registry walk is entered only with a non-NULL matching dictionary;
 * IOServiceMatching returns NULL, so none of these is reached. */
PATINA_INTROSPECTION_TRAP(IOIteratorNext)
PATINA_INTROSPECTION_TRAP(IOObjectRelease)
PATINA_INTROSPECTION_TRAP(IORegistryEntryCreateCFProperty)
PATINA_INTROSPECTION_TRAP(IORegistryEntryGetName)
PATINA_INTROSPECTION_TRAP(IOServiceGetMatchingServices)

#undef PATINA_FRAMEWORK_TRAP
#undef PATINA_INTROSPECTION_TRAP

/* --- BSD per-process introspection (sysinfo process refresh) ---
 *
 * The deterministic world is a single process — the guest, pid 1 (getpid()==1,
 * getppid()==0). proc_listallpids honestly enumerates that one pid: the sizing
 * call (buffer==NULL) reports one pid; the fill call writes pid 1. (sysinfo's
 * get_proc_list treats a fill that exactly reaches the reported capacity as "the
 * list grew, retry" and drops it, so under sysinfo the *detailed* list ends up
 * empty and proc_pidpath/proc_pidinfo/proc_pid_rusage are not reached via
 * new_all — that is sysinfo's own capacity heuristic, not a fabricated count
 * here; the honest pid count is 1.) The three per-pid queries are still
 * converted to honest deterministic results so any DIRECT caller runs
 * deterministically rather than aborting. */
int proc_listallpids(void *buffer, int buffersize) {
    if (buffer == NULL || buffersize <= 0) {
        return 1; /* one pid exists: the guest, pid 1 */
    }
    if ((size_t)buffersize < sizeof(int)) {
        return 0;
    }
    *(int *)buffer = 1;
    return 1;
}
/* proc_pidpath: the guest's virtual executable path (a fixed deterministic
 * identity, never the host's real path — the gethostname/_NSGetExecutablePath
 * doctrine). Other pids: no such process. */
int proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (buffer == NULL) {
        errno = EFAULT;
        return -1;
    }
    size_t len = sizeof(patina_proc_pid1_path) - 1;
    if ((size_t)buffersize < len + 1) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(buffer, patina_proc_pid1_path, len + 1);
    return (int)len; /* real proc_pidpath returns the length, excluding the NUL */
}
/* proc_pidinfo: pid 1 exists, but its kernel-internal BSD/task/vnode info is not
 * modeled — report zero bytes filled. A caller (sysinfo's get_bsd_info /
 * get_cwd_root) reads that as "no info for this flavor" and degrades gracefully
 * (falls back to the proc_pidpath name) rather than aborting. Other pids: ESRCH. */
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    (void)flavor;
    (void)arg;
    (void)buffer;
    (void)buffersize;
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}
/* proc_pid_rusage: pid 1 has no modeled per-process resource accounting, so
 * report an all-zero rusage for the one flavor real consumers request
 * (RUSAGE_INFO_V2, sysinfo's disk-io read); zeroing only that known-size struct
 * keeps the write in bounds. Other flavors/pids: deterministic error. */
int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (buffer == NULL) {
        errno = EFAULT;
        return -1;
    }
    if (flavor == RUSAGE_INFO_V2) {
        memset(buffer, 0, sizeof(struct rusage_info_v2));
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* --- Mach host / VM introspection (sysinfo memory + CPU refresh) ---
 * Prototyped by the mach headers (included for the task_info interposer above),
 * so these spell the real signatures. */

/* mach_host_self: a fixed synthetic host port. Its only consumers are the
 * deterministic host_statistics64 / host_processor_info below, which ignore the
 * port, so a real Mach host port is never needed. */
mach_port_t mach_host_self(void) { return (mach_port_t)0x484f5354u; /* 'HOST' */ }

/* host_statistics64(HOST_VM_INFO64): fixed VM page statistics consistent with the
 * shim's 8 GiB world (PATINA_PHYSICAL_MEMORY_BYTES) at 4 KiB pages = 2,097,152
 * pages, split into a stable, self-consistent free/active/inactive/wired layout.
 * Only the HOST_VM_INFO64 flavor is modeled (the one sysinfo requests). */
kern_return_t host_statistics64(host_t host_priv, host_flavor_t flavor,
                                host_info64_t host_info64_out,
                                mach_msg_type_number_t *host_info64_outCnt) {
    (void)host_priv;
    if (flavor != HOST_VM_INFO64 || host_info64_out == NULL ||
        host_info64_outCnt == NULL || *host_info64_outCnt < HOST_VM_INFO64_COUNT) {
        return KERN_INVALID_ARGUMENT;
    }
    struct vm_statistics64 stat;
    memset(&stat, 0, sizeof stat);
    stat.free_count = 524288;     /* 2 GiB free */
    stat.active_count = 786432;   /* 3 GiB active */
    stat.inactive_count = 524288; /* 2 GiB inactive */
    stat.wire_count = 262144;     /* 1 GiB wired */
    memcpy(host_info64_out, &stat, sizeof stat);
    *host_info64_outCnt = HOST_VM_INFO64_COUNT;
    return KERN_SUCCESS;
}

/* host_processor_info(PROCESSOR_CPU_LOAD_INFO): fixed single-CPU load ticks,
 * consistent with the cpu-count=1 world model (sysctl HW_NCPU=1). sysinfo pushes
 * one Cpu from this, so System::cpus().len() == 1. The buffer is a real one-page
 * mmap because sysinfo frees it two ways: macos/system.rs via munmap(ptr,
 * vm_page_size) — a real munmap of this real mapping (munmap is NOT interposed,
 * so a static buffer would unmap program data) — and apple/cpu.rs via
 * vm_deallocate, which the shim no-ops (that path leaks one page per CPU refresh,
 * bounded and negligible). */
kern_return_t host_processor_info(host_t host, processor_flavor_t flavor,
                                  natural_t *out_processor_count,
                                  processor_info_array_t *out_processor_info,
                                  mach_msg_type_number_t *out_processor_infoCnt) {
    (void)host;
    if (flavor != PROCESSOR_CPU_LOAD_INFO || out_processor_count == NULL ||
        out_processor_info == NULL || out_processor_infoCnt == NULL) {
        return KERN_INVALID_ARGUMENT;
    }
    int *buffer = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buffer == MAP_FAILED) {
        return KERN_RESOURCE_SHORTAGE;
    }
    buffer[CPU_STATE_USER] = 0;
    buffer[CPU_STATE_SYSTEM] = 0;
    buffer[CPU_STATE_IDLE] = 1000; /* wholly idle; a fixed nonzero total avoids NaN */
    buffer[CPU_STATE_NICE] = 0;
    *out_processor_count = 1;
    *out_processor_info = (processor_info_array_t)buffer;
    *out_processor_infoCnt = CPU_STATE_MAX;
    return KERN_SUCCESS;
}

/* vm_deallocate: a memory-safe no-op. Its one guest caller frees the
 * host_processor_info buffer above; unmapping a caller-chosen address here would
 * not be safe, and the companion munmap free path reclaims its own copies. */
kern_return_t vm_deallocate(vm_map_t target_task, vm_address_t address,
                            vm_size_t size) {
    (void)target_task;
    (void)address;
    (void)size;
    return KERN_SUCCESS;
}

/*
 * Data symbols cannot be trapped on read, so they get fixed deterministic
 * values. Each is only ever passed into a call that is either an honest entry
 * point above (which ignores or safely consumes the value) or an unreachable
 * trap; these bindings satisfy the data reference and drop the symbol off the
 * import table.
 */
void *const kCFAllocatorDefault = NULL; /* CF's own "default allocator" sentinel */
void *const kCFAllocatorNull = NULL;
/* CFArrayCallBacks {version, retain, release, copyDescription, equal}: a zeroed
 * "no custom management" struct, only ever handed to the honest CFArrayCreate
 * (which ignores it — the empty array has no elements to manage). */
const struct {
    long version;
    void *retain;
    void *release;
    void *copy_description;
    void *equal;
} kCFTypeArrayCallBacks = {0, NULL, NULL, NULL, NULL};
unsigned int kIOMasterPortDefault = 0; /* IOKit default master port; only reaches
                                        * the unreachable IOServiceGetMatchingServices */
/* mach_task_self_ is the task's send-right port name (a mach_port_t). A
 * synthetic, obviously-non-real value; its consumer (vm_deallocate) is a no-op,
 * so it is never used as a real port. */
unsigned int mach_task_self_ = 0x50415400u; /* 'PAT\0' */
/* vm_page_size (vm_size_t): the shim's single world-model page size, matching
 * sysconf(_SC_PAGESIZE) and sysctl(HW_PAGESIZE). Read by sysinfo's munmap free
 * path for the host_processor_info buffer (a real one-page mmap). */
unsigned long vm_page_size = 4096;
#endif
