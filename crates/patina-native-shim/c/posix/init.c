/*
 * Init: syscall-user-dispatch arming, the libc `syscall(2)` vehicle that
 * forwards into the same dispatcher, the timestamp-counter trap, the
 * `__libc_start_main` wrapper, and the constructor/atexit lifecycle.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
/*
 * The libc `syscall(2)` vehicle. glibc's is a register shuffle straight into
 * the kernel; this one forwards EVERY number into the same dispatcher the
 * SIGSYS handler uses (`patina_sud_dispatch`, generated from the syscall
 * registry), so the three vehicles a guest has — the libc wrapper, this
 * wrapper, and a raw `syscall` instruction — cannot answer one number
 * differently. Rust std reaches it for futex (Mutex/Condvar/parking) and the
 * `getrandom` crate for SYS_getrandom; both were the old two-entry allowlist
 * and are now ordinary registry rows.
 *
 * All six arguments are read from the variadic list, as musl's syscall() does:
 * a caller that passed fewer leaves the rest as whatever the registers and
 * stack hold, exactly what the kernel would have seen. The dispatcher's raw
 * `-errno` is reshaped into this wrapper's `-1`/`errno` contract. The faulting
 * address argument is 0: this is a call, not a trap.
 */
long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    uint64_t args[6];
    for (int i = 0; i < 6; i++) args[i] = va_arg(ap, uint64_t);
    va_end(ap);
    long result = patina_sud_dispatch((long)number, args[0], args[1], args[2], args[3],
                                      args[4], args[5], 0);
    if (result < 0 && result > -4096) {
        errno = (int)-result;
        return -1;
    }
    return result;
}

/* ==========================================================================
 * Syscall-user-dispatch (SUD).
 *
 * Arms the kernel's syscall-user-dispatch so a guest's raw inline `syscall`
 * instruction (rustix's default linux_raw backend, hand-written asm, ...) —
 * invisible to the import audit and refused by the instruction scan — is trapped
 * into the deterministic runtime instead of escaping it. Design: SUD-DESIGN.md.
 *
 * Mode: allowed region = glibc's single executable segment, NULL selector, so
 * every syscall instruction OUTSIDE glibc text unconditionally delivers a
 * thread-directed SIGSYS (there is no guest-writable selector byte to protect).
 * The shim itself reaches the kernel only through glibc host aliases (audit
 * proven: shim/guest text contains zero syscall opcodes), so glibc text is the
 * exact allowed region. Two arming sites, zero selector sites, zero disarm
 * sites: the main thread here in `__libc_start_main`, every managed thread in
 * the Rust `thread_trampoline`. The config does not survive clone/fork/exec, so
 * each thread arms once.
 *
 * All host vehicles the SUD paths touch (prctl, sigaction, the /proc/self/maps
 * reader's open/read/close) are resolved through `__real_dlsym(RTLD_NEXT, ...)`
 * — the `-Wl,--wrap=dlsym` alias — so those names never appear as undefined
 * externals in the shim objects (host-alias doctrine) and so `open`/`read`
 * reach the REAL glibc descriptors rather than this shim's interposed
 * (deterministic-FS) strong defs.
 * ========================================================================== */

extern void *__real_dlsym(void *handle, const char *symbol);

/* prctl SUD op numbers (6.8 UAPI headers may predate the constants). */
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF 0
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif
/* si_code for a syscall-user-dispatch SIGSYS. */
#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

typedef int (*patina_prctl_fn)(int, unsigned long, unsigned long, unsigned long,
                               void *);
typedef int (*patina_host_open_fn)(const char *, int, ...);
typedef ssize_t (*patina_host_read_fn)(int, void *, size_t);
typedef int (*patina_host_close_fn)(int);
typedef int (*patina_host_sigaction_fn)(int, const struct sigaction *,
                                        struct sigaction *);

static patina_prctl_fn patina_host_prctl;
static patina_host_open_fn patina_host_open;
static patina_host_read_fn patina_host_read_real;
static patina_host_close_fn patina_host_close_real;
static patina_host_sigaction_fn patina_host_sigaction;

/* The glibc allowed region (its one executable segment) and the main
 * executable's text span. Discovered once from /proc/self/maps at arming. */
static unsigned long patina_sud_libc_off;
static unsigned long patina_sud_libc_len;
static uintptr_t patina_sud_text_lo;
static uintptr_t patina_sud_text_hi;
static int patina_sud_armed; /* set once the main thread arms; gates thread arming */
static int patina_tsc_armed; /* set once the main thread arms the TSC trap; gates thread arming */

/* Rust side of the boundary (see src/sud.rs / lib.rs). */
extern long patina_sud_dispatch(long nr, unsigned long a0, unsigned long a1,
                                unsigned long a2, unsigned long a3,
                                unsigned long a4, unsigned long a5,
                                uintptr_t call_addr);
_Noreturn void patina_sud_report_fatal(const char *message);
_Noreturn void patina_sud_report_fatal_addr(const char *message, long nr,
                                            uintptr_t addr);
/* The arming flag is OWNED by the Rust lib (an exported AtomicU8 in a writable
 * section); the C arming path stores into it so `sud_armed_metadata` can read it
 * without the C→Rust link direction that left the lib's own test binary with an
 * undefined symbol. C is only ever linked where the Rust lib is present. */
extern unsigned char PATINA_SUD_ARMED;
/* The scrubbed auxv region (base pointer + byte length through AT_NULL,
 * inclusive), captured during the init scrub below and OWNED by the Rust lib
 * (exported AtomicUsize, same C→Rust direction and rationale as
 * PATINA_SUD_ARMED). The Rust PR_GET_AUXV dispatch row copies from here so a raw
 * prctl(PR_GET_AUXV) serves the shim's determinized auxv, never the kernel's
 * pristine saved_auxv. */
extern uintptr_t PATINA_SUD_AUXV_BASE;
extern uintptr_t PATINA_SUD_AUXV_LEN;

/* Lazily resolve the REAL glibc sigaction through the wrap alias, so the shim's
 * own SIGSYS-hardening `sigaction` strong def below can forward to it without
 * naming `sigaction` as an undefined external. Shared by the SIGSYS installer
 * and the interposer. */
static patina_host_sigaction_fn patina_real_sigaction(void) {
    if (patina_host_sigaction == NULL) {
        patina_host_sigaction =
            (patina_host_sigaction_fn)__real_dlsym(RTLD_NEXT, "sigaction");
    }
    return patina_host_sigaction;
}

static int patina_env_has(const char *name, char **argv, int argc) {
    char **envp = argv + argc + 1;
    size_t nlen = strlen(name);
    for (char **e = envp; *e != NULL; e++) {
        if (strncmp(*e, name, nlen) == 0 && (*e)[nlen] == '=') return 1;
    }
    return 0;
}

static uintptr_t patina_parse_hex(const char **cursor) {
    uintptr_t value = 0;
    const char *s = *cursor;
    for (;;) {
        char c = *s;
        uintptr_t digit;
        if (c >= '0' && c <= '9') digit = (uintptr_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uintptr_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uintptr_t)(c - 'A' + 10);
        else break;
        value = (value << 4) | digit;
        s++;
    }
    *cursor = s;
    return value;
}

/* Slurp /proc/self/maps through the REAL glibc open/read/close (never the
 * interposed deterministic-FS strong defs). Fails closed (never a partial parse
 * on a guessed region) if the file is larger than the buffer. */
static int patina_sud_read_maps(char *buffer, size_t capacity, size_t *out_len) {
    int fd = patina_host_open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    for (;;) {
        if (total >= capacity) {
            patina_host_close_real(fd);
            return -1;
        }
        ssize_t n = patina_host_read_real(fd, buffer + total, capacity - total);
        if (n < 0) {
            patina_host_close_real(fd);
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    patina_host_close_real(fd);
    *out_len = total;
    return 0;
}

/* Discover (a) glibc's single executable segment (the allowed region) and (b)
 * the main executable's text span (which must contain the guest's syscall
 * sites). The text span is identified as the executable segment that contains
 * this handler's own code address — guest + shim + std share the one main-exe
 * r-xp mapping, so no path/readlink is needed. Returns 0 on success; -1 (fail
 * closed) unless exactly one executable libc segment and a text span are found.
 */
static void patina_sud_sigsys(int sig, siginfo_t *info, void *ucontext);

static int patina_sud_discover_regions(void) {
    /* 1 MiB comfortably covers /proc/self/maps for a statically-shim-linked
     * program; a larger map fails closed rather than parse a truncated view. */
    size_t capacity = 1u << 20;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) return -1;
    size_t length = 0;
    if (patina_sud_read_maps(buffer, capacity, &length) != 0) {
        free(buffer);
        return -1;
    }
    uintptr_t marker = (uintptr_t)(void *)&patina_sud_sigsys;
    int libc_exec_segments = 0;
    int text_found = 0;
    size_t index = 0;
    while (index < length) {
        char *line = buffer + index;
        /* NUL-terminate this line so string ops stay within it. */
        char *newline = memchr(line, '\n', length - index);
        size_t line_len = newline ? (size_t)(newline - line) : (length - index);
        line[line_len] = '\0';
        index += line_len + 1;

        const char *cursor = line;
        uintptr_t start = patina_parse_hex(&cursor);
        if (*cursor != '-') continue;
        cursor++;
        uintptr_t end = patina_parse_hex(&cursor);
        if (*cursor != ' ') continue;
        cursor++;
        /* perms are exactly 4 chars: e.g. "r-xp". */
        if (cursor[0] == '\0' || cursor[1] == '\0' || cursor[2] == '\0') continue;
        int executable = cursor[2] == 'x';
        if (!executable) continue;

        /* Main-executable text: the executable segment containing our own code. */
        if (marker >= start && marker < end) {
            patina_sud_text_lo = start;
            patina_sud_text_hi = end;
            text_found = 1;
        }

        /* libc: match the mapped pathname's basename. */
        const char *path = strchr(line, '/');
        if (path != NULL) {
            const char *slash = strrchr(path, '/');
            const char *base = slash ? slash + 1 : path;
            /* `libc-` is the legacy glibc spelling (libc-2.31.so), so it must be
             * followed by the VERSION digit: a guest binary that happens to be
             * named `libc-something` is not glibc, and counting it as a second
             * libc segment refuses the whole run (it fails closed, but on a
             * name). */
            if (strncmp(base, "libc.so.6", 9) == 0 ||
                (strncmp(base, "libc-", 5) == 0 && base[5] >= '0' && base[5] <= '9')) {
                libc_exec_segments++;
                patina_sud_libc_off = (unsigned long)start;
                patina_sud_libc_len = (unsigned long)(end - start);
            }
        }
    }
    free(buffer);
    if (libc_exec_segments != 1 || !text_found) return -1;
    return 0;
}

/* Close the vDSO escape (SUD-DESIGN.md §6): rewrite the initial-stack auxv
 * entry AT_SYSINFO_EHDR to AT_IGNORE. glibc's getauxval walks this same array
 * (only AT_HWCAP is cached), so rustix's `getauxval(AT_SYSINFO_EHDR)` then
 * returns 0, its vDSO pointer is null, and it falls back to raw `clock_gettime`
 * — which SUD traps. glibc consumed the auxv before this scrub (host aliases
 * keep working). */
static void patina_sud_scrub_auxv(int argc, char **argv) {
    char **envp = argv + argc + 1;
    char **walk = envp;
    while (*walk != NULL) walk++;
    walk++; /* step over envp's NULL terminator to the auxv array */
    ElfW(auxv_t) *aux = (ElfW(auxv_t) *)walk;
    ElfW(auxv_t) *base = aux;
    for (; aux->a_type != AT_NULL; aux++) {
        if (aux->a_type == AT_SYSINFO_EHDR) aux->a_type = AT_IGNORE;
    }
    /* `aux` now points at the terminating AT_NULL entry. Publish the scrubbed
     * auxv region — base and length through AT_NULL inclusive — to the Rust-owned
     * cells so the PR_GET_AUXV dispatch row copies THIS determinized array (this
     * runs after AT_RANDOM determinization and the AT_SYSINFO_EHDR rename, both
     * before SUD is armed, so no trap can observe an un-scrubbed region). */
    PATINA_SUD_AUXV_BASE = (uintptr_t)base;
    PATINA_SUD_AUXV_LEN = (uintptr_t)((char *)(aux + 1) - (char *)base);
}

/* AT_RANDOM determinization (SUD-DESIGN.md §9 slice 3). The kernel seeds the
 * auxv AT_RANDOM entry with 16 real-random bytes that glibc consumes at startup
 * for the stack canary and pointer guard AND that a guest can read directly via
 * getauxval(AT_RANDOM) — a nondeterminism/entropy leak. Unlike AT_SYSINFO_EHDR
 * (scrubbed to AT_IGNORE), AT_RANDOM must be REPLACED in place: glibc
 * dereferences the pointer during startup, so AT_IGNORE-ing it (a null return)
 * would crash the canary setup. Overwrite the 16 bytes with seed-derived
 * deterministic bytes. Kernel-INDEPENDENT: this runs on every managed run,
 * before guest ctors, whether or not SUD is armed. */
#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif

static uint64_t patina_sud_splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Read the PATINA_SEED value from the still-intact environ (the ctor scrub runs
 * later), or 0 if absent/unset. */
static uint64_t patina_sud_env_seed(int argc, char **argv) {
    char **envp = argv + argc + 1;
    static const char prefix[] = "PATINA_SEED=";
    size_t plen = sizeof prefix - 1;
    for (char **e = envp; *e != NULL; e++) {
        if (strncmp(*e, prefix, plen) == 0) {
            const char *v = *e + plen;
            uint64_t seed = 0;
            while (*v >= '0' && *v <= '9') {
                seed = seed * 10 + (uint64_t)(*v - '0');
                v++;
            }
            return seed;
        }
    }
    return 0;
}

static void patina_sud_determinize_at_random(int argc, char **argv) {
    /* Domain-separate the AT_RANDOM stream from every other seeded draw. */
    uint64_t state = patina_sud_env_seed(argc, argv) ^ 0x52414E444F4D0001ULL;
    char **envp = argv + argc + 1;
    char **walk = envp;
    while (*walk != NULL) walk++;
    walk++; /* step over envp's NULL terminator to the auxv array */
    ElfW(auxv_t) *aux = (ElfW(auxv_t) *)walk;
    for (; aux->a_type != AT_NULL; aux++) {
        if (aux->a_type == AT_RANDOM) {
            unsigned char *bytes = (unsigned char *)(uintptr_t)aux->a_un.a_val;
            if (bytes != NULL) {
                uint64_t lo = patina_sud_splitmix64(&state);
                uint64_t hi = patina_sud_splitmix64(&state);
                memcpy(bytes, &lo, sizeof lo);
                memcpy(bytes + sizeof lo, &hi, sizeof hi);
            }
        }
    }
}

/* The SIGSYS dispatch handler. A syscall-user-dispatch SIGSYS is SYNCHRONOUS —
 * delivered on the faulting thread at the exact IP of the guest's own syscall
 * instruction (the kernel already rolled it back), semantically identical to the
 * guest having called an interposed effect. So re-entering the deterministic
 * runtime (which the Rust dispatch does) is sound; see SUD-DESIGN.md §4.2. This
 * handler decodes the number and six argument registers per arch, validates the
 * provenance, and hands off to the arch-agnostic Rust dispatcher, then writes the
 * raw return value back into the syscall's return register. */
static void patina_sud_sigsys(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    long nr = info->si_syscall;
    uintptr_t call_addr = (uintptr_t)info->si_call_addr;
    /* Provenance: only a genuine syscall-user-dispatch SIGSYS is ours. A seccomp
     * or `kill -SYS` SIGSYS is a determinism escape and aborts loudly. */
    if (info->si_code != SYS_USER_DISPATCH) {
        patina_sud_report_fatal_addr(
            "SUD: SIGSYS with unexpected si_code (not syscall-user-dispatch)", nr,
            call_addr);
    }
#if defined(__x86_64__)
    if (info->si_arch != AUDIT_ARCH_X86_64) {
        patina_sud_report_fatal_addr("SUD: SIGSYS with unexpected si_arch", nr,
                                     call_addr);
    }
#elif defined(__aarch64__)
    if (info->si_arch != AUDIT_ARCH_AARCH64) {
        patina_sud_report_fatal_addr("SUD: SIGSYS with unexpected si_arch", nr,
                                     call_addr);
    }
#endif
    /* The faulting IP must lie in the main executable's text. Anything else — a
     * syscall from ld.so or another DSO — is unmodeled and aborts by name (§2.3),
     * rather than being emulated as if it were guest code. */
    if (call_addr < patina_sud_text_lo || call_addr >= patina_sud_text_hi) {
        patina_sud_report_fatal_addr(
            "SUD: trapped a syscall outside the main executable text (ld.so / DSO / "
            "vDSO); this path is not modeled",
            nr, call_addr);
    }

    ucontext_t *uc = (ucontext_t *)ucontext;
    int saved_errno = errno;
    unsigned long a0, a1, a2, a3, a4, a5;
#if defined(__x86_64__)
    greg_t *r = uc->uc_mcontext.gregs;
    a0 = (unsigned long)r[REG_RDI];
    a1 = (unsigned long)r[REG_RSI];
    a2 = (unsigned long)r[REG_RDX];
    a3 = (unsigned long)r[REG_R10];
    a4 = (unsigned long)r[REG_R8];
    a5 = (unsigned long)r[REG_R9];
#elif defined(__aarch64__)
    a0 = (unsigned long)uc->uc_mcontext.regs[0];
    a1 = (unsigned long)uc->uc_mcontext.regs[1];
    a2 = (unsigned long)uc->uc_mcontext.regs[2];
    a3 = (unsigned long)uc->uc_mcontext.regs[3];
    a4 = (unsigned long)uc->uc_mcontext.regs[4];
    a5 = (unsigned long)uc->uc_mcontext.regs[5];
#else
#error "SUD SIGSYS handler: unsupported architecture"
#endif
    long ret = patina_sud_dispatch(nr, a0, a1, a2, a3, a4, a5, call_addr);
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = (greg_t)ret;
#elif defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (unsigned long long)ret;
#endif
    /* Raw-syscall callers read the return register, not errno, but outer guest
     * frames may have a live errno the dispatch path clobbered — restore it. */
    errno = saved_errno;
}

/* Arm SUD on the calling thread from the cached region. Called on the main
 * thread at startup and on every managed thread from the Rust trampoline (the
 * config does not survive clone, so each thread arms once). A no-op when SUD was
 * not armed for this run (non-SUD kernel or standalone binary). */
void patina_sud_arm_thread(void) {
    if (!patina_sud_armed) return;
    if (patina_host_prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
                          patina_sud_libc_off, patina_sud_libc_len, NULL) != 0) {
        patina_sud_report_fatal(
            "SUD: failed to arm syscall-user-dispatch on a managed thread");
    }
}

/* Main-thread SUD setup, called from the `__libc_start_main` interposer BEFORE
 * guest constructors run. Arms only a managed run on a SUD-capable kernel; every
 * other case is a deliberate no-op (a binary that actually needs SUD was already
 * refused by the pre-run gate, and one that does not runs fine unarmed). */
static void patina_sud_init(int argc, char **argv) {
    /* A standalone run (no PATINA_MODE) is left unarmed: its first interposed
     * boundary already fails closed via ensure_runtime, and an unarmed raw
     * syscall there is no worse than today. environ is still intact here (the
     * ctor's scrub runs later), so read it directly. */
    if (!patina_env_has("PATINA_MODE", argv, argc)) return;

    /* AT_RANDOM determinization is kernel-independent: close the entropy leak on
     * EVERY managed run (SUD kernel or not), before the SUD kernel probe gate
     * below can early-return. */
    patina_sud_determinize_at_random(argc, argv);

    patina_host_prctl = (patina_prctl_fn)__real_dlsym(RTLD_NEXT, "prctl");
    patina_host_open = (patina_host_open_fn)__real_dlsym(RTLD_NEXT, "open");
    patina_host_read_real = (patina_host_read_fn)__real_dlsym(RTLD_NEXT, "read");
    patina_host_close_real = (patina_host_close_fn)__real_dlsym(RTLD_NEXT, "close");
    (void)patina_real_sigaction();
    if (patina_host_prctl == NULL || patina_host_open == NULL ||
        patina_host_read_real == NULL || patina_host_close_real == NULL ||
        patina_host_sigaction == NULL) {
        /* Defensive: these are core glibc symbols. Leave unarmed rather than arm
         * with a missing vehicle. */
        return;
    }

    /* Kernel support probe: PR_SYS_DISPATCH_OFF with all-zero args returns 0 on a
     * SUD kernel and -EINVAL where the feature is absent (arm64 <= 6.18, pre-5.11
     * x86). Same process, same kernel as the guest. */
    if (patina_host_prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0,
                          NULL) != 0) {
        return; /* no kernel SUD: do not arm (pre-run gate handles refusal) */
    }

    if (patina_sud_discover_regions() != 0) {
        patina_sud_report_fatal(
            "SUD: could not determine glibc's single executable segment and the "
            "main-executable text from /proc/self/maps; refusing to arm on a "
            "guessed region");
    }

    patina_sud_scrub_auxv(argc, argv);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = patina_sud_sigsys;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (patina_host_sigaction(SIGSYS, &action, NULL) != 0) {
        patina_sud_report_fatal("SUD: failed to install the SIGSYS dispatch handler");
    }

    patina_sud_armed = 1;
    /* Publish the armed state to the Rust-owned flag (writable section) so the
     * config path records the `sud` trace-metadata field. */
    PATINA_SUD_ARMED = 1;
    patina_sud_arm_thread(); /* arm the main thread */
}

/* ==========================================================================
 * Timestamp-counter trap (x86-64 Linux). `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`
 * sets CR4.TSD for the thread (Time Stamp Disable — the counter becomes
 * privileged), so `rdtsc`/`rdtscp` raise #GP in user mode, which the kernel
 * delivers as a SYNCHRONOUS, thread-directed SIGSEGV at the exact faulting
 * instruction. That makes an inline counter read a real effect boundary — the
 * same shape as an interposed `clock_gettime` — instead of the silent host-time
 * escape it is otherwise (invisible to the import audit, refused by the
 * instruction scan, untrappable by SUD, which sees only syscalls).
 *
 * The handler decodes at the faulting RIP and answers ONLY `rdtsc` (0f 31) and
 * `rdtscp` (0f 01 f9), from the run's virtual clock through the same
 * `patina_clock_now` entry point every interposer uses (see src/tsc.rs for the
 * frequency mapping and the parity argument). Every other SIGSEGV — a genuine
 * null dereference, a stack-overflow guard page — falls through to the previous
 * disposition untouched: the trap contains a determinism escape, it never
 * swallows a fault.
 *
 * Interaction with Rust std: std installs its stack-overflow SIGSEGV handler
 * only when the current disposition is SIG_DFL (`sys::pal::unix::stack_overflow
 * ::init`), and this arms first (from `__libc_start_main`, before guest
 * constructors). So under an armed trap a stack overflow dies on the default
 * action rather than printing std's "has overflowed its stack" message. That is
 * the honest trade: the fault still kills the process, at the right address,
 * with a core dump. std still installs its SIGBUS handler and its altstacks.
 * ========================================================================== */

/* prctl TSC op numbers (x86 only; present since 2.6.26). */
#ifndef PR_GET_TSC
#define PR_GET_TSC 25
#endif
#ifndef PR_SET_TSC
#define PR_SET_TSC 26
#endif
#ifndef PR_TSC_SIGSEGV
#define PR_TSC_SIGSEGV 2
#endif

/* Rust side of the boundary (see src/tsc.rs). The dispatch symbol is also the
 * audit's trap marker: a binary that DEFINES it carries a trap-capable shim. */
extern int patina_tsc_dispatch(const unsigned char *bytes, size_t available,
                               unsigned long long *tsc_out, unsigned int *aux_out,
                               size_t *length_out);
/* The armed flag is OWNED by the Rust lib (an exported AtomicU8), the same C→Rust
 * ownership direction and rationale as PATINA_SUD_ARMED. */
extern unsigned char PATINA_TSC_ARMED;

/* The longest instruction the trap decodes (`rdtscp`, 3 bytes). */
#define PATINA_TSC_MAX_INSN 3

#endif

#ifdef __linux__
#if defined(__x86_64__)
/* The SIGSEGV disposition the trap displaced, so a fault it does not recognize
 * is taken exactly as it would have been. x86-only, like the handler that reads
 * it — an unused static would not survive -Wall -Wextra -Werror on aarch64. */
static struct sigaction patina_tsc_prev;

/* Take the fault the way it would have been taken had the trap not been armed:
 * hand it to the disposition we displaced, or — when that was the default —
 * restore the default and return, so the faulting instruction re-executes and
 * the kernel kills the process with the true si_addr and a core dump. Never a
 * swallow: this path always ends in the fault being taken. */
static void patina_tsc_take_real_fault(int sig, siginfo_t *info, void *ucontext) {
    if ((patina_tsc_prev.sa_flags & SA_SIGINFO) != 0 &&
        patina_tsc_prev.sa_sigaction != NULL) {
        patina_tsc_prev.sa_sigaction(sig, info, ucontext);
        return;
    }
    if (patina_tsc_prev.sa_handler != SIG_DFL &&
        patina_tsc_prev.sa_handler != SIG_IGN &&
        patina_tsc_prev.sa_handler != NULL) {
        patina_tsc_prev.sa_handler(sig);
        return;
    }
    (void)patina_host_sigaction(sig, &patina_tsc_prev, NULL);
}

static void patina_tsc_sigsegv(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    greg_t *r = uc->uc_mcontext.gregs;
    uintptr_t rip = (uintptr_t)r[REG_RIP];
    /* Provenance, exactly as the SIGSYS handler requires it: the faulting
     * instruction must lie in the main executable's text. A counter read from
     * ld.so, another DSO, or the vDSO is not guest code — reading three bytes at
     * an arbitrary faulting address would itself fault, and answering it would
     * emulate a path the runtime does not model. */
    if (rip >= patina_sud_text_lo && rip < patina_sud_text_hi) {
        size_t available = (size_t)(patina_sud_text_hi - rip);
        if (available > PATINA_TSC_MAX_INSN) available = PATINA_TSC_MAX_INSN;
        int saved_errno = errno;
        unsigned long long tsc = 0;
        unsigned int aux = 0;
        size_t length = 0;
        int kind = patina_tsc_dispatch((const unsigned char *)rip, available, &tsc,
                                       &aux, &length);
        errno = saved_errno;
        if (kind != PATINA_TSC_NONE) {
            /* Both instructions write 32-bit halves, which zero-extend into the
             * full 64-bit registers exactly as the hardware's do. */
            r[REG_RAX] = (greg_t)(tsc & 0xffffffffULL);
            r[REG_RDX] = (greg_t)((tsc >> 32) & 0xffffffffULL);
            if (kind == PATINA_TSC_RDTSCP) { /* rdtscp also reports IA32_TSC_AUX */
                r[REG_RCX] = (greg_t)aux;
            }
            r[REG_RIP] = (greg_t)(rip + length);
            return;
        }
    }
    patina_tsc_take_real_fault(sig, info, ucontext);
}

#endif
#endif

#ifdef __linux__
/* Arm the timestamp-counter trap on the calling thread. Called on the main
 * thread at startup and on every managed thread from the Rust trampoline: the
 * TSC flag is per-thread, so — like the SUD config — each thread arms once
 * rather than trusting clone(2) to carry it. A no-op when the trap was not armed
 * for this run (non-x86, no PR_SET_TSC, or a standalone binary). */
void patina_tsc_arm_thread(void) {
    if (!patina_tsc_armed) return;
    if (patina_host_prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, NULL) != 0) {
        patina_sud_report_fatal(
            "TSC: failed to arm the timestamp-counter trap on a managed thread");
    }
}

/* Main-thread setup, called from the `__libc_start_main` interposer after
 * `patina_sud_init` (which resolves the host aliases and discovers the text
 * span) and BEFORE guest constructors. Arms only a managed run on an x86-64
 * kernel with PR_SET_TSC; every other case is a deliberate no-op, and the
 * pre-run gate is what refuses a binary that actually needs the trap. */
static void patina_tsc_init(int argc, char **argv) {
#if defined(__x86_64__)
    if (!patina_env_has("PATINA_MODE", argv, argc)) return;
    if (patina_host_prctl == NULL) {
        patina_host_prctl = (patina_prctl_fn)__real_dlsym(RTLD_NEXT, "prctl");
    }
    (void)patina_real_sigaction();
    if (patina_host_prctl == NULL || patina_host_sigaction == NULL) return;

    /* Kernel support probe: PR_GET_TSC into local storage reads the current
     * per-thread setting and mutates nothing. It returns 0 where the facility
     * exists and -EINVAL where it does not. */
    int tsc_mode = 0;
    if (patina_host_prctl(PR_GET_TSC, (unsigned long)(uintptr_t)&tsc_mode, 0, 0,
                          NULL) != 0) {
        return; /* no PR_SET_TSC here: leave unarmed (the gate refuses) */
    }

    /* The handler needs the main executable's text span to bound its decode.
     * `patina_sud_init` discovers it when it arms; when SUD did not arm (its own
     * kernel probe failed) it is still needed here. Fail CLOSED rather than arm
     * a handler that cannot validate a faulting RIP: leaving the trap unarmed
     * after the audit cleared the binary as trap-managed would turn a contained
     * escape into a silent one. */
    if (patina_sud_text_hi == 0 && patina_sud_discover_regions() != 0) {
        patina_sud_report_fatal(
            "TSC: could not determine the main-executable text span from "
            "/proc/self/maps; refusing to arm the timestamp-counter trap on a "
            "guessed region");
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = patina_tsc_sigsegv;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (patina_host_sigaction(SIGSEGV, &action, &patina_tsc_prev) != 0) {
        patina_sud_report_fatal("TSC: failed to install the SIGSEGV trap handler");
    }

    if (patina_host_prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, NULL) != 0) {
        patina_sud_report_fatal(
            "TSC: PR_GET_TSC succeeded but PR_SET_TSC(PR_TSC_SIGSEGV) failed; "
            "refusing to run with the timestamp counter readable");
    }
    patina_tsc_armed = 1;
    /* Publish the armed state to the Rust-owned flag so the config path records
     * the `tsc` trace-metadata field. */
    PATINA_TSC_ARMED = 1;
#else
    (void)argc;
    (void)argv;
#endif
}

/*
 * `__libc_start_main` interposer (Linux only). The `exit` interposer above
 * catches only EXPLICIT `exit(3)` calls from guest/executable code: on the
 * natural `main`-return path glibc's `__libc_start_main` calls `exit()` through a
 * hidden internal alias (bound at libc build time, not via the PLT), so ELF
 * interposition never sees it and the root task's post-`main` --yield-points
 * teardown yields would still be recorded nondeterministically. crt1.o in the
 * EXECUTABLE references `__libc_start_main`, and the executable's own strong
 * definition wins at static link (no --wrap), so this runs BEFORE glibc gets
 * control — immune to the internal binding. We stash the guest's real `main` and
 * hand glibc a wrapper that runs it and then sets the teardown flag BEFORE
 * returning the code into glibc's exit path (which then runs the thread-local
 * destructors, now silenced in the shim's sched_point). The real
 * `__libc_start_main` is resolved locally via `__real_dlsym(RTLD_NEXT, ...)`:
 * this runs before patina_native_start's constructor, so the shim host-alias
 * table is not yet built and must not be used; `__real_dlsym` is the
 * `-Wl,--wrap=dlsym` alias (guest/std `dlsym` binds to
 * `__wrap_dlsym`, so plain `dlsym` cannot reach the real resolver). Darwin uses a
 * different C runtime entry and is untouched (the `exit` interposer above already
 * covers its explicit-exit path; Darwin teardown is already deterministic).
 */
typedef int (*patina_main_fn)(int, char **, char **);
typedef int (*patina_libc_start_main_fn)(patina_main_fn, int, char **, void *,
                                         void *, void *, void *);

extern void *__real_dlsym(void *handle, const char *symbol);

static patina_main_fn patina_real_main;

static int patina_main_wrapper(int argc, char **argv, char **envp) {
    int code = patina_real_main(argc, argv, envp);
    /*
     * The guest's `main` has returned. Mark teardown NOW — before the code
     * re-enters glibc's `exit()`, which drives `__call_tls_dtors` — so the root
     * task's instrumented thread-local destructors take no scheduling point.
     */
    patina_note_main_returned();
    /*
     * And record the status the guest itself reached. glibc calls `exit()`
     * through a hidden internal alias on this path, so the `exit` interposer
     * below never sees it; if finalization then fails, the atexit hook aborts
     * and SIGABRT is all anything downstream could otherwise observe. A guest
     * that panicked (101) or returned an error (1) must not be filed as patina
     * infrastructure just because the recorder gave out on the same run.
     */
    patina_note_guest_exit_status(code);
    return code;
}

int __libc_start_main(patina_main_fn main_fn, int argc, char **argv, void *init,
                      void *fini, void *rtld_fini, void *stack_end) {
    patina_real_main = main_fn;
    /* Arm syscall-user-dispatch (managed run on a SUD kernel) BEFORE the real
     * __libc_start_main runs the guest constructors: parse the libc region,
     * scrub AT_SYSINFO_EHDR from the auxv, install the SIGSYS handler, and arm
     * the main thread. environ is still intact here (the ctor scrub runs later),
     * so PATINA_MODE is readable. A no-op on a non-SUD kernel or standalone run. */
    patina_sud_init(argc, argv);
    /* Arm the timestamp-counter trap (managed run on an x86-64 kernel with
     * PR_SET_TSC), reusing the host aliases and text span SUD discovered, so a
     * guest's inline rdtsc/rdtscp is answered from the virtual clock instead of
     * reading the host counter. A no-op on every other platform or run. */
    patina_tsc_init(argc, argv);
    patina_libc_start_main_fn real =
        (patina_libc_start_main_fn)__real_dlsym(RTLD_NEXT, "__libc_start_main");
    if (real == NULL) {
        /*
         * Defensive and effectively unreachable: glibc always exports
         * __libc_start_main, and this file is only ever linked with
         * -Wl,--wrap=dlsym, so __real_dlsym is the genuine resolver. Fail closed
         * LOUDLY (SIGABRT) rather than run the guest unwrapped — which would
         * silently reintroduce the nondeterministic teardown yields this
         * interposer exists to remove. `abort()` is the real libc abort (the shim
         * does not interpose it), so it works before the runtime is installed and
         * without touching the interposed `syscall`/`write` layer.
         */
        abort();
    }
    return real(patina_main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}

#endif

/*
 * Packaged startup. An ordinary program built with `cargo patina native-build`
 * must not need Patina-specific init calls: the boundary sits BELOW application
 * code. This constructor installs the deterministic runtime from the PATINA_*
 * protocol (idempotent) and registers finalization through atexit, so record
 * mode is finalized on any normal exit path (main return or exit()) without an
 * explicit patina_shutdown. A standalone run (no PATINA_MODE) is left
 * uninstalled; the first effect boundary then fails closed with a clear message
 * (see ensure_runtime in the Rust layer). The public interposed getenv reads only
 * the deterministic guest map after startup (NULL before startup and when unset);
 * startup reads the PATINA_* control plane through the private snapshot accessor
 * before scrubbing the ambient environ and publishing the deterministic one that
 * guest code sees.
 */
static void patina_finalize_atexit(void) {
#ifdef __linux__
    /*
     * Interposer-engagement canary. This atexit hook runs AFTER the thread-local
     * destructors on every exit-chain path that reaches it, so on Linux the
     * teardown flag MUST already be set (natural return via the __libc_start_main
     * wrapper, explicit exit via the `exit` interposer). If it is not, the
     * teardown interposer did not engage on this platform/toolchain and the root
     * task's --yield-points teardown yields were not silenced: fail LOUDLY here
     * (before finalizing the trace) rather than let the miss surface later as an
     * op-count divergence. `_exit`/`_Exit`/`abort` skip atexit, so a genuinely
     * abrupt exit never reaches this check.
     */
    patina_assert_teardown_engaged();
#endif
    if (patina_shutdown() != 0) {
        /* patina_shutdown already emitted the runtime error; atexit return values
         * are ignored, so abort to make record/replay finalization failures loud. */
        abort();
    }
}

/* Priority 101 runs before default-priority constructors on toolchains that
 * honor constructor priorities, minimizing false early-init failures while still
 * letting deliberately earlier constructors (the e2e uses .init_array.00099 on
 * ELF) prove the fail-closed path. */
__attribute__((constructor(101))) static void patina_native_start(void) {
    atexit(patina_finalize_atexit);
    patina_capture_control_plane();
    /* Register before init: installing the runtime publishes environ from the
     * guest env map, and a deferred harness install happens after this
     * constructor returns. */
    patina_register_environ_installer(patina_environ_install);
    /* Deferred harness init (PATINA_DEFER_INIT=1, set by `cargo patina run
     * --harness`): still capture the control plane, still register finalization,
     * still scrub the environment — but leave the runtime UNINSTALLED so
     * patina-dst-harness can apply its configuration overlay and install
     * explicitly. An interposed effect before that install fails closed in the
     * Rust ensure_runtime (never auto-inits under defer). */
    const char *defer = patina_control_getenv("PATINA_DEFER_INIT");
    int deferred = defer != NULL && strcmp(defer, "1") == 0;
    if (patina_control_getenv("PATINA_MODE") != NULL && !deferred) {
        patina_init_from_env();
    }
    patina_scrub_environ();
    patina_publish_environ();
    patina_note_startup_constructor_finished();
}
