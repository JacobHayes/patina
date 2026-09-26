/*
 * Signals and process control: sigaction/signal/pthread_sigmask, pause/kill,
 * exit, and the process-class deny-traps (fork/exec/spawn/wait/credentials).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifndef __linux__
int pause(void) {
    errno = ENOSYS;
    return -1;
}
#endif

/*
 * `exit(3)` interposer. When the guest's `main` returns, the C runtime calls
 * `exit(status)`; a guest's own `exit`/`std::process::exit` routes here too. This
 * is the sole point that runs on the exiting thread AFTER its managed body but
 * BEFORE the C runtime drives the guest's thread-local destructors — whose
 * `--yield-points` yield hooks would otherwise record trailing, host-teardown-
 * ordering-dependent scheduling points that diverge record from replay (see
 * patina_exit and the shim's thread::sched_point). The teardown flag MUST be set
 * here, not via atexit: glibc runs __call_tls_dtors() BEFORE the atexit list, so
 * the packaged atexit finalizer is too late to precede the destructors.
 * `_exit`/`_Exit` bypass the destructors entirely and are deliberately not
 * interposed. patina_exit sets the flag and terminates through the real libc
 * `exit` (resolved via the shim host-alias table), so the atexit chain (trace
 * finalization in record mode) and the destructors still run, now with the flag
 * set. This interposer lives in the POSIX layer, so a consumer that links only
 * the C-ABI staticlib (no POSIX layer, no --wrap=dlsym) keeps libc's own `exit`
 * and never reaches the host-alias table at teardown.
 */
_Noreturn void exit(int status) {
    patina_exit(status);
}

#ifdef __linux__
/*
 * SIGSYS-registration hardening (SUD-DESIGN.md §7.5, slice 1). Under SUD the
 * SIGSYS handler IS the deterministic containment; a guest `sigaction(SIGSYS,…)`
 * would replace it. Interpose `sigaction`/`signal` with strong defs that forward
 * every other signal to the real glibc registration (preserving std's
 * SIGSEGV/SIGBUS stack-overflow guard exactly) and fail closed for SIGSYS. The
 * raw door (a trapped `rt_sigaction(SIGSYS)`) is closed by the dispatch table.
 * The shim's own handler install above uses the resolved real sigaction, never
 * this interposer, so it is not self-blocked.
 */
#endif

#ifdef __linux__
/* glibc's reserved signals, SIGCANCEL (32) and SIGSETXID (33)
 * (nptl/pthreadP.h, internal-signals.h), `patina_signal_reserved`: its libc
 * face never installs an action for them, blocks them or sends them, whatever
 * the caller asks. The raw rows keep the kernel's answers. */

/* A copy of `set` with the reserved signals cleared (glibc's
 * `__clear_internal_signals`), or `set` itself when it holds neither. */
static const sigset_t *patina_clear_internal_signals(const sigset_t *set, sigset_t *copy) {
    const uint64_t internal = (UINT64_C(1) << 31) | (UINT64_C(1) << 32);
    uint64_t word;
    if (set == NULL) return NULL;
    memcpy(&word, set, sizeof word);
    if ((word & internal) == 0) return set;
    memcpy(copy, set, sizeof *copy);
    word &= ~internal;
    memcpy(copy, &word, sizeof word);
    return copy;
}

/* glibc's `_sigintr` (signal/siginterrupt.c): the signals `siginterrupt(sig,
 * 1)` last named, which `signal` then installs without SA_RESTART. Bit
 * `sig - 1`. */
static uint64_t patina_sigintr;

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
    struct patina_signal_action prior, next;
    if (patina_signal_reserved(sig)) {
        errno = EINVAL;
        return -1;
    }
    if (act != NULL) {
        next.handler = (uintptr_t)act->sa_handler;
        next.flags = (uint32_t)act->sa_flags;
        next.restorer = (uintptr_t)act->sa_restorer;
        memcpy(&next.mask, &act->sa_mask, sizeof next.mask);
    }
    int64_t rc = patina_signal_action_libc(sig, act ? &next : NULL, &prior);
    if (old != NULL && rc == 0) {
        memset(old, 0, sizeof *old);
        old->sa_handler = (void (*)(int))prior.handler;
        old->sa_flags = (int)prior.flags;
        old->sa_restorer = (void (*)(void))prior.restorer;
        memcpy(&old->sa_mask, &prior.mask, sizeof prior.mask);
    }
    return signal_result(rc);
}
/* glibc's `signal` (signal/signal.c `__bsd_signal`): the handler runs with
 * its own signal blocked, restarting interrupted calls unless `siginterrupt`
 * named the signal. */
void (*signal(int sig, void (*handler)(int)))(int) {
    if (handler == SIG_ERR || sig < 1 || sig > 64 || patina_signal_reserved(sig)) {
        errno = EINVAL;
        return SIG_ERR;
    }
    uint64_t bit = UINT64_C(1) << (sig - 1);
    struct patina_signal_action next = {
        .handler = (uintptr_t)handler,
        .flags = (patina_sigintr & bit) != 0 ? 0 : SA_RESTART,
    }, old;
    memset(&next.mask, 0, sizeof next.mask);
    memcpy(&next.mask, &bit, sizeof bit);
    if (signal_result(patina_signal_action_libc(sig, &next, &old)) < 0)
        return SIG_ERR;
    return (void (*)(int))old.handler;
}
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old) {
    sigset_t copy;
    set = patina_clear_internal_signals(set, &copy);
    int64_t rc = patina_signal_mask(how, (const uint64_t *)set, (uint64_t *)old, sizeof(uint64_t));
    patina_signal_deliver();
    return (int)-rc;
}
int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    sigset_t copy;
    set = patina_clear_internal_signals(set, &copy);
    return signal_result(patina_signal_mask(how, (const uint64_t *)set, (uint64_t *)old, sizeof(uint64_t)));
}
int sigpending(sigset_t *set) {
    memset(set, 0, sizeof *set);
    return signal_result(patina_signal_pending((uint8_t *)set, sizeof(uint64_t)));
}
int sigaltstack(const stack_t *stack, stack_t *old) {
    return signal_result(patina_signal_altstack(stack, old));
}
int pause(void) {
    return signal_result(patina_signal_wait(NULL, NULL, NULL,
        sizeof(uint64_t), PATINA_SIGNAL_PAUSE));
}
int sigsuspend(const sigset_t *set) {
    return signal_result(patina_signal_wait((const uint64_t *)set, NULL, NULL,
        sizeof(uint64_t), PATINA_SIGNAL_SUSPEND));
}
/* glibc's `sigtimedwait` (sysdeps/unix/sysv/linux/sigtimedwait.c), which
 * `sigwaitinfo` calls: a signal `raise` sent (the kernel's SI_TKILL) reads as
 * sent by `kill`, SI_USER. */
static int patina_sigtimedwait(const sigset_t *set, siginfo_t *info,
                               const struct timespec *timeout) {
    int rc = signal_result(patina_signal_wait((const uint64_t *)set, info, timeout,
        sizeof(uint64_t), PATINA_SIGNAL_DEQUEUE));
    if (rc > 0 && info != NULL && info->si_code == SI_TKILL) info->si_code = SI_USER;
    return rc;
}
int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout) {
    return patina_sigtimedwait(set, info, timeout);
}
int sigwaitinfo(const sigset_t *set, siginfo_t *info) {
    return patina_sigtimedwait(set, info, NULL);
}
int sigwait(const sigset_t *set, int *sig) {
    int64_t rc;
    do {
        rc = patina_signal_wait((const uint64_t *)set, NULL, NULL,
                                sizeof(uint64_t), PATINA_SIGNAL_DEQUEUE);
        patina_signal_deliver();
    } while (rc == -EINTR);
    if (rc < 0) return (int)-rc;
    *sig = rc;
    return 0;
}
int sigqueue(pid_t pid, int sig, const union sigval value) {
    siginfo_t info;
    memset(&info, 0, sizeof info);
    info.si_signo = sig; info.si_code = SI_QUEUE;
    info.si_pid = patina_pid(); info.si_uid = (uid_t)patina_uid(); info.si_value = value;
    return signal_result(patina_sud_dispatch(SYS_rt_sigqueueinfo,
        (uint64_t)pid, (uint64_t)sig, (uintptr_t)&info, 0, 0, 0, 0));
}
/* glibc's signal descriptions in the C locale (string/strsignal.c, the
 * `sigdescr` table); NULL for a number without one (0, the reserved 32 and 33,
 * the realtime signals, anything out of range). */
static const char *patina_sigdescr(int sig) {
    static const char *const descriptions[] = {
        NULL, "Hangup", "Interrupt", "Quit", "Illegal instruction",
        "Trace/breakpoint trap", "Aborted", "Bus error", "Floating point exception",
        "Killed", "User defined signal 1", "Segmentation fault", "User defined signal 2",
        "Broken pipe", "Alarm clock", "Terminated", "Stack fault", "Child exited",
        "Continued", "Stopped (signal)", "Stopped", "Stopped (tty input)",
        "Stopped (tty output)", "Urgent I/O condition", "CPU time limit exceeded",
        "File size limit exceeded", "Virtual timer expired", "Profiling timer expired",
        "Window changed", "I/O possible", "Power failure", "Bad system call",
    };
    if (sig < 1 || sig >= (int)(sizeof descriptions / sizeof descriptions[0])) return NULL;
    return descriptions[sig];
}

/* Append `text` to the `cap`-byte buffer `out` at `at`, keeping room for a
 * NUL; answers the new length. */
static size_t patina_append(char *out, size_t at, size_t cap, const char *text) {
    while (*text != '\0' && at + 1 < cap) out[at++] = *text++;
    out[at] = '\0';
    return at;
}

/* `text` then `number` in decimal ("Unknown signal -1"). */
static size_t patina_append_numbered(char *out, size_t cap, const char *text, int number) {
    char digits[12];
    size_t count = 0;
    long long value = number;
    int negative = value < 0;
    if (negative) value = -value;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    size_t at = patina_append(out, 0, cap, text);
    if (negative) at = patina_append(out, at, cap, "-");
    while (count > 0 && at + 1 < cap) out[at++] = digits[--count];
    out[at] = '\0';
    return at;
}

/* glibc's `strsignal`: the description, "Real-time signal N" counted from
 * SIGRTMIN (34), or "Unknown signal N", formatted into a per-thread buffer
 * the thread's next call reuses. */
static char *patina_strsignal(int sig) {
    static __thread char buffer[32];
    const char *description = patina_sigdescr(sig);
    if (description != NULL) return (char *)description;
    if (sig >= 34 && sig <= 64) {
        patina_append_numbered(buffer, sizeof buffer, "Real-time signal ", sig - 34);
    } else {
        patina_append_numbered(buffer, sizeof buffer, "Unknown signal ", sig);
    }
    return buffer;
}
char *strsignal(int sig) { return patina_strsignal(sig); }

/* The stdio slice's stream-to-descriptor map and its trap (stdio.c, later in
 * this translation unit). */
static int patina_sentinel_fd(FILE *stream);
__attribute__((noreturn)) static void patina_stdio_trap(const char *symbol);

/* glibc's `psignal` (signal/psignal.c `__fxprintf`): "<prefix>: <description>\n"
 * (the bare description for a NULL or empty prefix) to the `stderr` stream,
 * in one write whatever the prefix's length. Unlike `strsignal` it numbers no
 * realtime signal: any number without a description is "Unknown signal N". */
static void patina_psignal(int sig, const char *prefix) {
    char unknown[32];
    const char *description = patina_sigdescr(sig);
    if (description == NULL) {
        patina_append_numbered(unknown, sizeof unknown, "Unknown signal ", sig);
        description = unknown;
    }
    int fd = patina_sentinel_fd(stderr);
    if (fd < 0) {
        patina_stdio_trap("psignal");
    }
    struct iovec parts[4];
    int count = 0;
    if (prefix != NULL && *prefix != '\0') {
        parts[count++] = (struct iovec){(void *)prefix, strlen(prefix)};
        parts[count++] = (struct iovec){(void *)": ", 2};
    }
    parts[count++] = (struct iovec){(void *)description, strlen(description)};
    parts[count++] = (struct iovec){(void *)"\n", 1};
    (void)patina_writev(fd, parts, count, 0);
}
void psignal(int sig, const char *prefix) { patina_psignal(sig, prefix); }
_Noreturn void abort(void) { patina_abort(); }
int pthread_kill(pthread_t thread, int sig) {
    return patina_pthread_kill((uintptr_t)thread, sig);
}
/* glibc's killpg: kill of the negated group (0: the caller's). */
int killpg(pid_t group, int sig) {
    if (group < 0) { errno = EINVAL; return -1; }
    return signal_result(patina_sud_dispatch(SYS_kill, (uint64_t)(int64_t)-group,
        (uint64_t)sig, 0, 0, 0, 0, 0));
}
/* glibc's `siginterrupt`: record the choice for later `signal` calls, and
 * apply it to the installed action; through `__sigaction`, which refuses the
 * reserved signals. */
int siginterrupt(int sig, int interrupt) {
    struct patina_signal_action act;
    if (patina_signal_reserved(sig)) {
        errno = EINVAL;
        return -1;
    }
    if (signal_result(patina_signal_action_libc(sig, NULL, &act)) < 0)
        return -1;
    uint64_t bit = UINT64_C(1) << (sig - 1);
    if (interrupt) {
        patina_sigintr |= bit;
        act.flags &= ~SA_RESTART;
    } else {
        patina_sigintr &= ~bit;
        act.flags |= SA_RESTART;
    }
    return signal_result(patina_signal_action_libc(sig, &act, NULL));
}
int tgkill(pid_t tgid, pid_t tid, int sig) {
    return signal_result(patina_sud_dispatch(SYS_tgkill, (uint64_t)tgid,
        (uint64_t)tid, (uint64_t)sig, 0, 0, 0, 0));
}
int tkill(pid_t tid, int sig) {
    return signal_result(patina_sud_dispatch(SYS_tkill, (uint64_t)tid,
        (uint64_t)sig, 0, 0, 0, 0, 0));
}
/* glibc's `raise` is `__pthread_kill` of the caller, which refuses the
 * reserved signals. */
int raise(int sig) {
    if (patina_signal_reserved(sig)) {
        errno = EINVAL;
        return -1;
    }
    return signal_result(patina_sud_dispatch(SYS_tgkill, (uint64_t)patina_pid(),
        (uint64_t)patina_thread_id(), (uint64_t)sig, 0, 0, 0, 0));
}
#endif

/*
 * Process-class deny-traps. The fork/exec/spawn/reap surface is a
 * deterministic-runtime non-goal: a managed guest never legitimately enters
 * it and the runtime models none of it. Real guests still LINK this
 * surface (std::process and dormant subprocess helper paths that a plain
 * run never triggers), and a reachability audit cannot clear it — the spawn
 * path is statically wired into the main loop by direct calls and only a
 * runtime flag keeps it dormant (see crates/patina-target/ESCAPE-CLASSES.md).
 *
 * So interpose the whole family with strong definitions that ABORT
 * deterministically if ever reached. Two wins over leaving them as imports: the
 * symbols drop off the import table (the pre-run gate needs no allowance), AND a
 * guest that genuinely spawns fails LOUD and reproducibly instead of escaping
 * the runtime silently. A trap fires only if CALLED, so merely linking the
 * surface is inert and a plain search is unaffected.
 */
__attribute__((noreturn)) static void patina_process_trap(const char *symbol) {
    static const char prefix[] = "patina: process spawn reached under patina: ";
    (void)patina_stdio_write(2, prefix, sizeof prefix - 1);
    (void)patina_stdio_write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; the process class is a deterministic-runtime non-goal; failing closed\n";
    (void)patina_stdio_write(2, suffix, sizeof suffix - 1);
    /* Private host abort skips the atexit shutdown flush, so push the captured guest output
     * and this diagnostic to the real descriptors before terminating. */
    patina_flush_captured_stdio();
    patina_host_abort();
}

pid_t fork(void) { patina_process_trap("fork"); }
int execvp(const char *file, char *const argv[]) {
    (void)file;
    (void)argv;
    patina_process_trap("execvp");
}
pid_t waitpid(pid_t pid, int *status, int options) {
#ifdef __linux__
    return signal_result(patina_sud_dispatch(SYS_wait4, (uint64_t)pid,
        (uintptr_t)status, (uint64_t)options, 0, 0, 0, 0));
#else
    (void)pid; (void)status; (void)options;
    errno = ECHILD;
    return -1;
#endif
}
#ifdef __linux__
/*
 * The credential and session rows an unprivileged caller meets, answered by
 * the one Rust model (the SUD rows; src/identity.rs): the own ids and the own
 * group succeed and change nothing, everything else is refused as the kernel
 * refuses it.
 */
pid_t setsid(void) {
    return signal_result(patina_sud_dispatch(SYS_setsid, 0, 0, 0, 0, 0, 0, 0));
}
int setgid(gid_t gid) {
    return signal_result(patina_sud_dispatch(SYS_setgid, (uint64_t)gid, 0, 0, 0, 0, 0, 0));
}
int setuid(uid_t uid) {
    return signal_result(patina_sud_dispatch(SYS_setuid, (uint64_t)uid, 0, 0, 0, 0, 0, 0));
}
int setpgid(pid_t pid, pid_t pgid) {
    return signal_result(patina_sud_dispatch(SYS_setpgid, (uint64_t)pid, (uint64_t)pgid,
        0, 0, 0, 0, 0));
}
int setgroups(size_t count, const gid_t *groups) {
    return signal_result(patina_sud_dispatch(SYS_setgroups, (uint64_t)count,
        (uintptr_t)groups, 0, 0, 0, 0, 0));
}
#else
/*
 * The same identity under XNU's rules (bsd/kern/kern_prot.c): setuid/setgid
 * accept the caller's own id and refuse anything else without privilege (no
 * `-1` special case); a process-group leader cannot start a session; setpgid
 * keeps the group the process leads (a negative group EINVAL, any other pid
 * ESRCH, any other group EPERM); setgroups needs privilege.
 */
static int patina_refuse(int error) {
    errno = error;
    return -1;
}
pid_t setsid(void) { return patina_refuse(EPERM); }
int setgid(gid_t gid) { return gid == (gid_t)patina_gid() ? 0 : patina_refuse(EPERM); }
int setuid(uid_t uid) { return uid == (uid_t)patina_uid() ? 0 : patina_refuse(EPERM); }
int setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0) return patina_refuse(EINVAL);
    if (pid != 0 && pid != getpid()) return patina_refuse(ESRCH);
    if (pgid != 0 && pgid != getpid()) return patina_refuse(EPERM);
    return 0;
}
int setgroups(int count, const gid_t *groups) {
    (void)count;
    (void)groups;
    return patina_refuse(EPERM);
}
#endif
int posix_spawnp(pid_t *restrict pid, const char *restrict file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *restrict attrp, char *const argv[restrict],
                 char *const envp[restrict]) {
    (void)pid;
    (void)file;
    (void)file_actions;
    (void)attrp;
    (void)argv;
    (void)envp;
    patina_process_trap("posix_spawnp");
}
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *acts) {
    (void)acts;
    patina_process_trap("posix_spawn_file_actions_init");
}
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *acts, int fd, int newfd) {
    (void)acts;
    (void)fd;
    (void)newfd;
    patina_process_trap("posix_spawn_file_actions_adddup2");
}
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *acts) {
    (void)acts;
    patina_process_trap("posix_spawn_file_actions_destroy");
}
int posix_spawnattr_init(posix_spawnattr_t *attr) {
    (void)attr;
    patina_process_trap("posix_spawnattr_init");
}
int posix_spawnattr_destroy(posix_spawnattr_t *attr) {
    (void)attr;
    patina_process_trap("posix_spawnattr_destroy");
}
int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags) {
    (void)attr;
    (void)flags;
    patina_process_trap("posix_spawnattr_setflags");
}
int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup) {
    (void)attr;
    (void)pgroup;
    patina_process_trap("posix_spawnattr_setpgroup");
}
int posix_spawnattr_setsigdefault(posix_spawnattr_t *restrict attr,
                                  const sigset_t *restrict sigdefault) {
    (void)attr;
    (void)sigdefault;
    patina_process_trap("posix_spawnattr_setsigdefault");
}

#ifdef __linux__
/*
 * Process descriptors, advice and reaping through them, and the calling
 * process's memory by pid: glibc's thin wrappers, each entering its row's one
 * model through the SUD dispatcher.
 */
int pidfd_open(pid_t pid, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_pidfd_open, (uint64_t)(int64_t)pid,
        (uint64_t)flags, 0, 0, 0, 0, 0));
}
int pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_pidfd_getfd, (uint64_t)(int64_t)pidfd,
        (uint64_t)(int64_t)targetfd, (uint64_t)flags, 0, 0, 0, 0));
}
int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_pidfd_send_signal, (uint64_t)(int64_t)pidfd,
        (uint64_t)(int64_t)sig, (uintptr_t)info, (uint64_t)flags, 0, 0, 0));
}
/* Advice covers at most MAX_RW_COUNT bytes (import_iovec), which an int
 * holds. */
ssize_t process_madvise(int pidfd, const struct iovec *iov, size_t vlen, int advice,
                        unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_process_madvise, (uint64_t)(int64_t)pidfd,
        (uintptr_t)iov, (uint64_t)vlen, (uint64_t)(int64_t)advice, (uint64_t)flags, 0, 0));
}
int process_mrelease(int pidfd, unsigned int flags) {
    return signal_result(patina_sud_dispatch(SYS_process_mrelease, (uint64_t)(int64_t)pidfd,
        (uint64_t)flags, 0, 0, 0, 0, 0));
}
/* A copy moves at most MAX_RW_COUNT bytes, which an int holds. */
ssize_t process_vm_readv(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                         const struct iovec *remote, unsigned long riovcnt,
                         unsigned long flags) {
    return signal_result(patina_sud_dispatch(SYS_process_vm_readv, (uint64_t)(int64_t)pid,
        (uintptr_t)local, (uint64_t)liovcnt, (uintptr_t)remote, (uint64_t)riovcnt,
        (uint64_t)flags, 0));
}
ssize_t process_vm_writev(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                          const struct iovec *remote, unsigned long riovcnt,
                          unsigned long flags) {
    return signal_result(patina_sud_dispatch(SYS_process_vm_writev, (uint64_t)(int64_t)pid,
        (uintptr_t)local, (uint64_t)liovcnt, (uintptr_t)remote, (uint64_t)riovcnt,
        (uint64_t)flags, 0));
}
#endif

#ifdef __linux__
/*
 * Linux-only spawn/IPC/effect surface that newer glibc's std pulls in and macOS
 * does not (so it only shows up in the Linux import audit). These follow the
 * fork/posix_spawnp deny-trap doctrine above: a strong def drops the symbol off
 * the guest import table (the pre-run gate needs no allowance) and fails LOUD and
 * reproducibly if the guest ever genuinely reaches it. A plain search never
 * calls them, so linking the surface is inert. The `_GNU_SOURCE` prototypes are
 * visible here, so each definition matches glibc's exact signature.
 */
pid_t pidfd_getpid(int pidfd) {
    (void)pidfd;
    patina_process_trap("pidfd_getpid");
}
int pidfd_spawnp(int *restrict pidfd, const char *restrict file,
                 const posix_spawn_file_actions_t *restrict file_actions,
                 const posix_spawnattr_t *restrict attrp, char *const argv[restrict],
                 char *const envp[restrict]) {
    (void)pidfd;
    (void)file;
    (void)file_actions;
    (void)attrp;
    (void)argv;
    (void)envp;
    patina_process_trap("pidfd_spawnp");
}
int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *acts,
                                         const char *path) {
    (void)acts;
    (void)path;
    patina_process_trap("posix_spawn_file_actions_addchdir_np");
}
int posix_spawn_file_actions_addchdir(posix_spawn_file_actions_t *acts, const char *path) {
    (void)acts;
    (void)path;
    patina_process_trap("posix_spawn_file_actions_addchdir");
}
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
    return signal_result(patina_sud_dispatch(SYS_waitid, (uint64_t)idtype,
        id, (uintptr_t)infop, (uint64_t)options, 0, 0, 0));
}

/*
 * glibc's RT-signal-range probe (libc::SIGRTMAX() reads it; tokio's signal
 * machinery links it). A pure host-configuration query with no boundary
 * effect: return glibc's own upper bound (64 — NPTL reserves 32/33 below
 * SIGRTMIN, which does not move the max) as a fixed deterministic value, the
 * gethostname doctrine above. tokio does not import __libc_current_sigrtmin,
 * so only the max probe is defined.
 */
int __libc_current_sigrtmax(void) { return 64; }

#endif

/*
 * Cross-platform members converted from deny-traps to honest deterministic
 * results: a runtime abort is not "support"; where the API admits an honest
 * answer, return it so a guest that reaches the path runs deterministically.
 *
 * `kill` against the virtual process tree (on Linux the dispatcher's row;
 * the Darwin model here): the guest is pid 2, the child of init, pid 1, which
 * runs as the same user and has no handlers. A signal-0 probe (an
 * existence/permission check that delivers nothing) reports the guest and init
 * alive and every other pid absent (ESRCH) — the shape sysinfo's
 * `check_if_pid_is_alive` and libc liveness probes rely on. A real signal to
 * init answers 0 and is dropped; to any other pid it is ESRCH (no such
 * process). On Darwin a real signal to SELF is not modeled:
 * the runtime delivers no asynchronous signals beyond its own SIGSYS
 * containment, so rather than silently claim delivery (a lie) or abort (not
 * support) it fails closed with a loud line and a recoverable ENOSYS.
 */
int kill(pid_t pid, int sig) {
#ifdef __linux__
    return signal_result(patina_sud_dispatch(SYS_kill, (uint64_t)pid, (uint64_t)sig, 0, 0, 0, 0, 0));
#else
    if (sig < 0 || sig > 64) {
        errno = EINVAL;
        return -1;
    }
    if (sig == 0 && (pid == getpid() || pid == 0 || pid == -1)) {
        return 0; /* the guest process/group exists; signal 0 delivers nothing */
    }
    if (pid == getppid()) {
        return 0; /* init exists and takes nothing (no handlers) */
    }
    if (pid != getpid()) {
        errno = ESRCH;
        return -1;
    }
    return patina_posix_deny("patina: kill(self, signal) delivery is not modeled "
                             "by the deterministic runtime; failing closed\n");
#endif
}

#ifdef __linux__
int signalfd(int fd, const sigset_t *mask, int flags) {
    return signal_result(patina_signalfd(fd, (const uint64_t *)mask, sizeof(uint64_t), flags));
}
#endif
