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
int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
    struct patina_signal_action prior, next;
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
void (*signal(int sig, void (*handler)(int)))(int) {
    struct patina_signal_action next = {
        .handler = (uintptr_t)handler, .flags = SA_RESTART
    }, old;
    if (signal_result(patina_signal_action_libc(sig, &next, &old)) < 0)
        return SIG_ERR;
    return (void (*)(int))old.handler;
}
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old) {
    int64_t rc = patina_signal_mask(how, (const uint64_t *)set, (uint64_t *)old, sizeof(uint64_t));
    patina_signal_deliver();
    return (int)-rc;
}
int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
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
int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout) {
    return signal_result(patina_signal_wait((const uint64_t *)set, info, timeout,
        sizeof(uint64_t), PATINA_SIGNAL_DEQUEUE));
}
int sigwaitinfo(const sigset_t *set, siginfo_t *info) {
    return signal_result(patina_signal_wait((const uint64_t *)set, info, NULL,
        sizeof(uint64_t), PATINA_SIGNAL_DEQUEUE));
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
    info.si_pid = 1; info.si_uid = 1000; info.si_value = value;
    return signal_result(patina_sud_dispatch(SYS_rt_sigqueueinfo,
        (uint64_t)pid, (uint64_t)sig, (uintptr_t)&info, 0, 0, 0, 0));
}
_Noreturn void abort(void) { patina_abort(); }
int pthread_kill(pthread_t thread, int sig) {
    return patina_pthread_kill((uintptr_t)thread, sig);
}
int killpg(pid_t group, int sig) {
    if (group < 0) { errno = EINVAL; return -1; }
    if (group > 1) { errno = ESRCH; return -1; }
    return signal_result(patina_sud_dispatch(SYS_kill, 0, (uint64_t)sig, 0, 0, 0, 0, 0));
}
int siginterrupt(int sig, int interrupt) {
    struct patina_signal_action act;
    if (signal_result(patina_signal_action_libc(sig, NULL, &act)) < 0)
        return -1;
    if (interrupt) act.flags &= ~SA_RESTART;
    else act.flags |= SA_RESTART;
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
int raise(int sig) {
    return signal_result(patina_sud_dispatch(SYS_tgkill, 1, patina_thread_id(), (uint64_t)sig, 0, 0, 0, 0));
}
#endif

/*
 * Process-class deny-traps. The fork/exec/spawn/reap/credential/session surface
 * is a deterministic-runtime non-goal: a managed guest never legitimately enters
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
pid_t setsid(void) { patina_process_trap("setsid"); }
int setgid(gid_t gid) {
    (void)gid;
    patina_process_trap("setgid");
}
int setuid(uid_t uid) {
    (void)uid;
    patina_process_trap("setuid");
}
int setpgid(pid_t pid, pid_t pgid) {
    (void)pid;
    (void)pgid;
    patina_process_trap("setpgid");
}
#ifdef __APPLE__
int setgroups(int count, const gid_t *groups) {
#else
int setgroups(size_t count, const gid_t *groups) {
#endif
    (void)count;
    (void)groups;
    patina_process_trap("setgroups");
}
int chroot(const char *path) {
    (void)path;
    patina_process_trap("chroot");
}
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
 * `kill` in the single-process deterministic world: the guest is pid 1
 * (with a stable synthetic parent pid) and no other process exists. A signal-0 probe
 * (an existence/permission check that delivers nothing) reports the guest alive
 * and every other pid absent (ESRCH) — this is the shape sysinfo's
 * `check_if_pid_is_alive` and libc liveness probes rely on. A real signal to
 * ANOTHER pid is ESRCH (no such process). A real signal to SELF is not modeled:
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
    if (sig == 0 && (pid == 1 || pid == 0 || pid == -1)) {
        return 0; /* the guest process/group exists; signal 0 delivers nothing */
    }
    if (pid != 1) {
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
