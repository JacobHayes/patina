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

int pause(void) {
    errno = ENOSYS;
    return -1;
}

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
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (signum == SIGSYS) {
        patina_posix_deny(
            "patina: sigaction(SIGSYS) refused: a guest may not register the "
            "syscall-dispatch signal (it would disable deterministic containment)\n");
        errno = EPERM;
        return -1;
    }
    if (signum == SIGSEGV && act != NULL && patina_tsc_armed) {
        /* Same hardening, second trap: while the timestamp-counter trap is armed
         * the SIGSEGV handler IS the containment for rdtsc/rdtscp, so replacing
         * it would turn every counter read into a crash (or, worse, into a
         * guest-handled fault that reads on). Rust std never reaches this — it
         * installs its stack-overflow handler only over SIG_DFL, and the trap
         * armed first — so this refuses a deliberate guest registration only.
         * A pure QUERY (act == NULL) is still answered. */
        patina_posix_deny(
            "patina: sigaction(SIGSEGV) refused: a guest may not replace the "
            "timestamp-counter trap handler (it would disable deterministic "
            "containment of rdtsc/rdtscp)\n");
        errno = EPERM;
        return -1;
    }
    return patina_real_sigaction()(signum, act, oldact);
}

void (*signal(int signum, void (*handler)(int)))(int) {
    if (signum == SIGSYS) {
        patina_posix_deny(
            "patina: signal(SIGSYS) refused: a guest may not register the "
            "syscall-dispatch signal (it would disable deterministic containment)\n");
        errno = EPERM;
        return SIG_ERR;
    }
    if (signum == SIGSEGV && patina_tsc_armed) {
        /* The `sigaction` hardening below reaches this path too: `signal()`
         * installs through the REAL sigaction, so it would otherwise walk around
         * the refusal and displace the timestamp-counter trap handler. */
        patina_posix_deny(
            "patina: signal(SIGSEGV) refused: a guest may not replace the "
            "timestamp-counter trap handler (it would disable deterministic "
            "containment of rdtsc/rdtscp)\n");
        errno = EPERM;
        return SIG_ERR;
    }
    /* Emulate signal() over the real sigaction to avoid a second host-alias:
     * install the handler with the classic (restarting) semantics and return the
     * previous handler. */
    struct sigaction action;
    struct sigaction previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (patina_real_sigaction()(signum, &action, &previous) != 0) {
        return SIG_ERR;
    }
    return previous.sa_handler;
}

/*
 * glibc init-reachable helpers a custom global allocator (tikv-jemallocator)
 * links on Linux, made deterministic so the guest audits clean and runs
 * reproducibly. Each is a strong def, so it also drops off the guest import table.
 */

/* Signal masking is inert under Patina (no ambient signals are ever delivered),
 * so forward to the real glibc mask op for faithful `oldset` semantics — but NEVER
 * let the guest block SIGSYS: under syscall-user-dispatch a blocked synchronous
 * SIGSYS would kill the process and disable deterministic containment. Strip SIGSYS
 * from any block/setmask set, mirroring the `sigaction(SIGSYS)` hardening above.
 * The shim uses no `pthread_sigmask` internally, so this never self-blocks. */
typedef int (*patina_host_pthread_sigmask_fn)(int, const sigset_t *, sigset_t *);
static patina_host_pthread_sigmask_fn patina_host_pthread_sigmask_ptr;
static patina_host_pthread_sigmask_fn patina_real_pthread_sigmask(void) {
    if (patina_host_pthread_sigmask_ptr == NULL) {
        patina_host_pthread_sigmask_ptr =
            (patina_host_pthread_sigmask_fn)__real_dlsym(RTLD_NEXT, "pthread_sigmask");
    }
    return patina_host_pthread_sigmask_ptr;
}
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    if (set != NULL && (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t adjusted = *set;
        sigdelset(&adjusted, SIGSYS);
        if (patina_tsc_armed) {
            /* A blocked synchronous SIGSEGV would kill the process at the first
             * rdtsc instead of being answered from the virtual clock — the same
             * containment argument as SIGSYS above. */
            sigdelset(&adjusted, SIGSEGV);
        }
        return patina_real_pthread_sigmask()(how, &adjusted, oldset);
    }
    return patina_real_pthread_sigmask()(how, set, oldset);
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
    /* abort() skips the atexit shutdown flush, so push the captured guest output
     * and this diagnostic to the real descriptors before terminating. */
    patina_flush_captured_stdio();
    abort();
}

pid_t fork(void) { patina_process_trap("fork"); }
int execvp(const char *file, char *const argv[]) {
    (void)file;
    (void)argv;
    patina_process_trap("execvp");
}
pid_t waitpid(pid_t pid, int *status, int options) {
    (void)pid;
    (void)status;
    (void)options;
    patina_process_trap("waitpid");
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
int chdir(const char *path) {
    (void)path;
    patina_process_trap("chdir");
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
    (void)idtype;
    (void)id;
    (void)infop;
    (void)options;
    patina_process_trap("waitid");
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
 * (getpid()==1, getppid()==0) and no other process exists. A signal-0 probe
 * (an existence/permission check that delivers nothing) reports the guest alive
 * and every other pid absent (ESRCH) — this is the shape sysinfo's
 * `check_if_pid_is_alive` and libc liveness probes rely on. A real signal to
 * ANOTHER pid is ESRCH (no such process). A real signal to SELF is not modeled:
 * the runtime delivers no asynchronous signals beyond its own SIGSYS
 * containment, so rather than silently claim delivery (a lie) or abort (not
 * support) it fails closed with a loud line and a recoverable ENOSYS.
 */
int kill(pid_t pid, int sig) {
    if (pid != 1) {
        errno = ESRCH;
        return -1;
    }
    if (sig == 0) {
        return 0; /* the guest (pid 1) exists; signal 0 delivers nothing */
    }
    return patina_posix_deny("patina: kill(self, signal) delivery is not modeled "
                             "by the deterministic runtime; failing closed\n");
}
