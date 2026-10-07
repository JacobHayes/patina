/*
 * Init: the frames startup and the shim's signal handlers keep in C. Startup,
 * host resolution, trap arming and decoding, and the constructor are Rust
 * (src/posix/lifecycle/); the bodies here call its returning helpers before
 * anything can leave nonlocally.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/* The extraction anchor (src/variadic.rs): this object's unresolved reference
 * extracts the Rust archive member holding the constructor and interposers,
 * even where libc or libSystem already satisfied their public names. */
extern void patina_variadic_link(void);
__attribute__((used)) static void (*const patina_link_anchor)(void) = patina_variadic_link;

#ifdef __linux__
/* glibc's old-style cleanup records, pushed and popped by Rust over storage in
 * the calling frame: glibc's forced unwind runs a record as it leaves it. */
extern void patina_cleanup_push(struct _pthread_cleanup_buffer *buffer, void (*routine)(void *),
                                void *arg);
extern void patina_cleanup_pop(struct _pthread_cleanup_buffer *buffer, int execute);

/* ==========================================================================
 * The SIGSYS handler for syscall-user-dispatch (SUD-DESIGN.md): Rust decodes
 * the trap (provenance, a guest restorer's rt_sigreturn, the registers) and
 * completes it (frame fixups, the return register) around the dispatch, whose
 * signal delivery may leave this frame by siglongjmp. Raw-syscall callers read
 * the return register, not errno, but the guest's live errno is restored.
 * ========================================================================== */
struct patina_sud_trap {
    long nr;
    unsigned long args[6];
    uintptr_t call_addr;
    uintptr_t sp;
};
extern int patina_sud_decode(siginfo_t *info, ucontext_t *uc, struct patina_sud_trap *trap);
extern void patina_sud_complete(ucontext_t *uc, long ret);
extern long patina_sud_dispatch(long nr, unsigned long a0, unsigned long a1, unsigned long a2,
                                unsigned long a3, unsigned long a4, unsigned long a5,
                                uintptr_t call_addr);
void patina_note_guest_sp(uintptr_t sp, stack_t *stack);
_Static_assert(offsetof(siginfo_t, si_call_addr) == 16 && offsetof(siginfo_t, si_syscall) == 24 &&
                   offsetof(siginfo_t, si_arch) == 28,
               "Rust SIGSYS siginfo words");

__attribute__((visibility("hidden"))) void patina_sud_sigsys(int sig, siginfo_t *info,
                                                             void *ucontext) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)ucontext;
    int saved_errno = errno;
    struct patina_sud_trap trap;
    if (patina_sud_decode(info, uc, &trap)) {
        patina_note_guest_sp(trap.sp, &uc->uc_stack);
        long ret = patina_sud_dispatch(trap.nr, trap.args[0], trap.args[1], trap.args[2],
                                       trap.args[3], trap.args[4], trap.args[5], trap.call_addr);
        patina_sud_complete(uc, ret);
    }
    errno = saved_errno;
}

/* Every shim handler's side of the boundary with the Rust signal state (see
 * src/thread/signals/fault.rs): it takes the thread for the shim first, and a
 * fault while the shim already owned it is a named stop. */
enum {
    PATINA_FAULT_DEFAULT = 0,
    PATINA_FAULT_HANDLER = 1,
};
extern int patina_trap_enter(uintptr_t sp, stack_t *stack);
extern void patina_trap_leave(void);
_Noreturn void patina_trap_shim_fault(const siginfo_t *info, uintptr_t pc);
_Noreturn void patina_trap_take_default(int sig);

/* What the Rust startup resolved and discovered for these handlers. */
extern __attribute__((visibility("hidden"))) uintptr_t patina_sud_text_lo;
extern __attribute__((visibility("hidden"))) uintptr_t patina_sud_text_hi;
extern __attribute__((visibility("hidden"))) int (*patina_host_sigaction)(int, const struct sigaction *,
                                                                        struct sigaction *);
extern __attribute__((visibility("hidden"))) long (*patina_fault_host_syscall)(long, ...);

/* The private frame a shim handler runs a guest handler from, and where the
 * guest handler runs (src/thread/signals/fault.rs `Frame`, frames.rs). The
 * guest handler's return goes through `patina_signal_fault_return`. */
struct patina_fault_frame {
    uintptr_t sp;               /* the interrupted stack pointer */
    stack_t *stack;             /* the frame's uc_stack */
    volatile uint64_t *canary;  /* every guest frame of the handler is below it */
    uint64_t *mask;             /* the frame's uc_sigmask */
    uintptr_t floor;            /* the lowest private stack this frame's shim code reaches */
    uintptr_t target;           /* the guest stack pointer to call at; 0: in place */
    stack_t nested;             /* the host registration while the handler runs */
    stack_t host;               /* uc_stack as the kernel saved it */
    uintptr_t resume;           /* the stack pointer the frame resumes at */
    uintptr_t position;         /* where the handler runs, for SIGSEGV's scope */
};
extern void patina_signal_fault_return(const struct patina_fault_frame *frame);
/* The routes (src/thread/signals/fault.rs): the counter trap's SIGSEGV route
 * and the front route. */
typedef int (*patina_route_fn)(int, siginfo_t *, const ucontext_t *, struct patina_fault_frame *,
                               struct patina_signal_action *);
extern int patina_tsc_route(int sig, siginfo_t *info, const ucontext_t *uc,
                            struct patina_fault_frame *frame, struct patina_signal_action *handler);
extern int patina_fault_route(int sig, siginfo_t *info, const ucontext_t *uc,
                              struct patina_fault_frame *frame,
                              struct patina_signal_action *handler);

/* Room below this handler's frame for its own locals, the call below, and the
 * return path: its level of the private stack must hold them (frames.rs). */
#define PATINA_FRAME_MARGIN 4096
static _Noreturn void patina_fault_stop(const char *message, size_t length);

/* Call `handler(sig, info, uc)` with the stack pointer at `target`, and return
 * on the caller's stack (assembly in src/posix/lifecycle/traps.rs). */
__attribute__((visibility("hidden"))) void patina_call_guest_handler(uintptr_t handler, long sig,
                                                                     siginfo_t *info, void *uc,
                                                                     uintptr_t target);

static uintptr_t patina_frame_pc(const ucontext_t *uc) {
#if defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.pc;
#endif
}
static uintptr_t patina_frame_sp(const ucontext_t *uc) {
#if defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
#elif defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.sp;
#endif
}

/* The shim handlers a frame can be interrupted at the entry of: the kernel
 * builds several frames on one return to user space, each over the last. */
__attribute__((visibility("hidden"))) void patina_fault_front(int sig, siginfo_t *info,
                                                              void *ucontext);
#if defined(__x86_64__)
__attribute__((visibility("hidden"))) void patina_tsc_sigsegv(int sig, siginfo_t *info,
                                                              void *ucontext);
#endif

/* The stack pointer the code a frame interrupted was at. A frame built over
 * another the kernel has not entered yet interrupted that one's shim handler
 * at its first instruction, with the stack pointer at that frame: what it
 * stands for is what that one interrupted. Read before the handler takes the
 * thread, so it stays here. */
static uintptr_t patina_interrupted_sp(const ucontext_t *uc) {
    uintptr_t sp = patina_frame_sp(uc);
    for (;;) {
        uintptr_t pc = patina_frame_pc(uc);
        int entry = pc == (uintptr_t)(void *)patina_fault_front;
#if defined(__x86_64__)
        entry |= pc == (uintptr_t)(void *)patina_tsc_sigsegv;
        /* `rt_sigframe`: the restorer's return address, then the ucontext. */
        const ucontext_t *below = (const ucontext_t *)(sp + sizeof(void *));
#elif defined(__aarch64__)
        /* `rt_sigframe`: siginfo, then the ucontext. */
        const ucontext_t *below = (const ucontext_t *)(sp + sizeof(siginfo_t));
#endif
        if (!entry) return sp;
        uc = below;
        sp = patina_frame_sp(uc);
    }
}

static void patina_host_altstack(const stack_t *stack) {
    if (patina_fault_host_syscall(SYS_sigaltstack, stack, NULL) != 0) {
        static const char message[] = "patina: host private signal stack switch failed\n";
        patina_fault_stop(message, sizeof message - 1);
    }
}

/* Run the guest handler a route chose, from the private frame `uc`, where the
 * route put it: on the guest stack it asked for, with the host registration
 * naming a level of the private stack no running handler owns while it runs
 * (a trap it takes builds its frame there), or in place on a thread without a
 * private stack. */
static void patina_run_guest_handler(int sig, siginfo_t *info, ucontext_t *uc,
                                     struct patina_fault_frame *frame,
                                     const struct patina_signal_action *handler) {
    if (frame->target == 0) {
        /* The kernel passes siginfo and ucontext to every handler, whether it
         * asked for SA_SIGINFO or not. */
        ((void (*)(int, siginfo_t *, void *))handler->handler)(sig, info, uc);
        return;
    }
    patina_host_altstack(&frame->nested);
    patina_call_guest_handler(handler->handler, sig, info, uc, frame->target);
    /* Back in the shim: nested frames go below this one, in its level, until
     * the frame's rt_sigreturn installs the registration it names. */
    static const stack_t off = {.ss_flags = SS_DISABLE};
    patina_host_altstack(&off);
}

/* A signal for a guest handler reached a shim handler (`route` chose it: the
 * counter trap's SIGSEGV route or the front route), or a fault the guest's
 * action takes as the default (FAULT_DEFAULT is answered). */
static int patina_guest_signal(int sig, siginfo_t *info, ucontext_t *uc, patina_route_fn route) {
    uintptr_t sp = patina_interrupted_sp(uc);
    int saved_errno = errno;
    if (!patina_trap_enter(sp, &uc->uc_stack)) patina_trap_shim_fault(info, patina_frame_pc(uc));
    volatile uint64_t canary = 0;
    struct patina_fault_frame frame = {
        .sp = sp,
        .stack = &uc->uc_stack,
        .canary = &canary,
        .mask = (uint64_t *)(void *)&uc->uc_sigmask,
        .floor = (uintptr_t)__builtin_frame_address(0) - PATINA_FRAME_MARGIN,
        .host = uc->uc_stack,
        .resume = sp,
    };
    struct patina_signal_action handler;
    int routed = route(sig, info, uc, &frame, &handler);
    patina_trap_leave();
    errno = saved_errno;
    if (routed != PATINA_FAULT_HANDLER) return routed;
    patina_run_guest_handler(sig, info, uc, &frame, &handler);
    /* errno is the thread's, as natively: the handler's value stands. */
    saved_errno = errno;
    /* As it stands: a frame built over another resumes into that one's
     * shim handler, and restores the registration the kernel saved. */
    frame.resume = patina_frame_sp(uc);
    (void)patina_trap_enter(frame.resume, NULL);
    patina_signal_fault_return(&frame);
    patina_trap_leave();
    errno = saved_errno;
    return routed;
}

#if defined(__x86_64__)
/* ==========================================================================
 * Timestamp-counter trap (x86-64, src/tsc.rs): `rdtsc`/`rdtscp` raise a
 * synchronous SIGSEGV. Only a kernel-sent (`SI_KERNEL`) `rdtsc` (0f 31) or
 * `rdtscp` (0f 01 f9) in the main executable's text is answered, from the
 * virtual clock; any other SIGSEGV goes where the kernel would send it under
 * the guest's virtual action (src/thread/signals/fault.rs), from this frame.
 * The decode precedes `patina_trap_enter`, so it stays here.
 * ========================================================================== */
extern int patina_tsc_dispatch(const unsigned char *bytes, size_t available,
                               unsigned long long *tsc_out, unsigned int *aux_out,
                               size_t *length_out);
/* The longest instruction the trap decodes (`rdtscp`, 3 bytes). */
#define PATINA_TSC_MAX_INSN 3

/* The SIGSEGV disposition the trap displaced (Rust startup stored it). */
extern __attribute__((visibility("hidden"))) struct sigaction patina_tsc_prev;
_Static_assert(sizeof(struct sigaction) == 152, "Rust sigaction storage");

/* Take the fault as it would have been taken without the trap: the displaced
 * disposition, or the default restored so the retried instruction faults with
 * the true si_addr and a core dump. Never a swallow. */
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
    /* A SIGSEGV the kernel sends itself need not be a fault the retried
     * instruction raises again (a signal frame that did not fit on its stack
     * is one): taken now, it is never lost with the trap left disarmed. */
    if (info->si_code == SI_KERNEL) patina_trap_take_default(sig);
    (void)patina_host_sigaction(sig, &patina_tsc_prev, NULL);
}

void patina_tsc_sigsegv(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    greg_t *r = uc->uc_mcontext.gregs;
    uintptr_t rip = (uintptr_t)r[REG_RIP];
    uintptr_t sp = (uintptr_t)r[REG_RSP];
    /* Provenance, as the SIGSYS handler requires it: the kernel's own #GP in
     * the main executable's text; elsewhere, reading three bytes could fault. */
    if (info->si_code == SI_KERNEL && rip >= patina_sud_text_lo && rip < patina_sud_text_hi) {
        size_t available = (size_t)(patina_sud_text_hi - rip);
        if (available > PATINA_TSC_MAX_INSN) available = PATINA_TSC_MAX_INSN;
        const unsigned char *bytes = (const unsigned char *)rip;
        /* Exact encodings only, paired with tsc::classify and the
         * rdtsc/rdtscp/prefixed-counter containment probes. */
        int counter = available >= 2 && bytes[0] == 0x0f &&
            (bytes[1] == 0x31 || (available >= 3 && bytes[1] == 0x01 && bytes[2] == 0xf9));
        if (counter) {
            unsigned long long tsc = 0;
            unsigned int aux = 0;
            size_t length = 0;
            int saved_errno = errno;
            if (!patina_trap_enter(sp, &uc->uc_stack)) patina_trap_shim_fault(info, rip);
            int kind = patina_tsc_dispatch(bytes, available, &tsc, &aux, &length);
            if (kind == PATINA_TSC_NONE) {
                static const char message[] = "patina: C and Rust counter classifiers disagree\n";
                patina_fault_stop(message, sizeof message - 1);
            }
            patina_trap_leave();
            errno = saved_errno;
            /* Both instructions write 32-bit halves, which zero-extend into
             * the full 64-bit registers exactly as the hardware's do. */
            r[REG_RAX] = (greg_t)(tsc & 0xffffffffULL);
            r[REG_RDX] = (greg_t)((tsc >> 32) & 0xffffffffULL);
            if (kind == PATINA_TSC_RDTSCP) { /* rdtscp also reports IA32_TSC_AUX */
                r[REG_RCX] = (greg_t)aux;
            }
            r[REG_RIP] = (greg_t)(rip + length);
            return;
        }
    }
    if (patina_guest_signal(sig, info, uc, patina_tsc_route) == PATINA_FAULT_DEFAULT) {
        patina_tsc_take_real_fault(sig, info, ucontext);
    }
}
#endif

/* Resolved before installing the front handler. The stop must never enter
 * Rust, resolve a symbol, format, or use an interposed vehicle. glibc's
 * syscall is a leaf and is inside SUD's allowed text region. */
static _Noreturn void patina_fault_stop(const char *message, size_t length) {
    static const unsigned long default_action[4] = {0, 0, 0, 0};
    static const uint64_t unblock = UINT64_C(1) << (SIGABRT - 1);
    (void)patina_fault_host_syscall(SYS_write, 2, message, length);
    /* Private abort, not guest abort: reset/unblock SIGABRT and send it to
     * this thread. No Rust scope, trace finalization or guest handler. */
    (void)patina_fault_host_syscall(SYS_rt_sigaction, SIGABRT, default_action, NULL, 8);
    (void)patina_fault_host_syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &unblock, NULL, 8);
    long pid = patina_fault_host_syscall(SYS_getpid);
    long tid = patina_fault_host_syscall(SYS_gettid);
    (void)patina_fault_host_syscall(SYS_tgkill, pid, tid, SIGABRT);
    (void)patina_fault_host_syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}

/* The front handler: the host disposition of every signal a guest handler
 * runs for and of the signals an instruction raises (src/thread/signals/fault.rs). */
void patina_fault_front(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    if (patina_guest_signal(sig, info, uc, patina_fault_route) == PATINA_FAULT_HANDLER) return;
    /* The retried instruction takes the fault under the default action; a
     * trap (int3 resumes past itself) or a signal the kernel sent itself need
     * not raise it again, so those are taken now. */
    if (sig == SIGTRAP || info->si_code == SI_KERNEL) patina_trap_take_default(sig);
    struct sigaction deflt;
    memset(&deflt, 0, sizeof deflt);
    deflt.sa_handler = SIG_DFL;
    (void)patina_host_sigaction(sig, &deflt, NULL);
}

/*
 * `__libc_start_main`: crt1.o's reference binds here, before glibc gets
 * control, so the wrapper sees the natural `main` return glibc's hidden `exit`
 * alias hides from the `exit` interposer. Rust prepares the process
 * (src/posix/lifecycle/linux.rs) and answers glibc's own; the host call stays
 * here, never relying on an optimizer tail call to leave a guarded Rust frame.
 */
typedef int (*patina_main_fn)(int, char **, char **);
typedef int (*patina_libc_start_main_fn)(patina_main_fn, int, char **, void *, void *, void *,
                                         void *);
extern patina_libc_start_main_fn patina_start_prepare(int argc, char **argv, int sud_probe);
extern void patina_main_exited(void *unused);

static patina_main_fn patina_real_main;

/* The main thread's pthread_exit unwinds out of `main`, running every
 * frame's cleanup records; this outermost one tells the model the main
 * thread has ended (src/posix/lifecycle/linux.rs `patina_main_exited`). */
static int patina_main_wrapper(int argc, char **argv, char **envp) {
    struct _pthread_cleanup_buffer exited;
    patina_cleanup_push(&exited, patina_main_exited, NULL);
    int code = patina_real_main(argc, argv, envp);
    patina_cleanup_pop(&exited, 0);
    /* Mark teardown before glibc's `exit()` runs the thread-local destructors
     * (no scheduling point in them), and record the guest's own status, so a
     * finalization failure never files a guest error as infrastructure. */
    patina_note_main_returned();
    patina_note_guest_exit_status(code);
    return code;
}

/* Acceptance-only object build: exercise the unavailable-kernel SUD branch.
 * Production compiler flags do not define this hook. */
#ifdef PATINA_TEST_NO_SUD
#define PATINA_SUD_PROBE 0
#else
#define PATINA_SUD_PROBE 1
#endif

int __libc_start_main(patina_main_fn main_fn, int argc, char **argv, void *init,
                      void *fini, void *rtld_fini, void *stack_end) {
    patina_libc_start_main_fn real = patina_start_prepare(argc, argv, PATINA_SUD_PROBE);
    patina_real_main = main_fn;
    return real(patina_main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}
#endif
