/*
 * Delivery: the C driver that starts guest signal handlers, so that no Rust
 * frame of the shim is beneath one (a handler may leave by siglongjmp or
 * setcontext, which would discard it). Rust prepares each release in
 * returning steps (src/thread/signals/delivery.rs) and reads back what the
 * handlers' returns left; only the release itself, which builds the frames
 * the kernel runs the handlers on, happens here.
 *
 * The trap handlers in init.c that take the thread from guest code (the
 * counter trap, the fault front's return) end in this driver while they still
 * hold the thread. Every other delivery point still releases from Rust
 * (signals::deliver), and under a trap handler's hold leaves the signals
 * pending for this exit instead.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
/* One delivery's state between its steps, in the driver's frame (Rust's
 * signals::delivery::Exit, whose layout this mirrors). Only Rust fills it. */
struct patina_exit {
    uint64_t mask;       /* PATINA_RELEASE_UNBLOCK's host mask */
    uint64_t scope_word; /* the delivery's SIGSEGV scope word */
    uint64_t swapped;
    uint64_t ticket;
    uintptr_t held_sp; /* the trap handler's hold while the handlers run */
    uint64_t held_entry;
    uint64_t info[16]; /* PATINA_RELEASE_QUEUE's siginfo */
    int32_t pid;
    int32_t tid;
    int32_t sig;
    uint8_t release;
    uint8_t scope_open;
    uint8_t was_releasing;
    uint8_t outer_dirty;
    uint64_t plan_old; /* what the trapped call left its exit to do */
    uint64_t plan_segv;
    uint64_t plan_word;
    uint8_t plan;
};
_Static_assert(sizeof(struct patina_exit) == 224, "Rust signals::delivery::Exit layout");

enum {
    PATINA_RELEASE_UNBLOCK = 1, /* install `mask`: the queued batch is built at once */
    PATINA_RELEASE_QUEUE = 2,   /* queue `info` for `sig`, unblocked: built as it returns */
};

/*
 * How a trap handler's exit runs the driver. IN_FRAME releases inside the
 * trap handler's frame: a handler's context is the release's. The guest
 * context `uc` (the trap's kernel frame) is where a delivery that builds the
 * handler's frame over the interrupted guest code itself would start from,
 * at the trap's sigreturn; no mode does yet.
 */
enum { PATINA_EXIT_IN_FRAME = 1 };
struct patina_trap_exit {
    struct patina_exit exit;
    ucontext_t *uc;
    int mode;
};

extern int patina_exit_begin(struct patina_exit *delivery);
extern int patina_exit_end(struct patina_exit *delivery, long ret);
extern int patina_exit_next(struct patina_exit *delivery);
extern int patina_exit_released(struct patina_exit *delivery);
extern void patina_trap_hand_over(struct patina_exit *delivery);
extern void patina_trap_take_back(const struct patina_exit *delivery);
extern __attribute__((visibility("hidden"))) long (*patina_fault_host_syscall)(long, ...);
static _Noreturn void patina_fault_stop(const char *message, size_t length);

/* The only code that starts a guest handler for a signal the shim queued. */
static void patina_release(const struct patina_exit *delivery) {
    long rc;
    if (delivery->release == PATINA_RELEASE_UNBLOCK) {
        rc = patina_fault_host_syscall(SYS_rt_sigprocmask, SIG_SETMASK, &delivery->mask, NULL, 8);
    } else {
        rc = patina_fault_host_syscall(SYS_rt_tgsigqueueinfo, (long)delivery->pid, (long)delivery->tid,
                                       (long)delivery->sig, delivery->info);
    }
    if (rc != 0) {
        static const char message[] = "patina: host signal release failed\n";
        patina_fault_stop(message, sizeof message - 1);
    }
}

/* Deliver what is pending, then carry out what the trapped call left its
 * exit to do (a temporary mask to restore); answers whether the call, which
 * answered `ret`, runs again (a restart SA_RESTART asked for). Called only
 * from a C frame whose caller is the trap's kernel frame, while the trap
 * handler holds the thread: the steps refuse any other caller by name. The
 * handlers run with the thread theirs. */
__attribute__((visibility("hidden"))) int patina_exit_drive(struct patina_exit *delivery,
                                                            long ret) {
    int begun = patina_exit_begin(delivery);
    if (begun & 1) {
        while (patina_exit_next(delivery)) {
            do {
                patina_trap_hand_over(delivery);
                patina_release(delivery);
                patina_trap_take_back(delivery);
            } while (patina_exit_released(delivery));
        }
    }
    return (begun & 2) ? patina_exit_end(delivery, ret) : 0;
}

static int patina_trap_exit_drive(ucontext_t *uc, long ret) {
    struct patina_trap_exit trap = {.uc = uc, .mode = PATINA_EXIT_IN_FRAME};
    return patina_exit_drive(&trap.exit, ret);
}
#endif
