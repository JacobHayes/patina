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
    uint8_t call; /* the interrupted call's charge state, while the handlers run */
    int32_t plan_errno;
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

/* The C side's host system calls go through the private vehicle with
 * syscall-user-dispatch's selector allowing them (src/sud/arming.rs): some
 * are made outside any hold, the thread already the guest's (a release that
 * starts guest handlers, a signal frame's stack switch, the fault stop), where
 * the selector otherwise blocks. A handler that runs on the call's return
 * leaves the selector as it found it. */
extern uint8_t patina_sud_host_open(void);
extern void patina_sud_host_close(uint8_t previous);
extern uint8_t patina_sud_guest_open(void);
static long patina_host_syscall(long nr, long a0, long a1, long a2, long a3) {
    uint8_t previous = patina_sud_host_open();
    long rc = patina_fault_host_syscall(nr, a0, a1, a2, a3);
    patina_sud_host_close(previous);
    return rc;
}

/* The only code that starts a guest handler for a signal the shim queued. */
static void patina_release(const struct patina_exit *delivery) {
    long rc;
    if (delivery->release == PATINA_RELEASE_UNBLOCK) {
        rc = patina_host_syscall(SYS_rt_sigprocmask, SIG_SETMASK, (long)&delivery->mask, 0, 8);
    } else {
        rc = patina_host_syscall(SYS_rt_tgsigqueueinfo, (long)delivery->pid, (long)delivery->tid,
                                 (long)delivery->sig, (long)delivery->info);
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

/*
 * The libc doors that forward to the syscall model (src/posix/door_thunks.rs)
 * and syscall(2) hold the thread around the Rust door as a trap handler
 * does: what the door makes deliverable is left pending for its exit, which
 * delivers once the door returned. A door's errno is written after the
 * handlers ran, as glibc's wrapper writes it after the kernel's return
 * delivered them; a door that failed EINTR from a wait SA_RESTART restarts
 * runs again from the same registers.
 */
/* A trap handler's hold on the thread (src/panic_boundary.rs `Claim`), kept
 * in the handler's frame from `patina_trap_enter` to `patina_trap_leave`,
 * which gives the thread back to what held it before. `took`: the hold took
 * the thread from guest code, and its exit delivers. A hold that found the
 * thread already the shim's took nothing, and asks whether its call nests
 * (`patina_trap_nested_syscall`, `patina_door_nested_call`, in
 * src/thread/signals/fault.rs) before it runs. One made under a shim entry,
 * outside any dispatch (guest code the shim called, its C allocator say, made
 * it), nests in the shim's call, and its exit delivers nothing. One made
 * beneath a dispatch (whoever entered it) or under a trap handler's or a
 * door's hold is shim code reaching its own boundary (std's futex waits lower
 * to syscall(2)), or guest code that code called: a named stop. */
struct patina_claim {
    uint8_t previous;
    uint8_t took;
};
extern int patina_trap_enter(uintptr_t sp, stack_t *stack, struct patina_claim *claim);
extern void patina_trap_leave(struct patina_claim claim);
extern void patina_door_nested_call(const struct patina_claim *claim, long number);

/* A held door's state, in its thunk's frame (one 8-byte slot): the hold, and
 * the errno the door's call met, which its handlers see, as the kernel's
 * return delivers them before glibc's wrapper writes errno. A nested door's
 * errno is the one it wrote. */
struct patina_door_hold {
    struct patina_claim claim;
    int32_t call_errno;
};
_Static_assert(sizeof(struct patina_door_hold) == 8, "the door thunks' hold slot");

/* Hold the thread for the door syscall(2) serves as `number` (-1: a door
 * the thunks forward) whose caller's stack pointer is `sp`. */
static void patina_door_take(uintptr_t sp, struct patina_door_hold *door, long number) {
    door->call_errno = errno;
    (void)patina_trap_enter(sp, NULL, &door->claim);
    if (!door->claim.took) patina_door_nested_call(&door->claim, number);
}

/* The door's caller's stack pointer is `sp`. */
__attribute__((visibility("hidden"))) void patina_door_hold(uintptr_t sp,
                                                            struct patina_door_hold *door) {
    patina_door_take(sp, door, -1);
}

/* After the Rust door returned: answers whether it runs again (still held).
 * The exit writes the errno the door owes once its handlers ran, if the door
 * does not run again; the next run meets what they left. */
__attribute__((visibility("hidden"))) int patina_door_exit(struct patina_door_hold *door) {
    if (door->claim.took) {
        struct patina_exit delivery;
        memset(&delivery, 0, sizeof delivery);
        errno = door->call_errno;
        if (patina_exit_drive(&delivery, 0)) {
            door->call_errno = errno;
            return 1;
        }
    }
    patina_trap_leave(door->claim);
    return 0;
}

/* syscall(2): its assembly entry (src/variadic/syscall.rs) captured the six
 * argument words; the door is the fixed Rust entry. */
extern long patina_libc_syscall_fixed(long number, const uint64_t (*words)[6]);
__attribute__((visibility("hidden"))) long patina_libc_syscall_door(
    long number, const uint64_t (*words)[6], uintptr_t sp) {
    struct patina_door_hold door;
    patina_door_take(sp, &door, number);
    long ret;
    do ret = patina_libc_syscall_fixed(number, words);
    while (patina_door_exit(&door));
    return ret;
}
#endif
