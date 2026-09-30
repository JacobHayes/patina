/* Class pairing: signal handlers of guest code on small stacks (a runtime
 * with small thread stacks runs its code on stacks of a few KiB, makes raw
 * syscalls there and runs its handlers on alternate stacks it checks the
 * bounds of, and a coroutine runtime switches stacks inside handlers). A
 * delivery must use no more of the guest's stacks than natively: the
 * handler runs on the stack it asked for, and the trap it is sent from uses
 * none (`small_stack_probe.rs` records and replays the raw syscalls alone).
 * Syscalls go through the raw instruction (x86_64, which SUD contains) or,
 * with a `-libc` case suffix and on every other arch, glibc's `syscall(2)`,
 * which the shim interposes. Named cases, each printing SMALL_STACK_OK after
 * its own line:
 *
 *   altstack   an SA_ONSTACK handler, sent by a tgkill from a 2 KiB stack,
 *              runs inside the alternate stack it registered (as a runtime
 *              that checks its signal stack's bounds requires), is told so
 *              by sigaltstack and its uc_stack, makes syscalls and libc calls
 *              there, and nests a second handler on the same stack;
 *   autodisarm the same on an SS_AUTODISARM stack, which the handler finds
 *              disabled and its return registers again;
 *   escape     SA_ONSTACK and ordinary-stack handlers that make a syscall and
 *              leave by siglongjmp, sent by tgkill and by raise, many times
 *              over: none of them is ever returned to, and the run goes on;
 *   swap-WSNT  a handler swapcontexts to a coroutine on a stack of its
 *              own, which makes syscalls and swaps back, and the handler
 *              returns intact, three times. W: the coroutine's stack is a
 *              mapping (m) or a local array of a frame above the handler (l);
 *              S: the handler runs on an alternate stack (a), an
 *              SS_AUTODISARM one (d) or the thread's own (o); N: plain (-),
 *              the handler runs inside another's (n), or the coroutine
 *              raises a signal whose handler returns (s); T: on the main
 *              thread (-) or a second one (t);
 *   exit-escape  a second thread's handler leaves by siglongjmp, the thread
 *              ends, and a thread-local destructor then makes a syscall;
 *   interleave[-alt]  one handler suspends into a coroutine whose own
 *              handler suspends into another, which resumes the first: the
 *              handlers return in the other order, with traps and a delivery
 *              between (-alt: on an SS_AUTODISARM alternate stack);
 *   outer[-alt]  a nested handler leaves by siglongjmp into the outer one,
 *              which returns, 500 times;
 *   chain-N    N handlers suspended at once, each in a coroutine of its own,
 *              then unwound in reverse: the shim stops by name past 64;
 *   shallower-N  N handlers left by siglongjmp, each from a strictly
 *              shallower depth of the thread's stack whose slot nothing
 *              writes again: the shim cannot prove them left (the file
 *              frames.rs documents why) and stops by name past 64.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31) /* <linux/signal.h>, which glibc's headers lack */
#endif

/* The door syscalls go through: the raw instruction, or glibc's syscall(2). */
static int libc_door;
static long raw(long nr, long a0, long a1, long a2) {
#if defined(__x86_64__)
    if (!libc_door) {
        long result;
        __asm__ volatile("syscall"
                         : "=a"(result)
                         : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
                         : "rcx", "r11", "memory");
        return result;
    }
#endif
    long result = syscall(nr, a0, a1, a2);
    return result == -1 ? -errno : result;
}

/* Call `body` with the stack pointer at `top`, and return on this stack. */
extern void on_stack(void (*body)(void), void *top);
#if defined(__x86_64__)
__asm__(".text\n"
        ".globl on_stack\n"
        ".type on_stack,@function\n"
        "on_stack:\n"
        "  pushq %rbp\n"
        "  movq %rsp, %rbp\n"
        "  movq %rsi, %rsp\n"
        "  callq *%rdi\n"
        "  movq %rbp, %rsp\n"
        "  popq %rbp\n"
        "  ret\n"
        ".size on_stack, .-on_stack\n");
#elif defined(__aarch64__)
__asm__(".text\n"
        ".globl on_stack\n"
        ".type on_stack,%function\n"
        "on_stack:\n"
        "  stp x29, x30, [sp, #-16]!\n"
        "  mov x29, sp\n"
        "  mov sp, x1\n"
        "  blr x0\n"
        "  mov sp, x29\n"
        "  ldp x29, x30, [sp], #16\n"
        "  ret\n"
        ".size on_stack, .-on_stack\n");
#endif

#define SMALL 2048
#define REGION (64 * 1024)
#define SENTINEL 0xa5

/* A small stack at the top of a sentinel-filled region: how many bytes below
 * its 2 KiB were written is how far a call on it overran it. */
struct small {
    unsigned char *region;
};
static struct small small_new(void) {
    unsigned char *region =
        mmap(NULL, REGION, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(region != MAP_FAILED);
    memset(region, SENTINEL, REGION);
    return (struct small){region};
}
static void *small_top(struct small s) {
    return s.region + REGION;
}
static size_t small_overrun(struct small s) {
    size_t first = 0;
    while (first < REGION - SMALL && s.region[first] == SENTINEL) first++;
    return REGION - SMALL - first;
}

/* The alternate stack a handler must run inside, and what it saw there. */
static stack_t registered;
static int autodisarm;
static volatile sig_atomic_t outer_in, inner_in, outer_flags, uc_matches, inner_ran, raw_pid_ok,
    libc_ok;
static int within(uintptr_t sp) {
    uintptr_t base = (uintptr_t)registered.ss_sp;
    return sp > base && sp - base <= registered.ss_size;
}

static void inner(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    inner_in = within((uintptr_t)__builtin_frame_address(0));
    inner_ran++;
    raw_pid_ok &= raw(SYS_getpid, 0, 0, 0) == getpid();
}

static void outer(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    (void)sig;
    (void)info;
    outer_in = within((uintptr_t)__builtin_frame_address(0));
    uc_matches = uc->uc_stack.ss_sp == registered.ss_sp &&
                 uc->uc_stack.ss_size == registered.ss_size &&
                 uc->uc_stack.ss_flags == registered.ss_flags;
    stack_t current;
    assert(raw(SYS_sigaltstack, 0, (long)&current, 0) == 0);
    outer_flags = current.ss_flags;
    raw_pid_ok = raw(SYS_getpid, 0, 0, 0) == getpid();
    struct timespec ts;
    libc_ok = clock_gettime(CLOCK_MONOTONIC, &ts) == 0;
    /* A second handler nests below this one, on the same stack. */
    assert(raw(SYS_tgkill, getpid(), raw(SYS_gettid, 0, 0, 0), SIGUSR2) == 0);
    raw_pid_ok &= raw(SYS_getpid, 0, 0, 0) == getpid();
}

static void install(int sig, void (*handler)(int, siginfo_t *, void *), int flags) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&action.sa_mask);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void send_urg(void) {
    assert(raw(SYS_tgkill, raw(SYS_getpid, 0, 0, 0), raw(SYS_gettid, 0, 0, 0), SIGURG) == 0);
}

static void altstack_case(int disarm) {
    size_t size = 32 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    autodisarm = disarm;
    registered = (stack_t){.ss_sp = stack, .ss_size = size,
                           .ss_flags = disarm ? (int)SS_AUTODISARM : 0};
    assert(raw(SYS_sigaltstack, (long)&registered, 0, 0) == 0);
    install(SIGURG, outer, SA_ONSTACK);
    install(SIGUSR2, inner, SA_ONSTACK);
    struct small s = small_new();
    /* Through libc's door the shim's code runs on the caller's stack, as any
     * library's does: that door sends from this ordinary stack. */
    if (libc_door) send_urg();
    else on_stack(send_urg, small_top(s));
    stack_t after;
    assert(sigaltstack(NULL, &after) == 0);
    printf("handler: on-alt=%d nested-on-alt=%d nested-ran=%d uc_stack=%d query=%s raw=%d libc=%d "
           "restored=%d overrun=%zu\n",
           (int)outer_in, (int)inner_in, (int)inner_ran, (int)uc_matches,
           outer_flags == SS_ONSTACK ? "onstack"
           : outer_flags == SS_DISABLE ? "disabled"
                                       : "other",
           (int)raw_pid_ok, (int)libc_ok,
           after.ss_sp == registered.ss_sp && after.ss_size == registered.ss_size &&
               after.ss_flags == registered.ss_flags,
           small_overrun(s));
    assert(outer_in && inner_in && inner_ran == 1 && uc_matches && raw_pid_ok && libc_ok);
    assert(outer_flags == (disarm ? SS_DISABLE : SS_ONSTACK));
    assert(small_overrun(s) == 0);
}

static sigjmp_buf escape;
static volatile sig_atomic_t escaped;
static void leaves(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    escaped += raw(SYS_getpid, 0, 0, 0) == getpid();
    siglongjmp(escape, 1);
}

static void escape_case(void) {
    enum { ROUNDS = 5000 };
    size_t size = 64 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    stack_t alt = {.ss_sp = stack, .ss_size = size, .ss_flags = 0};
    assert(sigaltstack(&alt, NULL) == 0);
    install(SIGUSR1, leaves, SA_ONSTACK);
    install(SIGUSR2, leaves, 0);
    for (int round = 0; round < ROUNDS; round++) {
        int sig = round % 2 ? SIGUSR2 : SIGUSR1;
        if (sigsetjmp(escape, 1) == 0) {
            /* Sent through the syscall trap, and through libc's door. */
            if (round % 3 == 2) raise(sig);
            else raw(SYS_tgkill, getpid(), raw(SYS_gettid, 0, 0, 0), sig);
            assert(!"a handler that leaves by siglongjmp returned");
        }
    }
    printf("escape: rounds=%d escaped=%d\n", ROUNDS, (int)escaped);
    assert(escaped == ROUNDS);
}

/* A handler that runs a coroutine on a stack of its own and comes back. The
 * coroutine's stack is a mapping, or a local array of a frame above the
 * handler's on the thread's own stack (as coroutine runtimes carve them). */
static ucontext_t handler_context, coroutine_context;
static char *coroutine_stack;
#define COROUTINE_STACK (128 * 1024)
/* 0: SIGUSR1's handler swaps; 'n': it raises SIGUSR2, whose handler swaps;
 * 's': it swaps, and the coroutine raises SIGUSR2, whose handler returns. */
static char nesting;
static volatile sig_atomic_t swapped_back, coroutine_calls, inner_runs;
static void send(int sig) {
    assert(raw(SYS_tgkill, getpid(), raw(SYS_gettid, 0, 0, 0), sig) == 0);
}
static void coroutine(void) {
    for (int i = 0; i < 8; i++) coroutine_calls += raw(SYS_getpid, 0, 0, 0) == getpid();
    if (nesting == 's') send(SIGUSR2);
    for (int i = 0; i < 8; i++) coroutine_calls += raw(SYS_getpid, 0, 0, 0) == getpid();
    swapcontext(&coroutine_context, &handler_context);
}
static void swap_to_coroutine(void) {
    assert(getcontext(&coroutine_context) == 0);
    coroutine_context.uc_stack.ss_sp = coroutine_stack;
    coroutine_context.uc_stack.ss_size = COROUTINE_STACK;
    coroutine_context.uc_link = NULL;
    makecontext(&coroutine_context, coroutine, 0);
    assert(swapcontext(&handler_context, &coroutine_context) == 0);
    assert(raw(SYS_getpid, 0, 0, 0) == getpid());
    swapped_back++;
}
static void outer_swaps(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    if (nesting == 'n') send(SIGUSR2);
    else swap_to_coroutine();
}
static void inner_swaps(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    inner_runs++;
    assert(raw(SYS_getpid, 0, 0, 0) == getpid());
    if (nesting == 'n') swap_to_coroutine();
}

/* Three rounds, from a frame below whatever the coroutine stack is in. */
static void __attribute__((noinline)) swap_rounds(int onstack) {
    volatile char pad[2048];
    pad[0] = 0;
    install(SIGUSR1, outer_swaps, onstack ? SA_ONSTACK : 0);
    install(SIGUSR2, inner_swaps, onstack ? SA_ONSTACK : 0);
    for (int round = 0; round < 3; round++) send(SIGUSR1);
    (void)pad[0];
}

/* where: 'm' a mapping, 'l' a local array above the handler; stack: 'a' an
 * alternate stack, 'd' an SS_AUTODISARM one, 'o' the thread's own. */
static char swap_where, swap_stack;
static void __attribute__((noinline)) swap_run(void) {
    char local[COROUTINE_STACK] __attribute__((aligned(16)));
    if (swap_where == 'l') {
        coroutine_stack = local;
    } else {
        coroutine_stack = mmap(NULL, COROUTINE_STACK, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(coroutine_stack != MAP_FAILED);
    }
    if (swap_stack != 'o') {
        size_t size = 64 * 1024;
        void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(stack != MAP_FAILED);
        stack_t alt = {.ss_sp = stack, .ss_size = size,
                       .ss_flags = swap_stack == 'd' ? (int)SS_AUTODISARM : 0};
        assert(sigaltstack(&alt, NULL) == 0);
    }
    swap_rounds(swap_stack != 'o');
    __asm__ volatile("" : : "r"(local) : "memory");
}
static void *swap_thread(void *unused) {
    (void)unused;
    swap_run();
    return NULL;
}

/* swap-<where><stack><nesting><thread>, e.g. swap-ma-- or swap-lost. */
static void swap_case(const char *how) {
    assert(strlen(how) == 4);
    swap_where = how[0];
    swap_stack = how[1];
    nesting = how[2] == '-' ? 0 : how[2];
    if (how[3] == 't') {
        pthread_t thread;
        assert(pthread_create(&thread, NULL, swap_thread, NULL) == 0);
        assert(pthread_join(thread, NULL) == 0);
    } else {
        swap_run();
    }
    printf("swap-%s: returned=%d coroutine-calls=%d inner=%d\n", how, (int)swapped_back,
           (int)coroutine_calls, (int)inner_runs);
    assert(swapped_back == 3 && coroutine_calls == 48);
    assert(inner_runs == (nesting ? 3 : 0));
}

/* A thread whose handler left by siglongjmp, with no syscall since, ends;
 * a thread-local destructor, run after the thread's end, makes one. */
static pthread_key_t exit_key;
static volatile sig_atomic_t destructor_pid_ok;
static void exit_destructor(void *value) {
    (void)value;
    destructor_pid_ok = raw(SYS_getpid, 0, 0, 0) == getpid();
}
static void *exit_thread(void *unused) {
    (void)unused;
    assert(pthread_setspecific(exit_key, (void *)1) == 0);
    if (sigsetjmp(escape, 1) == 0) {
        raw(SYS_tgkill, getpid(), raw(SYS_gettid, 0, 0, 0), SIGUSR1);
        assert(!"a handler that leaves by siglongjmp returned");
    }
    return NULL;
}
static void exit_escape_case(void) {
    install(SIGUSR1, leaves, 0);
    assert(pthread_key_create(&exit_key, exit_destructor) == 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, exit_thread, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    printf("exit-escape: escaped=%d destructor=%d\n", (int)escaped, (int)destructor_pid_ok);
    assert(escaped == 1 && destructor_pid_ok);
}

/* Handlers that return out of order, suspended at depth, or left by
 * siglongjmp in shapes the shim cannot prove (see the file comment). */
static void traps(int n) {
    for (int i = 0; i < n; i++) assert(raw(SYS_getpid, 0, 0, 0) == getpid());
}
#define GRAPH_STACK (128 * 1024)
static void make(ucontext_t *uc, void (*fn)(void)) {
    assert(getcontext(uc) == 0);
    uc->uc_stack.ss_sp =
        mmap(NULL, GRAPH_STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(uc->uc_stack.ss_sp != MAP_FAILED);
    uc->uc_stack.ss_size = GRAPH_STACK;
    uc->uc_link = NULL;
    makecontext(uc, fn, 0);
}
static int graph_onstack;

/* interleave: H1 suspends into C1; C1's H2 suspends into C2; C2 resumes H1,
 * which returns first; main takes traps and a delivery, then resumes H2,
 * which returns last. */
static ucontext_t main_context, h1_context, h2_context, c1_context, c2_context;
static volatile sig_atomic_t h1_done, h2_done, hup_runs;
static void c2(void) {
    traps(8);
    swapcontext(&c2_context, &h1_context);
    abort();
}
static void h2(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    make(&c2_context, c2);
    swapcontext(&h2_context, &c2_context);
    traps(8);
    h2_done = 1;
}
static void c1(void) {
    send(SIGUSR2);
    traps(8);
    swapcontext(&c1_context, &main_context);
    abort();
}
static void h1(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    make(&c1_context, c1);
    swapcontext(&h1_context, &c1_context);
    traps(8);
    h1_done = 1;
}
static void on_hup(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    traps(8);
    hup_runs++;
}
static void interleave_case(void) {
    install(SIGUSR1, h1, graph_onstack);
    install(SIGUSR2, h2, graph_onstack);
    install(SIGHUP, on_hup, graph_onstack);
    send(SIGUSR1);
    assert(h1_done && !h2_done);
    traps(16);
    send(SIGHUP);
    traps(16);
    swapcontext(&main_context, &h2_context);
    assert(h2_done && hup_runs == 1);
    traps(4);
    printf("interleave: h1=%d h2=%d hup=%d\n", (int)h1_done, (int)h2_done, (int)hup_runs);
}

/* chain-N: N handlers suspended at once, each in a coroutine of its own,
 * then unwound in reverse. */
static int chain_n, chain_depth;
static ucontext_t chain_handler_context[128], chain_coroutine_context[128];
static void chain_coroutine(void) {
    if (chain_depth < chain_n) send(SIGUSR1);
    else swapcontext(&chain_coroutine_context[chain_depth - 1],
                     &chain_handler_context[chain_depth - 1]);
    abort();
}
static void chain_handler(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    int me = chain_depth++;
    make(&chain_coroutine_context[me], chain_coroutine);
    swapcontext(&chain_handler_context[me], &chain_coroutine_context[me]);
    traps(2);
    if (me > 0) swapcontext(&chain_coroutine_context[me], &chain_handler_context[me - 1]);
}
static void chain_case(int n) {
    assert(n <= 128);
    chain_n = n;
    install(SIGUSR1, chain_handler, SA_NODEFER);
    send(SIGUSR1);
    traps(2);
    printf("chain: depth=%d\n", chain_depth);
}

/* shallower-N: N handlers left by siglongjmp, each from a strictly shallower
 * depth of the thread's stack than the last, whose slots nothing writes
 * again. */
static sigjmp_buf graph_escape;
static void graph_leaves(int sig) {
    (void)sig;
    siglongjmp(graph_escape, 1);
}
static void __attribute__((noinline)) recurse(int depth, int target) {
    volatile char pad[64 * 1024];
    pad[0] = (char)depth;
    if (depth == target) {
        if (sigsetjmp(graph_escape, 1) == 0) send(SIGUSR1);
    } else {
        recurse(depth + 1, target);
    }
    (void)pad[0];
}
static void shallower_case(int n) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = graph_leaves;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    for (int target = n; target >= 1; target--) recurse(1, target);
    traps(2);
    printf("shallower: rounds=%d\n", n);
}

/* outer: a nested handler leaves by siglongjmp into the outer one, which
 * returns; repeated. */
static sigjmp_buf outer_escape;
static volatile sig_atomic_t outer_returns;
static void inner_leaves(int sig) {
    (void)sig;
    siglongjmp(outer_escape, 1);
}
static void outer_handler(int sig) {
    (void)sig;
    if (sigsetjmp(outer_escape, 1) == 0) {
        send(SIGUSR2);
        abort();
    }
    traps(2);
    outer_returns++;
}
static void outer_case(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    sigemptyset(&action.sa_mask);
    action.sa_flags = graph_onstack;
    action.sa_handler = outer_handler;
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    action.sa_handler = inner_leaves;
    assert(sigaction(SIGUSR2, &action, NULL) == 0);
    for (int i = 0; i < 500; i++) {
        send(SIGUSR1);
        traps(1);
    }
    printf("outer: returns=%d\n", (int)outer_returns);
    assert(outer_returns == 500);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char name[64];
    snprintf(name, sizeof name, "%s", argv[1]);
    char *suffix = strstr(name, "-libc");
    if (suffix != NULL && suffix[5] == '\0') *suffix = '\0';
#if defined(__x86_64__)
    libc_door = suffix != NULL;
#else
    libc_door = 1;
#endif
    if (strcmp(name, "altstack") == 0) {
        altstack_case(0);
    } else if (strcmp(name, "autodisarm") == 0) {
        altstack_case(1);
    } else if (strcmp(name, "escape") == 0) {
        escape_case();
    } else if (strcmp(name, "exit-escape") == 0) {
        exit_escape_case();
    } else if (strncmp(name, "interleave", 10) == 0 || strncmp(name, "outer", 5) == 0) {
        if (strstr(name, "-alt") != NULL) {
            stack_t alt = {.ss_sp = mmap(NULL, GRAPH_STACK, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                           .ss_size = GRAPH_STACK, .ss_flags = (int)SS_AUTODISARM};
            assert(alt.ss_sp != MAP_FAILED && sigaltstack(&alt, NULL) == 0);
            graph_onstack = SA_ONSTACK;
        }
        if (name[0] == 'i') interleave_case();
        else outer_case();
    } else if (strncmp(name, "chain-", 6) == 0) {
        chain_case(atoi(name + 6));
    } else if (strncmp(name, "shallower-", 10) == 0) {
        shallower_case(atoi(name + 10));
    } else if (strncmp(name, "swap-", 5) == 0) {
        swap_case(name + 5);
    } else {
        fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    puts("SMALL_STACK_OK");
    return 0;
}
