/* Class pairing: a guest's own SIGSEGV handler under the timestamp-counter
 * trap, which keeps the host SIGSEGV disposition and routes every fault it
 * does not answer to the guest's action. Named cases, run natively as the
 * oracle and under the shim, each printing what the kernel gave the handler:
 *
 *   overflow      an SA_ONSTACK handler catches a stack overflow on its
 *                 alternate stack and siglongjmps out; the same handler then
 *                 catches an access fault the same way, and a counter read
 *                 after both is still answered;
 *   raise         a SIGSEGV the guest raises reaches an SA_RESETHAND handler
 *                 with the sender's code, and sigaction then reports the
 *                 default handler with the flags kept;
 *   resume        a handler steps the faulting context past the store, and
 *                 the edited context is what resumes;
 *   nested        a fault inside an SA_ONSTACK handler that blocks SIGSEGV
 *                 takes the default action, never a second run of the
 *                 handler (which exits 42);
 *   nested-stack  the same on the ordinary stack, where the shim cannot tell
 *                 it from a siglongjmp'd handler and stops by name instead;
 *   reraise       a handler that resets SIGSEGV and raises it keeps it
 *                 pending, runs on, and dies as it returns;
 *   masked-fault  an SA_ONSTACK handler for a genuine SIGFPE (x86_64: idiv by
 *                 zero; arm64: SIGTRAP, brk) whose sa_mask blocks every
 *                 signal reads SIGSEGV back blocked, then faults: the default
 *                 action, never the SIGSEGV handler (which exits 42);
 *   front-small   the masked-fault signal's SA_ONSTACK handler, which leaves
 *                 by siglongjmp, on an alternate stack with room for the
 *                 kernel's frame and 1.5 KiB: natively it runs, under the
 *                 shim the fault handler's route would not fit below the
 *                 frame, a named stop;
 *   order-shared  a process-directed SIGSEGV pending with a thread-directed
 *                 SIGUSR1: the private one is dequeued first, so the SIGSEGV
 *                 frame is on top and its handler runs first;
 *   order-mask    a SIGSEGV whose sa_mask blocks everything, pending with a
 *                 lower-numbered SIGUSR1: synchronous first, so only it runs,
 *                 with SIGUSR1 still pending, and SIGUSR1 after it;
 *   order-escape  order-shared with a SIGSEGV handler that recovers by
 *                 siglongjmp: SIGUSR1's frame, built beneath it, is lost with
 *                 it, and unblocking SIGUSR1 again delivers nothing;
 *   order-reset   order-shared with a SIGSEGV handler that resets SIGUSR1 to
 *                 the default: SIGUSR1's frame, built beneath it, still runs
 *                 the handler it was dequeued with;
 *   nodefer-std   an SA_NODEFER SIGUSR1 pending both to the thread and to the
 *                 process: two frames, the process's (dequeued second) on
 *                 top, so its handler runs first, under the first one's mask;
 *   nodefer-rt    the same with two queued SIGRTMIN instances: the second
 *                 queued runs first, and only its frame saves the first
 *                 handler's mask;
 *   nodefer-edit  nodefer-std whose first handler edits its frame's saved
 *                 mask, which the second starts under natively: under the
 *                 shim a named stop;
 *   autodisarm-high  an SA_ONSTACK handler whose sa_mask blocks SIGSEGV runs
 *                 on an SS_AUTODISARM alternate stack that lies above the
 *                 stack it was delivered from (a local array of an outer
 *                 frame), and reads SIGSEGV back blocked there;
 *   alarm         (x86_64) SA_ONSTACK alarms fire while counter reads taken
 *                 on the alternate stack are served: native, the handlers run
 *                 and the reads go on; under the shim a handler that would run
 *                 during such a read is a named stop;
 *   alarm-small   (x86_64) the alarm case on an alternate stack with room for
 *                 about two signal frames: under the shim the trap's frame
 *                 leaves too little below it for a nested one, a named stop;
 *   prefixed      (x86_64) a REX-prefixed rdtsc, which the CPU executes as a
 *                 counter read and the trap does not answer: never a SIGSEGV
 *                 for the guest's handler (which exits 97).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31) /* <linux/signal.h>, which glibc's headers lack */
#endif

#define ALT_SIZE (256 * 1024)
static char alt[ALT_SIZE];
static sigjmp_buf escape;
static volatile sig_atomic_t on_alt, code, calls;
static volatile int never = -1;

static void on_segv(int sig, siginfo_t *info, void *context) {
    (void)context;
    char here;
    assert(sig == SIGSEGV);
    on_alt = (uintptr_t)&here - (uintptr_t)alt < ALT_SIZE;
    code = info->si_code;
    calls++;
    siglongjmp(escape, 1);
}

static int descend(int depth) {
    volatile char frame[512];
    frame[0] = (char)depth;
    if (depth == never) return 0;
    return descend(depth + 1) + frame[0];
}

static void counter_read(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    (void)lo;
    (void)hi;
#endif
}

static void overflow(void) {
    stack_t stack = {.ss_sp = alt, .ss_size = ALT_SIZE, .ss_flags = 0};
    assert(sigaltstack(&stack, NULL) == 0);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_segv;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    if (sigsetjmp(escape, 1) == 0) descend(0);
    printf("OVERFLOW calls=%d on_alt=%d code=%d\n", (int)calls, (int)on_alt, (int)code);
    volatile char *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(page != MAP_FAILED);
    if (sigsetjmp(escape, 1) == 0) page[0] = 1;
    printf("ACCESS calls=%d on_alt=%d code=%d\n", (int)calls, (int)on_alt, (int)code);
    counter_read();
}

static void on_raise(int sig, siginfo_t *info, void *context) {
    (void)context;
    assert(sig == SIGSEGV);
    code = info->si_code;
    calls++;
}

static void raised(void) {
    struct sigaction action, old;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_raise;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGSEGV, &action, &old) == 0);
    printf("INITIAL default=%d\n", old.sa_handler == SIG_DFL);
    assert(raise(SIGSEGV) == 0);
    assert(sigaction(SIGSEGV, NULL, &old) == 0);
    printf("RAISED calls=%d code=%d default=%d flags=%#x\n", (int)calls, (int)code,
           old.sa_handler == SIG_DFL, old.sa_flags & (SA_SIGINFO | SA_RESETHAND | SA_ONSTACK));
    counter_read();
}

static void say(const char *text) {
    assert(write(1, text, strlen(text)) == (ssize_t)strlen(text));
}

static volatile char *no_access(void) {
    volatile char *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(page != MAP_FAILED);
    return page;
}

static void install(int sig, void (*handler)(int, siginfo_t *, void *), int flags, int fill) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO | flags;
    if (fill) sigfillset(&action.sa_mask);
    else sigemptyset(&action.sa_mask);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void on_alt_stack(void) {
    stack_t stack = {.ss_sp = alt, .ss_size = ALT_SIZE, .ss_flags = 0};
    assert(sigaltstack(&stack, NULL) == 0);
}

/* One byte stored at `page`, as one instruction of a known length. */
static void store(volatile char *page) {
#if defined(__x86_64__)
    __asm__ volatile("movb $1, (%0)" : : "D"(page) : "memory"); /* c6 07 01: 3 bytes */
#elif defined(__aarch64__)
    __asm__ volatile("strb wzr, [%0]" : : "r"(page) : "memory"); /* 4 bytes */
#endif
}

static void on_resume(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    (void)sig;
    code = info->si_code;
    calls++;
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RIP] += 3;
#elif defined(__aarch64__)
    uc->uc_mcontext.pc += 4;
#endif
}

static void resume(void) {
    install(SIGSEGV, on_resume, 0, 0);
    store(no_access());
    printf("RESUMED calls=%d code=%d\n", (int)calls, (int)code);
}

static volatile char *wild;
static volatile sig_atomic_t entered;
static void on_nested(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    /* Run again where the kernel takes the default action. */
    if (entered++) _exit(42);
    say("HANDLER\n");
    wild[0] = 1;
    say("HANDLER RETURNED\n");
}

static void nested(int onstack) {
    if (onstack) on_alt_stack();
    install(SIGSEGV, on_nested, onstack ? SA_ONSTACK : 0, 0);
    wild = no_access();
    wild[0] = 1;
    say("NOT KILLED\n");
}

static void on_segv_exit(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    _exit(42);
}

static void on_masked(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    sigset_t now;
    assert(sigprocmask(SIG_BLOCK, NULL, &now) == 0);
    say(sigismember(&now, SIGSEGV) ? "blocked=1\n" : "blocked=0\n");
    wild[0] = 1;
    say("HANDLER RETURNED\n");
}

/* A genuine fault of a signal other than SIGSEGV that runs `handler` on the
 * alternate stack: SIGFPE (idiv by zero) on x86_64, SIGTRAP (brk) on arm64. */
static void other_fault(void (*handler)(int, siginfo_t *, void *), int fill) {
#if defined(__x86_64__)
    install(SIGFPE, handler, SA_ONSTACK, fill);
    int low = 1, high = 0, zero = 0;
    __asm__ volatile("idivl %2" : "+a"(low), "+d"(high) : "r"(zero));
#else
    install(SIGTRAP, handler, SA_ONSTACK, fill);
    __builtin_trap();
#endif
}

static void masked_fault(void) {
    on_alt_stack();
    install(SIGSEGV, on_segv_exit, 0, 0);
    wild = no_access();
    other_fault(on_masked, 1);
    say("NOT KILLED\n");
}

static void on_escape(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    siglongjmp(escape, 1);
}

static void front_small(void) {
    size_t size = getauxval(AT_MINSIGSTKSZ) + 1536;
    char *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    stack_t registered = {.ss_sp = stack, .ss_size = size, .ss_flags = 0};
    assert(sigaltstack(&registered, NULL) == 0);
    if (sigsetjmp(escape, 1) == 0) other_fault(on_escape, 0);
    say("FRONT SMALL RAN\n");
}

static void on_reraise(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    signal(SIGSEGV, SIG_DFL);
    assert(raise(SIGSEGV) == 0);
    say("AFTER RAISE\n");
}

static void reraise(void) {
    on_alt_stack();
    install(SIGSEGV, on_reraise, SA_ONSTACK, 0);
    assert(raise(SIGSEGV) == 0);
    say("NOT KILLED\n");
}

static char order[8];
static volatile sig_atomic_t ordered;
static void note(char c) {
    order[ordered++] = c;
}
static void on_usr1(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    note('U');
}
enum order_case { ORDER_RETURN, ORDER_ESCAPE, ORDER_RESET };
static enum order_case order_how;
static sigjmp_buf order_escape;
static void on_ordered_segv(int sig, siginfo_t *info, void *context) {
    sigset_t pending;
    (void)sig;
    (void)info;
    (void)context;
    assert(sigpending(&pending) == 0);
    note('S');
    if (sigismember(&pending, SIGUSR1)) note('p');
    if (order_how == ORDER_ESCAPE) siglongjmp(order_escape, 1);
    if (order_how == ORDER_RESET) signal(SIGUSR1, SIG_DFL);
}

static void block_both(int how) {
    sigset_t both;
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, SIGSEGV);
    assert(sigprocmask(how, &both, NULL) == 0);
}

static void *order_sender(void *main_thread) {
    assert(pthread_kill(*(pthread_t *)main_thread, SIGUSR1) == 0);
    assert(kill(getpid(), SIGSEGV) == 0);
    return NULL;
}

static void ordered_delivery(int shared, enum order_case how) {
    order_how = how;
    install(SIGUSR1, on_usr1, 0, 0);
    install(SIGSEGV, on_ordered_segv, 0, !shared);
    block_both(SIG_BLOCK);
    sigset_t blocked;
    assert(sigprocmask(SIG_BLOCK, NULL, &blocked) == 0);
    assert(sigismember(&blocked, SIGSEGV));
    if (shared) {
        pthread_t self = pthread_self(), sender;
        assert(pthread_create(&sender, NULL, order_sender, &self) == 0);
        assert(pthread_join(sender, NULL) == 0);
    } else {
        assert(raise(SIGUSR1) == 0);
        assert(raise(SIGSEGV) == 0);
    }
    assert(ordered == 0);
    if (sigsetjmp(order_escape, 1) == 0) block_both(SIG_UNBLOCK);
    printf("ORDER %.*s\n", (int)ordered, order);
    if (how == ORDER_RETURN) return;
    sigset_t pending;
    struct sigaction now;
    assert(sigpending(&pending) == 0);
    assert(sigaction(SIGUSR1, NULL, &now) == 0);
    block_both(SIG_UNBLOCK);
    printf("AFTER %.*s pending=%d default=%d\n", (int)ordered, order,
           sigismember(&pending, SIGUSR1), now.sa_handler == SIG_DFL);
}

static char runs[16];
static volatile sig_atomic_t ran;
static int edit;
static void on_nodefer(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    if (sig == SIGUSR1) runs[ran++] = info->si_code == SI_TKILL ? 't' : 'k';
    else runs[ran++] = (char)('0' + info->si_value.sival_int);
    runs[ran++] = sigismember(&uc->uc_sigmask, sig) ? 'B' : '-';
    runs[ran++] = sigismember(&uc->uc_sigmask, SIGUSR2) ? 'M' : '-';
    if (edit) sigaddset(&uc->uc_sigmask, SIGWINCH);
}

/* Each run prints who sent it and whether its frame's saved mask blocks the
 * signal itself (B) and the handler's sa_mask (M). */
static void nodefer(int rt) {
    int sig = rt ? SIGRTMIN : SIGUSR1;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_nodefer;
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGUSR2);
    assert(sigaction(sig, &action, NULL) == 0);
    sigset_t one;
    sigemptyset(&one);
    sigaddset(&one, sig);
    assert(sigprocmask(SIG_BLOCK, &one, NULL) == 0);
    if (rt) {
        assert(sigqueue(getpid(), sig, (union sigval){.sival_int = 1}) == 0);
        assert(sigqueue(getpid(), sig, (union sigval){.sival_int = 2}) == 0);
    } else {
        assert(pthread_kill(pthread_self(), sig) == 0);
        assert(kill(getpid(), sig) == 0);
    }
    assert(sigprocmask(SIG_UNBLOCK, &one, NULL) == 0);
    printf("NODEFER %.*s\n", (int)ran, runs);
}

static volatile sig_atomic_t high_on_alt, high_blocked;
static char *high_alt;
static void on_high(int sig) {
    char here;
    sigset_t now;
    (void)sig;
    high_on_alt = (uintptr_t)&here - (uintptr_t)high_alt < ALT_SIZE;
    assert(sigprocmask(SIG_BLOCK, NULL, &now) == 0);
    high_blocked = sigismember(&now, SIGSEGV);
}

static void autodisarm_high(void) {
    char above[ALT_SIZE];
    high_alt = above;
    stack_t stack = {.ss_sp = above, .ss_size = ALT_SIZE, .ss_flags = (int)SS_AUTODISARM};
    assert(sigaltstack(&stack, NULL) == 0);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_high;
    action.sa_flags = SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGSEGV);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    assert(raise(SIGUSR1) == 0);
    printf("AUTODISARM on_alt=%d blocked=%d\n", (int)high_on_alt, (int)high_blocked);
    stack_t off = {.ss_flags = SS_DISABLE};
    assert(sigaltstack(&off, NULL) == 0);
}

static volatile sig_atomic_t alarms;
static void on_alarm(int sig) {
    (void)sig;
    alarms++;
}

static void alarm_reads(int small) {
    if (small) {
        size_t size = 2 * getauxval(AT_MINSIGSTKSZ) - 512;
        void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(stack != MAP_FAILED);
        stack_t registered = {.ss_sp = stack, .ss_size = size, .ss_flags = 0};
        assert(sigaltstack(&registered, NULL) == 0);
    } else {
        on_alt_stack();
    }
    install(SIGSEGV, on_resume, SA_ONSTACK, 0);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_alarm;
    action.sa_flags = SA_ONSTACK;
    assert(sigaction(SIGALRM, &action, NULL) == 0);
    struct itimerval every = {{0, 1000}, {0, 1000}};
    assert(syscall(SYS_setitimer, ITIMER_REAL, &every, NULL) == 0);
    while (alarms < 5) counter_read();
    struct itimerval off = {{0, 0}, {0, 0}};
    assert(syscall(SYS_setitimer, ITIMER_REAL, &off, NULL) == 0);
    printf("ALARMS %d\n", (int)alarms);
}

static void on_counter(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)info;
    (void)context;
    _exit(97);
}

static void prefixed(void) {
    install(SIGSEGV, on_counter, 0, 0);
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile(".byte 0x48, 0x0f, 0x31" : "=a"(lo), "=d"(hi)); /* rex.w rdtsc */
    (void)lo;
    (void)hi;
#endif
    puts("PREFIXED");
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "overflow") == 0) {
        overflow();
    } else if (strcmp(argv[1], "raise") == 0) {
        raised();
    } else if (strcmp(argv[1], "resume") == 0) {
        resume();
    } else if (strcmp(argv[1], "nested") == 0) {
        nested(1);
    } else if (strcmp(argv[1], "nested-stack") == 0) {
        nested(0);
    } else if (strcmp(argv[1], "reraise") == 0) {
        reraise();
    } else if (strcmp(argv[1], "masked-fault") == 0) {
        masked_fault();
    } else if (strcmp(argv[1], "front-small") == 0) {
        front_small();
    } else if (strcmp(argv[1], "order-shared") == 0) {
        ordered_delivery(1, ORDER_RETURN);
    } else if (strcmp(argv[1], "order-mask") == 0) {
        ordered_delivery(0, ORDER_RETURN);
    } else if (strcmp(argv[1], "order-escape") == 0) {
        ordered_delivery(1, ORDER_ESCAPE);
    } else if (strcmp(argv[1], "order-reset") == 0) {
        ordered_delivery(1, ORDER_RESET);
    } else if (strcmp(argv[1], "nodefer-std") == 0) {
        nodefer(0);
    } else if (strcmp(argv[1], "nodefer-rt") == 0) {
        nodefer(1);
    } else if (strcmp(argv[1], "nodefer-edit") == 0) {
        edit = 1;
        nodefer(0);
    } else if (strcmp(argv[1], "autodisarm-high") == 0) {
        autodisarm_high();
    } else if (strcmp(argv[1], "alarm") == 0) {
        alarm_reads(0);
    } else if (strcmp(argv[1], "alarm-small") == 0) {
        alarm_reads(1);
    } else if (strcmp(argv[1], "prefixed") == 0) {
        prefixed();
    } else {
        fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    puts("SEGV_ROUTING_OK");
    return 0;
}
