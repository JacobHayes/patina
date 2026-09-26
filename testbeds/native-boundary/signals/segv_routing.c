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
