// Synchronous faults. `sig-fault handled` installs handlers and recovers with
// siglongjmp from a nil dereference (si_addr, faulting pc), a second synchronous trap
// (x86_64: integer division by zero, SIGFPE; arm64, where no arithmetic traps: a breakpoint,
// SIGTRAP), an undefined instruction and an access to a file mapping beyond end of file; each
// line prints what it got and what the kernel gives. `sig-fault die-<kind>` makes the same
// fault with the default action, so the process dies of the signal (it prints the signal
// first); `sig-fault modes` lists the die-<kind> modes.
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

extern char segv_ip[], trap_ip[], ill_ip[], bus_ip[];
static volatile char *bus_addr;

#if defined(__x86_64__)
#define PC(uc) ((uc)->uc_mcontext.gregs[REG_RIP])
#define TRAP "fpe"
#define TRAP_SIG SIGFPE
#define TRAP_CODE FPE_INTDIV
#define ILL_CODE ILL_ILLOPN
__attribute__((noinline)) static void do_segv(void) {
    asm volatile(".globl segv_ip\nsegv_ip: movl (%0), %%eax" ::"r"(16L) : "eax", "memory");
}
__attribute__((noinline)) static void do_trap(void) {
    asm volatile("xor %%edx, %%edx\n mov $7, %%eax\n xor %%ecx, %%ecx\n.globl trap_ip\ntrap_ip: idiv %%ecx" ::: "eax", "ecx",
                 "edx");
}
__attribute__((noinline)) static void do_ill(void) {
    asm volatile(".globl ill_ip\nill_ip: ud2");
}
__attribute__((noinline)) static void do_bus(void) {
    asm volatile(".globl bus_ip\nbus_ip: movb (%0), %%al" ::"r"(bus_addr) : "eax", "memory");
}
#elif defined(__aarch64__)
#define PC(uc) ((uc)->uc_mcontext.pc)
#define TRAP "trap"
#define TRAP_SIG SIGTRAP
#define TRAP_CODE TRAP_BRKPT
#define ILL_CODE ILL_ILLOPC
__attribute__((noinline)) static void do_segv(void) {
    asm volatile(".globl segv_ip\nsegv_ip: ldr w9, [%0]" ::"r"(16L) : "x9", "memory");
}
__attribute__((noinline)) static void do_trap(void) {
    asm volatile(".globl trap_ip\ntrap_ip: brk #7");
}
__attribute__((noinline)) static void do_ill(void) {
    asm volatile(".globl ill_ip\nill_ip: udf #0");
}
__attribute__((noinline)) static void do_bus(void) {
    asm volatile(".globl bus_ip\nbus_ip: ldrb w9, [%0]" ::"r"(bus_addr) : "x9", "memory");
}
#endif

static void map_short_file(void) {
    int fd = open("/work/short", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fd = open("short", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (write(fd, "0123456789", 10) != 10) perror("write");
    char *p = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) perror("mmap");
    close(fd);
    bus_addr = p + 4096;
}

static sigjmp_buf env;
static volatile int got_sig, got_code;
static volatile uintptr_t got_addr, got_rip;

static void on_fault(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    got_sig = sig;
    got_code = si->si_code;
    got_addr = (uintptr_t)si->si_addr;
    got_rip = (uintptr_t)PC(uc);
    siglongjmp(env, 1);
}

static void check(const char *name, void (*f)(void), int sig, int code, uintptr_t want_addr, char *want_ip) {
    got_sig = 0;
    if (!sigsetjmp(env, 1)) f();
    printf("%s sig=%d want=%d code=%d want_code=%d addr_ok=%d rip_ok=%d\n", name, got_sig, sig, got_code, code,
           got_addr == want_addr, got_rip == (uintptr_t)want_ip);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "handled";
    if (!strcmp(mode, "modes")) {
        printf("die-segv die-%s die-ill die-bus die-term die-abort die-blocked-segv\n", TRAP);
        return 0;
    }
    map_short_file();
    if (!strcmp(mode, "handled")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        int sigs[] = {SIGSEGV, TRAP_SIG, SIGILL, SIGBUS};
        for (int i = 0; i < 4; i++) sigaction(sigs[i], &sa, NULL);
        for (int round = 0; round < 2; round++) {
            check("segv", do_segv, SIGSEGV, SEGV_MAPERR, 16, segv_ip);
            check(TRAP, do_trap, TRAP_SIG, TRAP_CODE, (uintptr_t)trap_ip, trap_ip);
            check("ill", do_ill, SIGILL, ILL_CODE, (uintptr_t)ill_ip, ill_ip);
            check("bus", do_bus, SIGBUS, BUS_ADRERR, (uintptr_t)bus_addr, bus_ip);
        }
        return 0;
    }
    int want = !strcmp(mode, "die-segv") || !strcmp(mode, "die-blocked-segv") ? SIGSEGV
               : !strcmp(mode, "die-" TRAP)                                    ? TRAP_SIG
               : !strcmp(mode, "die-ill")                                      ? SIGILL
               : !strcmp(mode, "die-bus")                                      ? SIGBUS
               : !strcmp(mode, "die-term")                                     ? SIGTERM
               : !strcmp(mode, "die-abort")                                    ? SIGABRT
                                                                               : 0;
    printf("about to fault: %s want=%d\n", mode, want);
    fflush(stdout);
    if (!strcmp(mode, "die-segv")) do_segv();
    if (!strcmp(mode, "die-" TRAP)) do_trap();
    if (!strcmp(mode, "die-ill")) do_ill();
    if (!strcmp(mode, "die-bus")) do_bus();
    if (!strcmp(mode, "die-term")) raise(SIGTERM);
    if (!strcmp(mode, "die-abort")) abort();
    if (!strcmp(mode, "die-blocked-segv")) {
        // A blocked fault signal is not held: the kernel unblocks it and the process dies.
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        sigset_t m;
        sigfillset(&m);
        sigprocmask(SIG_SETMASK, &m, NULL);
        do_segv();
    }
    printf("still alive\n");
    return 0;
}
