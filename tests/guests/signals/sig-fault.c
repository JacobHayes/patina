// signals item 5: synchronous faults. `sig-fault handled` installs handlers and recovers with
// siglongjmp from a nil dereference (si_addr, faulting rip), integer division by zero,
// ud2 and an access to a file mapping beyond end of file. `sig-fault die-<kind>` makes the
// same fault with the default action, so the process dies of the signal.
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

extern char segv_ip[], fpe_ip[], ill_ip[], bus_ip[];

__attribute__((noinline)) static void do_segv(void) {
    asm volatile(".globl segv_ip\nsegv_ip: movl (%0), %%eax" ::"r"(16L) : "eax", "memory");
}
__attribute__((noinline)) static void do_fpe(void) {
    asm volatile("xor %%edx, %%edx\n mov $7, %%eax\n xor %%ecx, %%ecx\n.globl fpe_ip\nfpe_ip: idiv %%ecx" ::: "eax", "ecx",
                 "edx");
}
__attribute__((noinline)) static void do_ill(void) {
    asm volatile(".globl ill_ip\nill_ip: ud2");
}
static volatile char *bus_addr;
__attribute__((noinline)) static void do_bus(void) {
    asm volatile(".globl bus_ip\nbus_ip: movb (%0), %%al" ::"r"(bus_addr) : "eax", "memory");
}

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
    got_rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    siglongjmp(env, 1);
}

static void check(const char *name, void (*f)(void), int sig, uintptr_t want_addr, char *want_ip) {
    got_sig = 0;
    if (!sigsetjmp(env, 1)) f();
    printf("%s sig=%d want=%d code=%d addr_ok=%d rip_ok=%d\n", name, got_sig, sig, got_code, got_addr == want_addr,
           got_rip == (uintptr_t)want_ip);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "handled";
    map_short_file();
    if (!strcmp(mode, "handled")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        int sigs[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS};
        for (int i = 0; i < 4; i++) sigaction(sigs[i], &sa, NULL);
        for (int round = 0; round < 2; round++) {
            check("segv", do_segv, SIGSEGV, 16, segv_ip);
            check("fpe", do_fpe, SIGFPE, (uintptr_t)fpe_ip, fpe_ip);
            check("ill", do_ill, SIGILL, (uintptr_t)ill_ip, ill_ip);
            check("bus", do_bus, SIGBUS, (uintptr_t)bus_addr, bus_ip);
        }
        return 0;
    }
    printf("about to fault: %s\n", mode);
    fflush(stdout);
    if (!strcmp(mode, "die-segv")) do_segv();
    if (!strcmp(mode, "die-fpe")) do_fpe();
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
