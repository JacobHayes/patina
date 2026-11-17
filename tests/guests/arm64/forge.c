// rt_sigreturn with a frame the kernel refuses: `forge mis` a stack pointer not 16-byte
// aligned, `forge rt` a frame where the runtime lives (unmapped for the program), `forge top`
// one above every mapping. Each gets SIGSEGV; its handler (on the alternate stack) prints what
// it got, which must be what the kernel gives: the code, whether si_addr and the saved sp are
// the forged pointer (an unreadable frame leaves the registers 0), the saved x0 (the call
// returns 0).
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
static uint64_t want_sp;
static void on_segv(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    printf("sig=%d code=%d addr_is_sp=%d x0=%lu sp_kept=%d\n", sig, si->si_code, (uint64_t)si->si_addr == want_sp,
           (unsigned long)uc->uc_mcontext.regs[0], uc->uc_mcontext.sp == want_sp);
    fflush(stdout);
    _exit(0);
}
int main(int argc, char **argv) {
    stack_t ss = {.ss_sp = malloc(65536), .ss_size = 65536};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    uint64_t sp;
    if (!strcmp(argv[1], "mis")) {
        asm volatile("mov %0, sp" : "=r"(sp));
        sp -= 4104;
    } else if (!strcmp(argv[1], "rt")) {
        sp = 0x600000001000;
    } else {
        sp = 0x7ffffffff000; // above everything
    }
    want_sp = sp;
    asm volatile("mov x9, sp\n mov sp, %0\n mov x0, #77\n mov x8, #139\n svc #0\n mov sp, x9" ::"r"(sp) : "x0", "x8", "x9", "memory");
    printf("returned\n");
    return 1;
}
