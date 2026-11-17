// Live SME state at a signal: `sme-state za` turns on the ZA array and raises SIGUSR1 (ZA
// survives the call); `sme-state sm` enters streaming mode and executes an undefined
// instruction (a system call would leave streaming mode). Natively the handler's frame holds
// the state (the array, too large for the frame's 4,096 bytes, behind an extra-context record;
// an SVE record flagged streaming); Patina does not build those records. The handler notes
// the records it got. Only for hosts with SME (elsewhere the first instruction is undefined).
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

static volatile int handled;
static char recs[256];

// The handler notes the frame's records (magic:size:flags) and steps over a udf.
static void on_sig(int sig, siginfo_t *si, void *ucv) {
    (void)si;
    if (sig == SIGILL) ((ucontext_t *)ucv)->uc_mcontext.pc += 4;
    uint8_t *r = ((ucontext_t *)ucv)->uc_mcontext.__reserved;
    int n = 0;
    for (int off = 0; off + 16 <= 4096 && n < 200;) {
        uint32_t magic = *(uint32_t *)(r + off), size = *(uint32_t *)(r + off + 4);
        if (magic == 0 || size < 8) break;
        n += snprintf(recs + n, sizeof recs - n, "%x:%u:%x ", magic, size, *(uint16_t *)(r + off + 10));
        off += size;
    }
    handled++;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "za";
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    if (!strcmp(mode, "sm")) {
        asm volatile(".inst 0xd503437f\n udf #0\n .inst 0xd503467f" ::: "memory"); // smstart sm; udf; smstop
    } else {
        asm volatile(".inst 0xd503457f" ::: "memory"); // smstart za
        raise(SIGUSR1);
        asm volatile(".inst 0xd503467f" ::: "memory"); // smstop
    }
    printf("%s handled=%d records %s\n", mode, handled, recs);
    return 0;
}
