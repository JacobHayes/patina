/* Uninitialised memory: stack pages below the stack pointer after signals and after deep
 * calls, fresh heap and mmap pages, a MAP_UNINITIALIZED request, the signal frame's FP
 * state byte for byte, the bytes after the auxv. */
#define _GNU_SOURCE
#include "../common.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <ucontext.h>
#include <unistd.h>
extern char **environ;
static uint64_t frame_hash; static size_t frame_len;
static void on_sig(int s, siginfo_t *si, void *uc) {
    (void)s; ucontext_t *u = uc;
    frame_hash = fnv_add(FNV0, si, sizeof *si);
#ifdef __x86_64__
    frame_hash = fnv_add(frame_hash, &u->uc_mcontext.gregs, sizeof u->uc_mcontext.gregs);
    if (u->uc_mcontext.fpregs) { frame_hash = fnv_add(frame_hash, u->uc_mcontext.fpregs, 512); frame_len = 512; }
    /* XSAVE header and beyond, as far as the frame claims */
    unsigned char *fp = (unsigned char *)u->uc_mcontext.fpregs;
    if (fp) { uint32_t magic1 = *(uint32_t *)(fp + 464), xsz = *(uint32_t *)(fp + 468 + 4);
        if (magic1 == 0x46505853u && xsz < 16384) { frame_hash = fnv_add(frame_hash, fp, xsz); frame_len = xsz; } }
#else
    /* the registers and the context records (FPSIMD and the rest), byte for byte */
    frame_hash = fnv_add(frame_hash, &u->uc_mcontext, sizeof u->uc_mcontext);
    frame_len = sizeof u->uc_mcontext;
#endif
}
static __attribute__((noinline)) uint64_t deep(int n) { volatile char pad[512]; for (int i = 0; i < 512; i++) pad[i] = (char)(n + i); return n ? deep(n - 1) + pad[3] : pad[7]; }
static __attribute__((noinline)) void below(const char *tag) {
    unsigned char *sp = (unsigned char *)__builtin_frame_address(0);
    printf("%s below-sp hash %016llx\n", tag, (unsigned long long)fnv_add(FNV0, sp - 60000, 60000 - 256));
}
int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = on_sig; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, 0);
    below("start");
    double x = 1.5; for (int i = 0; i < 10; i++) x *= 1.0001;
    raise(SIGUSR1);
    printf("frame len %zu hash %016llx x=%f\n", frame_len, (unsigned long long)frame_hash, x);
    below("after-signal");
    printf("deep %llu\n", (unsigned long long)deep(300));
    below("after-deep");
    unsigned char *m = malloc(1 << 20); printf("malloc fresh %016llx\n", (unsigned long long)fnv_add(FNV0, m, 1 << 20));
    unsigned char *s = malloc(100); printf("malloc small %016llx\n", (unsigned long long)fnv_add(FNV0, s, 100));
    unsigned char *p = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x4000000 /*MAP_UNINITIALIZED*/, -1, 0);
    printf("map_uninit %s %016llx\n", p == MAP_FAILED ? "fail" : "ok", p == MAP_FAILED ? 0ull : (unsigned long long)fnv_add(FNV0, p, 1 << 20));
    char **e = environ; while (*e) e++;
    unsigned long *av = (unsigned long *)(e + 1); int k = 0; while (av[2 * k]) k++;
    unsigned char *after = (unsigned char *)(av + 2 * k + 2);
    uintptr_t top = (uintptr_t)after; for (char **q = environ; *q; q++) if ((uintptr_t)*q > top) top = (uintptr_t)*q;
    top = (top + 4095) & ~(uintptr_t)4095;
    size_t len = top - (uintptr_t)after; if (len > 256) len = 256;
    printf("auxv entries %d after-auxv %zu %016llx\n", k, len, (unsigned long long)fnv_add(FNV0, after, len));
    hexline("after-auxv-head", after, len < 64 ? len : 64);
    return 0;
}
