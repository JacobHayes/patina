/* determinism hardening attack guest: madvise advice values whose answer could depend on host memory
 * state, and memory contents after madvise/mremap/fork. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
static uint64_t fnv(const unsigned char *b, size_t n) { uint64_t h = 0xcbf29ce484222325ull; for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ull; } return h; }
int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 20;
    int adv[] = {MADV_HUGEPAGE, 25 /*COLLAPSE*/, MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_COLD, MADV_PAGEOUT,
                 MADV_MERGEABLE, MADV_UNMERGEABLE, MADV_NOHUGEPAGE, MADV_WIPEONFORK, MADV_KEEPONFORK, MADV_DONTDUMP,
                 MADV_SEQUENTIAL, MADV_WILLNEED, MADV_REMOVE, MADV_FREE, MADV_DONTNEED, 102, 103};
    for (int r = 0; r < rounds; r++) {
        size_t sz = 8 << 20;
        unsigned char *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        unsigned char *a = (unsigned char *)(((uintptr_t)p + (2 << 20) - 1) & ~((uintptr_t)(2 << 20) - 1));
        memset(a, r + 1, 4 << 20);
        printf("round %d", r);
        for (unsigned i = 0; i < sizeof adv / sizeof *adv; i++) {
            int x = madvise(a, 4 << 20, adv[i]);
            printf(" %d:%d", adv[i], x ? errno : 0);
            if (adv[i] == 25) printf("(%016llx)", (unsigned long long)fnv(a, 4 << 20));
        }
        printf(" h=%016llx\n", (unsigned long long)fnv(a, 4 << 20));
        munmap(p, sz);
    }
    /* mremap growth, fork contents */
    unsigned char *q = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(q, 7, 1 << 16);
    q = mremap(q, 1 << 16, 1 << 20, MREMAP_MAYMOVE);
    printf("mremap grow h=%016llx\n", (unsigned long long)fnv(q, 1 << 20));
    pid_t c = fork();
    if (c == 0) { memset(q, 9, 4096); printf("child h=%016llx\n", (unsigned long long)fnv(q, 1 << 20)); fflush(stdout); _exit(0); }
    int st; waitpid(c, &st, 0);
    printf("parent h=%016llx\n", (unsigned long long)fnv(q, 1 << 20));
    /* below the stack pointer */
    volatile unsigned char below[1]; unsigned char *sp = (unsigned char *)below;
    printf("below-sp h=%016llx\n", (unsigned long long)fnv(sp - 65536, 65536));
    return 0;
}
