// files memory: 100k mmap/munmap of mixed sizes, mremap growth, brk grow and shrink,
// MADV_DONTNEED reading zeros and MADV_FREE refused. Prints every address so that runs with and
// without ASLR can be compared, and a hash over all of them.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint64_t h = 1469598103934665603ULL;
static void mix(uint64_t v) {
    for (int i = 0; i < 8; i++) {
        h ^= (v >> (i * 8)) & 0xff;
        h *= 1099511628211ULL;
    }
}

static uint64_t rng = 88172645463325252ULL;
static uint64_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

#define LIVE 64
int main(void) {
    const long pg = 4096;
    static const size_t sizes[] = {1, 4096, 8192, 12288, 65536, 1 << 20, 3 << 20, 2 << 20};
    void *live[LIVE] = {0};
    size_t lsz[LIVE] = {0};
    for (int i = 0; i < 100000; i++) {
        int s = next() % LIVE;
        if (live[s]) {
            if (munmap(live[s], lsz[s]) != 0) { printf("munmap failed at %d\n", i); return 1; }
            live[s] = 0;
        }
        size_t sz = sizes[next() % (sizeof sizes / sizeof *sizes)];
        int prot = (next() & 1) ? PROT_READ | PROT_WRITE : PROT_READ;
        void *p = mmap(0, sz, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { printf("mmap failed at %d\n", i); return 1; }
        if (prot & PROT_WRITE) ((volatile char *)p)[0] = (char)i;
        live[s] = p;
        lsz[s] = sz;
        mix((uint64_t)p);
        if (i % 10000 == 0) printf("addr %d %p %zu\n", i, p, sz);
    }
    for (int s = 0; s < LIVE; s++)
        if (live[s]) munmap(live[s], lsz[s]);
    printf("mmap hash %016llx\n", (unsigned long long)h);

    // mremap growth, moving and in place
    char *m = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(m, 'a', pg);
    printf("addr mremap0 %p\n", m);
    for (int i = 1; i <= 8; i++) {
        char *n = mremap(m, pg * (1L << (i - 1)), pg * (1L << i), MREMAP_MAYMOVE);
        if (n == MAP_FAILED) { printf("mremap failed %d\n", i); return 1; }
        printf("addr mremap%d %p first %c\n", i, n, n[0]);
        m = n;
    }
    char *fixed = mmap(0, pg * 4, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *moved = mremap(m, pg * 256, pg * 4, MREMAP_MAYMOVE | MREMAP_FIXED, fixed);
    printf("addr mremap-fixed %p == %p first %c\n", moved, fixed, moved[0]);
    munmap(moved, pg * 4);

    // brk grow and shrink
    char *b0 = sbrk(0);
    printf("addr brk0 %p\n", b0);
    for (int i = 0; i < 10; i++) {
        char *b = sbrk(1 << 16);
        memset(b, 'b', 1 << 16);
        mix((uint64_t)b);
    }
    printf("addr brk-grown %p\n", sbrk(0));
    sbrk(-(5 << 16));
    printf("addr brk-shrunk %p\n", sbrk(0));
    char *b1 = sbrk(1 << 16);
    printf("addr brk-regrow %p byte %d\n", b1, b1[100]);

    // madvise: anonymous private pages read zero after DONTNEED; after FREE they read either
    // the old data or zero natively (the kernel decides under memory pressure), and under
    // patina FREE is refused (EINVAL) and they keep the old data; print what is seen.
    char *d = mmap(0, pg * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(d, 7, pg * 4);
    printf("madvise dontneed %d", madvise(d, pg * 2, MADV_DONTNEED));
    printf(" -> %d %d %d\n", d[0], d[pg + 1], d[pg * 2]);
    memset(d, 7, pg * 4);
    printf("madvise free %d", madvise(d, pg * 2, MADV_FREE));
    printf(" -> %d %d %d\n", d[0], d[pg + 1], d[pg * 2]);
    d[0] = 9;
    printf("after write %d\n", d[0]);
    printf("hash %016llx\n", (unsigned long long)h);
    return 0;
}
