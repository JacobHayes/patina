// files sparsemap: a database-style file (as bbolt keeps one): a small file mapped 2 GiB
// MAP_SHARED, grown to 1 GiB with ftruncate, two pages written through the mapping and
// synced, then shrunk to 64 KiB and grown again (the dropped range must read zeros), synced,
// and unmapped. Writes into a sparse file make it hold only what was written. Prints the
// file's allocated KiB and "sparsemap ok", or what was wrong.
//
// sparsemap cuts: a 16 MiB file written once, then 32 times mapped MAP_SHARED (Patina's copy of
// it holds every page) and unmapped in pieces: the head, a hole in the middle, then the two
// pieces left; the data reads back through each piece first.
// sparsemap many: 48 times a 1 GiB file mapped MAP_SHARED, one page written, unmapped.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAP (2UL << 30)
#define BIG (1UL << 30)

static int fail(const char *what) {
    printf("sparsemap: %s\n", what);
    return 1;
}

#define CUT (16UL << 20)
#define Q (CUT / 4)

static int cuts(void) {
    int fd = open("cut", O_RDWR | O_CREAT | O_TRUNC, 0600);
    static char buf[CUT];
    memset(buf, 'c', CUT);
    if (fd < 0 || pwrite(fd, buf, CUT, 0) != (ssize_t)CUT) return fail("cuts: create");
    for (int i = 0; i < 32; i++) {
        char *m = mmap(NULL, CUT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) return fail("cuts: mmap");
        for (int k = 0; k < 4; k++)
            if (m[k * Q + i] != 'c') return fail("cuts: data");
        if (munmap(m, Q) || munmap(m + 2 * Q, Q) || munmap(m + Q, Q) || munmap(m + 3 * Q, Q))
            return fail("cuts: munmap");
    }
    close(fd);
    printf("cuts ok\n");
    return 0;
}

static int many(void) {
    for (int i = 0; i < 48; i++) {
        int fd = open("many", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || ftruncate(fd, BIG)) return fail("many: create");
        char *m = mmap(NULL, BIG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) return fail("many: mmap");
        m[i * 4096] = 'x';
        if (munmap(m, BIG)) return fail("many: munmap");
        close(fd);
    }
    printf("many ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "cuts")) return cuts();
    if (argc > 1 && !strcmp(argv[1], "many")) return many();
    int fd = open("db", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, 32768) || pwrite(fd, "header", 6, 0) != 6) return fail("create");
    char *m = mmap(NULL, MAP, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) return fail("mmap");
    if (ftruncate(fd, BIG)) return fail("grow");
    memcpy(m + 4096, "page one", 8);
    memcpy(m + BIG / 2, "page two", 8);
    if (msync(m, BIG, MS_SYNC)) return fail("msync");
    if (ftruncate(fd, 65536) || ftruncate(fd, BIG)) return fail("shrink and grow");
    if (memcmp(m, "header", 6) || memcmp(m + 4096, "page one", 8)) return fail("data lost");
    char z[8] = {0};
    if (memcmp(m + BIG / 2, z, 8)) return fail("dropped page not zero");
    memcpy(m + BIG - 4096, "page three", 10);
    if (msync(m, BIG, MS_SYNC) || munmap(m, MAP)) return fail("msync or munmap");
    char b[10];
    if (pread(fd, b, 10, BIG - 4096) != 10 || memcmp(b, "page three", 10)) return fail("pread");
    struct stat st;
    if (fstat(fd, &st)) return fail("fstat");
    printf("allocated %ld KiB\nsparsemap ok\n", (long)st.st_blocks / 2);
    return 0;
}
