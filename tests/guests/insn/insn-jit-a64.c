/* The scanner's mapping paths for code the guest generates, arm64 (the twin of insn-jit.c,
 * built as `insn-jit` on arm64). The code is `yield; mrs x0, <reg>; ret`.
 * insn-jit [anon]: written into anonymous memory, made executable, run, with reg = CNTVCT_EL0.
 *   Not scanned (unscanned_exec_mappings >= 1), but the counter read is trapped wherever the code
 *   came from: the value is virtual, the same in every run of a seed.
 * insn-jit anon-rndr: the same with reg = RNDR: not patched, so it executes natively (SIGILL on
 *   a host without the instruction; the host's random value on one with it).
 * insn-jit file-mmap | file-mprotect | file-shared [rndr]: the code in a file under /tmp, mapped
 *   executable directly, mapped readable then made executable, or mapped shared. The first two
 *   are scanned and patched (the yield is a pause point; with `rndr`, the RNDR is answered from
 *   the seed); the shared one is not patched (a patch would write into the file) and is
 *   labelled.
 * insn-jit file-dontneed [rndr]: as file-mmap, run, then MADV_DONTNEED over the page (which drops
 *   the patched private copy: the file's bytes come back), and run again: patched both times. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MRS_CNTVCT_X0 0xd53be040u
#define MRS_RNDR_X0 0xd53b2400u

static uint32_t code[] = {0xd503203f /* yield */, MRS_CNTVCT_X0, 0xd65f03c0 /* ret */};

static unsigned char *from_file(const char *mode) {
    int fd = open("/tmp/code.bin", O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0 || write(fd, code, sizeof code) != sizeof code) return MAP_FAILED;
    unsigned char *p;
    if (!strcmp(mode, "file-mmap") || !strcmp(mode, "file-dontneed")) {
        p = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    } else if (!strcmp(mode, "file-shared")) {
        p = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    } else {
        p = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p != MAP_FAILED && mprotect(p, 4096, PROT_READ | PROT_EXEC)) return MAP_FAILED;
    }
    close(fd);
    return p;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "anon";
    int rndr = !strcmp(mode, "anon-rndr") || (argc > 2 && !strcmp(argv[2], "rndr"));
    if (rndr) code[1] = MRS_RNDR_X0;
    unsigned char *p;
    if (!strncmp(mode, "anon", 4)) {
        p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return 1;
        memcpy(p, code, sizeof code);
        __builtin___clear_cache((char *)p, (char *)p + sizeof code);
        if (mprotect(p, 4096, PROT_READ | PROT_EXEC)) return 2;
    } else {
        p = from_file(mode);
        if (p == MAP_FAILED) {
            perror(mode);
            return 3;
        }
    }
    uint64_t (*f)(void) = (uint64_t (*)(void))p;
    fflush(stdout);
    if (!strcmp(mode, "file-dontneed")) {
        uint64_t a = f();
        if (madvise(p, 4096, MADV_DONTNEED)) return 4;
        printf("%s %s %016llx %016llx\n", mode, rndr ? "rndr" : "cntvct", (unsigned long long)a,
               (unsigned long long)f());
        return 0;
    }
    printf("%s %s %016llx\n", mode, rndr ? "rndr" : "cntvct", (unsigned long long)f());
    return 0;
}
