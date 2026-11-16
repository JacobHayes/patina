/* instruction channels item 7 and the scanner's mapping paths.
 * insn-jit [anon]: write "rdrand eax; ret" into anonymous memory, make it executable, run it.
 *   The runtime does not scan anonymous executable memory: the value is the CPU's (it differs
 *   between runs) and the run is labelled with unscanned_exec_mappings >= 1.
 * insn-jit file-mmap | file-mprotect | file-shared: the same bytes in a file under /tmp, mapped
 *   executable directly, mapped readable then made executable, or mapped shared: the first two
 *   are scanned and patched (deterministic value); the shared one is not patched (a patch would
 *   write into the file) and is labelled. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const unsigned char code[] = {0x0f, 0xc7, 0xf0, 0xc3}; /* rdrand eax; ret */

static unsigned char *from_file(const char *mode) {
    int fd = open("/tmp/code.bin", O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0 || write(fd, code, sizeof code) != sizeof code) return MAP_FAILED;
    unsigned char *p;
    if (!strcmp(mode, "file-mmap")) {
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
    unsigned char *p;
    if (!strcmp(mode, "anon")) {
        p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return 1;
        memcpy(p, code, sizeof code);
        if (mprotect(p, 4096, PROT_READ | PROT_EXEC)) return 2;
    } else {
        p = from_file(mode);
        if (p == MAP_FAILED) {
            perror(mode);
            return 3;
        }
    }
    uint32_t (*f)(void) = (uint32_t (*)(void))p;
    printf("%s rdrand %08x\n", mode, f());
    return 0;
}
