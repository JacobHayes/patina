#include "patina_native.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * openat/renameat/unlinkat over the path-based deterministic filesystem. rustix
 * lowers its `fs` calls onto these; the shim models AT_FDCWD (a plain path) and
 * fails closed on a real dirfd. Deterministic by construction: a fixed seed and
 * a crash-free round-trip, so two same-seed runs are byte-identical.
 */
int main(int argc, char **argv) {
    uint64_t seed = argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 1;
    if (patina_init_crash(seed) != 0) return 10;
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 11;

    int fd = openat(AT_FDCWD, "/state/at", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 12;
    if (write(fd, "openat", 6) != 6) return 13;
    if (lseek(fd, 0, SEEK_SET) != 0) return 14;
    char contents[8] = {0};
    if (read(fd, contents, sizeof contents) != 6) return 15;
    if (memcmp(contents, "openat", 6) != 0) return 16;
    if (close(fd) != 0) return 17;

    /* A dirfd that names nothing is EBADF for a RELATIVE path, as the kernel
     * answers; an absolute path ignores the dirfd entirely (also the kernel's
     * rule), so the same bogus number with an absolute path resolves. */
    errno = 0;
    if (openat(99, "at", O_RDONLY) != -1 || errno != EBADF) return 18;
    fd = openat(99, "/state/at", O_RDONLY);
    if (fd < 0 || close(fd) != 0) return 18;

    /* renameat(AT_FDCWD, AT_FDCWD) routes to the deterministic rename. */
    if (renameat(AT_FDCWD, "/state/at", AT_FDCWD, "/state/at-renamed") != 0) return 19;
    errno = 0;
    if (renameat(99, "at-renamed", AT_FDCWD, "/x") != -1 || errno != EBADF) return 20;

    /* unlinkat with AT_REMOVEDIR removes a directory; without it, a file. */
    if (patina_mkdir(PATINA_AT_FDCWD, "/state/at-dir", 0777) != 0) return 21;
    if (unlinkat(AT_FDCWD, "/state/at-dir", AT_REMOVEDIR) != 0) return 22;
    if (unlinkat(AT_FDCWD, "/state/at-renamed", 0) != 0) return 23;
    if (patina_rmdir(PATINA_AT_FDCWD, "/state") != 0) return 24;

    /* printf is the shim's captured stdio now, not host stdio: print while the
     * context is live, then drain the capture to the real descriptors so the
     * harness can read it. */
    printf("NATIVE_OPENAT_RESULT seed=%" PRIu64 " contents=%s\n", seed, contents);
    if (patina_flush_captured_stdio() != 0) return 26;
    if (patina_shutdown() != 0) return 25;
    return 0;
}
