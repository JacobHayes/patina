/*
 * Mirror patina_posix.c's feature-test macros: on macOS `realpath` is asm-renamed
 * to `realpath$DARWIN_EXTSN` (the malloc-on-NULL variant Rust std/libc reference),
 * so the shim defines and the probe must call that same symbol -- without
 * _DARWIN_C_SOURCE the probe would bind the plain host `_realpath` and never
 * exercise the shim.
 */
#ifdef __linux__
#define _GNU_SOURCE 1
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "patina_native.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * realpath over the deterministic filesystem: std::fs::canonicalize reaches
 * realpath(path, NULL) on macOS (the allocating convention) and realpath(path,
 * buf) on Linux. Both must resolve an existing guest path -- including a
 * `..`/`.`/`//`-laden spelling of the same directory -- to the same canonical
 * absolute path, and the result must be byte-identical across two same-seed
 * runs. Before the runtime resolved paths itself the NULL convention returned ENOSYS.
 */
int main(int argc, char **argv) {
    uint64_t seed = argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 1;
    if (patina_init_crash(seed) != 0) return 10;
    if (patina_mkdir(PATINA_AT_FDCWD, "/root", 0777) != 0) return 11;
    if (patina_mkdir(PATINA_AT_FDCWD, "/root/fragments", 0777) != 0) return 12;

    char *allocated = realpath("/root/fragments", NULL);
    if (allocated == NULL) return 13;

    char buffer[PATH_MAX];
    char *filled = realpath("/root/../root/./fragments//", buffer);
    if (filled != buffer) return 14;

    if (strcmp(allocated, "/root/fragments") != 0) return 15;
    if (strcmp(allocated, filled) != 0) return 16;

    free(allocated);
    if (patina_rmdir(PATINA_AT_FDCWD, "/root/fragments") != 0) return 17;
    if (patina_rmdir(PATINA_AT_FDCWD, "/root") != 0) return 18;

    /* printf is the shim's captured stdio now, not host stdio: print while the
     * context is live, then drain the capture to the real descriptors so the
     * harness can read it. */
    printf("NATIVE_REALPATH_RESULT seed=%" PRIu64 " canonical=%s\n", seed, filled);
    if (patina_flush_captured_stdio() != 0) return 20;
    if (patina_shutdown() != 0) return 19;
    return 0;
}
