#include "patina_native.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "%s failed (patina errno %d)\n", operation, patina_errno());
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    int use_env = argc == 2 && strcmp(argv[1], "env") == 0;
    uint64_t seed = use_env ? 123 : (argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 123);
    unsigned char random[16];
    uint64_t before = UINT64_MAX;
    uint64_t after = 0;
    char contents[16] = {0};

    if (!check((use_env ? patina_init_from_env() : patina_init_crash(seed)) == 0, "init") ||
        !check(patina_entropy(random, sizeof random) == 0, "entropy") ||
        !check(patina_clock_now(PATINA_CLOCK_MONOTONIC, &before) == 0, "clock before") ||
        !check(patina_sleep_until(PATINA_CLOCK_MONOTONIC, 5000000) == 0, "sleep") ||
        !check(patina_clock_now(PATINA_CLOCK_MONOTONIC, &after) == 0, "clock after") ||
        !check(patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) == 0, "mkdir")) return 1;

    int root = patina_openat(PATINA_AT_FDCWD, "/", PATINA_O_READ, 0);
    if (!check(root >= 0, "open root") ||
        !check(patina_fsync(root) == 0, "fsync root") ||
        !check(patina_close(root) == 0, "close root")) return 1;

    int fd = patina_openat(PATINA_AT_FDCWD, "/state/value", PATINA_O_READ | PATINA_O_WRITE |
        PATINA_O_CREATE | PATINA_O_TRUNCATE, 0666);
    if (!check(fd >= 0, "open") ||
        !check(patina_write(fd, "stable", 6) == 6, "stable write") ||
        !check(patina_fsync(fd) == 0, "fsync") ||
        !check(patina_write(fd, "-volatile", 9) == 9, "volatile write")) return 1;

    int dir = patina_openat(PATINA_AT_FDCWD, "/state", PATINA_O_READ, 0);
    if (!check(dir >= 0, "open dir") ||
        !check(patina_fsync(dir) == 0, "fsync dir") ||
        !check(patina_close(dir) == 0, "close dir") ||
        !check(patina_crash() == 0, "crash") ||
        !check(patina_seek(fd, 0, PATINA_SEEK_START) == 0, "seek surviving descriptor") ||
        !check(patina_read(fd, contents, sizeof contents) == 6, "read surviving descriptor") ||
        !check(memcmp(contents, "stable", 6) == 0, "surviving descriptor sees checkpoint") ||
        !check(patina_close(fd) == 0, "pre-crash descriptor survives")) return 1;

    memset(contents, 0, sizeof contents);
    fd = patina_openat(PATINA_AT_FDCWD, "/state/value", PATINA_O_READ, 0);
    if (!check(fd >= 0, "reopen") ||
        !check(patina_read(fd, contents, sizeof contents) == 6, "read checkpoint") ||
        !check(patina_close(fd) == 0, "close") ||
        !check(patina_rename(PATINA_AT_FDCWD, "/state/value", PATINA_AT_FDCWD, "/state/renamed") == 0, "rename") ||
        !check(patina_unlink(PATINA_AT_FDCWD, "/state/renamed") == 0, "unlink") ||
        !check(patina_rmdir(PATINA_AT_FDCWD, "/state") == 0, "rmdir") ||
        !check(patina_shutdown() == 0, "shutdown")) return 1;

    printf("NATIVE_SHIM_RESULT seed=%" PRIu64 " random=", seed);
    for (size_t i = 0; i < sizeof random; ++i) printf("%02x", random[i]);
    printf(" before=%" PRIu64 " after=%" PRIu64 " contents=%s\n", before, after, contents);
    return 0;
}
