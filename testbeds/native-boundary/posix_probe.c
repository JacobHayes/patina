#include "patina_native.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char contents[8] = {0};
    if (patina_init_crash(7) != 0) return 10;
    if (patina_mkdir(PATINA_AT_FDCWD, "/state", 0777) != 0) return 11;
    int fd = open("/state/value", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 12;
    if (write(fd, "posix", 5) != 5) return 13;
    if (fsync(fd) != 0) return 14;
    if (lseek(fd, 0, SEEK_SET) != 0) return 15;
    if (read(fd, contents, sizeof contents) != 5) return 16;
    if (memcmp(contents, "posix", 5) != 0) return 17;
    if (ftruncate(fd, 3) != 0) return 18;
    if (close(fd) != 0) return 19;

    /* The descriptor table: lowest-free numbering, dup/dup2 sharing one open
     * file description, F_DUPFD bounded by RLIMIT_NOFILE, and the captured
     * streams being ordinary dup-able descriptors. */
    int base = open("/state/dup", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (base < 0) return 30;
    int duplicate = dup(base);
    if (duplicate != base + 1) return 32;
    if (write(base, "posix", 5) != 5) return 33;
    if (lseek(duplicate, 0, SEEK_CUR) != 5) return 34;
    if (dup2(base, 99) != 99 || lseek(99, 0, SEEK_CUR) != 5 || close(99) != 0) return 35;
    if (dup2(base, base) != base) return 36;
    errno = 0;
    if (fcntl(base, F_DUPFD, 1000000) != -1 || errno != EINVAL) return 37;
    int stdout_copy = dup(1);
    if (stdout_copy < 0 || close(stdout_copy) != 0) return 38;
    if (close(duplicate) != 0) return 39;
    if (write(base, "-more", 5) != 5) return 40;
    if (close(base) != 0) return 41;
    if (unlink("/state/dup") != 0) return 42;

    /* The deterministic environment starts empty, and the environment
     * functions are glibc's, over environ itself. Every assertion below checks
     * BOTH the getenv answer and the environ array, so a mutation that reached
     * only one of them fails here. */
    extern char **environ;
    if (environ == NULL || environ[0] != NULL) return 50;
    if (setenv("BETA", "2", 1) != 0) return 51;
    if (setenv("ALPHA", "1", 1) != 0) return 52;
    if (getenv("ALPHA") == NULL || strcmp(getenv("ALPHA"), "1") != 0) return 53;
    /* New names are appended (insertion order), NULL-terminated at the right
     * length, and getenv answers the entry's own bytes. */
    if (environ[0] == NULL || strcmp(environ[0], "BETA=2") != 0) return 54;
    if (environ[1] == NULL || strcmp(environ[1], "ALPHA=1") != 0) return 55;
    if (environ[2] != NULL) return 56;
    if (getenv("ALPHA") != environ[1] + 6) return 79;
    /* overwrite=0 leaves an existing value alone; overwrite=1 replaces the
     * entry in place. */
    if (setenv("ALPHA", "ignored", 0) != 0) return 57;
    if (strcmp(getenv("ALPHA"), "1") != 0) return 58;
    if (setenv("ALPHA", "3", 1) != 0) return 59;
    if (strcmp(getenv("ALPHA"), "3") != 0) return 60;
    if (strcmp(environ[1], "ALPHA=3") != 0) return 61;
    /* Malformed names are EINVAL (POSIX) and must not touch the array. */
    errno = 0;
    if (setenv("BAD=NAME", "x", 1) != -1 || errno != EINVAL) return 62;
    errno = 0;
    if (setenv("", "x", 1) != -1 || errno != EINVAL) return 63;
    if (environ[2] != NULL) return 64;
    /* unsetenv drops the name from both readers; an absent name succeeds. */
    if (unsetenv("ALPHA") != 0) return 65;
    if (getenv("ALPHA") != NULL) return 66;
    if (environ[0] == NULL || strcmp(environ[0], "BETA=2") != 0) return 67;
    if (environ[1] != NULL) return 68;
    if (unsetenv("NEVER_SET") != 0) return 69;
    /* putenv inserts the caller's own string, so a write through it changes
     * the environment, and a bare name removes that name. */
    {
#ifndef __APPLE__
        /* glibc guards putenv behind __USE_MISC/__USE_XOPEN, and
         * _POSIX_C_SOURCE alone sets neither, so declare it here (as for
         * clearenv below). Unlike clearenv, putenv DOES exist on macOS —
         * declared unconditionally there — so this guard is only about which
         * platform needs the declaration, not about where the function lives. */
        extern int putenv(char *);
#endif
        static char aliased[] = "GAMMA=3";
        static char bare[] = "BETA";
        if (putenv(aliased) != 0) return 70;
        if (getenv("GAMMA") != aliased + 6 || environ[1] != aliased) return 71;
        aliased[6] = '4';
        if (strcmp(getenv("GAMMA"), "4") != 0) return 72;
        if (putenv(bare) != 0 || getenv("BETA") != NULL) return 80;
        if (environ[0] != aliased || environ[1] != NULL) return 81;
    }
#ifndef __APPLE__
    /* clearenv (glibc/musl) leaves environ NULL.
     * _POSIX_C_SOURCE turns off _DEFAULT_SOURCE, so glibc does not declare it. */
    extern int clearenv(void);
    if (setenv("DELTA", "4", 1) != 0) return 73;
    if (clearenv() != 0) return 74;
    if (getenv("GAMMA") != NULL || getenv("DELTA") != NULL) return 75;
    if (environ != NULL) return 76;
#else
    if (unsetenv("GAMMA") != 0) return 77;
    if (environ[0] != NULL) return 78;
#endif

    if (rename("/state/value", "/state/renamed") != 0) return 20;
    if (unlink("/state/renamed") != 0) return 21;
    if (rmdir("/state") != 0) return 22;
    errno = 0;
    if (close(999) != -1 || errno != EBADF) return 23;
    if (patina_shutdown() != 0) return 24;
    return 0;
}
