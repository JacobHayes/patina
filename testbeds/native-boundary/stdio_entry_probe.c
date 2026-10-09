/*
 * Every character entry point glibc gives the standard streams beside
 * putc/getc — the `_unlocked` spellings, `_IO_putc`/`_IO_getc`, `fgetc`,
 * `putchar_unlocked`, and `__overflow`/`__uflow`, which the inline
 * `putc_unlocked`/`getc_unlocked` bodies call — and `ferror_unlocked`/
 * `feof_unlocked`, whose inline bodies read the stream's flags. `native_abi`
 * builds it at -O0 (calls) and -O2 (glibc's inline bodies), runs it natively
 * (unlinked) and under the shim on a pipe, and requires the same report.
 * It ends with glibc's internal lock spellings and `fclose(stdout)`, whose
 * flush reaches the pipe. argv[1] `getchar` reads stdin instead, `freopen`
 * reopens stdout and `foreign` writes to a stream fmemopen made: each a named
 * stop under the shim.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

extern int _IO_putc(int, FILE *);
extern int _IO_getc(FILE *);
extern void _IO_flockfile(FILE *);
extern void _IO_funlockfile(FILE *);

static int reader;
static char report[8192];
static size_t reported;

static void note(const char *what, long value) {
    int n = snprintf(report + reported, sizeof report - reported, "%s=%ld\n", what, value);
    if (n > 0) reported += (size_t)n;
}

static long pending(int fd) {
    int count = 0;
    return ioctl(fd, FIONREAD, &count) == 0 ? count : -1;
}

static void arrived(void) { note("  piped", pending(reader)); }

static void read_back(const char *what, int value) {
    note(what, value);
    note("  errno", errno);
    note("  ferror_unlocked", ferror_unlocked(stdout));
    note("  feof_unlocked", feof_unlocked(stdout));
    clearerr(stdout);
    errno = 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "getchar") == 0) {
        printf("getchar=%d\n", getchar());
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "freopen") == 0) {
        printf("freopen=%d\n", freopen("/dev/null", "w", stdout) != NULL);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "foreign") == 0) {
        static char memory[16];
        FILE *other = fmemopen(memory, sizeof memory, "w");
        printf("fputc=%d\n", other != NULL ? fputc('x', other) : -2);
        return 0;
    }
    int original = dup(1);
    int ends[2];
    if (original < 0 || pipe2(ends, O_NONBLOCK) != 0 || dup2(ends[1], 1) != 1) return 1;
    close(ends[1]);
    reader = ends[0];

    note("putc_unlocked a", putc_unlocked('a', stdout));
    note("fputc_unlocked b", fputc_unlocked('b', stdout));
    note("_IO_putc c", _IO_putc('c', stdout));
    note("putchar_unlocked d", putchar_unlocked('d'));
    note("putchar e", putchar('e'));
    note("__overflow f", __overflow(stdout, 'f'));
    arrived();
    note("__overflow EOF", __overflow(stdout, EOF));
    arrived();
    note("putc_unlocked g", putc_unlocked('g', stdout));
    errno = 0;
    read_back("getc_unlocked, output pending", getc_unlocked(stdout));
    arrived();
    read_back("fgetc", fgetc(stdout));
    read_back("fgetc_unlocked", fgetc_unlocked(stdout));
    read_back("_IO_getc", _IO_getc(stdout));
    read_back("__uflow", __uflow(stdout));
    note("ferror_unlocked after clearerr", ferror_unlocked(stdout));
    note("fflush", fflush(stdout));
    arrived();
    _IO_flockfile(stdout);
    note("putc_unlocked under _IO_flockfile h", putc_unlocked('h', stdout));
    _IO_funlockfile(stdout);
    note("fclose stdout", fclose(stdout));
    arrived();
    if (dup2(original, 1) != 1) return 1;

    return write(original, report, reported) == (ssize_t)reported ? 0 : 1;
}
