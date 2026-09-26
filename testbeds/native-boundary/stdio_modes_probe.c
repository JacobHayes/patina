/*
 * glibc's buffering modes, observed on a pipe: `native_abi` runs this source
 * natively (unlinked) and under the shim and requires the same report. stdout
 * is redirected onto a non-blocking pipe; after each call the report records
 * the call's answer and the bytes that reached the pipe (FIONREAD), so every
 * flush a mode makes (or does not make) is visible. The report goes to the
 * original stdout descriptor directly at the end.
 *
 * Covered: setvbuf's three modes (before the first write, after writes, with
 * a caller's buffer, an unknown mode), setbuf, setlinebuf, line buffering
 * through printf/fputs/putchar (a message longer than printf's staging),
 * ferror/clearerr after a failed flush, flockfile/funlockfile nesting, and
 * setvbuf on stderr.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

static void drain(void) {
    char chunk[4096];
    while (read(reader, chunk, sizeof chunk) > 0) {
    }
}

int main(void) {
    static char message[300];
    static char caller[16];
    memset(message, 'x', sizeof message);
    message[50] = '\n';
    message[250] = '\n';
    message[sizeof message - 1] = '\0';

    int original = dup(1);
    int ends[2];
    if (original < 0 || pipe2(ends, O_NONBLOCK) != 0 || dup2(ends[1], 1) != 1) return 1;
    close(ends[1]);
    reader = ends[0];

    note("setvbuf _IOLBF before any write", setvbuf(stdout, NULL, _IOLBF, 0));
    note("printf a\\nb", printf("a\nb"));
    arrived();
    note("fputs c\\n", fputs("c\n", stdout));
    arrived();
    note("putchar d", putchar('d'));
    arrived();
    note("putchar \\n", putchar('\n'));
    arrived();
    note("printf 299 bytes, two lines", printf("%s", message));
    arrived();
    note("fflush", fflush(stdout));
    arrived();
    drain();

    note("setvbuf _IONBF", setvbuf(stdout, NULL, _IONBF, 0));
    note("printf xy", printf("xy"));
    arrived();
    note("setvbuf unknown mode", setvbuf(stdout, NULL, 42, 0) != 0);
    note("setvbuf _IOFBF, a 16-byte caller buffer", setvbuf(stdout, caller, _IOFBF, sizeof caller));
    note("fputs 10", fputs("0123456789", stdout));
    arrived();
    note("fputs 10", fputs("0123456789", stdout));
    arrived();
    note("printf 299 bytes", printf("%s", message));
    arrived();
    note("fflush", fflush(stdout));
    arrived();
    drain();

    setlinebuf(stdout);
    note("fputs q\\nr after setlinebuf", fputs("q\nr", stdout));
    arrived();
    setbuf(stdout, NULL);
    arrived();
    note("fputs s after setbuf NULL", fputs("s", stdout));
    arrived();
    drain();

    note("setvbuf _IOFBF", setvbuf(stdout, NULL, _IOFBF, 0));
    close(1);
    note("ferror before", ferror(stdout));
    note("printf z", printf("z"));
    errno = 0;
    note("fflush onto a closed descriptor", fflush(stdout));
    note("  errno", errno);
    note("ferror after", ferror(stdout));
    clearerr(stdout);
    note("ferror after clearerr", ferror(stdout));
    flockfile(stdout);
    flockfile(stdout);
    note("fputs under flockfile", fputs("t", stdout));
    funlockfile(stdout);
    funlockfile(stdout);
    if (dup2(original, 1) != 1) return 1;

    note("setvbuf stderr _IOFBF", setvbuf(stderr, NULL, _IOFBF, 0));
    int errors[2];
    int saved = dup(2);
    if (saved < 0 || pipe2(errors, O_NONBLOCK) != 0 || dup2(errors[1], 2) != 2) return 1;
    close(errors[1]);
    note("fputs stderr, now buffered", fputs("e", stderr));
    note("  piped", pending(errors[0]));
    note("fflush stderr", fflush(stderr));
    note("  piped", pending(errors[0]));
    if (dup2(saved, 2) != 2) return 1;

    return write(original, report, reported) == (ssize_t)reported ? 0 : 1;
}
