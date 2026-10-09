/*
 * The character and positioning calls a C++ runtime makes on the standard
 * streams (libstdc++'s stdio_sync_filebuf: putc, getc, ungetc, fread,
 * fileno, fseeko64, ftello64), observed on a pipe and on a regular file:
 * `native_abi` runs this source natively (unlinked) and under the shim and
 * requires the same report. After each call the report records its answer
 * and the bytes that reached the pipe (FIONREAD), so a flush a call makes is
 * visible. The report goes to the original stdout descriptor at the end.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

int main(void) {
    int original = dup(1);
    int ends[2];
    if (original < 0 || pipe2(ends, O_NONBLOCK) != 0 || dup2(ends[1], 1) != 1) return 1;
    close(ends[1]);
    reader = ends[0];

    note("putc a", putc('a', stdout));
    arrived();
    note("fileno stdout", fileno(stdout));
    note("fileno stderr", fileno(stderr));
    errno = 0;
    note("getc stdout, output pending", getc(stdout));
    note("  errno", errno);
    arrived();
    note("ferror", ferror(stdout));
    clearerr(stdout);
    char byte;
    errno = 0;
    note("fread stdout", (long)fread(&byte, 1, 1, stdout));
    note("  errno", errno);
    note("fread nothing", (long)fread(&byte, 1, 0, stdout));
    clearerr(stdout);
    note("ungetc EOF", ungetc(EOF, stdout));
    note("putc b", putc('b', stdout));
    errno = 0;
    note("ftello64 on a pipe", (long)ftello64(stdout));
    note("  errno", errno);
    errno = 0;
    note("fseeko64 on a pipe", fseeko64(stdout, 0, SEEK_SET));
    note("  errno", errno);
    arrived();
    errno = 0;
    note("fseeko64 bad whence", fseeko64(stdout, 0, 42));
    note("  errno", errno);

    int file = memfd_create("stdio-chars", 0);
    if (file < 0 || fflush(stdout) != 0 || dup2(file, 1) != 1) return 1;
    note("fputs abc to a file", fputs("abc", stdout));
    note("ftello64, three bytes buffered", (long)ftello64(stdout));
    note("fseeko64 to 0", fseeko64(stdout, 0, SEEK_SET));
    note("ftello64", (long)ftello64(stdout));
    note("putc Z", putc('Z', stdout));
    note("ftello64, one byte buffered", (long)ftello64(stdout));
    note("fseeko64 SEEK_END", fseeko64(stdout, 0, SEEK_END));
    note("ftello64", (long)ftello64(stdout));
    note("fflush", fflush(stdout));
    char contents[8] = {0};
    note("pread", (long)pread(file, contents, sizeof contents - 1, 0));
    note(contents, 0);
    if (dup2(original, 1) != 1) return 1;

    return write(original, report, reported) == (ssize_t)reported ? 0 : 1;
}
