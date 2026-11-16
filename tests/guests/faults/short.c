/* short: copy 64 KiB through a file and a pipe, with correct transfer loops or with code
 * that assumes every read and write transfers the full count.
 *
 *   short correct | short naive
 *
 * Writes /work/src (a known pattern), copies it to /work/dst through a pipe, then compares.
 * Prints "copy OK" or "copy BAD (n bytes differ, size s)" and a checksum of dst.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE 65536
#define CHUNK 8192
static int naive;
static unsigned char pat[SIZE], got[SIZE];

static ssize_t wr(int fd, const void *b, size_t n) {
    if (naive) return write(fd, b, n);
    size_t done = 0;
    while (done < n) {
        ssize_t r = write(fd, (const char *)b + done, n - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return r;
        }
        done += r;
    }
    return done;
}

static ssize_t rd(int fd, void *b, size_t n) {
    if (naive) return read(fd, b, n);
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)b + done, n - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            return r;
        }
        if (r == 0) break;
        done += r;
    }
    return done;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    naive = argc > 1 && strcmp(argv[1], "naive") == 0;
    for (int i = 0; i < SIZE; i++) pat[i] = (unsigned char)(i * 7 + i / 251);
    int fd = open("src", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    for (int off = 0; off < SIZE; off += CHUNK) wr(fd, pat + off, CHUNK);
    close(fd);
    /* src -> pipe -> dst, one chunk at a time (the pipe holds a chunk) */
    int p[2];
    if (pipe(p) != 0) return 1;
    int in = open("src", O_RDONLY), out = open("dst", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    unsigned char buf[CHUNK];
    for (int off = 0; off < SIZE; off += CHUNK) {
        ssize_t n = rd(in, buf, CHUNK);
        if (n <= 0) break;
        wr(p[1], buf, n);
        ssize_t m = rd(p[0], buf, n);
        if (m <= 0) break;
        wr(out, buf, m);
    }
    close(in);
    close(out);
    fd = open("dst", O_RDONLY);
    ssize_t n = 0, r;
    while ((r = read(fd, got + n, SIZE - n)) > 0) n += r;
    close(fd);
    long diff = 0;
    unsigned long sum = 0;
    for (ssize_t i = 0; i < n; i++) sum = sum * 31 + got[i];
    for (int i = 0; i < SIZE; i++)
        if (i >= n || got[i] != pat[i]) diff++;
    if (n == SIZE && diff == 0)
        printf("copy OK (%zd bytes, sum %lx)\n", n, sum);
    else
        printf("copy BAD (%ld bytes differ, size %zd, sum %lx)\n", diff, n, sum);
    return 0;
}
