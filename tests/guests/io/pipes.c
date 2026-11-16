/* Pipes between threads. A: 1-byte, 4096-byte and 1 MiB writes (the last force
 * partial blocking writes) checked byte for byte. B: the reader closes early, the writer
 * gets EPIPE (SIGPIPE ignored). C: the writer closes, the reader gets EOF. D: a FIFO opened
 * by two threads, both orders. */
#include "common.h"
#include <sys/stat.h>

static int pa[2];
static uint8_t pat(uint64_t i) { return (uint8_t)(i * 31 + 7 + (i >> 9)); }
enum { N1 = 1000, N4K = 100, NMB = 4, MB = 1 << 20 };
static uint64_t total_a = (uint64_t)N1 + (uint64_t)N4K * 4096 + (uint64_t)NMB * MB;

static void *prod_a(void *x) {
    (void)x;
    static uint8_t buf[MB];
    uint64_t pos = 0;
    for (int i = 0; i < N1; i++, pos++) {
        uint8_t b = pat(pos);
        CHECK(write(pa[1], &b, 1) == 1, "1-byte write");
    }
    for (int i = 0; i < N4K; i++) {
        for (int j = 0; j < 4096; j++) buf[j] = pat(pos + j);
        CHECK(write(pa[1], buf, 4096) == 4096, "4096-byte write");
        pos += 4096;
    }
    for (int i = 0; i < NMB; i++) {
        for (int j = 0; j < MB; j++) buf[j] = pat(pos + j);
        ssize_t r = write(pa[1], buf, MB);
        CHECK(r == MB, "1 MiB blocking write returned %zd", r);
        pos += MB;
    }
    CHECK(close(pa[1]) == 0, "close");
    return NULL;
}

static void *cons_a(void *x) {
    (void)x;
    static uint8_t buf[65536];
    uint64_t pos = 0, reads = 0;
    for (;;) {
        ssize_t r = read(pa[0], buf, sizeof buf);
        CHECK(r >= 0, "read");
        if (r == 0) break;
        reads++;
        for (ssize_t j = 0; j < r; j++) CHECK(buf[j] == pat(pos + j), "byte %llu wrong", (unsigned long long)(pos + j));
        pos += r;
    }
    CHECK(pos == total_a, "got %llu bytes", (unsigned long long)pos);
    return NULL;
}

static int pb[2];
static void *reader_b(void *x) {
    (void)x;
    char buf[10];
    CHECK(readn(pb[0], buf, 10) == 10, "read 10");
    CHECK(close(pb[0]) == 0, "close read end");
    return NULL;
}

static int pc[2];
static void *writer_c(void *x) {
    (void)x;
    CHECK(write(pc[1], "hello", 5) == 5, "write");
    CHECK(close(pc[1]) == 0, "close");
    return NULL;
}

static const char *FIFO = "/work/fifo";
static void *fifo_writer(void *x) {
    (void)x;
    int fd = open(FIFO, O_WRONLY);
    CHECK(fd >= 0, "open fifo for writing");
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0, "fifo writer left non-blocking");
    for (int i = 0; i < 3; i++) {
        char m[16];
        int n = snprintf(m, sizeof m, "msg%d;", i);
        CHECK(write(fd, m, n) == n, "fifo write");
    }
    CHECK(close(fd) == 0, "close");
    return NULL;
}
static void *fifo_reader(void *x) {
    char *out = x;
    int fd = open(FIFO, O_RDONLY);
    CHECK(fd >= 0, "open fifo for reading");
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0, "fifo reader left non-blocking");
    size_t got = 0;
    for (;;) {
        ssize_t r = read(fd, out + got, 63 - got);
        CHECK(r >= 0, "fifo read");
        if (r == 0) break;
        got += r;
    }
    out[got] = 0;
    CHECK(close(fd) == 0, "close");
    return NULL;
}

int main(void) {
    pthread_t t1, t2;
    signal(SIGPIPE, SIG_IGN);

    CHECK(pipe(pa) == 0, "pipe");
    CHECK(fcntl(pa[0], F_GETPIPE_SZ) == 65536, "pipe size");
    spawn(&t1, prod_a, NULL);
    spawn(&t2, cons_a, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    close(pa[0]);
    printf("A bytes=%llu ok\n", (unsigned long long)total_a);

    CHECK(pipe(pb) == 0, "pipe");
    spawn(&t1, reader_b, NULL);
    static char chunk[65536];
    uint64_t sent = 0;
    for (;;) {
        ssize_t r = write(pb[1], chunk, sizeof chunk);
        if (r < 0) {
            CHECK(errno == EPIPE, "expected EPIPE");
            break;
        }
        sent += r;
        CHECK(sent < (64u << 20), "no EPIPE after 64 MiB");
    }
    pthread_join(t1, NULL);
    close(pb[1]);
    printf("B epipe ok (at least 10 bytes sent: %d)\n", sent >= 10);

    CHECK(pipe(pc) == 0, "pipe");
    spawn(&t1, writer_c, NULL);
    char buf[16];
    ssize_t n = readn(pc[0], buf, sizeof buf);
    CHECK(n == 5 && memcmp(buf, "hello", 5) == 0, "short read %zd", n);
    CHECK(read(pc[0], buf, 1) == 0, "EOF");
    pthread_join(t1, NULL);
    close(pc[0]);
    printf("C eof after 5 bytes\n");

    CHECK(mkfifo(FIFO, 0600) == 0, "mkfifo");
    for (int order = 0; order < 2; order++) {
        char got[64];
        if (order == 0) {
            spawn(&t1, fifo_reader, got);
            spawn(&t2, fifo_writer, NULL);
        } else {
            spawn(&t2, fifo_writer, NULL);
            spawn(&t1, fifo_reader, got);
        }
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        CHECK(strcmp(got, "msg0;msg1;msg2;") == 0, "fifo got '%s'", got);
        printf("D fifo order %d: %s\n", order, got);
    }
    unlink(FIFO);
    printf("pipes ok\n");
    return 0;
}
