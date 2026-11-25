/* marks MODE: SDK marks whose labels `patina inspect events` shows in clear.
 *   edge     a 255-byte label; a label with a newline, a quote, a backslash, a byte that is not
 *            UTF-8 and a NUL; a mark with text; a payload ending at the end of a mapping;
 *            payloads at a bad pointer and across the end of a mapping (EFAULT, no label).
 *            Prints each raw call's answer.
 *   threads  two threads and a forked child mark "t1 I", "t2 I", "child I". */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "patina.h"

/* A mark built by hand at `buf`: any bytes, any text. */
static long raw_mark(unsigned char *buf, const void *label, size_t ll, const char *text, size_t tl) {
    uint16_t l16 = (uint16_t)ll;
    uint32_t t32 = (uint32_t)tl;
    memset(buf, 0, 32);
    buf[0] = PATINA_KIND_REACHABLE;
    memcpy(buf + 2, &l16, 2);
    memcpy(buf + 4, &t32, 4);
    memcpy(buf + 32, label, ll);
    if (tl) memcpy(buf + 32 + ll, text, tl);
    return patina__sys(PATINA_OP_MARK, buf, 32 + ll + tl);
}

static void *marker(void *arg) {
    char label[16];
    for (int i = 0; i < 5; i++) {
        snprintf(label, sizeof label, "%s %d", (const char *)arg, i);
        patina_mark(label);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *m = argc > 1 ? argv[1] : "";
    if (!patina_is_simulated()) return 3;
    if (!strcmp(m, "edge")) {
        static unsigned char buf[32 + PATINA_LABEL_MAX + PATINA_TEXT_MAX];
        char big[PATINA_LABEL_MAX + 1];
        for (int i = 0; i < PATINA_LABEL_MAX; i++) big[i] = (char)('0' + i % 10);
        big[PATINA_LABEL_MAX] = 0;
        patina_mark(big);
        static const char odd[] = "a\nb\"c\\d\xff\0e";
        printf("odd %ld\n", raw_mark(buf, odd, sizeof odd - 1, 0, 0));
        printf("text %ld\n", raw_mark(buf, "with-text", 9, "some text", 9));
        long pg = sysconf(_SC_PAGESIZE);
        unsigned char *map = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || munmap(map + pg, pg)) return 2;
        /* The payload's last byte is the mapping's last. */
        printf("end %ld\n", raw_mark(map + pg - 32 - 7, "at-end!", 7, 0, 0));
        printf("bad %ld\n", patina__sys(PATINA_OP_MARK, (void *)8, 40));
        /* Two bytes past the end of the mapping. */
        unsigned char *p = map + pg - 32 - 5;
        uint16_t l16 = 7;
        memset(p, 0, 32);
        p[0] = PATINA_KIND_REACHABLE;
        memcpy(p + 2, &l16, 2);
        printf("across %ld\n", patina__sys(PATINA_OP_MARK, p, 32 + 7));
        return 0;
    }
    if (!strcmp(m, "threads")) {
        pid_t c = fork();
        if (c == 0) {
            marker("child");
            _exit(0);
        }
        pthread_t a, b;
        pthread_create(&a, 0, marker, "t1");
        pthread_create(&b, 0, marker, "t2");
        pthread_join(a, 0);
        pthread_join(b, 0);
        int st;
        waitpid(c, &st, 0);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 3;
    }
    fprintf(stderr, "usage: marks edge|threads\n");
    return 2;
}
