/* LD_PRELOAD shim for the launcher (time variant, faketime-style skew): every clock the
 * launcher reads through libc is moved by SKEW_S seconds (default 3 years). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
static long skew(void) { const char *s = getenv("SKEW_S"); return s ? atol(s) : 94608000L; }
int clock_gettime(clockid_t c, struct timespec *t) {
    static int (*real)(clockid_t, struct timespec *);
    if (!real) real = dlsym(RTLD_NEXT, "clock_gettime");
    int r = real(c, t);
    if (r == 0) t->tv_sec += skew();
    return r;
}
int gettimeofday(struct timeval *tv, void *tz) {
    struct timespec t; clock_gettime(CLOCK_REALTIME, &t);
    if (tv) { tv->tv_sec = t.tv_sec; tv->tv_usec = t.tv_nsec / 1000; }
    return 0;
}
time_t time(time_t *p) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); if (p) *p = t.tv_sec; return t.tv_sec; }
