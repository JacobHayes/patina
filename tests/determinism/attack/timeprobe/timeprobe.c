/* Every clock, timer and timestamp the guest can reach, at start and after a 60-virtual-second
 * sleep. Nothing printed may correlate with wall time. */
#define _GNU_SOURCE
#include "../common.h"
#include <fcntl.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>
static void dump(const char *tag) {
    int clocks[] = {CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW,
                    CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM, CLOCK_TAI};
    for (unsigned i = 0; i < sizeof clocks / sizeof *clocks; i++) {
        struct timespec t = {0}, r = {0}; int a = clock_gettime(clocks[i], &t), b = clock_getres(clocks[i], &r);
        printf("%s clock %d %d %lld.%09ld res %d %ld\n", tag, clocks[i], a, (long long)t.tv_sec, t.tv_nsec, b, r.tv_nsec);
    }
    struct timeval tv; gettimeofday(&tv, 0); printf("%s gtod %lld.%06ld time %lld\n", tag, (long long)tv.tv_sec, (long)tv.tv_usec, (long long)time(0));
    struct tms tm; clock_t c = times(&tm); printf("%s times %ld %ld %ld\n", tag, (long)c, (long)tm.tms_utime, (long)tm.tms_stime);
    struct rusage ru; getrusage(RUSAGE_SELF, &ru); hexline("rusage", &ru, sizeof ru);
    struct sysinfo si; sysinfo(&si); printf("%s uptime %ld\n", tag, si.uptime);
    printf("%s rdtsc %llu\n", tag, (unsigned long long)__rdtsc());
    unsigned aux; printf("%s rdtscp %llu %u\n", tag, (unsigned long long)__rdtscp(&aux), aux);
    char b[256]; int fd = open("/proc/uptime", O_RDONLY); int n = read(fd, b, 255); b[n > 0 ? n : 0] = 0; close(fd); printf("%s /proc/uptime %s", tag, b);
    fd = open("/proc/self/stat", O_RDONLY); n = read(fd, b, 255); b[n > 0 ? n : 0] = 0; close(fd); printf("%s stat %s\n", tag, b);
    struct stat st; stat("/work/t", &st); hexline("work-stat", &st, sizeof st);
    stat("/usr/bin/true", &st); hexline("usr-stat", &st, sizeof st);
    fstat(1, &st); hexline("stdout-stat", &st, sizeof st);
    stat("/proc/self", &st); hexline("proc-self-stat", &st, sizeof st);
    stat("/dev/null", &st); hexline("devnull-stat", &st, sizeof st);
}
int main(void) {
    close(open("/work/t", O_CREAT | O_WRONLY, 0644));
    int tf = timerfd_create(CLOCK_REALTIME, 0); struct itimerspec it = {{0, 0}, {3600, 0}};
    timerfd_settime(tf, 0, &it, 0);
    dump("start");
    struct itimerspec cur; timerfd_gettime(tf, &cur); printf("timerfd left %lld.%09ld\n", (long long)cur.it_value.tv_sec, cur.it_value.tv_nsec);
    sleep(60);
    dump("after60");
    timerfd_gettime(tf, &cur); printf("timerfd left %lld.%09ld\n", (long long)cur.it_value.tv_sec, cur.it_value.tv_nsec);
    char *ct = ctime(&(time_t){time(0)}); printf("ctime %s", ct);
    return 0;
}
