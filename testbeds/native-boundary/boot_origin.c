#define _GNU_SOURCE
#include "patina_native.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif
#ifdef __linux__
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/timerfd.h>
#include <unistd.h>
#endif

/* Every call costs virtual time (and CPU time): a reading taken after
 * another is that one plus the calls charged between, never less and never
 * by much. */
#define SOON_AFTER(later, earlier) \
    assert((later) >= (earlier) && (later) - (earlier) < 100000)

static uint64_t now(clockid_t clock) {
    struct timespec ts;
    assert(clock_gettime(clock, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

int main(void) {
    uint64_t bootstrap, bootstrap_realtime;
    assert(patina_clock_now(PATINA_CLOCK_MONOTONIC, &bootstrap) == 0);
    assert(patina_clock_now(PATINA_CLOCK_REALTIME, &bootstrap_realtime) == 0);
    assert(patina_init_crash(3) == 0);
    const uint64_t start = now(CLOCK_MONOTONIC);
    SOON_AFTER(start, bootstrap);
    const uint64_t realtime = now(CLOCK_REALTIME);
    SOON_AFTER(realtime, bootstrap_realtime);
    assert(realtime - start - (bootstrap_realtime - bootstrap) < 100000);
    uint64_t cpu;
    assert(patina_cpu_time_nanos(&cpu) == 0);
    assert(start > 0 && cpu < start);
#ifdef __APPLE__
    SOON_AFTER(mach_absolute_time(), start);
#endif
#ifdef __linux__
    SOON_AFTER(now(CLOCK_PROCESS_CPUTIME_ID), cpu);
    SOON_AFTER(now(CLOCK_BOOTTIME), start);
    SOON_AFTER(now(CLOCK_MONOTONIC_RAW), start);
    struct timespec resolution;
    assert(clock_getres(CLOCK_MONOTONIC_COARSE, &resolution) == 0);
    const uint64_t coarse_tick = (uint64_t)resolution.tv_sec * 1000000000 + (uint64_t)resolution.tv_nsec;
    assert(coarse_tick > 0);
    const uint64_t coarse = now(CLOCK_MONOTONIC_COARSE);
    assert(coarse % coarse_tick == 0);
    SOON_AFTER(coarse, start / coarse_tick * coarse_tick);
    const uint64_t coarse_realtime = now(CLOCK_REALTIME_COARSE);
    /* The realtime epoch is what the bootstrap window read, before any call
     * was charged: the coarse realtime clock is it plus a tick-floored
     * monotonic reading. */
    assert((coarse_realtime - (bootstrap_realtime - bootstrap)) % coarse_tick == 0);
    SOON_AFTER(coarse_realtime, realtime / coarse_tick * coarse_tick);
    SOON_AFTER(now(CLOCK_THREAD_CPUTIME_ID), cpu);
    struct sysinfo info;
    assert(sysinfo(&info) == 0);
    assert((uint64_t)info.uptime == (now(CLOCK_MONOTONIC) + 999999999) / 1000000000);
    const long ticks_per_second = sysconf(_SC_CLK_TCK);
    assert(ticks_per_second > 0);
    const uint64_t cpu_tick = 1000000000 / (uint64_t)ticks_per_second;
    assert(cpu_tick > 0);
    const uint64_t before_ticks = now(CLOCK_BOOTTIME);
    const long ticks = syscall(SYS_times, NULL);
    // A tiny absolute deadline is in the past, not a relative sleep.
    struct timespec past = {0, 1};
    assert(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &past, NULL) == 0);
    SOON_AFTER(now(CLOCK_MONOTONIC), start);
#endif
    const uint64_t slept_from = now(CLOCK_MONOTONIC);
    const uint64_t slept_from_realtime = now(CLOCK_REALTIME);
    struct timespec delay = {0, 456789123};
    assert(nanosleep(&delay, NULL) == 0);
    SOON_AFTER(now(CLOCK_MONOTONIC) - slept_from, (uint64_t)delay.tv_nsec);
    SOON_AFTER(now(CLOCK_REALTIME) - slept_from_realtime, (uint64_t)delay.tv_nsec);
    // The sleep is not CPU time: only the calls' own charges.
    uint64_t cpu_after;
    assert(patina_cpu_time_nanos(&cpu_after) == 0);
    SOON_AFTER(cpu_after, cpu);
#ifdef __linux__
    SOON_AFTER(now(CLOCK_PROCESS_CPUTIME_ID), cpu);
    const uint64_t advanced = now(CLOCK_BOOTTIME);
    assert(sysinfo(&info) == 0);
    assert((uint64_t)info.uptime == (advanced + 999999999) / 1000000000);
    const long elapsed_ticks = syscall(SYS_times, NULL) - ticks;
    const long slept_ticks = (long)(advanced / cpu_tick - before_ticks / cpu_tick);
    assert(elapsed_ticks >= slept_ticks && elapsed_ticks - slept_ticks <= 1);
    int fd = (int)syscall(SYS_timerfd_create, CLOCK_BOOTTIME, 0);
    assert(fd >= 0);
    uint64_t deadline = advanced + 100;
    struct itimerspec timer = {{0, 0}, {(time_t)(deadline / 1000000000), (long)(deadline % 1000000000)}};
    assert(syscall(SYS_timerfd_settime, fd, TFD_TIMER_ABSTIME, &timer, NULL) == 0);
    uint64_t expirations = 0;
    assert(read(fd, &expirations, sizeof expirations) == sizeof expirations);
    assert(expirations == 1);
    SOON_AFTER(now(CLOCK_MONOTONIC), deadline);
    assert(close(fd) == 0);
#endif
    printf("BOOT_ORIGIN start=%llu realtime=%llu cpu=%llu\n",
           (unsigned long long)start, (unsigned long long)realtime, (unsigned long long)cpu);
    assert(patina_shutdown() == 0);
    return 0;
}
