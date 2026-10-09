#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/timerfd.h>
#include <sys/syscall.h>
extern int __setitimer(int, const struct itimerval *, struct itimerval *);
extern int __getitimer(int, struct itimerval *);
extern int __timerfd_settime(int, int, const struct itimerspec *, struct itimerspec *);
extern int __timerfd_gettime(int, struct itimerspec *);
extern int ___timer_create(clockid_t, struct sigevent *, timer_t *);
extern int ___timer_delete(timer_t);
extern int ___timer_getoverrun(timer_t);
#if defined(__x86_64__)
extern int ___timer_settime_new(timer_t, int, const struct itimerspec *, struct itimerspec *);
extern int ___timer_gettime_new(timer_t, struct itimerspec *);
#define archive_settime ___timer_settime_new
#define archive_gettime ___timer_gettime_new
#else
extern int ___timer_settime64(timer_t, int, const struct itimerspec *, struct itimerspec *);
extern int ___timer_gettime64(timer_t, struct itimerspec *);
#define archive_settime ___timer_settime64
#define archive_gettime ___timer_gettime64
#endif
#endif

/* A timer's remaining time read back soon after arming it for `full`: that,
 * less the calls charged in between (each costs virtual time). */
#define LEFT_NS(left, full) ((left) <= (full) && (left) > (full) - 100000)
#define LEFT_US(left, full) ((left) <= (full) && (left) > (full) - 100)

static volatile sig_atomic_t alarms;
#ifdef __linux__
static int payload;
#endif
static void on_alarm(int sig, siginfo_t *info, void *context) {
    (void)context;
    assert(sig == SIGALRM);
#ifdef __linux__
    if (info->si_code == SI_TIMER) assert(info->si_value.sival_int == payload);
#else
    (void)info;
#endif
    ++alarms;
}
static void await_alarm(void) {
    struct timespec delay = { .tv_nsec = 2000000 };
    int before = alarms;
    int rc = nanosleep(&delay, NULL);
    assert(rc == -1 && errno == EINTR);
    assert(alarms == before + 1);
}
int main(int argc, char **argv) {
    if (argc > 1) {
#ifdef __linux__
        assert(strcmp(argv[1], "thread") == 0);
        struct sigevent event = { .sigev_notify = SIGEV_THREAD };
        timer_t id;
        timer_create(CLOCK_MONOTONIC, &event, &id);
#else
        struct itimerval value = {0};
        if (!strcmp(argv[1], "setitimer")) setitimer(ITIMER_REAL, &value, NULL);
        else if (!strcmp(argv[1], "getitimer")) getitimer(ITIMER_REAL, &value);
        else if (!strcmp(argv[1], "alarm")) alarm(1);
        else if (!strcmp(argv[1], "ualarm")) ualarm(1, 0);
        else assert(0);
#endif
        assert(0); /* Every unsupported path must refuse by name. */
    }
    struct sigaction action = { .sa_sigaction = on_alarm, .sa_flags = SA_SIGINFO };
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGALRM, &action, NULL) == 0);
    struct itimerval setting = { .it_value = { .tv_usec = 1000 } }, current;
    assert(setitimer(ITIMER_REAL, &setting, NULL) == 0);
    assert(getitimer(ITIMER_REAL, &current) == 0);
    assert(current.it_value.tv_sec == 0 && LEFT_US(current.it_value.tv_usec, 1000));
    await_alarm();
    assert(ualarm(1000, 0) == 0);
    await_alarm();
    assert(alarm(1) == 0);
    struct timespec second = { .tv_sec = 2 };
    assert(nanosleep(&second, NULL) == -1 && errno == EINTR);
    assert(alarms == 3);
#ifdef __linux__
    timer_t timer = (timer_t)(uintptr_t)UINT64_MAX;
    assert(timer_create(CLOCK_MONOTONIC, NULL, &timer) == 0);
    assert(timer == (timer_t)0); /* The full pointer-sized handle is written. */
    struct itimerspec spec = { .it_value = { .tv_nsec = 1000000 } }, got;
    assert(timer_settime(timer, 0, &spec, NULL) == 0);
    assert(timer_gettime(timer, &got) == 0);
    assert(LEFT_NS(got.it_value.tv_nsec, 1000000));
    await_alarm();
    assert(timer_getoverrun(timer) == 0);
    assert(timer_delete(timer) == 0);
    /* Static-archive aliases and the public/raw doors share the same state. */
    assert(__setitimer(ITIMER_REAL, &setting, NULL) == 0);
    assert(__getitimer(ITIMER_REAL, &current) == 0 && LEFT_US(current.it_value.tv_usec, 1000));
    assert(syscall(SYS_getitimer, ITIMER_REAL, &current) == 0 && LEFT_US(current.it_value.tv_usec, 1000));
    await_alarm();
    assert(___timer_create(CLOCK_MONOTONIC, NULL, &timer) == 0);
    assert(archive_settime(timer, 0, &spec, NULL) == 0);
    assert(archive_gettime(timer, &got) == 0 && LEFT_NS(got.it_value.tv_nsec, 1000000));
    await_alarm();
    assert(___timer_getoverrun(timer) == 0);
    assert(___timer_delete(timer) == 0);
    struct sigevent event = { .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGALRM,
        .sigev_value.sival_int = 73 };
    payload = 73;
    assert(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
    assert(timer_settime(timer, 0, &spec, NULL) == 0);
    await_alarm();
    assert(timer_delete(timer) == 0);
    errno = 0;
    assert(ualarm(1000000, 0) == (useconds_t)-1 && errno == EINVAL);
    errno = 0;
    assert(getitimer(-1, &current) == -1 && errno == EINVAL);
    errno = 0;
    assert(timer_gettime(timer, &got) == -1 && errno == EINVAL);
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    assert(fd >= 0);
    assert(timerfd_settime(fd, 0, &spec, NULL) == 0);
    assert(timerfd_gettime(fd, &got) == 0 && LEFT_NS(got.it_value.tv_nsec, 1000000));
    struct timespec delay = { .tv_nsec = 2000000 };
    assert(nanosleep(&delay, NULL) == 0);
    uint64_t ticks;
    assert(read(fd, &ticks, sizeof(ticks)) == sizeof(ticks) && ticks == 1);
    assert(__timerfd_settime(fd, 0, &spec, NULL) == 0);
    assert(__timerfd_gettime(fd, &got) == 0 && LEFT_NS(got.it_value.tv_nsec, 1000000));
    assert(nanosleep(&delay, NULL) == 0);
    assert(read(fd, &ticks, sizeof(ticks)) == sizeof(ticks) && ticks == 1);
    assert(close(fd) == 0);
    assert(alarms == 7);
#endif
    puts("LIBC_TIMERS_OK");
}
