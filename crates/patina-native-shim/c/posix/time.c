/*
 * Time: clocks, sleeps, and localtime_r.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

int clock_gettime(clockid_t clock_id, struct timespec *time) {
    patina_note_boundary_symbol("clock_gettime");
#ifdef __linux__
    /* Every Linux clock id is decoded once, in Rust, for both doors. */
    int64_t result = patina_clock_gettime((int)clock_id, time);
    if (result < 0) {
        errno = (int)-result;
        return -1;
    }
    return 0;
#else
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC
#ifdef __APPLE__
        || clock_id == CLOCK_UPTIME_RAW
#endif
    ) patina_clock = PATINA_CLOCK_MONOTONIC;
    else {
        errno = EINVAL;
        return -1;
    }
    uint64_t nanos = 0;
    if (patina_clock_now(patina_clock, &nanos) != 0) {
        errno = patina_errno();
        return -1;
    }
    time->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    time->tv_nsec = (long)(nanos % UINT64_C(1000000000));
    return 0;
#endif
}

/*
 * Whole-second CLOCK_REALTIME. Bundled C libraries reach for `time` where Rust
 * would use `SystemTime::now` (SQLite's `unixCurrentTime`/`unixRandomness` seed
 * themselves from it), and an uninterposed `time` reads the HOST clock, which
 * makes the run non-reproducible without any diagnostic. Answers from the same
 * virtual clock `gettimeofday` does, truncated the way the API defines.
 */
time_t time(time_t *out) {
    patina_note_boundary_symbol("time");
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_REALTIME, &nanos) != 0) {
        errno = patina_errno();
        return (time_t)-1;
    }
    time_t seconds = (time_t)(nanos / UINT64_C(1000000000));
    if (out != NULL) *out = seconds;
    return seconds;
}

int gettimeofday(struct timeval *restrict time, void *restrict zone) {
    patina_note_boundary_symbol("gettimeofday");
    (void)zone;
    uint64_t nanos = 0;
    if (patina_clock_now(PATINA_CLOCK_REALTIME, &nanos) != 0) {
        errno = patina_errno();
        return -1;
    }
    time->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    time->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / UINT64_C(1000));
    return 0;
}

static int patina_nanosleep(const struct timespec *duration, struct timespec *remaining) {
    if (duration == NULL || duration->tv_sec < 0 || duration->tv_nsec < 0 ||
        duration->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    uint64_t now = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &now) != 0) {
        errno = patina_errno();
        return -1;
    }
    uint64_t seconds = (uint64_t)duration->tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t delta = seconds * UINT64_C(1000000000) + (uint64_t)duration->tv_nsec;
    if (delta > UINT64_MAX - now) {
        errno = EOVERFLOW;
        return -1;
    }
    if (patina_sleep_until_remaining(PATINA_CLOCK_MONOTONIC, now + delta, (int64_t *)remaining) != 0) {
        errno = patina_errno();
        return -1;
    }
    if (remaining != NULL) memset(remaining, 0, sizeof *remaining);
    return 0;
}

int nanosleep(const struct timespec *duration, struct timespec *remaining) {
    return patina_nanosleep(duration, remaining);
}

#ifdef __linux__
/*
 * Rust's std::thread::sleep on Linux sleeps through clock_nanosleep rather
 * than nanosleep. Unlike nanosleep, this call returns the error number
 * directly and never sets errno. Darwin has no clock_nanosleep. glibc's
 * wrapper refuses the calling thread's CPU clock itself (EINVAL) and passes
 * everything else to the kernel row, which answers here from the one Rust
 * decode of the clock id.
 */
int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request,
                    struct timespec *remain) {
    if (clock_id == CLOCK_THREAD_CPUTIME_ID) return EINVAL;
    return (int)-patina_clock_nanosleep((int)clock_id, flags, request, remain);
}

#endif

/*
 * localtime_r: glibc's time zone over the virtual machine (src/localtime.rs):
 * TZ, read at the first call as glibc reads it, names a POSIX rule string or a
 * zoneinfo file; the machine ships no zoneinfo, so a name glibc cannot find a
 * file for answers what glibc answers then (UTC for an unset or empty TZ, the
 * rule string otherwise), and a zoneinfo file the guest put where glibc would
 * read it is a named refusal. A year past `int` is EOVERFLOW.
 */
struct tm *localtime_r(const time_t *timep, struct tm *result) {
    if (timep == NULL || result == NULL) {
        errno = EFAULT;
        return NULL;
    }
    struct patina_tm tm;
    if (patina_localtime((int64_t)*timep, patina_env_lookup("TZ"), patina_env_lookup("TZDIR"),
                         &tm) != 0) {
        errno = patina_errno();
        return NULL;
    }
    result->tm_sec = tm.sec;
    result->tm_min = tm.min;
    result->tm_hour = tm.hour;
    result->tm_mday = tm.mday;
    result->tm_mon = tm.mon;
    result->tm_year = tm.year;
    result->tm_wday = tm.wday;
    result->tm_yday = tm.yday;
    result->tm_isdst = tm.isdst;
    result->tm_gmtoff = (long)tm.gmtoff;
    result->tm_zone = (char *)tm.zone;
    return result;
}

/* sleep() is the whole-second face of the same interruptible sleep. POSIX
 * rounds a fractional unslept second up in its unsigned return value. */
unsigned int sleep(unsigned int seconds) {
    struct timespec duration = {(time_t)seconds, 0};
    struct timespec remaining = {0, 0};
    if (patina_nanosleep(&duration, &remaining) == 0) return 0;
    if (errno == EINTR)
        return (unsigned int)remaining.tv_sec + (remaining.tv_nsec != 0);
    return seconds;
}

#ifndef __linux__
/* Split a nanosecond count into a `struct timeval` (the Darwin getrusage; the
 * Linux rows fill theirs in Rust). All virtual CPU time is user time. */
static void patina_timeval_from_nanos(uint64_t nanos, struct timeval *out) {
    out->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    out->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / 1000);
}
#endif
