/*
 * Time: clocks, sleeps, and the UTC-only localtime model.
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

int nanosleep(const struct timespec *duration, struct timespec *remaining) {
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
    if (patina_sleep_until(PATINA_CLOCK_MONOTONIC, now + delta) != 0) {
        errno = patina_errno();
        return -1;
    }
    if (remaining != NULL) memset(remaining, 0, sizeof *remaining);
    return 0;
}

#ifdef __linux__
/*
 * Rust's std::thread::sleep on Linux sleeps through clock_nanosleep rather
 * than nanosleep. Unlike nanosleep, this call returns the error number
 * directly and never sets errno. Darwin has no clock_nanosleep.
 */
int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request,
                    struct timespec *remain) {
    uint32_t patina_clock;
    if (clock_id == CLOCK_REALTIME) patina_clock = PATINA_CLOCK_REALTIME;
    else if (clock_id == CLOCK_MONOTONIC) patina_clock = PATINA_CLOCK_MONOTONIC;
    else return EINVAL;
    if ((flags & ~TIMER_ABSTIME) != 0) return EINVAL;
    if (request == NULL || request->tv_sec < 0 || request->tv_nsec < 0 ||
        request->tv_nsec >= 1000000000L) {
        return EINVAL;
    }
    uint64_t seconds = (uint64_t)request->tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) return EINVAL;
    uint64_t request_nanos = seconds * UINT64_C(1000000000) + (uint64_t)request->tv_nsec;
    uint64_t deadline = request_nanos;
    if ((flags & TIMER_ABSTIME) == 0) {
        uint64_t now = 0;
        if (patina_clock_now(patina_clock, &now) != 0) return patina_errno();
        if (request_nanos > UINT64_MAX - now) return EINVAL;
        deadline = now + request_nanos;
    }
    if (patina_sleep_until(patina_clock, deadline) != 0) return patina_errno();
    if (remain != NULL) memset(remain, 0, sizeof *remain);
    return 0;
}

#endif

/* The single fixed timezone the runtime models. A mutable static (not a string
 * literal) so it binds to `struct tm::tm_zone` whether the platform types that
 * field as `char *` (Darwin/BSD) or `const char *` (glibc) without a cast. */
static char patina_tm_zone_utc[] = "UTC";

/*
 * Broken-down UTC from a time_t, as a PURE function of the input seconds — no
 * host timezone database, /etc/localtime, or environment. The runtime models a
 * single fixed timezone (UTC): tm_gmtoff is 0 and tm_zone is "UTC" (the BSD/GNU
 * `struct tm` extension fields, visible here under _DARWIN_C_SOURCE/_GNU_SOURCE),
 * so a local-offset probe observes a zero offset and `now_local()` collapses
 * onto `now_utc()`. The civil-from-days decomposition is Howard Hinnant's
 * algorithm (proleptic Gregorian, whole time_t range), so identical seconds
 * always yield identical fields regardless of host locale or clock.
 */
static void patina_utc_from_time(time_t seconds, struct tm *out) {
    int64_t secs = (int64_t)seconds;
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int sec_of_day = (int)rem;
    out->tm_hour = sec_of_day / 3600;
    out->tm_min = (sec_of_day % 3600) / 60;
    out->tm_sec = sec_of_day % 60;
    /* 1970-01-01 was a Thursday (=4). Floor-mod into 0..6 with Sunday=0. */
    int wday = (int)(((days % 7) + 4) % 7);
    if (wday < 0) {
        wday += 7;
    }
    out->tm_wday = wday;
    /* days-from-civil inverse (epoch shifted to 0000-03-01 so leap days fall at
     * the end of the 400-year era). */
    int64_t z = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);                          /* [0, 146096] */
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; /* [0, 399]   */
    int64_t y = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100); /* [0, 365] */
    unsigned mp = (5 * doy + 2) / 153;                      /* [0, 11]  */
    unsigned d = doy - (153 * mp + 2) / 5 + 1;              /* [1, 31]  */
    unsigned m = mp < 10 ? mp + 3 : mp - 9;                 /* [1, 12]  */
    if (m <= 2) {
        y += 1;
    }
    out->tm_mday = (int)d;
    out->tm_mon = (int)m - 1;
    out->tm_year = (int)(y - 1900);
    static const int cumulative[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    int leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 1 : 0;
    out->tm_yday = cumulative[out->tm_mon] + (int)d - 1 + (out->tm_mon > 1 ? leap : 0);
    out->tm_isdst = 0;
    out->tm_gmtoff = 0;
    out->tm_zone = patina_tm_zone_utc;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
    if (timep == NULL || result == NULL) {
        errno = EFAULT;
        return NULL;
    }
    memset(result, 0, sizeof *result);
    patina_utc_from_time(*timep, result);
    return result;
}

/*
 * sleep(): the second-granularity blocking sleep (mimalloc's `mi_atomic_yield`
 * fallback issues `sleep(0)`). Route it through the virtual clock exactly like
 * nanosleep/usleep so it never blocks a real host thread. Always returns 0: under
 * virtual time the full interval elapses, so no seconds remain.
 */
unsigned int sleep(unsigned int seconds) {
    uint64_t now = 0;
    if (patina_clock_now(PATINA_CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    uint64_t delta = (uint64_t)seconds * UINT64_C(1000000000);
    if (delta <= UINT64_MAX - now) {
        (void)patina_sleep_until(PATINA_CLOCK_MONOTONIC, now + delta);
    }
    return 0;
}

/* Split a nanosecond count into a `struct timeval`. The CPU-time model attributes
 * ALL modeled time to user time (ru_utime); system time (ru_stime) stays 0 by
 * convention — the runtime does not partition guest work into user/kernel phases. */
static void patina_timeval_from_nanos(uint64_t nanos, struct timeval *out) {
    out->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
    out->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / 1000);
}
