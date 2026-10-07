/*
 * Time: the clock seams that store into caller memory, and the sleeps an
 * acting cancellation surrounds. Clock and sleep calculation, Darwin's clocks
 * and localtime_r are Rust (src/posix/time.rs).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

#ifdef __linux__
/* glibc asks the vDSO, which answers the clocks the kernel keeps in user
 * space (patina_clock_in_vdso) and stores the answer there itself: so does
 * this store, outside every shim entry, so a time it cannot write faults here,
 * in the caller, as the guest's own SIGSEGV with the kernel's siginfo. The
 * vDSO hands every other clock to the system call, which answers EFAULT. */
static void patina_vdso_store(struct timespec *out, struct timespec value) {
    volatile struct timespec *target = out;
    target->tv_sec = value.tv_sec;
    target->tv_nsec = value.tv_nsec;
}

static int patina_clock_gettime_libc(clockid_t clock_id, struct timespec *time) {
    /* Every Linux clock id is decoded once, in Rust, for both doors. */
    struct timespec now;
    int vdso = patina_clock_in_vdso((int)clock_id);
    int64_t result = patina_clock_gettime((int)clock_id, vdso ? &now : time);
    if (result < 0) {
        errno = (int)-result;
        return -1;
    }
    if (vdso) patina_vdso_store(time, now);
    return 0;
}

int clock_gettime(clockid_t clock_id, struct timespec *time) {
    patina_note_boundary_symbol("clock_gettime");
    return patina_clock_gettime_libc(clock_id, time);
}

/* glibc's internal spelling (GLIBC_PRIVATE), which static archives built
 * against glibc call directly: the same clock. */
int __clock_gettime(clockid_t clock_id, struct timespec *time) {
    patina_note_boundary_symbol("__clock_gettime");
    return patina_clock_gettime_libc(clock_id, time);
}

/* The clock_getres row: the high-resolution clocks resolve to 1 ns, a NULL
 * `res` is not written, an unknown clock is EINVAL; the vDSO's clocks store
 * their resolution in user space, as clock_gettime's do. */
int clock_getres(clockid_t clock_id, struct timespec *res) {
    patina_note_boundary_symbol("clock_getres");
    struct timespec resolution;
    int vdso = patina_clock_in_vdso((int)clock_id);
    int64_t result = patina_clock_getres((int)clock_id, vdso ? &resolution : res);
    if (result < 0) {
        errno = (int)-result;
        return -1;
    }
    if (vdso && res != NULL) patina_vdso_store(res, resolution);
    return 0;
}
#endif

/* The realtime clock as whole seconds and microseconds (src/posix/time.rs);
 * 0, or -1 with errno set. The stores into caller memory stay here, outside
 * every shim entry, so a time the caller cannot take faults in the caller. */
extern int patina_time_of_day(int64_t *seconds, int64_t *micros);

/*
 * Whole-second CLOCK_REALTIME. Bundled C libraries reach for `time` where Rust
 * would use `SystemTime::now` (SQLite's `unixCurrentTime`/`unixRandomness` seed
 * themselves from it), and an uninterposed `time` reads the HOST clock, which
 * makes the run non-reproducible without any diagnostic. Answers from the same
 * virtual clock `gettimeofday` does, truncated the way the API defines.
 */
time_t time(time_t *out) {
    patina_note_boundary_symbol("time");
    int64_t seconds, micros;
    if (patina_time_of_day(&seconds, &micros) != 0) return (time_t)-1;
    if (out != NULL) *out = (time_t)seconds;
    return (time_t)seconds;
}

/* glibc's gettimeofday (sysdeps/unix/sysv/linux/gettimeofday.c): a time zone
 * it is given is zeroed, never the kernel's `sys_tz`; the time is the
 * realtime clock in microseconds. */
static int patina_gettimeofday(struct timeval *restrict time, void *restrict zone) {
    if (zone != NULL) memset(zone, 0, sizeof(struct timezone));
    int64_t seconds, micros;
    if (patina_time_of_day(&seconds, &micros) != 0) return -1;
    time->tv_sec = (time_t)seconds;
    time->tv_usec = (suseconds_t)micros;
    return 0;
}

int gettimeofday(struct timeval *restrict time, void *restrict zone) {
    patina_note_boundary_symbol("gettimeofday");
    return patina_gettimeofday(time, zone);
}

#ifdef __linux__
/* The IFUNC-resolved internal spelling static archives reach. */
int __gettimeofday(struct timeval *restrict time, void *restrict zone) {
    patina_note_boundary_symbol("__gettimeofday");
    return patina_gettimeofday(time, zone);
}
#endif

#ifdef __linux__
/* The sleep (src/posix/time.rs) inside the acting cancellation point. */
extern int patina_nanosleep(const struct timespec *duration, struct timespec *remaining);

int nanosleep(const struct timespec *duration, struct timespec *remaining) {
    PATINA_CANCEL_ENTER(outer);
    int rc = patina_nanosleep(duration, remaining);
    PATINA_CANCEL_LEAVE(outer);
    return rc;
}

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
    PATINA_CANCEL_ENTER(outer);
    int rc = (int)-patina_clock_nanosleep((int)clock_id, flags, request, remain);
    PATINA_CANCEL_LEAVE(outer);
    return rc;
}

/* sleep() is the whole-second face of the same interruptible sleep. POSIX
 * rounds a fractional unslept second up in its unsigned return value. */
unsigned int sleep(unsigned int seconds) {
    struct timespec duration = {(time_t)seconds, 0};
    struct timespec remaining = {0, 0};
    PATINA_CANCEL_ENTER(outer);
    int rc = patina_nanosleep(&duration, &remaining);
    PATINA_CANCEL_LEAVE(outer);
    if (rc == 0) return 0;
    if (errno == EINTR)
        return (unsigned int)remaining.tv_sec + (remaining.tv_nsec != 0);
    return seconds;
}
#endif
