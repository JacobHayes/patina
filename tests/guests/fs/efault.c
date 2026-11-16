/* Bad and boundary pointers: each call is given a pointer it cannot use and must answer
 * EFAULT (never crash whoever answers it). Pointer kinds: a small dangling one (0x4, what
 * Rust passes for an empty slice), a page that was unmapped, an address in the range
 * Patina's runtime occupies (unmapped natively), a read-only page (outputs only), and an
 * object that runs off the end of a mapping. Raw system calls, so libc checks nothing.
 * Prints one line per case and exits 1 if any answer is not EFAULT. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int bad;
static char *page, *ro;

/* Kinds: 0 small, 1 unmapped, 2 runtime range, 3 read-only page, 4 crossing the end of a
 * mapping (`len` bytes, the last of them unmapped). */
static const char *kname[] = {"small", "unmapped", "rt-range", "read-only", "edge"};
static long ptr(int k, long len) {
    switch (k) {
    case 0: return 4;
    case 1: return (long)page + 4096;
    case 2: return 0x600000001000L;
    case 3: return (long)ro;
    default: return (long)page + 4096 - (len > 1 ? len / 2 : 1);
    }
}

static void expect(const char *name, int k, long r) {
    int e = r < 0 ? errno : 0;
    printf("%s %s: %ld %s\n", name, kname[k], r < 0 ? -1L : r, r < 0 ? strerrorname_np(e) : "ok");
    if (!(r == -1 && e == EFAULT)) bad = 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* page: one mapped page followed by an unmapped one; ro: a read-only page. */
    page = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || ro == MAP_FAILED || munmap(page + 4096, 4096)) return 2;
    memset(page, 'a', 4096); /* a path at the edge runs off the mapping, unterminated */
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd < 0) return 2;

    for (int k = 0; k < 5; k++) { /* outputs */
        expect("clock_gettime", k, syscall(SYS_clock_gettime, CLOCK_MONOTONIC, ptr(k, 16)));
        expect("gettimeofday", k, syscall(SYS_gettimeofday, ptr(k, 16), 0));
        expect("sysinfo", k, syscall(SYS_sysinfo, ptr(k, 112)));
        expect("getrusage", k, syscall(SYS_getrusage, 0, ptr(k, 144)));
        expect("rt_sigpending", k, syscall(SYS_rt_sigpending, ptr(k, 8), 8));
        expect("uname", k, syscall(SYS_uname, ptr(k, 390)));
        expect("stat", k, syscall(SYS_stat, "/", ptr(k, 144)));
        expect("statx", k, syscall(SYS_statx, AT_FDCWD, "/", 0, 0xfff, ptr(k, 256)));
        expect("pipe", k, syscall(SYS_pipe, ptr(k, 8)));
        if (k != 4) { /* these write less than they are given, or report a partial count */
            expect("sched_getaffinity", k, syscall(SYS_sched_getaffinity, 0, 128, ptr(k, 128)));
            expect("getrandom", k, syscall(SYS_getrandom, ptr(k, 16), 16, 0));
            expect("read-urandom", k, syscall(SYS_read, rnd, ptr(k, 16), 16));
            expect("getgroups", k, syscall(SYS_getgroups, 64, ptr(k, 256)));
        }
    }
    memset(page, 'a', 4096); /* the outputs above may have written into it */
    for (int k = 0; k < 5; k++) { /* inputs */
        if (k == 3) continue;
        expect("open", k, syscall(SYS_open, ptr(k, 16), O_RDONLY));
        expect("stat-path", k, syscall(SYS_stat, ptr(k, 16), page));
        expect("execve", k, syscall(SYS_execve, ptr(k, 16), 0, 0));
        expect("nanosleep", k, syscall(SYS_nanosleep, ptr(k, 16), 0));
        expect("rt_sigaction", k, syscall(SYS_rt_sigaction, SIGUSR1, ptr(k, 32), 0, 8));
        expect("poll", k, syscall(SYS_poll, ptr(k, 8), 1, 0));
        if (k != 4) /* the edge word straddles the end: aligned kinds only */
            expect("futex", k, syscall(SYS_futex, ptr(k, 4), FUTEX_WAIT, 0, 0, 0, 0));
    }
    char *argv_bad[] = {(char *)4, NULL};
    expect("execve-argv", 0, syscall(SYS_execve, "/bin/true", argv_bad, 0));
    expect("execve-argv", 1, syscall(SYS_execve, "/bin/true", page + 4096, 0));
    /* A size of 0 asks for the count only: the pointer is not used. */
    long n = syscall(SYS_getgroups, 0, 4);
    printf("getgroups(0, 0x4): %s\n", n > 0 ? "a count" : "FAILED");
    if (n <= 0) bad = 1;
    if (bad) {
        fprintf(stderr, "INVARIANT efault\n");
        return 1;
    }
    return 0;
}
