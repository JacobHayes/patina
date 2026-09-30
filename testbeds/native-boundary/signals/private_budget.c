/* Class pairing: the private signal stack's per-level budget. Every trap's
 * kernel frame and dispatch, and every delivery's front handler, run on the
 * shim's private stack (src/thread/signals/frames.rs), which is a fixed
 * number of levels of one budget each: a trap from guest code lands at the
 * top of a level and everything the shim runs for it stays there, so the
 * depth stop is the handler count on every host, recording or not, only
 * while a level's use fits its budget. This guest (linked with a shim built
 * with `planted-faults`) fills the first three levels with a sentinel, then
 * makes syscalls (raw instructions on x86_64, which the syscall trap serves
 * on the private stack; glibc's `syscall(2)` elsewhere), takes a signal
 * whose handler makes them, and inside it a second one whose handler does,
 * and prints how much of each level was used:
 * `PRIVATE_BUDGET level=N used=A,B,C`. Run it recording. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int patina_planted_private_stack(uintptr_t *out);

#define SENTINEL 0x5a
#define LEVELS 3

static long sys(long nr, long a0, long a1, long a2, long a3) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
#else
    return syscall(nr, a0, a1, a2, a3);
#endif
}

/* One level's worth of syscalls, a file's included. */
static void calls(void) {
    unsigned char entropy[32];
    struct timespec now;
    static const char line[] = "private budget\n";
    assert(sys(SYS_getrandom, (long)entropy, sizeof entropy, 0, 0) == sizeof entropy);
    assert(sys(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&now, 0, 0) == 0);
    long fd = sys(SYS_openat, AT_FDCWD, (long)"/budget", O_CREAT | O_RDWR, 0600);
    assert(fd >= 0);
    assert(sys(SYS_write, fd, (long)line, sizeof line - 1, 0) == sizeof line - 1);
    assert(sys(SYS_close, fd, 0, 0, 0) == 0);
    assert(sys(SYS_sched_yield, 0, 0, 0, 0) == 0);
}

static void send(int sig) {
    assert(sys(SYS_tgkill, getpid(), sys(SYS_gettid, 0, 0, 0, 0), sig, 0) == 0);
}

static volatile sig_atomic_t inner_ran, outer_ran;
static void inner(int sig) {
    (void)sig;
    calls();
    inner_ran++;
}
static void outer(int sig) {
    (void)sig;
    calls();
    send(SIGUSR2);
    outer_ran++;
}

int main(void) {
    uintptr_t out[3];
    assert(patina_planted_private_stack(out) == 0);
    uintptr_t base = out[0], size = out[1], level = out[2];
    assert(LEVELS * level < size);
    unsigned char *top = (unsigned char *)(base + size);
    memset(top - LEVELS * level, SENTINEL, LEVELS * level);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    sigemptyset(&action.sa_mask);
    action.sa_handler = outer;
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    action.sa_handler = inner;
    assert(sigaction(SIGUSR2, &action, NULL) == 0);
    calls();
    send(SIGUSR1);
    assert(outer_ran == 1 && inner_ran == 1);

    printf("PRIVATE_BUDGET level=%zu used=", (size_t)level);
    for (int index = 0; index < LEVELS; index++) {
        unsigned char *low = top - (index + 1) * level;
        size_t first = 0;
        while (first < level && low[first] == SENTINEL) first++;
        printf("%s%zu", index ? "," : "", (size_t)(level - first));
    }
    puts("");
    return 0;
}
