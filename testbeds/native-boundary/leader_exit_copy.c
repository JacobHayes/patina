/*
 * The main thread leaves by a raw exit (the thread row, not exit_group)
 * while a worker runs on. The worker's process_vm_readv of its own memory
 * by its own thread id copies, and by the exited leader's pid is ESRCH
 * (mm_access finds no memory behind the leader). Under a shim built with
 * planted-faults the leader's host thread is held after its exit
 * (patina_planted_hold_leader_exit), as a loaded host can leave it: the
 * answers are the same.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

__attribute__((weak)) void patina_planted_hold_leader_exit(void);

static atomic_int leaving;

static void pause_ms(long ms) {
    struct timespec request = {0, ms * 1000000L};
    nanosleep(&request, NULL);
}

/* One process_vm_readv of a byte by `pid`, reported as its result and errno. */
static int copy_by(long pid, char *line, size_t size, const char *label) {
    char source = 0x5a;
    char target = 0;
    struct iovec local = {&target, 1};
    struct iovec remote = {&source, 1};
    errno = 0;
    long copied = syscall(SYS_process_vm_readv, pid, &local, 1UL, &remote, 1UL, 0UL);
    int error = copied < 0 ? errno : 0;
    return snprintf(line, size, "LEADER_EXIT_COPY %s ret=%ld errno=%d copied=%d\n", label,
                    copied, error, target == source);
}

static void *worker(void *arg) {
    (void)arg;
    while (!atomic_load(&leaving)) {
        pause_ms(2);
    }
    pause_ms(40);
    char line[256];
    int length = copy_by(syscall(SYS_gettid), line, sizeof line, "by-tid");
    (void)!write(1, line, (size_t)length);
    length = copy_by(getpid(), line, sizeof line, "by-leader");
    (void)!write(1, line, (size_t)length);
    syscall(SYS_exit_group, 0);
    return NULL;
}

int main(void) {
    if (patina_planted_hold_leader_exit) {
        patina_planted_hold_leader_exit();
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 1;
    }
    atomic_store(&leaving, 1);
    syscall(SYS_exit, 0);
    return 1;
}
