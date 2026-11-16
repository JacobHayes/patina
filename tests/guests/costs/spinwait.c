/* cost measurement spin-wait patterns: which busy-waits survive scheduling only at system calls?
 *   spinwait MODE [ITERS]   two threads, ITERS (default 2000) lock/unlock rounds each
 *     glibc-spin   pthread_spin_lock (an unbounded spin inside libc), a getppid inside the
 *                  critical section
 *     own-spin     the same with this file's own atomic test-and-set spin lock (compiled
 *                  code, so a --mem build has memory-access points in the spin)
 *     own-spin-nocall  own spin lock, critical section with no system call
 *     bounded      own spin lock that calls sched_yield after 100 failed spins (the idiom of
 *                  Rust std, parking_lot, crossbeam and Go's lock2), getppid inside
 *     mutex        pthread_mutex (spins briefly, then futex), getppid inside
 * Prints the counter (must be 2 x ITERS). */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_spinlock_t gs;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int own;
static long counter, iters;
static int mode; /* 0 glibc-spin, 1 own-spin, 2 own-spin-nocall, 3 bounded, 4 mutex */

static void own_lock(int bounded)
{
	int spins = 0;
	while (atomic_exchange_explicit(&own, 1, memory_order_acquire)) {
		while (atomic_load_explicit(&own, memory_order_relaxed)) {
			__builtin_ia32_pause();
			if (bounded && ++spins >= 100) { spins = 0; sched_yield(); }
		}
	}
}
static void own_unlock(void) { atomic_store_explicit(&own, 0, memory_order_release); }

static void *worker(void *a)
{
	(void)a;
	for (long i = 0; i < iters; i++) {
		switch (mode) {
		case 0: pthread_spin_lock(&gs); counter += syscall(SYS_getppid) >= 0; pthread_spin_unlock(&gs); break;
		case 1: own_lock(0); counter += syscall(SYS_getppid) >= 0; own_unlock(); break;
		case 2: own_lock(0); counter++; own_unlock(); if ((i & 63) == 0) syscall(SYS_getppid); break;
		case 3: own_lock(1); counter += syscall(SYS_getppid) >= 0; own_unlock(); break;
		case 4: pthread_mutex_lock(&mu); counter += syscall(SYS_getppid) >= 0; pthread_mutex_unlock(&mu); break;
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	static const char *names[] = { "glibc-spin", "own-spin", "own-spin-nocall", "bounded", "mutex" };
	if (argc < 2) return 2;
	mode = -1;
	for (int i = 0; i < 5; i++) if (!strcmp(argv[1], names[i])) mode = i;
	if (mode < 0) return 2;
	iters = argc > 2 ? atol(argv[2]) : 2000;
	pthread_spin_init(&gs, PTHREAD_PROCESS_PRIVATE);
	pthread_t a, b;
	pthread_create(&a, NULL, worker, NULL);
	pthread_create(&b, NULL, worker, NULL);
	pthread_join(a, NULL);
	pthread_join(b, NULL);
	printf("%s counter=%ld\n", argv[1], counter);
	return counter == 2 * iters ? 0 : 1;
}
