/* A spin lock on an exclusive pair (arm64 only; built -march=armv8-a -mno-outline-atomics, so
 * the atomics below are ldaxr/stxr loops, not single LSE instructions).
 *   llsc-spin xchg [ITERS]  test-and-set: the waiter's every attempt stores 1 over 1
 *   llsc-spin cas [ITERS]   compare-and-swap: the waiter's attempts leave the pair early
 * Two threads, ITERS (default 200) rounds each; the holder makes a system call inside the
 * critical section. No spin hint: only a spin probe makes the waiter yield. Prints the
 * counter (must be 2 x ITERS). */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int lock;
static long counter, iters;
static int cas;

static void acquire(void)
{
	if (cas) {
		int zero;
		do zero = 0;
		while (!__atomic_compare_exchange_n(&lock, &zero, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));
	} else {
		while (__atomic_exchange_n(&lock, 1, __ATOMIC_ACQUIRE)) {}
	}
}

static void *worker(void *a)
{
	(void)a;
	for (long i = 0; i < iters; i++) {
		acquire();
		counter += syscall(SYS_getppid) >= 0;
		__atomic_store_n(&lock, 0, __ATOMIC_RELEASE);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc < 2 || (strcmp(argv[1], "xchg") && strcmp(argv[1], "cas"))) return 2;
	cas = !strcmp(argv[1], "cas");
	iters = argc > 2 ? atol(argv[2]) : 200;
	pthread_t a, b;
	pthread_create(&a, NULL, worker, NULL);
	pthread_create(&b, NULL, worker, NULL);
	pthread_join(a, NULL);
	pthread_join(b, NULL);
	printf("%s counter=%ld\n", argv[1], counter);
	return counter == 2 * iters ? 0 : 1;
}
