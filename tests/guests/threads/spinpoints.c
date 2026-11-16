/* Spin-waits without a system call or `pause`, for the spin probe and compute-stall checks.
 *   spinpoints flag    a second thread waits for main by spinning on a flag (`while (!flag);`):
 *                      each iteration leaves its state unchanged, so a probe finds it
 *   spinpoints count   the same wait, counting its iterations in memory: no fixed point,
 *                      Patina cannot preempt it (compute-stall)
 *   spinpoints alone MS  one thread computes for about MS ms (no other thread): not a stall
 * The waiting thread starts spinning before main sets the flag: main waits for it with
 * sched_yield, and once it spins it holds the turn. Prints "done" when the wait ends. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int flag, started;
static volatile unsigned long count;

static void *waiter(void *a)
{
	int counting = *(int *)a;
	started = 1;
	if (counting)
		while (!flag) count++;
	else
		while (!flag) {}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc < 2) return 2;
	if (!strcmp(argv[1], "alone")) {
		long ms = argc > 2 ? atol(argv[2]) : 2000;
		unsigned long h = 88172645463325252UL;
		/* Sized by iterations (about MS ms on the measuring host): no clock read, no trap. */
		for (unsigned long n = (unsigned long)ms * 900000UL; n; n--) { h ^= h << 13; h ^= h >> 7; h ^= h << 17; }
		printf("alone %lx\n", h);
		return 0;
	}
	int counting = !strcmp(argv[1], "count");
	if (!counting && strcmp(argv[1], "flag")) return 2;
	pthread_t t;
	pthread_create(&t, NULL, waiter, &counting);
	while (!started) sched_yield();
	flag = 1;
	pthread_join(t, NULL);
	printf("done\n");
	return 0;
}
