/* Per-call cost probes, timed from outside by the wall clock of whole runs.
 *   costs MODE N
 *     getppid      N x raw getppid            (class Pass)
 *     clock        N x clock_gettime(MONOTONIC) (class Virt; natively the vDSO)
 *     pipe         N x (write 1 byte; read 1 byte) on one pipe, one thread (class Attempt)
 *     futex-wake   N x FUTEX_WAKE on a word nobody waits on (uncontended futex)
 *     futex-pair   two threads ping-pong N times through two futex words (contended:
 *                  every round is a wait and a wake on each side)
 *     yield        N x sched_yield (a supervisor round trip under patina)
 * Static glibc; prints one line. N = 0 gives the fixed cost of the run. */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long fut(atomic_int *w, int op, int val)
{
	return syscall(SYS_futex, w, op, val, NULL, NULL, 0);
}

static atomic_int turn; /* 0: ping's turn, 1: pong's */
static long rounds;

static void *pong(void *a)
{
	(void)a;
	for (long i = 0; i < rounds; i++) {
		while (atomic_load(&turn) != 1) fut(&turn, FUTEX_WAIT_PRIVATE, 0);
		atomic_store(&turn, 0);
		fut(&turn, FUTEX_WAKE_PRIVATE, 1);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc < 3) return 2;
	const char *m = argv[1];
	long n = atol(argv[2]);
	long acc = 0;
	if (!strcmp(m, "getppid")) {
		for (long i = 0; i < n; i++) acc += syscall(SYS_getppid);
	} else if (!strcmp(m, "clock")) {
		struct timespec t;
		for (long i = 0; i < n; i++) { clock_gettime(CLOCK_MONOTONIC, &t); acc += t.tv_nsec & 1; }
	} else if (!strcmp(m, "pipe")) {
		int p[2];
		char c = 'x';
		if (pipe(p)) return 3;
		for (long i = 0; i < n; i++) {
			if (write(p[1], &c, 1) != 1 || read(p[0], &c, 1) != 1) return 4;
		}
	} else if (!strcmp(m, "futex-wake")) {
		static atomic_int w;
		for (long i = 0; i < n; i++) acc += fut(&w, FUTEX_WAKE_PRIVATE, 1);
	} else if (!strcmp(m, "futex-pair")) {
		rounds = n;
		pthread_t t;
		pthread_create(&t, NULL, pong, NULL);
		for (long i = 0; i < n; i++) {
			atomic_store(&turn, 1);
			fut(&turn, FUTEX_WAKE_PRIVATE, 1);
			while (atomic_load(&turn) != 0) fut(&turn, FUTEX_WAIT_PRIVATE, 1);
		}
		pthread_join(t, NULL);
	} else if (!strcmp(m, "yield")) {
		for (long i = 0; i < n; i++) sched_yield();
	} else {
		return 2;
	}
	printf("%s %ld %ld\n", m, n, acc);
	return 0;
}
