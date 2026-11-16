/* A program that writes into its own compute-point cell, for tests/compute/03-inert.
 *   cellpoke scribble   two threads add to a total under a mutex while main writes 0, -1 and a
 *                       huge value into the cell between rounds: each run of a seed is the same
 *   cellpoke unmap      the same, then main unmaps the cell's page: the run ends compute-cell
 *   cellpoke drain      empties the cell forever: each emptying is charged as a full refill,
 *                       so at compute-gap=0 the run reaches its time limit
 * The cell's address comes from a second COMPUTE_HELLO (the hook file made the first). Outside
 * Patina that call fails and nothing is written. Prints the total. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long total;

static void *adder(void *a)
{
	long k = (long)a;
	for (long i = 0; i < 20000; i++) {
		pthread_mutex_lock(&mu);
		total += k + (i & 7);
		pthread_mutex_unlock(&mu);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) return 2;
	int unmap = !strcmp(argv[1], "unmap"), drain = !strcmp(argv[1], "drain");
	if (!unmap && !drain && strcmp(argv[1], "scribble")) return 2;
	long r = syscall(0x7061, 8L, 1L | 3L << 8, 0L);
	volatile long *cell = r > 0 ? (volatile long *)r : 0;
	if (drain) {
		if (!cell) return 1;
		for (;;) *cell = 0;
	}
	pthread_t t[2];
	for (long i = 0; i < 2; i++) pthread_create(&t[i], 0, adder, (void *)(i + 1));
	const long poke[] = { 0, -1, 0x7000000000000000L };
	for (int round = 0; round < 30; round++) {
		if (cell) *cell = poke[round % 3];
		pthread_mutex_lock(&mu);
		total += 1000;
		pthread_mutex_unlock(&mu);
	}
	if (unmap && cell) munmap((void *)cell, 4096);
	for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
	printf("total=%ld\n", total);
	return 0;
}
