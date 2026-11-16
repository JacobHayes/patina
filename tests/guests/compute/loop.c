/* loop N: N iterations of a load and an add between two CLOCK_MONOTONIC reads, no system call
 * between them; prints the nanoseconds between the reads (virtual under Patina). Built
 * instrumented (loop) and stock (loop-stock). */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long table[256];
static volatile long sink;

int main(int argc, char **argv)
{
	if (argc < 2) return 2;
	long n = atol(argv[1]);
	for (int i = 0; i < 256; i++) table[i] = i + argc; /* not a constant the compiler can fold */
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	long s = 0;
	for (long i = 0; i < n; i++) s += table[i & 255];
	sink = s;
	clock_gettime(CLOCK_MONOTONIC, &b);
	long long ns = (long long)(b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec);
	printf("loop %ld sum=%ld elapsed_ns=%lld\n", n, s, ns);
	return 0;
}
