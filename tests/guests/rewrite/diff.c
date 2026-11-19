// The rewriter's differential guest in C: library loops (qsort, snprintf, strlen), recursion, and
// four threads that add under a mutex and with atomics. Prints the same lines on every run.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 20000
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long locked, atomic_sum;

static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static void *work(void *arg)
{
	long id = (long)arg;
	for (int i = 0; i < 50000; i++) {
		pthread_mutex_lock(&mu);
		locked += id;
		pthread_mutex_unlock(&mu);
		__atomic_fetch_add(&atomic_sum, i % 7, __ATOMIC_SEQ_CST);
	}
	return NULL;
}

int main(void)
{
	static int a[N];
	unsigned x = 1;
	for (int i = 0; i < N; i++) {
		x = x * 1103515245 + 12345;
		a[i] = x % 100000;
	}
	qsort(a, N, sizeof a[0], cmp);
	long s = 0;
	char buf[64];
	for (int i = 0; i < N; i++) {
		snprintf(buf, sizeof buf, "%d:%x", a[i], a[i]);
		s += (long)strlen(buf) * a[i];
	}
	pthread_t t[4];
	for (long i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, work, (void *)(i + 1));
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	printf("sorted %d..%d sum %ld fib %ld\n", a[0], a[N - 1], s, fib(24));
	printf("locked %ld atomic %ld\n", locked, atomic_sum);
	return 0;
}
