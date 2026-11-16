/* A shared library for compute points, built as libcomp.so and libcompdl.so (instrumented,
 * each with its own copy of the hook file) and libplain.so (stock). LIB_work(n) runs a loop
 * of n steps on a thread of its own and returns its sum. C, and C++ for g++. */
#include <pthread.h>

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#ifdef __cplusplus
extern "C" long CAT(LIB, _work)(long n);
#endif

static void *loop(void *arg)
{
	long n = *(long *)arg, s = 0;
	for (long i = 0; i < n; i++) s += (i * 7) % 13;
	*(long *)arg = s;
	return 0;
}

long CAT(LIB, _work)(long n)
{
	pthread_t t;
	if (pthread_create(&t, 0, loop, &n)) return -1;
	pthread_join(t, 0);
	return n;
}
