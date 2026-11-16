/* Instrumented and stock code across images, built as `shlib` (instrumented) and
 * `shlib-stock` (stock), each linked against libcomp.so (instrumented) and libplain.so
 * (stock) and loading libcompdl.so (instrumented) with dlopen twice, closing it each time.
 * Its own loop runs in main. Prints the sums and "ok". */
#include <dlfcn.h>
#include <stdio.h>

long comp_work(long n);
long plain_work(long n);

#define N 5000
#define WANT 29992 /* the sum of (i * 7) % 13 for i < N */

int main(void)
{
	long own = 0;
	for (long i = 0; i < N; i++) own += (i * 7) % 13;
	long a = comp_work(N), b = plain_work(N), d[2] = {0, 0};
	for (int k = 0; k < 2; k++) {
		void *h = dlopen("libcompdl.so", RTLD_NOW);
		long (*f)(long) = h ? (long (*)(long))dlsym(h, "compdl_work") : 0;
		if (!f) {
			printf("dlopen: %s\n", dlerror());
			return 2;
		}
		d[k] = f(N);
		dlclose(h);
	}
	int ok = own == WANT && a == WANT && b == WANT && d[0] == WANT && d[1] == WANT;
	printf("own=%ld comp=%ld plain=%ld compdl=%ld,%ld %s\n", own, a, b, d[0], d[1], ok ? "ok" : "BAD");
	return !ok;
}
