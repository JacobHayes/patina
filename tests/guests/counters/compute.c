/* counter preemption compute guests: work with few or no system calls, for counter preemption.
 *   compute MODE [SCALE [DIV]]   prints a checksum of the work (deterministic for a given MODE/SCALE)
 *     loops     nested integer loops with data-dependent branches
 *     recur     recursion (fib, ackermann, a recursive quicksort)
 *     indirect  calls through function-pointer tables and a switch jump table
 *     strings   memcpy/memset/memmove/strlen/strcmp/memchr on growing buffers (rep string
 *               instructions and vector code in glibc), and an inline rep movsb/stosb/cmpsb
 *               (x86_64; byte loops elsewhere)
 *     fp        floating point: double, long double (x87 on x86_64, binary128 on arm64), libm
 *               (sqrt, sin, exp, log)
 *     signals   a thread computing while another thread sends it SIGUSR1 every few ms of
 *               compute (handlers compute too), and an interval timer (SIGALRM)
 *     threads   16 threads computing, combining results under a mutex
 *     traps     SCALE x 100000 getppid calls (per-trap cost)
 *     bursts    SCALE x 2000 bursts of loop iterations, nine short (1150) then one long (2600),
 *               a getppid after each: with N between the two and the period just under the
 *               short ones, an overflow every few microseconds, more than the kernel lets
 *               through per tick before it throttles (stops) the event
 */
#define _GNU_SOURCE
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static long scale = 1, wdiv = 1;
static uint64_t mix(uint64_t h, uint64_t v) { h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2); return h; }

static uint64_t loops(long n)
{
	uint64_t h = 1, x = 88172645463325252ULL;
	for (long i = 0; i < n; i++) {
		for (int j = 0; j < 1000; j++) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			if (x & 1) h += x >> 3;
			else if (x & 2) h ^= x;
			else h = h * 31 + j;
		}
	}
	return h;
}

static uint64_t fib(int n) { return n < 2 ? (uint64_t)n : fib(n - 1) + fib(n - 2); }
static uint64_t ack(uint64_t m, uint64_t n)
{
	if (m == 0) return n + 1;
	if (n == 0) return ack(m - 1, 1);
	return ack(m - 1, ack(m, n - 1));
}
static void qs(uint32_t *a, long lo, long hi)
{
	if (lo >= hi) return;
	uint32_t p = a[(lo + hi) / 2];
	long i = lo, j = hi;
	while (i <= j) {
		while (a[i] < p) i++;
		while (a[j] > p) j--;
		if (i <= j) { uint32_t t = a[i]; a[i] = a[j]; a[j] = t; i++; j--; }
	}
	qs(a, lo, j); qs(a, i, hi);
}
static uint64_t recur(long n)
{
	uint64_t h = 0;
	for (long r = 0; r < n; r++) {
		h = mix(h, fib(24));
		h = mix(h, ack(2, 300));
		static uint32_t a[20000];
		uint32_t x = 2463534242u + r;
		for (int i = 0; i < 20000; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; a[i] = x; }
		qs(a, 0, 19999);
		h = mix(h, a[0] ^ a[9999] ^ a[19999]);
	}
	return h;
}

typedef uint64_t (*op_t)(uint64_t, uint64_t);
static uint64_t o0(uint64_t a, uint64_t b) { return a + b; }
static uint64_t o1(uint64_t a, uint64_t b) { return a ^ (b << 1); }
static uint64_t o2(uint64_t a, uint64_t b) { return a * 3 + b; }
static uint64_t o3(uint64_t a, uint64_t b) { return (a >> 1) | b; }
static uint64_t o4(uint64_t a, uint64_t b) { return a - b * 7; }
static op_t ops[5] = { o0, o1, o2, o3, o4 };
__attribute__((noinline)) static uint64_t sw(int k, uint64_t a)
{
	switch (k) {
	case 0: return a + 1; case 1: return a * 5; case 2: return a ^ 0x55; case 3: return a >> 3;
	case 4: return a << 2; case 5: return a - 9; case 6: return ~a; case 7: return a | 1;
	case 8: return a & 0xfff0; case 9: return a + 77; default: return a;
	}
}
static uint64_t indirect(long n)
{
	uint64_t h = 7, x = 12345;
	for (long i = 0; i < n * 200000; i++) {
		x = x * 6364136223846793005ULL + 1442695040888963407ULL;
		op_t f = ops[(x >> 33) % 5];
		h = f(h, x);
		h = sw((int)((x >> 40) % 11), h);
	}
	return h;
}

static uint64_t strings(long n)
{
	uint64_t h = 0;
	size_t cap = 1 << 20;
	char *a = malloc(cap), *b = malloc(cap);
	for (long r = 0; r < n * 4; r++) {
		for (size_t len = 1; len < cap; len = len * 3 + 1) {
			memset(a, 'a' + (int)(r % 26), len);
			a[len - 1] = 0;
			memcpy(b, a, len);
			memmove(b + 1, b, len - 1);
			h = mix(h, strlen(a));
			h = mix(h, (uint64_t)strcmp(a, b) + 3);
			h = mix(h, (uint64_t)(memchr(a, 0, len) ? 1 : 0));
			size_t k = len;
			char *d = b, *s = a;
#if defined(__x86_64__)
			__asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(k) : : "memory");
			k = len / 2; d = a;
			__asm__ volatile("rep stosb" : "+D"(d), "+c"(k) : "a"('z') : "memory");
			k = len; s = a; d = b;
			__asm__ volatile("repe cmpsb" : "+D"(d), "+S"(s), "+c"(k) : : "memory", "cc");
#else
			/* The same three operations as byte loops (no string instructions). */
			for (; k; k--) *(volatile char *)d++ = *s++;
			for (k = len / 2, d = a; k; k--) *(volatile char *)d++ = 'z';
			for (k = len, s = a, d = b; k;) { k--; if (*(volatile char *)s++ != *d++) break; }
#endif
			h = mix(h, k);
		}
	}
	free(a); free(b);
	return h;
}

static uint64_t fp(long n)
{
	double s = 0;
	long double l = 1;
	for (long i = 1; i < n * 300000; i++) {
		double x = (double)i * 0.001;
		s += sqrt(x) * sin(x) + exp(-x * 0.01) - log(x + 1);
		l = l * 1.0000001L + (long double)s * 1e-12L;
		if (s > 1e9) s = fmod(s, 1000.0);
	}
	uint64_t h;
	memcpy(&h, &s, 8);
	uint64_t h2 = (uint64_t)(l * 1000.0L);
	return mix(h, h2);
}

static volatile sig_atomic_t usr1, alrm;
static volatile uint64_t sigwork;
static void on_sig(int s)
{
	uint64_t x = sigwork;
	for (int i = 0; i < 5000; i++) x = x * 2862933555777941757ULL + 3037000493ULL + (x & 1 ? i : 0);
	sigwork = x;
	if (s == SIGUSR1) usr1++;
	else alrm++;
}
static pthread_t worker_t;
static volatile int done;
static void *sender(void *a)
{
	(void)a;
	uint64_t x = 1;
	while (!done) {
		for (int i = 0; i < 200000; i++) x = x * 6364136223846793005ULL + i;
		pthread_kill(worker_t, SIGUSR1);
	}
	return (void *)(uintptr_t)(x & 1);
}
static uint64_t signals(long n)
{
	signal(SIGUSR1, on_sig);
	signal(SIGALRM, on_sig);
	struct itimerval it = { { 0, 2000 }, { 0, 2000 } };
	setitimer(ITIMER_REAL, &it, NULL);
	worker_t = pthread_self();
	pthread_t t;
	pthread_create(&t, NULL, sender, NULL);
	uint64_t h = loops(n * 20);  /* n = 3000 x SCALE */
	done = 1;
	pthread_join(t, NULL);
	struct itimerval z = { { 0, 0 }, { 0, 0 } };
	setitimer(ITIMER_REAL, &z, NULL);
	/* how many signals arrived depends on the schedule: print it, keep it out of the checksum */
	fprintf(stderr, "usr1 %d alrm %d\n", (int)usr1, (int)alrm);
	return h;
}

static uint64_t bursts(long n)
{
	uint64_t h = 1, x = 88172645463325252ULL;
	for (long i = 0; i < n; i++) {
		/* nine short bursts, then a long one (about one branch per iteration) */
		int k = i % 10 == 9 ? 2600 : 1150;
		for (int j = 0; j < k; j++) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			h += x;
		}
		h += (uint64_t)syscall(SYS_getppid);
	}
	return h;
}

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t total;
static void *tw(void *a)
{
	long k = (long)(uintptr_t)a;
	uint64_t h = loops(scale * 3000 / wdiv + k % 3) ^ fib(18 + k % 4);
	pthread_mutex_lock(&mu);
	total += h;
	pthread_mutex_unlock(&mu);
	return NULL;
}
static uint64_t threads(void)
{
	pthread_t t[16];
	for (long i = 0; i < 16; i++) pthread_create(&t[i], NULL, tw, (void *)(uintptr_t)i);
	for (int i = 0; i < 16; i++) pthread_join(t[i], NULL);
	return total;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "loops";
	if (argc > 2) scale = atol(argv[2]);
	if (argc > 3) wdiv = atol(argv[3]); /* DIV divides the amount of work (small runs) */
	uint64_t h;
	if (!strcmp(m, "loops")) h = loops(scale * 100000 / wdiv);
	else if (!strcmp(m, "recur")) h = recur(scale * 150 / wdiv);
	else if (!strcmp(m, "indirect")) h = indirect(scale * 100 / wdiv);
	else if (!strcmp(m, "strings")) h = strings(scale * 1500 / wdiv);
	else if (!strcmp(m, "fp")) h = fp(scale * 60 / wdiv);
	else if (!strcmp(m, "signals")) h = signals(scale * 3000 / wdiv);
	else if (!strcmp(m, "threads")) h = threads();
	else if (!strcmp(m, "bursts")) h = bursts(scale * 2000 / wdiv);
	else if (!strcmp(m, "traps")) { h = 0; for (long i = 0; i < scale * 100000; i++) h += syscall(SYS_getppid); }
	else { fprintf(stderr, "unknown mode %s\n", m); return 2; }
	printf("%s %016llx\n", m, (unsigned long long)h);
	return 0;
}
