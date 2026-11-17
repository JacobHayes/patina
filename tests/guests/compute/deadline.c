/* Deadlines inside computation (rebuilt with compute points; no system call in its loops):
 *   deadline [MS]   arms ITIMER_REAL for MS ms (default 50) and computes until its handler sets
 *                   a flag; prints the virtual ns from before the arming to the handler and to
 *                   the loop's end, and exits 0 if the loop ran MS to MS*1.2 ms, else 1
 *   endless [MS]    sleeps MS ms (default 0), then computes forever (only --time-limit or
 *                   --timeout ends it)
 *   cpu N           N iterations, then prints the thread's and the process's CPU time (each
 *                   iteration is at least one event, so under Patina each is at least N ns)
 * The stock engine cannot end `deadline` except by compute-stall or --timeout: its clock does
 * not move while the loop runs. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static volatile sig_atomic_t flag;
static volatile long sink;
static long table[256];
static struct timespec at_handler;

static long long ns(struct timespec t) { return (long long)t.tv_sec * 1000000000LL + t.tv_nsec; }

static void on_alarm(int sig)
{
	(void)sig;
	clock_gettime(CLOCK_MONOTONIC, &at_handler);
	flag = 1;
}

int main(int argc, char **argv)
{
	if (argc < 2) return 2;
	for (int i = 0; i < 256; i++) table[i] = i + argc; /* not a constant the compiler can fold */
	long s = 0, i = 0;
	if (!strcmp(argv[1], "endless")) {
		long ms = argc > 2 ? atol(argv[2]) : 0;
		struct timespec z = {ms / 1000, (ms % 1000) * 1000000L};
		nanosleep(&z, NULL);
		for (;;) s += table[i++ & 255], sink = s;
	}
	if (!strcmp(argv[1], "cpu") && argc > 2) {
		long n = atol(argv[2]);
		for (i = 0; i < n; i++) s += table[i & 255];
		sink = s;
		struct timespec th, pr;
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &th);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &pr);
		printf("cpu %ld thread_ns=%lld process_ns=%lld\n", n, ns(th), ns(pr));
		return 0;
	}
	if (strcmp(argv[1], "deadline")) return 2;
	long ms = argc > 2 ? atol(argv[2]) : 50;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alarm;
	sigaction(SIGALRM, &sa, NULL);
	struct itimerval it = {{0, 0}, {ms / 1000, (ms % 1000) * 1000}};
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	setitimer(ITIMER_REAL, &it, NULL);
	while (!flag) s += table[i++ & 255];
	sink = s;
	clock_gettime(CLOCK_MONOTONIC, &b);
	long long loop = ns(b) - ns(a), handler = ns(at_handler) - ns(a), want = ms * 1000000LL;
	printf("deadline %ld ms: handler_ns=%lld loop_ns=%lld\n", ms, handler, loop);
	return loop >= want && loop <= want + want / 5 ? 0 : 1;
}
