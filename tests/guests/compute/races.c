/* Planted races: an ordinary pthread program, no Patina API.
 *   races a   check-then-act on a shared balance with a write(2) between check and act
 *   races b   the same with no system call in the window (as scope/experiments-dream/e2/bank.c)
 * Two threads start together at a barrier and each withdraws 100 from a balance of 100.
 * Exit 1 and "DOUBLE-SPEND" if both withdrew. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static long balance = 100, withdrawn;
static int mode_a;
static pthread_barrier_t start;

static void *withdraw(void *arg)
{
	(void)arg;
	pthread_barrier_wait(&start);
	if (balance >= 100) {                 /* check */
		if (mode_a && write(2, "", 0) < 0) /* a: a system call inside the window */
			return 0;
		long b = balance;                 /* act */
		balance = b - 100;
		withdrawn += 100;
	}
	return 0;
}

int main(int argc, char **argv)
{
	mode_a = argc > 1 && !strcmp(argv[1], "a");
	pthread_barrier_init(&start, 0, 2);
	pthread_t t[2];
	for (int i = 0; i < 2; i++) pthread_create(&t[i], 0, withdraw, 0);
	for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
	printf("balance=%ld withdrawn=%ld %s\n", balance, withdrawn, withdrawn > 100 ? "DOUBLE-SPEND" : "ok");
	return withdrawn > 100;
}
