/* Races whose window is straight-line code: no system call, loop, call or atomic inside it,
 * so only a switch inside a block reaches it (tests/rewrite/05-walks). An ordinary pthread
 * program, built stock. Two threads start together at a barrier; exit 1 when the race showed.
 *   lms      load/modify/store: each thread adds 1 to a shared counter 2000 times with a plain
 *            load and store; LOST-UPDATE when the total is short
 *   publish  a writer publishes a pointer to a struct before it fills the struct in; the
 *            reader, spinning on the pointer, sees HALF-INITIALISED fields
 *   dcl      double-checked initialisation that sets its flag one store too early; the thread
 *            that skips the lock sees UNINITIALISED data
 *   sys      no race: one thread makes short system calls in a loop, then blocks reading a pipe
 *            the other writes after a loop of its own; prints what it read (a walk that
 *            reaches a system call or the blocking read ends there)
 *   flags    no race: two threads save their flags (x86_64 `pushf`) in a loop and restore them
 *            later (`popf`); FLAGS-TRACED when a saved copy had the trap flag set (a walk that
 *            stepped the `pushf`). Elsewhere it only loops */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { ROUNDS = 2000 };

static pthread_barrier_t start;
static int mode;
static int bad;

static volatile long counter;
/* Reached through a pointer: the load and the store are short register-indirect forms, so
 * no instruction of the loop's block but its branch can carry a count (x86_64). */
static volatile long *volatile cp = &counter;

struct obj {
	volatile long a, b, c;
};
static struct obj *volatile shared;

static int pipefd[2];
static volatile long work;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int inited;
static struct {
	volatile long x, y;
} cfg;

static long get(void)
{
	if (!inited) {
		pthread_mutex_lock(&lock);
		if (!inited) {
			cfg.x = 40;
			inited = 1; /* the bug: published before y is set */
			cfg.y = 2;
		}
		pthread_mutex_unlock(&lock);
	}
	return cfg.x + cfg.y;
}

static void *run(void *arg)
{
	long me = (long)arg;
	pthread_barrier_wait(&start);
	switch (mode) {
	case 0: {
		volatile long *c = cp;
		for (int i = 0; i < ROUNDS; i++) {
			long v = *c; /* load */
			*c = v + 1;  /* store */
		}
		break;
	}
	case 1:
		if (me == 0) {
			struct obj *o = malloc(sizeof *o);
			shared = o; /* the bug: published before it is filled in */
			o->a = 1;
			o->b = 2;
			o->c = 3;
		} else {
			struct obj *p;
			while (!(p = shared))
				;
			if (p->a + p->b + p->c != 6)
				bad = 1;
		}
		break;
	case 2:
		if (get() != 42)
			bad = 1;
		break;
	case 4:
		for (int i = 0; i < ROUNDS; i++) {
			unsigned long f = 0;
#if defined(__x86_64__)
			__asm__ volatile("pushfq; popq %0" : "=r"(f));
			work = work + 1;
			__asm__ volatile("pushq %0; popfq" : : "r"(f) : "cc", "memory");
#endif
			if (f & 0x100)
				bad = 1;
		}
		break;
	case 3:
		if (me == 0) {
			char b = 0;
			for (int i = 0; i < 200; i++)
				syscall(SYS_getppid);
			if (read(pipefd[0], &b, 1) != 1 || b != 'x')
				bad = 1;
		} else {
			for (int i = 0; i < ROUNDS; i++)
				work = work + i;
			if (write(pipefd[1], "x", 1) != 1)
				bad = 1;
		}
		break;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";
	mode = !strcmp(m, "lms")       ? 0
	       : !strcmp(m, "publish") ? 1
	       : !strcmp(m, "dcl")     ? 2
	       : !strcmp(m, "sys")     ? 3
	       : !strcmp(m, "flags")   ? 4
	                               : -1;
	if (mode < 0 || pipe(pipefd)) {
		fprintf(stderr, "usage: rw-races lms|publish|dcl|sys|flags\n");
		return 2;
	}
	pthread_barrier_init(&start, 0, 2);
	pthread_t t[2];
	for (long i = 0; i < 2; i++)
		pthread_create(&t[i], 0, run, (void *)i);
	for (int i = 0; i < 2; i++)
		pthread_join(t[i], 0);
	if (mode == 0 && counter != 2 * ROUNDS) {
		printf("LOST-UPDATE: %ld of %d\n", counter, 2 * ROUNDS);
		return 1;
	}
	if (bad) {
		printf("%s\n", mode == 1 ? "HALF-INITIALISED" : mode == 2 ? "UNINITIALISED" : mode == 3 ? "SYS-FAILED" : "FLAGS-TRACED");
		return 1;
	}
	printf("ok\n");
	return 0;
}
