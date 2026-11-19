/* Spin-waits without a system call or `pause`, for the spin probe and compute-stall checks.
 *   spinpoints flag    a second thread waits for main by spinning on a flag (`while (!flag);`):
 *                      each iteration leaves its state unchanged, so a probe finds it
 *   spinpoints count   the same wait, counting its iterations in memory: no fixed point,
 *                      Patina cannot preempt it (compute-stall)
 *   spinpoints memcount  the same, but each iteration leaves the registers as they were: only
 *                      the counter in memory changes (compute-stall; found only if a probe
 *                      missed the write)
 *   spinpoints nested N  the flag wait with a bounded delay loop of N passes in each iteration
 *                      (`while (!flag) for (i = 0; i < N; i++);`): the inner loop's counter
 *                      changes, the outer loop's state does not, so a probe finds the outer
 *                      loop wherever it arrives
 *   spinpoints text N  N rounds of the flag wait, each a new thread found by a probe; the
 *                      checksum of every executable segment (the program's and its
 *                      libraries') is taken before and after each round and must not change
 *                      (no planted breakpoint is left in code once a probe has ended).
 *                      Prints "text same after N rounds"
 *   spinpoints twice   the waiter spins on a first flag, then at once on a second (no system
 *                      call between: two spin points in a row); then main runs the same two
 *                      loops itself with both flags set (no planted breakpoint may be left in
 *                      the first). Prints "twice done"
 *   spinpoints jit     JIT-style code: a second thread runs a branch to itself in anonymous
 *                      writable, executable memory; once it spins, main signals it, and
 *                      the handler (on the spinning thread) patches the branch into a no-op,
 *                      so the code returns. A breakpoint planted there and restored after the
 *                      handler would undo the patch. Prints "jit patched"
 *   spinpoints alone MS  one thread computes for about MS ms (no other thread): not a stall
 *   spinpoints wander MS  the same along a path that never repeats (each pass calls one of two
 *                      functions, picked by a pseudo-random bit): every probe gives up at its
 *                      trace limit (for the cost of such a probe)
 * The waiting thread starts spinning before main sets the flag: main waits for it with
 * sched_yield, and once it spins it holds the turn. Prints "done" when the wait ends. */
#define _GNU_SOURCE
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int flag, started;
static volatile unsigned long count;
static int mode; /* 0 flag, 1 count, 2 memcount, 3 nested */
static int inner;

static volatile unsigned long acc;
static __attribute__((noinline)) void wa(void) { acc += 1; }
static __attribute__((noinline)) void wb(void) { acc ^= 3; }

static volatile int flag2, stage;

/* Two spin-waits in a row, no system call between. */
static __attribute__((noinline)) void two_waits(void)
{
	while (!flag) {}
	stage = 2;
	while (!flag2) {}
}

static void *two(void *a)
{
	(void)a;
	started = 1;
	two_waits();
	return NULL;
}

static void *waiter(void *a)
{
	(void)a;
	started = 1;
	if (mode == 1)
		while (!flag) count++;
	else if (mode == 2)
		while (!flag) {
			/* count += 1 through a register that is zeroed again */
#if defined(__x86_64__)
			__asm__ volatile("movq %0, %%rax\n\tincq %%rax\n\tmovq %%rax, %0\n\txorl %%eax, %%eax" : "+m"(count) : : "rax", "cc");
#else
			__asm__ volatile("ldr x9, %0\n\tadd x9, x9, #1\n\tstr x9, %0\n\tmov x9, #0" : "+m"(count) : : "x9");
#endif
		}
	else if (mode == 3)
		while (!flag)
			for (volatile int i = 0; i < inner; i++) {}
	else
		while (!flag) {}
	return NULL;
}

static void wait_once(void)
{
	pthread_t t;
	flag = started = 0;
	pthread_create(&t, NULL, waiter, NULL);
	while (!started) sched_yield();
	flag = 1;
	pthread_join(t, NULL);
}

static int sum_seg(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	uint64_t *sum = data;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *p = &info->dlpi_phdr[i];
		if (p->p_type != PT_LOAD || !(p->p_flags & PF_X) || !(p->p_flags & PF_R)) continue;
		const uint32_t *w = (const uint32_t *)(info->dlpi_addr + p->p_vaddr);
		for (size_t k = 0; k < p->p_memsz / 4; k++) *sum = *sum * 31 + w[k];
	}
	return 0;
}

static uint64_t text_sum(void)
{
	uint64_t s = 0;
	dl_iterate_phdr(sum_seg, &s);
	return s;
}

static unsigned char *jit;

/* The code: a branch to itself, then a return. */
#if defined(__x86_64__)
static const unsigned char jit_code[] = {0xeb, 0xfe, 0xc3};      /* jmp .; ret */
static const unsigned char jit_nop[] = {0x66, 0x90};             /* xchg ax, ax */
#else
static const uint32_t jit_code[] = {0x14000000u, 0xd65f03c0u};    /* b .; ret */
static const uint32_t jit_nop[] = {0xd503201fu};                 /* nop */
#endif

static void jit_patch(int sig)
{
	(void)sig;
	memcpy(jit, jit_nop, sizeof jit_nop);
	__builtin___clear_cache((char *)jit, (char *)jit + sizeof jit_code);
}

static void *jit_run(void *a)
{
	(void)a;
	started = 1;
	((void (*)(void))jit)();
	return NULL;
}

static int jit_main(void)
{
	jit = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (jit == MAP_FAILED) return 3;
	memcpy(jit, jit_code, sizeof jit_code);
	__builtin___clear_cache((char *)jit, (char *)jit + sizeof jit_code);
	signal(SIGUSR1, jit_patch);
	pthread_t t;
	pthread_create(&t, NULL, jit_run, NULL);
	while (!started) sched_yield();
	pthread_kill(t, SIGUSR1);
	pthread_join(t, NULL);
	printf("jit patched\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) return 2;
	if (!strcmp(argv[1], "alone") || !strcmp(argv[1], "wander")) {
		int wander = argv[1][0] == 'w';
		long ms = argc > 2 ? atol(argv[2]) : 2000;
		unsigned long h = 88172645463325252UL;
		/* Sized by iterations (about MS ms on the measuring host): no clock read, no trap. */
		for (unsigned long n = (unsigned long)ms * (wander ? 200000UL : 900000UL); n; n--) {
			h ^= h << 13; h ^= h >> 7; h ^= h << 17;
			if (!wander) continue;
			if (h & 1) wa(); else wb();
		}
		printf("%s %lx\n", argv[1], h ^ acc);
		return 0;
	}
	if (!strcmp(argv[1], "text")) {
		long n = argc > 2 ? atol(argv[2]) : 10;
		uint64_t s0 = text_sum();
		for (long r = 0; r < n; r++) {
			wait_once();
			if (text_sum() != s0) {
				printf("text changed after round %ld\n", r + 1);
				return 1;
			}
		}
		printf("text same after %ld rounds\n", n);
		return 0;
	}
	if (!strcmp(argv[1], "twice")) {
		pthread_t t;
		pthread_create(&t, NULL, two, NULL);
		while (!started) sched_yield();
		flag = 1;
		while (stage != 2) sched_yield();
		flag2 = 1;
		pthread_join(t, NULL);
		two_waits();
		printf("twice done\n");
		return 0;
	}
	if (!strcmp(argv[1], "jit")) return jit_main();
	if (!strcmp(argv[1], "count")) mode = 1;
	else if (!strcmp(argv[1], "memcount")) mode = 2;
	else if (!strcmp(argv[1], "nested")) mode = 3, inner = argc > 2 ? atoi(argv[2]) : 300;
	else if (strcmp(argv[1], "flag")) return 2;
	wait_once();
	printf("done\n");
	return 0;
}
