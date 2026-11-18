/* arm64 exclusive accesses that fault, and more exclusive sites than one process's patch table.
 *   excl map        1000 increments by ldxr/stxr retry loops of a word whose page is made
 *                   PROT_NONE (the load faults) or PROT_READ (the store faults) every 100
 *                   increments; the SIGSEGV handler makes it writable and returns, so the
 *                   faulting instruction runs again
 *   excl-many       (built with -DMANY) holds 2 x 2100 exclusive instructions, more than one
 *                   process's patch table, never run; prints a line
 * Each prints what it saw, the same natively and under Patina. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static char *page;
static volatile int faults;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
	(void)sig;
	(void)uc;
	if ((char *)si->si_addr < page || (char *)si->si_addr >= page + 4096)
		_exit(3);
	faults++;
	mprotect(page, 4096, PROT_READ | PROT_WRITE);
}

static void inc(uint64_t *p)
{
	uint64_t v;
	uint32_t fail;
	do {
		__asm__ volatile("ldxr %0, [%2]\n\tadd %0, %0, #1\n\tstxr %w1, %0, [%2]"
				 : "=&r"(v), "=&r"(fail)
				 : "r"(p)
				 : "memory");
	} while (fail);
}

#ifdef MANY
__attribute__((noinline, used)) static void many(uint64_t *p)
{
	__asm__ volatile(".rept 2100\n\tldxr x9, [%0]\n\tstxr w10, x9, [%0]\n\t.endr" : : "r"(p) : "x9", "x10", "memory");
}
#endif

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "map";
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_flags = SA_SIGINFO;
	if (!strcmp(mode, "map")) {
		page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		sa.sa_sigaction = on_segv;
		sigaction(SIGSEGV, &sa, NULL);
		uint64_t *w = (uint64_t *)(page + 64);
		for (int i = 0; i < 1000; i++) {
			if (i % 100 == 0)
				mprotect(page, 4096, i % 200 ? PROT_READ : PROT_NONE);
			inc(w);
		}
		printf("map: %lu increments, %d faults\n", (unsigned long)*w, faults);
	} else if (!strcmp(mode, "many")) {
		printf("many: loaded\n");
	}
	return 0;
}
