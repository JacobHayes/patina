/* arm64 exclusive accesses that fault, and more exclusive sites than one process's patch table.
 *   excl map        1000 increments by ldxr/stxr retry loops of a word whose page is made
 *                   PROT_NONE (the load faults) or PROT_READ (the store faults) every 100
 *                   increments; the SIGSEGV handler makes it writable and returns, so the
 *                   faulting instruction runs again
 *   excl align      every exclusive load and store form at offsets 0, 1, 2, 4, 8, 12, 14 and
 *                   15 of a 64-byte-aligned buffer (unaligned, within or across a 16-byte
 *                   block): one line each, `ok` or the signal, si_code and si_addr (as an
 *                   offset from the buffer) it raised; a store runs with the monitor clear,
 *                   and once more after a load-exclusive of the aligned word
 *   excl-many       (built with -DMANY) holds 2 x 2100 exclusive instructions, more than one
 *                   process's patch table, never run; prints a line
 * Each prints what it saw, the same natively and under Patina. */
#define _GNU_SOURCE
#include <setjmp.h>
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

static sigjmp_buf jb;
static volatile int got_sig, got_code;
static volatile uintptr_t got_addr;
static _Alignas(64) unsigned char buf[128];

static void on_fault(int sig, siginfo_t *si, void *uc)
{
	(void)uc;
	got_sig = sig;
	got_code = si->si_code;
	got_addr = (uintptr_t)si->si_addr;
	siglongjmp(jb, 1);
}

/* One exclusive instruction (or pair) on the address in x12; x9-x11 are its registers. */
#define FORM(name, text) \
	static void f_##name(unsigned char *p) \
	{ \
		__asm__ volatile("mov x12, %0\n\t" text "\n\tclrex" : : "r"(p) : "x9", "x10", "x11", "x12", "memory"); \
	}
FORM(ldxrb, "ldxrb w9, [x12]")
FORM(ldxrh, "ldxrh w9, [x12]")
FORM(ldxr_w, "ldxr w9, [x12]")
FORM(ldxr_x, "ldxr x9, [x12]")
FORM(ldaxrb, "ldaxrb w9, [x12]")
FORM(ldaxrh, "ldaxrh w9, [x12]")
FORM(ldaxr_w, "ldaxr w9, [x12]")
FORM(ldaxr_x, "ldaxr x9, [x12]")
FORM(ldxp_w, "ldxp w9, w10, [x12]")
FORM(ldxp_x, "ldxp x9, x10, [x12]")
FORM(ldaxp_w, "ldaxp w9, w10, [x12]")
FORM(ldaxp_x, "ldaxp x9, x10, [x12]")
FORM(stxrb, "clrex\n\tstxrb w11, w9, [x12]")
FORM(stxrh, "clrex\n\tstxrh w11, w9, [x12]")
FORM(stxr_w, "clrex\n\tstxr w11, w9, [x12]")
FORM(stxr_x, "clrex\n\tstxr w11, x9, [x12]")
FORM(stlxrb, "clrex\n\tstlxrb w11, w9, [x12]")
FORM(stlxrh, "clrex\n\tstlxrh w11, w9, [x12]")
FORM(stlxr_w, "clrex\n\tstlxr w11, w9, [x12]")
FORM(stlxr_x, "clrex\n\tstlxr w11, x9, [x12]")
FORM(stxp_w, "clrex\n\tstxp w11, w9, w10, [x12]")
FORM(stxp_x, "clrex\n\tstxp w11, x9, x10, [x12]")
FORM(stlxp_w, "clrex\n\tstlxp w11, w9, w10, [x12]")
FORM(stlxp_x, "clrex\n\tstlxp w11, x9, x10, [x12]")
/* A store after a load-exclusive of the buffer's first (aligned) word: the monitor is set. */
FORM(ld_stxr_w, "adrp x10, buf\n\tadd x10, x10, :lo12:buf\n\tldxr w9, [x10]\n\tstxr w11, w9, [x12]")
FORM(ld_stxr_x, "adrp x10, buf\n\tadd x10, x10, :lo12:buf\n\tldxr x9, [x10]\n\tstxr w11, x9, [x12]")
FORM(ld_stxp_x, "adrp x10, buf\n\tadd x10, x10, :lo12:buf\n\tldxp x9, x11, [x10]\n\tmov x10, x11\n\tstxp w11, x9, x10, [x12]")

static const struct {
	const char *name;
	void (*f)(unsigned char *);
} forms[] = {
#define F(n) {#n, f_##n}
	F(ldxrb), F(ldxrh), F(ldxr_w), F(ldxr_x), F(ldaxrb), F(ldaxrh), F(ldaxr_w), F(ldaxr_x),
	F(ldxp_w), F(ldxp_x), F(ldaxp_w), F(ldaxp_x), F(stxrb), F(stxrh), F(stxr_w), F(stxr_x),
	F(stlxrb), F(stlxrh), F(stlxr_w), F(stlxr_x), F(stxp_w), F(stxp_x), F(stlxp_w), F(stlxp_x),
	F(ld_stxr_w), F(ld_stxr_x), F(ld_stxp_x),
#undef F
};

static void align(void)
{
	static const int offs[] = {0, 1, 2, 4, 8, 12, 14, 15};
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sa.sa_sigaction = on_fault;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	for (unsigned i = 0; i < sizeof forms / sizeof forms[0]; i++)
		for (unsigned j = 0; j < sizeof offs / sizeof offs[0]; j++) {
			unsigned char *volatile p = buf + offs[j];
			got_sig = 0;
			if (!sigsetjmp(jb, 1))
				forms[i].f(p);
			if (got_sig)
				printf("%s +%d: %s code %d addr %+ld\n", forms[i].name, offs[j],
				       got_sig == SIGBUS ? "SIGBUS" : got_sig == SIGSEGV ? "SIGSEGV" : "other", got_code,
				       (long)(got_addr - (uintptr_t)buf));
			else
				printf("%s +%d: ok\n", forms[i].name, offs[j]);
		}
	printf("align: done\n");
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
	} else if (!strcmp(mode, "align")) {
		align();
	} else if (!strcmp(mode, "many")) {
		printf("many: loaded\n");
	}
	return 0;
}
