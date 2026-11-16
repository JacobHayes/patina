/* Patina compute points: the hooks of a program rebuilt with the compilers' coverage flags.
 *
 *   clang: CFLAGS += -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime
 *   gcc:   CFLAGS += -fsanitize-coverage=trace-pc        (edges only)
 *
 * and this file added once to each linked executable or shared library that has objects built
 * with the flags. Without it the link fails on `__sanitizer_cov_trace_pc`. Clang and gcc 12 or
 * later never instrument it, so it may be built with the flags; build it without them on older
 * gcc, whose hooks would call themselves. Outside Patina the first event makes one unknown
 * system call, so a seccomp filter that kills on unknown calls kills the program there.
 *
 * Each hook call is an event. Under Patina an event decrements one word of the program's own
 * memory, the cell, which the runtime refills; when it reaches 0 the thread enters the runtime
 * and the seed may switch threads there. Each event also costs 1 ns of virtual time. Outside
 * Patina the first event's call fails (ENOSYS) and every hook is a load and a branch after it.
 * The wire is `proto::sdk` (OP_COMPUTE_HELLO, OP_COMPUTE_POINT); the design is in
 * ARCHITECTURE.md, "Scheduling points". C99 and C++; no library calls, no TLS, no errno, so it
 * works in constructors, signal handlers and before libc is ready. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__)
#define PATINA_NOCOV __attribute__((no_sanitize("coverage")))
#elif defined(__has_attribute)
#if __has_attribute(no_sanitize_coverage)
#define PATINA_NOCOV __attribute__((no_sanitize_coverage))
#endif
#endif
#ifndef PATINA_NOCOV
#define PATINA_NOCOV
#endif
/* Each library keeps its own copy: its hooks bind to it, and it says hello on its own. */
#define PATINA_HOOK PATINA_NOCOV __attribute__((visibility("hidden")))

#define PATINA_SYSCALL 0x7061L
#define PATINA_OP_COMPUTE_HELLO 8L
#define PATINA_OP_COMPUTE_POINT 9L
#define PATINA_COMPUTE_VERSION 1L
#if defined(__clang__)
#define PATINA_COMPUTE_KINDS 3L /* edges and accesses */
#else
#define PATINA_COMPUTE_KINDS 1L /* edges */
#endif

static long patina_boot;                  /* 0: the first event takes the slow path */
static long *patina_cell = &patina_boot;  /* NULL once this is known not to run under Patina */

static PATINA_NOCOV inline long patina_compute_call(long op, long arg)
{
	long r;
	__asm__ volatile("syscall"
			 : "=a"(r)
			 : "a"(PATINA_SYSCALL), "D"(op), "S"(arg), "d"(0L)
			 : "rcx", "r11", "memory");
	return r;
}

static PATINA_NOCOV __attribute__((noinline, cold)) void patina_compute_slow(long *c)
{
	if (c == &patina_boot) {
		long r = patina_compute_call(PATINA_OP_COMPUTE_HELLO,
					     PATINA_COMPUTE_VERSION | PATINA_COMPUTE_KINDS << 8);
		__atomic_store_n(&patina_cell, r > 0 ? (long *)(uintptr_t)r : (long *)0, __ATOMIC_RELAXED);
		return;
	}
	patina_compute_call(PATINA_OP_COMPUTE_POINT, 0);
}

#define PATINA_EVENT()                                                   \
	do {                                                             \
		long *c_ = __atomic_load_n(&patina_cell, __ATOMIC_RELAXED); \
		if (c_ && __builtin_expect(--*c_ <= 0, 0))               \
			patina_compute_slow(c_);                         \
	} while (0)

PATINA_HOOK void __sanitizer_cov_trace_pc(void) { PATINA_EVENT(); }

#define PATINA_ACCESS(n)                                                              \
	PATINA_HOOK void __sanitizer_cov_load##n(void *p) { (void)p; PATINA_EVENT(); }  \
	PATINA_HOOK void __sanitizer_cov_store##n(void *p) { (void)p; PATINA_EVENT(); }
PATINA_ACCESS(1)
PATINA_ACCESS(2)
PATINA_ACCESS(4)
PATINA_ACCESS(8)
PATINA_ACCESS(16)

#ifdef __cplusplus
}
#endif
