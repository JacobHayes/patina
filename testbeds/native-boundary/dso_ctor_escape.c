/* A shared library whose constructor reaches the host before any of the
 * executable's own constructors: glibc runs it from _dl_init, after the main
 * executable's .preinit_array and before its .init_array. argv[1] selects what
 * it does, using no libc call (an interposed one would stop the run on its own
 * before the runtime is installed):
 *
 *   syscall  an inline getppid instruction, outside the main executable's text
 *   rdtsc    an inline timestamp-counter read (x86_64)
 *   rseq     the cpu_id glibc's restartable-sequence area holds
 *
 * dso_ctor_probe.c prints what it saw. */
#include <stddef.h>
#include <stdint.h>

long patina_dso_ctor_value = -1;
int patina_dso_ctor_ran = 0;

extern const ptrdiff_t __rseq_offset;

static int same(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static long raw_getppid(void) {
#if defined(__x86_64__)
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(110L) : "rcx", "r11", "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 173;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
#endif
}

static long counter(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (long)(((uint64_t)hi << 32 | lo) & 0x7fffffffffffffffULL);
#else
    return -2;
#endif
}

static long rseq_cpu(void) {
    const char *area = (const char *)__builtin_thread_pointer() + __rseq_offset;
    return (long)*(const volatile uint32_t *)(area + 4);
}

__attribute__((constructor)) static void patina_dso_ctor(int argc, char **argv, char **envp) {
    (void)envp;
    patina_dso_ctor_ran = 1;
    if (argc < 2) return;
    if (same(argv[1], "syscall")) patina_dso_ctor_value = raw_getppid();
    else if (same(argv[1], "rdtsc")) patina_dso_ctor_value = counter();
    else if (same(argv[1], "rseq")) patina_dso_ctor_value = rseq_cpu();
}
