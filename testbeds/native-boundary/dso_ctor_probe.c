/* The executable for dso_ctor_escape.c: prints what that library's
 * constructor saw, and for `rseq` what the main thread's area reads now. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern long patina_dso_ctor_value;
extern int patina_dso_ctor_ran;
extern const ptrdiff_t __rseq_offset;

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "none";
    uint32_t cpu;
    memcpy(&cpu, (const char *)__builtin_thread_pointer() + __rseq_offset + 4, sizeof cpu);
    printf("DSO_CTOR_RESULT mode=%s ran=%d value=%ld main_cpu=%u\n", mode, patina_dso_ctor_ran,
           patina_dso_ctor_value, (unsigned)cpu);
    return 0;
}
