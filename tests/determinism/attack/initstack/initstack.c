/* Every byte of argv, envp, auxv and the initial stack page, as the program sees them. */
#define _GNU_SOURCE
#include "../common.h"
#include <stdint.h>
#include <string.h>
int main(int argc, char **argv, char **envp) {
    uintptr_t sp = (uintptr_t)argv - sizeof(long);
    for (int i = 0; i < argc; i++) printf("argv[%d] %p %s\n", i, (void *)argv[i], argv[i]);
    char **e = envp; int ne = 0; for (; *e; e++, ne++) printf("env %p %s\n", (void *)*e, *e);
    unsigned long *av = (unsigned long *)(e + 1);
    for (int k = 0; av[2 * k]; k++) printf("auxv %lu %lx\n", av[2 * k], av[2 * k + 1]);
    uintptr_t page = sp & ~(uintptr_t)4095;
    uintptr_t top = (uintptr_t)argv[0]; while (top & 4095) top++;
    printf("sp %lx page %lx top %lx\n", (unsigned long)sp, (unsigned long)page, (unsigned long)top);
    for (uintptr_t p = page; p < top; p += 64) hexline("stk", (void *)p, 64);
    return 0;
}
