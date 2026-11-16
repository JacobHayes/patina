/* instruction channels item 3: dump every cpuid leaf and subleaf (basic, hypervisor, extended ranges; subleaves
 * 0..63 for every leaf), one line "leaf sub eax ebx ecx edx". Also rdpid (item 5) when asked. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void cpuid(uint32_t leaf, uint32_t sub, uint32_t r[4]) {
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

static void range(uint32_t base) {
    uint32_t r[4];
    cpuid(base, 0, r);
    uint32_t max = r[0];
    if (max < base || max > base + 0x100) max = base;
    for (uint32_t l = base; l <= max; l++)
        for (uint32_t s = 0; s < 64; s++) {
            cpuid(l, s, r);
            printf("%08x %02x %08x %08x %08x %08x\n", l, s, r[0], r[1], r[2], r[3]);
        }
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "rdpid")) {
        uint64_t v;
        __asm__ volatile("rdpid %0" : "=r"(v));
        printf("rdpid %llu\n", (unsigned long long)v);
        return 0;
    }
    range(0);
    range(0x40000000);
    range(0x80000000);
    return 0;
}
