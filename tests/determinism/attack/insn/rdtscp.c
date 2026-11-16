/* rdtscp under emulation: every general register before and after the instruction. */
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t r[16];
    __asm__ volatile(
        "mov $0x1111, %%rcx\n\t" "mov $0x2222, %%rdx\n\t" "mov $0x3333, %%rax\n\t" "mov $0x4444, %%r8\n\t"
        "mov $0x5555, %%r9\n\t" "mov $0x6666, %%r10\n\t" "mov $0x7777, %%r11\n\t" "mov $0x8888, %%rsi\n\t" "mov $0x9999, %%rdi\n\t"
        "rdtscp\n\t"
        "mov %%rax, 0(%0)\n\t" "mov %%rdx, 8(%0)\n\t" "mov %%rcx, 16(%0)\n\t" "mov %%r8, 24(%0)\n\t" "mov %%r9, 32(%0)\n\t"
        "mov %%r10, 40(%0)\n\t" "mov %%r11, 48(%0)\n\t" "mov %%rsi, 56(%0)\n\t" "mov %%rdi, 64(%0)\n\t"
        : : "b"(r) : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory");
    printf("rax %lx rdx %lx rcx %lx r8 %lx r9 %lx r10 %lx r11 %lx rsi %lx rdi %lx\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);
    unsigned aux = 0xdead; unsigned long long t = __builtin_ia32_rdtscp(&aux);
    printf("builtin aux %x t>0 %d\n", aux, t > 0);
    return 0;
}
