/* The counter-timer: reads of CNTFRQ_EL0 and CNTVCT_EL0, printed. Under the trap they answer
 * from virtual time. */
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uint64_t f, v[3];
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    for (int i = 0; i < 3; i++) __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v[i]));
    printf("cntfrq %llu\n", (unsigned long long)f);
    for (int i = 0; i < 3; i++) printf("cntvct %llu\n", (unsigned long long)v[i]);
    return 0;
}
