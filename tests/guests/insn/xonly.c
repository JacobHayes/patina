/* An image whose code segment is execute-only (build.sh clears its read flag after linking):
 * the loader scans and patches it like any other. One spin hint (x86 `pause`, arm64 `yield`),
 * a pause-point site, then "xonly ok". */
#include <stdio.h>

int main(void) {
#if defined(__x86_64__)
    __asm__ volatile("pause");
#else
    __asm__ volatile("yield");
#endif
    printf("xonly ok\n");
    return 0;
}
