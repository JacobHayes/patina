/* PAC: built with -mbranch-protection=standard, so show() signs its return address (paciasp)
 * before saving it in its frame record; it prints the saved word. With the keys enabled the
 * signature depends on a per-process random key; with them disabled the word is the plain
 * address. */
#include <stdio.h>

__attribute__((noinline)) static void show(void) {
    unsigned long *fp = __builtin_frame_address(0);
    printf("saved return address %#lx\n", fp[1]);
}

int main(void) {
    show();
    return 0;
}
