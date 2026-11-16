// the skeleton guest: loops forever without a syscall after one line of output.
#include <stdio.h>
int main(void) {
    printf("spinning\n");
    fflush(stdout);
    for (volatile unsigned long i = 0;; i++) {}
}
