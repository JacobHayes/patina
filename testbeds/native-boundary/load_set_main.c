// An executable that calls into the library it links: the probe the load-set
// fixtures place a library's references behind.
#include <stdio.h>

int lib_entry(void);

int main(void) {
    printf("LOAD_SET_MAIN %d\n", lib_entry());
    return 0;
}
