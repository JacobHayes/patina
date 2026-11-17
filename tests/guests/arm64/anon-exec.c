/* An anonymous executable mapping: memory the instruction scan does not read. */
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    void *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("mapped: %d\n", p != MAP_FAILED);
    return 0;
}
