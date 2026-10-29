// An executable with an IFUNC: the loader runs its resolver during
// relocation, before the executable's preinit array.
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>

static int answer(void) { return 42; }

static int (*resolve(void))(void) {
    static const char line[] = "IFUNC_RESOLVER_RAN\n";
    (void)!write(2, line, sizeof line - 1);
    return answer;
}

int chosen(void) __attribute__((ifunc("resolve")));

int main(void) {
    printf("IFUNC %d\n", chosen());
    return 0;
}
