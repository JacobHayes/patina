// A library linked -z initfirst: glibc runs its constructor before the
// executable's preinit array, where the shim arms its containment.
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>

__attribute__((constructor)) static void early(void) {
    static const char line[] = "INITFIRST_RAN\n";
    (void)!write(2, line, sizeof line - 1);
}

int lib_entry(void) { return 0; }
