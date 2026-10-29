// An undefined weak reference, called when it resolves. Built with
// -DWEAK_LIBC_EXPORT it names `getloadavg`, an export of glibc and of
// libSystem that Patina neither interposes nor names as an escape class: the
// loader binds it to the host's code, which reads host state. Built without,
// it names a hook no library defines, so it resolves to NULL and the guarded
// fallback runs, as aws-lc's allocator hooks do.
#include <stdio.h>

#ifdef WEAK_LIBC_EXPORT
#define WEAK_HOOK getloadavg
#else
#define WEAK_HOOK patina_probe_absent_hook
#endif

extern int WEAK_HOOK(double loads[], int count) __attribute__((weak));

int main(void) {
    if (WEAK_HOOK == NULL) {
        puts("WEAK_HOOK absent");
        return 0;
    }
    double loads[1] = {0};
    printf("WEAK_HOOK ran=%d\n", WEAK_HOOK(loads, 1));
    return 0;
}
