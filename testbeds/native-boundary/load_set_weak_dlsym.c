// A library probing the resolver weakly, as compatibility code does: a guest
// resolver, whatever the executable's own vehicle.
#include <stddef.h>

extern void *dlsym(void *handle, const char *name) __attribute__((weak));

int lib_entry(void) { return dlsym != NULL; }
