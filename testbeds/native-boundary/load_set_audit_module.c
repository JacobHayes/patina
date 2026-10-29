// An rtld-audit module: the loader calls la_version before it maps anything
// else, listing included.
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>

unsigned int la_version(unsigned int version) {
    static const char line[] = "AUDIT_MODULE_RAN\n";
    (void)!write(2, line, sizeof line - 1);
    return version;
}
