// A library doing modeled I/O: its `write` binds to the shim's definition the
// executable exports, unless the executable hides it.
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>

int lib_entry(void) {
    static const char line[] = "LOAD_SET_IO\n";
    return (int)write(1, line, sizeof line - 1);
}
