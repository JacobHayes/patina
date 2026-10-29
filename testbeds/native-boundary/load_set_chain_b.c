// The second library of a chain: it calls a libc export Patina neither
// interposes nor names as an escape class, which reads host state.
#define _DEFAULT_SOURCE
#include <stdlib.h>

int b_call(void) {
    double loads[1];
    return getloadavg(loads, 1);
}
