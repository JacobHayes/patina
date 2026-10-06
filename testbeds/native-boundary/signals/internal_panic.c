/* Arm the feature-only clock panic after startup, before any runtime lock. */
#include "patina_native.h"
#include <assert.h>
#include <stdint.h>
extern void patina_test_arm_clock_panic(void);
int main(void) {
    patina_test_arm_clock_panic();
    uint64_t nanos = 0;
    assert(patina_clock_now(1, &nanos) == 0);
    return 0;
}
