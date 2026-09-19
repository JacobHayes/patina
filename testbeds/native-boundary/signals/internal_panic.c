/* The harness plants a Rust panic at the clock ABI entry, after its ownership
 * guard but before any runtime lock. This guest uses no undefined inputs. */
#include "patina_native.h"
#include <assert.h>
#include <stdint.h>
int main(void) {
    uint64_t nanos = 0;
    assert(patina_clock_now(1, &nanos) == 0);
    return 0;
}
