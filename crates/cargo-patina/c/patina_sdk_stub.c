/* Weak stand-ins for the shim entries the SDK calls, for the programs a
 * Patina build compiles but does not link to the shim.
 *
 * `cfg(patina_shim)` is whole-graph: every crate Cargo compiles from source in
 * a Patina build calls the SDK's shim entries, while the shim itself is scoped
 * to the one target the build was asked for. Building an integration test also
 * builds the package's own binaries, beside the test and without the shim. One
 * that calls the SDK then has nothing to resolve those entries against.
 * Nothing runs that binary (a guest starts no process), but it has to link.
 *
 * These definitions are weak and this object is injected whole-graph in such a
 * build, so that link resolves. The test's own link also carries the shim,
 * whose strong definitions override these. A program that does reach a
 * stand-in was built for Patina and started without it: it says so and aborts,
 * rather than run with every fault site and invariant quietly inert.
 *
 * PATINA_SDK_ENTRIES is the SDK's own list (`patina_dst::__rt::SHIM_ENTRIES`),
 * passed by the tool: `X(name) X(name) ...`.
 */

#include <stdio.h>
#include <stdlib.h>

static void patina_shim_absent(const char *entry) {
    fprintf(stderr,
            "patina: %s was called in a program built for Patina but not linked to its runtime "
            "(a package's own binary, built beside a `patina test` harness); build it with "
            "`patina build` or plain cargo\n",
            entry);
    abort();
}

#define PATINA_STAND_IN(name) \
    __attribute__((weak)) void name(void) { patina_shim_absent(#name); }

PATINA_SDK_ENTRIES(PATINA_STAND_IN)
