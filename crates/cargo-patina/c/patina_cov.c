/* Edge-coverage instrumentation with OPTIONAL sampled preemption, for
 * `cargo patina build --coverage-points[=<STRIDE>]`.
 *
 * WHY THIS EXISTS. `patina_yield.c` (the `--yield-points` hook) does two
 * different jobs with one flag: it maintains the SanitizerCoverage edge counters
 * that `--coverage-out`/`--guided` read, AND it takes a deterministic scheduling
 * point at EVERY instrumented basic block. The second job is what costs: each
 * guard hit crosses into the shim, sets a thread-local site, takes the scheduler
 * spinlock, and runs a full `reschedule`. Measured on a real tokio guest
 * (turso_stress) that is a >200x slowdown, which makes coverage-guided campaigns
 * against such a guest impossible even though the counters themselves are nearly
 * free.
 *
 * This translation unit is the same instrumentation with the scheduler hook made
 * OPTIONAL and SAMPLED:
 *
 *   STRIDE == 0 (bare `--coverage-points`)   — counters only. The guest keeps the
 *       preemption boundaries it always had (interposed I/O, blocking, spawn,
 *       join, sleep, modeled atomics) and gains nothing but edge coverage, so
 *       `--coverage-out` and `campaign --guided` work at counter cost.
 *   STRIDE == N > 0 (`--coverage-points=N`)  — counters, plus a scheduling point
 *       every Nth instrumented basic block THIS THREAD executes. That bounds the
 *       number of guest basic blocks between consecutive preemption
 *       opportunities by N, which is precisely the property a narrow atomics-only
 *       race window needs, at 1/N of the yield cost.
 *
 * DETERMINISM. The countdown is `_Thread_local`, never shared: no cross-thread
 * state, so no dependence on host thread timing. A managed task's own basic-block
 * stream between two scheduling points is a pure function of the schedule Patina
 * chose, so the countdown — and therefore the exact set of sampled yield sites —
 * is a pure function of the seed and replays exactly. (A single shared counter
 * would NOT be safe: teardown code on a completed task can run outside the
 * scheduler's serialization.) The stride is baked in at compile time through
 * `-DPATINA_YIELD_STRIDE`, so it cannot drift from the binary, and it is stamped
 * into the marker string below so `cargo patina run` recovers it from the bytes
 * and folds it into the compatibility fingerprint.
 *
 * Like `patina_yield.c`, this layer is linked ONLY on its own build path; a plain
 * native build never sees it, and the two are mutually exclusive (they define the
 * same SanitizerCoverage entry points).
 */

#include <stdint.h>

/* Provided by the patina-dst-native-shim staticlib; see patina_yield.c. */
extern void patina_coverage_register(uint32_t *start, uint32_t *stop);
extern void patina_coverage_register_pcs(const uintptr_t *start, const uintptr_t *stop);
extern void patina_yield_point(const void *site);

/* Sampling stride, injected by the builder. 0 = never take a scheduling point. */
#ifndef PATINA_YIELD_STRIDE
#define PATINA_YIELD_STRIDE 0
#endif

#define PATINA_STRINGIFY_(x) #x
#define PATINA_STRINGIFY(x) PATINA_STRINGIFY_(x)

/* The build-mode marker `cargo patina run` scans for. Unlike the `--yield-points`
 * marker it CARRIES ITS PARAMETER: the stride is part of the schedule policy, so
 * two binaries built with different strides must not cross-replay, and the run
 * side must be able to recover the stride from the binary alone (no flag to
 * re-pass, exactly like the yield-point marker). The trailing ';' terminates the
 * digits for the scanner. `used` + `retain` keeps it past `-dead_strip`, and the
 * guard-init reference below anchors it on every toolchain. */
__attribute__((used, retain))
static const char PATINA_COVERAGE_POINTS_MARKER[] =
    "PATINA_COVERAGE_POINTS_V1 stride=" PATINA_STRINGIFY(PATINA_YIELD_STRIDE) ";";
const char *volatile patina_coverage_points_anchor;

/* SanitizerCoverage guard-array initializer. The guard words themselves are the
 * per-edge hit counters (zero means unseen), so init only registers the range
 * and anchors the marker symbol. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    patina_coverage_register(start, stop);
    patina_coverage_points_anchor = PATINA_COVERAGE_POINTS_MARKER;
}

/* SanitizerCoverage pc-table initializer. LLVM emits one (pc, flags) pair per
 * guard, and calls this from the same module constructor as guard init. */
void __sanitizer_cov_pcs_init(const uintptr_t *start, const uintptr_t *stop) {
    patina_coverage_register_pcs(start, stop);
}

#if PATINA_YIELD_STRIDE > 0
/* Per-thread countdown to the next sampled scheduling point. Thread-local so the
 * sampling decision never depends on interleaving with another host thread. */
static _Thread_local uint32_t patina_block_countdown = PATINA_YIELD_STRIDE;
#endif

/* Fired at every instrumented basic block in the guest. The counter bump is the
 * whole cost at stride 0; the sampled call is the whole cost above it. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t hits = *guard;
    if (hits != UINT32_MAX) {
        *guard = hits + 1;
    }
#if PATINA_YIELD_STRIDE > 0
    if (--patina_block_countdown == 0) {
        patina_block_countdown = PATINA_YIELD_STRIDE;
        patina_yield_point(__builtin_return_address(0));
    }
#endif
}
