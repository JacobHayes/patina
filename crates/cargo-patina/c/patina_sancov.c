/* The SanitizerCoverage hooks of an instrumented build
 * (`cargo patina build --instrument`).
 *
 * LLVM's trace-pc-guard instrumentation calls `__sanitizer_cov_trace_pc_guard`
 * at every instrumented edge, loop backedges included. Each call does two
 * things:
 *
 *   1. bumps that edge's guard word, which IS its hit counter (zero = unseen),
 *      for `--coverage-out` and `campaign --guided`;
 *   2. consults the run's yield stride, `PATINA_YIELD_STRIDE`, which the shim
 *      sets from `run --yield-stride N` (or from the trace on replay) once the
 *      runtime is installed. 0 takes no scheduling point; N takes one every Nth
 *      edge this thread executes. A scheduling point inside atomics-only code
 *      (a std `RwLock` fast path, a hand-rolled spin loop) is what makes a race
 *      window there reachable by the seeded scheduler.
 *
 * The stride is a run setting, not a build setting, so one binary serves both
 * cheap coverage-guided campaigns (stride 0) and dense schedule exploration
 * (stride 1). The stride is recorded into the trace's schedule policy, so a
 * replay takes the recorded stride and reproduces the same scheduling points.
 *
 * DETERMINISM. The countdown is `_Thread_local`, never shared: a managed task's
 * edge stream between two scheduling points is a pure function of the schedule
 * Patina chose, so the sampled sites are a pure function of the seed. The
 * stride is written once, at install, before any managed thread exists; edges
 * before that (constructors, shim bootstrap) see 0, on every run alike.
 *
 * This object is linked only into an instrumented guest's final link; a plain
 * build never sees it.
 */

#include <stdint.h>

/* Provided by the patina-dst-native-shim staticlib. The registration calls hand
 * the shim the guard-counter and pc-table ranges; `patina_yield_point` offers the
 * scheduler a switch, with the instrumented site so a record/replay divergence
 * can name the guest location. */
extern void patina_coverage_register(uint32_t *start, uint32_t *stop);
extern void patina_coverage_register_pcs(const uintptr_t *start, const uintptr_t *stop);
extern void patina_yield_point(const void *site);
/* The run's yield stride (an `AtomicU32` in the shim, defined in this same
 * executable, so the linker resolves the load to a direct one). */
extern uint32_t PATINA_YIELD_STRIDE;

/* The marker `cargo patina run` scans an executable for, to tell an instrumented
 * binary from a plain one and fold that into the compatibility fingerprint.
 * `used` + `retain` keeps it past `-dead_strip`, and the guard-init reference
 * below anchors it on every toolchain. */
__attribute__((used, retain))
static const char PATINA_INSTRUMENTED_MARKER[] = "PATINA_INSTRUMENTED_V1";
const char *volatile patina_instrumented_anchor;

/* Edges this thread has executed since its last sampled scheduling point. */
static _Thread_local uint32_t patina_edges_since_yield;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    patina_coverage_register(start, stop);
    patina_instrumented_anchor = PATINA_INSTRUMENTED_MARKER;
}

/* LLVM emits one (pc, flags) pair per guard, and calls this from the same module
 * constructor as guard init. */
void __sanitizer_cov_pcs_init(const uintptr_t *start, const uintptr_t *stop) {
    patina_coverage_register_pcs(start, stop);
}

/* Fired at every instrumented edge. At stride 0 the whole cost is the counter
 * bump plus one load and a predicted branch. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t hits = *guard;
    if (hits != UINT32_MAX) {
        *guard = hits + 1;
    }
    uint32_t stride = __atomic_load_n(&PATINA_YIELD_STRIDE, __ATOMIC_RELAXED);
    if (__builtin_expect(stride == 0, 1)) {
        return;
    }
    if (++patina_edges_since_yield >= stride) {
        patina_edges_since_yield = 0;
        patina_yield_point(__builtin_return_address(0));
    }
}
