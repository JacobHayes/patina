/* The SanitizerCoverage hooks of an instrumented build
 * (`patina build`, unless `--no-instrument`).
 *
 * LLVM's trace-pc-guard instrumentation calls `__sanitizer_cov_trace_pc_guard`
 * at every instrumented edge, loop backedges included. Each call does three
 * things:
 *
 *   1. bumps that edge's guard word, which IS its hit counter (zero = unseen),
 *      for `--coverage-out` and `campaign --guided`;
 *   2. counts the edge toward the thread's next edge-meter batch (below),
 *      while guest code owns the thread;
 *   3. consults the run's yield stride, `PATINA_YIELD_STRIDE`, which the shim
 *      sets from `run --yield-stride N` (or from the trace on replay) once the
 *      runtime is installed. 0 takes no scheduling point; N takes one every Nth
 *      guest edge this thread executes (the shim's own edges are not counted,
 *      as the meter does not count them). A scheduling point inside atomics-only code
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
extern void patina_edge_point(uint32_t edges);
extern void patina_edge_meter_register(void (*pause)(int), void (*reset)(void));
/* The run's yield stride (an `AtomicU32` in the shim, defined in this same
 * executable, so the linker resolves the load to a direct one). */
extern uint32_t PATINA_YIELD_STRIDE;

/* The marker `patina run` scans an executable for, to tell an instrumented
 * binary from a plain one and fold that into the compatibility fingerprint.
 * `used` + `retain` keeps it past `-dead_strip`, and the guard-init reference
 * below anchors it on every toolchain. */
__attribute__((used, retain))
static const char PATINA_INSTRUMENTED_MARKER[] = "PATINA_INSTRUMENTED_V1";
const char *volatile patina_instrumented_anchor;

/* Edges this thread has executed since its last sampled scheduling point. */
static _Thread_local uint32_t patina_edges_since_yield;

/* The edge meter: every edge is computation, charged as virtual CPU time.
 * This thread counts down to its next batch; every PATINA_EDGE_BATCH edges
 * the batch goes to the shim, which charges it, moves the clock, and may take
 * a scheduling point (`patina_edge_point`). The count is the thread's own, so
 * the batches fall at the same edges on every run. A batch is about 33
 * virtual microseconds: the most an operation's timestamp lags the edges
 * before it.
 *
 * Only guest code is metered. While the shim owns the thread, its own edges
 * (an instrumented guest allocator serving the shim, which allocates more
 * when recording than when replaying) are not the guest's computation: the
 * shim pauses the meter (`patina_edge_meter_pause`), which parks the
 * countdown out of reach and gives it back unchanged when the guest has the
 * thread again. The shim also resets the countdown when the runtime is
 * installed, so the edges before the modeled run began (constructors, which
 * read the host's environment) move no batch boundary. */
#define PATINA_EDGE_BATCH 16384u
#define PATINA_EDGE_PARKED 0x7fffffffu
static _Thread_local uint32_t patina_edges_until_batch = PATINA_EDGE_BATCH;
static _Thread_local uint32_t patina_edges_parked;
static _Thread_local uint8_t patina_edges_paused;

static void patina_edge_meter_pause(int paused) {
    if (paused && !patina_edges_paused) {
        patina_edges_parked = patina_edges_until_batch;
        patina_edges_until_batch = PATINA_EDGE_PARKED;
        patina_edges_paused = 1;
    } else if (!paused && patina_edges_paused) {
        patina_edges_until_batch = patina_edges_parked;
        patina_edges_paused = 0;
    }
}

static void patina_edge_meter_reset(void) {
    if (patina_edges_paused) {
        patina_edges_parked = PATINA_EDGE_BATCH;
    } else {
        patina_edges_until_batch = PATINA_EDGE_BATCH;
    }
}

/* The countdown reached zero: a batch is due, unless the meter is paused
 * (only after PATINA_EDGE_PARKED shim edges, which re-parks it). */
__attribute__((noinline))
static void patina_edge_batch_due(void) {
    if (patina_edges_paused) {
        patina_edges_until_batch = PATINA_EDGE_PARKED;
        return;
    }
    patina_edges_until_batch = PATINA_EDGE_BATCH;
    patina_edge_point(PATINA_EDGE_BATCH);
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    patina_coverage_register(start, stop);
    patina_edge_meter_register(patina_edge_meter_pause, patina_edge_meter_reset);
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
    if (__builtin_expect(--patina_edges_until_batch == 0, 0)) {
        patina_edge_batch_due();
    }
    uint32_t stride = __atomic_load_n(&PATINA_YIELD_STRIDE, __ATOMIC_RELAXED);
    if (__builtin_expect(stride == 0, 1)) {
        return;
    }
    /* The stride counts guest edges only, as the meter does: the shim's own
     * edges differ between record and replay, and a yield point is never
     * taken while the shim owns the thread. */
    if (patina_edges_paused) {
        return;
    }
    if (++patina_edges_since_yield >= stride) {
        patina_edges_since_yield = 0;
        patina_yield_point(__builtin_return_address(0));
    }
}
