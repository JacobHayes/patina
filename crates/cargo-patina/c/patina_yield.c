/* Build-time deterministic-preemption hook for `cargo patina build
 * --yield-points`.
 *
 * When a guest is compiled with LLVM SanitizerCoverage trace-pc-guard
 * instrumentation, the compiler emits a call to `__sanitizer_cov_trace_pc_guard`
 * at every instrumented basic block — including loop backedges. Routing each of
 * those calls into the shim's `patina_sched_yield` turns every basic block into
 * a cooperative scheduling point, so a race window that lives entirely in
 * atomics-only code (for example a `std::sync::RwLock` read-modify-write, whose
 * fast path issues no interposed syscall) becomes reachable by the seeded
 * deterministic scheduler.
 *
 * This layer is linked ONLY on the `--yield-points` build path; a plain native
 * build never sees it, so native behavior is unchanged. When no managed threads
 * are active (single-threaded guest, or the pre-thread startup window),
 * `patina_sched_yield` resolves to a cheap no-op inside the shim.
 */

#include <stdint.h>

/* Provided by the patina-dst-native-shim staticlib; offers the deterministic
 * scheduler a chance to switch tasks. */
extern int patina_sched_yield(void);

/* A distinctive marker so `cargo patina run` can detect a yield-point
 * binary from its bytes and fold that into the compatibility fingerprint, so a
 * trace recorded against yield-point schedules never silently replays against a
 * plain binary (or vice versa). `used` + `retain` keeps it past `-dead_strip`,
 * and the guard-init reference below anchors it on every toolchain. */
__attribute__((used, retain))
static const char PATINA_YIELD_POINTS_MARKER[] = "PATINA_YIELD_POINTS_V1";
const char *volatile patina_yield_points_anchor;

/* SanitizerCoverage guard-array initializer. The guards are unused (every point
 * yields unconditionally), so this only anchors the marker symbol. */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    (void)start;
    (void)stop;
    patina_yield_points_anchor = PATINA_YIELD_POINTS_MARKER;
}

/* Fired at every instrumented basic block in the guest. */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    (void)guard;
    patina_sched_yield();
}
