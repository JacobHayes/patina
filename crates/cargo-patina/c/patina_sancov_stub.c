/* Weak no-op SanitizerCoverage entry points, for the artifacts a
 * `--yield-points` build instruments but never runs.
 *
 * The instrumentation flags are whole-graph on purpose: every crate Cargo
 * compiles from source gains yield points, so a race window inside a dependency
 * is schedulable too. The real hooks live in `patina_yield.c`, which calls into
 * the shim staticlib, and both are scoped to the guest binary's own final link —
 * a dependency's shared library must not receive the shim (see
 * `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`).
 *
 * That leaves one gap. A dependency whose `[lib]` declares a `cdylib`/`dylib`
 * crate type is built by the same instrumented rustc invocation as its `rlib`,
 * and unlike an `rlib` it runs a real link of its own, where its instrumented
 * code's calls to `__sanitizer_cov_trace_pc_guard` have nothing to resolve
 * against. Nothing loads that library — it exists only because Cargo builds
 * every crate type a dependency declares — but it still has to link.
 *
 * These definitions are weak and this object is the one piece of Patina that
 * IS injected whole-graph, so such a link resolves against inert stubs. The
 * guest's own final link also carries `patina_yield.c`'s strong definitions,
 * which override these; the guest's hot path is byte-for-byte what it was, with
 * no added branch. Nothing here can mask a broken guest build: the strong hooks
 * carry the `PATINA_YIELD_POINTS_V1` marker that `cargo patina run` requires
 * before it will treat a binary as yield-instrumented, and these stubs
 * deliberately do not.
 */

#include <stdint.h>

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
                                                               uint32_t *stop) {
    (void)start;
    (void)stop;
}

__attribute__((weak)) void __sanitizer_cov_pcs_init(const uintptr_t *start,
                                                    const uintptr_t *stop) {
    (void)start;
    (void)stop;
}

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    (void)guard;
}
