/* The compute meter of a Python guest built by `cargo patina build --python`.
 *
 * Patina runs one guest thread at a time and moves virtual time by what
 * guest calls cost, so a thread computing without calls holds the thread:
 * the interpreter's own switch, the GIL holder dropping it when another
 * thread's timed wait for it ends, would never come, and nor would a timer.
 * The recipe compiles all of CPython with comparison instrumentation
 * (`-fsanitize-coverage=trace-cmp`), which calls the hooks below at each
 * comparison; every PATINA_PYTHON_METER_STRIDE of them on a thread are handed
 * to the shim (`patina_compute_point`), which charges them as virtual CPU
 * time and takes a scheduling point. The interpreter's eval breaker does the
 * rest, as the Go meter's preemptible loops do for Go.
 *
 * The countdown is `_Thread_local`, so the batches fall at the same
 * instructions on every run of a schedule and on its replay.
 *
 * Compiled twice: into the guest, and with PATINA_PYTHON_METER_INERT into the
 * programs CPython's own build links and runs on the host (the interpreter
 * that freezes the modules, and configure's test programs against the
 * instrumented zlib), where there is no shim and the hooks count nothing. The
 * inert hooks are weak, so a program linking the inert object twice links.
 * Never instrumented itself. */

#include <stdint.h>

#ifdef PATINA_PYTHON_METER_INERT
#define PATINA_TICK() ((void)0)
#define PATINA_HOOK __attribute__((weak)) void
#else
#define PATINA_HOOK void
extern void patina_compute_point(uint64_t units);

/* Comparisons between two scheduling points. */
#define PATINA_PYTHON_METER_STRIDE 4096

static _Thread_local uint32_t patina_python_meter_countdown = PATINA_PYTHON_METER_STRIDE;

static inline void patina_python_meter_tick(void) {
    if (--patina_python_meter_countdown == 0) {
        patina_python_meter_countdown = PATINA_PYTHON_METER_STRIDE;
        patina_compute_point(PATINA_PYTHON_METER_STRIDE);
    }
}
#define PATINA_TICK() patina_python_meter_tick()
#endif

PATINA_HOOK __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_cmpf(float a, float b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_cmpd(double a, double b) { (void)a; (void)b; PATINA_TICK(); }
PATINA_HOOK __sanitizer_cov_trace_switch(uint64_t value, uint64_t *cases) { (void)value; (void)cases; PATINA_TICK(); }
