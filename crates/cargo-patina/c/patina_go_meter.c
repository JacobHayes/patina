/* The compute meter of a Go guest built by `cargo patina build --go`.
 *
 * WHY THIS EXISTS. Patina runs one guest thread at a time and moves virtual
 * time by what guest calls cost, so a goroutine computing without calls would
 * hold the thread forever: its timers never come due, and sysmon, which
 * preempts it natively, never runs. The Go build compiles every package
 * outside the runtime with Go's libFuzzer instrumentation (`-d=libfuzzer`),
 * which calls the hooks below at each integer comparison. A comparison is the
 * meter's unit of work: every PATINA_GO_METER_STRIDE of them on a thread are
 * handed to the shim (`patina_compute_point`), which charges them as virtual
 * CPU time and takes a scheduling point. Go's own preemption then does the
 * rest: sysmon sees the goroutine run past its time slice and asks it to
 * yield, which a loop's back edge notices (GOEXPERIMENT=preemptibleloops).
 *
 * DETERMINISM. The countdown is `_Thread_local`: a thread's comparisons
 * between two scheduling points are a pure function of the schedule the seed
 * chose, so the batches fall at the same instructions on every run and on
 * replay. The stride is a constant of this object, stamped into the marker
 * below.
 *
 * The libFuzzer entry points that carry no work (the counter and pc-table
 * registrations) do nothing: the edge counters stay inline in the guest.
 * Linked only on the Go build path; never instrumented itself.
 */

#include <stdint.h>

/* Provided by the patina-dst-native-shim staticlib. */
extern void patina_compute_point(uint64_t units);

/* Comparisons between two scheduling points. */
#define PATINA_GO_METER_STRIDE 4096

#define PATINA_STRINGIFY_(x) #x
#define PATINA_STRINGIFY(x) PATINA_STRINGIFY_(x)

/* The build-mode marker `cargo patina run` scans for. */
__attribute__((used, retain))
static const char PATINA_GO_METER_MARKER[] =
    "PATINA_GO_METER_V1 stride=" PATINA_STRINGIFY(PATINA_GO_METER_STRIDE) ";";
const char *volatile patina_go_meter_anchor;

static _Thread_local uint32_t patina_go_meter_countdown = PATINA_GO_METER_STRIDE;

static inline void patina_go_meter_tick(void) {
    if (--patina_go_meter_countdown == 0) {
        patina_go_meter_countdown = PATINA_GO_METER_STRIDE;
        patina_compute_point(PATINA_GO_METER_STRIDE);
    }
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; patina_go_meter_tick(); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; patina_go_meter_tick(); }

/* A string comparison that differed: one unit, like an integer one. */
void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1, const char *s2, int result) {
    (void)caller_pc; (void)s1; (void)s2; (void)result;
    patina_go_meter_tick();
}

/* The runtime registers its edge counters and pc table at start-up. */
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
    (void)start; (void)stop;
    patina_go_meter_anchor = PATINA_GO_METER_MARKER;
}

void __sanitizer_cov_pcs_init(const uintptr_t *start, const uintptr_t *stop) {
    (void)start; (void)stop;
}
