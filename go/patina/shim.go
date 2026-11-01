//go:build patina

package patina

/*
#include <stddef.h>
#include <stdint.h>

// The native shim's SDK entries (crates/patina-native-shim/include/patina_native.h),
// resolved when `cargo patina build --go` links the shim beneath the guest.
int32_t patina_is_simulated(void);
int32_t patina_buggify(const uint8_t *label, size_t label_len,
                       const uint8_t *site, size_t site_len, int32_t prob_permille);
int32_t patina_buggify_delay(const uint8_t *label, size_t label_len,
                             const uint8_t *site, size_t site_len);
int64_t patina_buggify_knob(const uint8_t *label, size_t label_len,
                            const uint8_t *site, size_t site_len,
                            int64_t default_value, int64_t lo, int64_t hi);
int32_t patina_declare_site(uint8_t kind, const uint8_t *label, size_t label_len,
                            const uint8_t *site, size_t site_len);
int32_t patina_always(int32_t condition, const uint8_t *label, size_t label_len,
                      const uint8_t *site, size_t site_len);
int32_t patina_sometimes(int32_t condition, const uint8_t *label, size_t label_len,
                         const uint8_t *site, size_t site_len);
int32_t patina_reachable(const uint8_t *label, size_t label_len,
                         const uint8_t *site, size_t site_len);
uint64_t patina_rng(void);
intptr_t patina_param(const uint8_t *key, size_t key_len, uint8_t *out, size_t out_cap);
int32_t patina_lifecycle_setup_complete(void);
int32_t patina_lifecycle_event(const uint8_t *label, size_t label_len);
int32_t patina_verdict(uint32_t kind, const uint8_t *label, size_t label_len,
                       const uint8_t *detail, size_t detail_len);
int32_t patina_custom_op_begin(const uint8_t *label, size_t label_len, const uint8_t *key,
                               size_t key_len, int32_t fault_eligible, size_t *out_len);
intptr_t patina_custom_op_replay_result(uint8_t *out, size_t out_cap);
int32_t patina_custom_op_record(const uint8_t *result, size_t result_len);
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// data is a byte slice as the shim's (pointer, length) pair, under the same
// terms as text.
func data(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// text is a Go string as the shim's (pointer, length) pair. The bytes hold no
// Go pointers and the shim reads them only during the call.
func text(s string) (*C.uint8_t, C.size_t) {
	return (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(s))), C.size_t(len(s))
}

func flag(b bool) C.int32_t {
	if b {
		return 1
	}
	return 0
}

// refused fails loudly when the shim refuses a site call: a site the shim
// did not take is an oracle that silently checks nothing.
func refused(call string, s site, result C.int32_t) {
	if result < 0 {
		panic(fmt.Sprintf("patina: the shim refused %s for site %q at %s", call, s.label, s.where))
	}
}

func declareSite(kind uint8, s site) {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	refused("a declaration", s, C.patina_declare_site(C.uint8_t(kind), label, labelLen, where, whereLen))
}

func always(cond bool, s site, detail []any) {
	// The detail names the failing instance in a verdict of its own, reported
	// before the check ends the run.
	if !cond && len(detail) > 0 {
		// The verdict ABI takes UTF-8 only; a refused detail must not cost
		// the violation itself.
		verdict(Violation, s.label, strings.ToValidUTF8(fmt.Sprint(detail...), "\uFFFD"))
	}
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	refused("an Always check", s, C.patina_always(flag(cond), label, labelLen, where, whereLen))
}

func sometimes(cond bool, s site) {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	refused("a Sometimes check", s, C.patina_sometimes(flag(cond), label, labelLen, where, whereLen))
}

func reachable(s site) {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	refused("a Reachable mark", s, C.patina_reachable(label, labelLen, where, whereLen))
}

// IsSimulated reports whether the program runs under Patina.
func IsSimulated() bool { return C.patina_is_simulated() != 0 }

// Rng is a 64-bit draw from the run's seeded stream: under Patina a pure
// function of the seed, recorded and replayed with the run.
func Rng() uint64 { return uint64(C.patina_rng()) }

// Param is the run parameter key (`cargo patina run --param KEY=VALUE`),
// recorded in the trace and restored on replay; false when the run has none.
func Param(key string) (string, bool) {
	k, kLen := text(key)
	buf := make([]byte, 256)
	for {
		n := int(C.patina_param(k, kLen, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
		if n < 0 {
			return "", false
		}
		if n <= len(buf) {
			return string(buf[:n]), true
		}
		buf = make([]byte, n)
	}
}

func buggify(s site, permille int32) bool {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	fired := C.patina_buggify(label, labelLen, where, whereLen, C.int32_t(permille))
	refused("a Buggify evaluation", s, fired)
	return fired != 0
}

func buggifyDelay(s site) bool {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	delayed := C.patina_buggify_delay(label, labelLen, where, whereLen)
	refused("a BuggifyDelay evaluation", s, delayed)
	return delayed != 0
}

func knob(s site, def, low, high int64) int64 {
	label, labelLen := text(s.label)
	where, whereLen := text(s.where)
	return int64(C.patina_buggify_knob(label, labelLen, where, whereLen,
		C.int64_t(def), C.int64_t(low), C.int64_t(high)))
}

func verdict(kind VerdictKind, label, detail string) {
	l, lLen := text(label)
	d, dLen := text(detail)
	if C.patina_verdict(C.uint32_t(kind), l, lLen, d, dLen) < 0 {
		panic(fmt.Sprintf("patina: the shim refused verdict kind %d under %q", kind, label))
	}
}

func setupComplete() { C.patina_lifecycle_setup_complete() }

func lifecycleEvent(label string) {
	l, lLen := text(label)
	if C.patina_lifecycle_event(l, lLen) < 0 {
		panic(fmt.Sprintf("patina: the shim refused lifecycle event %q", label))
	}
}

// customOp drives the shim's custom-op protocol: begin says whether this is
// a record pass (perform, then record its bytes), a replay (fetch the
// recorded bytes, perform not run) or a seeded fault (the declared failure,
// perform not run). onFault present is the fault-eligibility declaration.
func customOp(label string, key []byte, onFault, perform func() []byte) []byte {
	l, lLen := text(label)
	k, kLen := data(key)
	eligible := C.int32_t(0)
	if onFault != nil {
		eligible = 1
	}
	var n C.size_t
	switch mode := C.patina_custom_op_begin(l, lLen, k, kLen, eligible, &n); mode {
	case 0:
		result := perform()
		r, rLen := data(result)
		if C.patina_custom_op_record(r, rLen) < 0 {
			panic(fmt.Sprintf("patina custom op %q: the runtime refused the recorded result", label))
		}
		if len(result) == 0 {
			return nil // as a replay of it returns
		}
		return result
	case 1:
		if n == 0 {
			return nil
		}
		result := make([]byte, int(n))
		r, rLen := data(result)
		if written := C.patina_custom_op_replay_result(r, rLen); written < 0 || C.size_t(written) != n {
			panic(fmt.Sprintf("patina custom op %q: the runtime returned %d bytes of a %d-byte recorded result",
				label, written, n))
		}
		return result
	case 2:
		if onFault == nil {
			panic(fmt.Sprintf("patina custom op %q: a fault on an operation that declared no failure", label))
		}
		return onFault()
	default:
		panic(fmt.Sprintf("patina custom op %q: the runtime refused the call (code %d)", label, mode))
	}
}
