//go:build patina

package patina

/*
#include <stddef.h>
#include <stdint.h>

// The native shim's SDK entries (crates/patina-native-shim/include/patina_native.h),
// resolved when `cargo patina build --go` links the shim beneath the guest.
int32_t patina_is_simulated(void);
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
*/
import "C"

import (
	"fmt"
	"unsafe"
)

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

func always(cond bool, s site) {
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
