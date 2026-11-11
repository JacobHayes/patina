//go:build !patina

package patina

import (
	"math/rand/v2"
	"sync"
)

func declareSite(uint8, site)             {}
func always(bool, site, []any)            {}
func sometimes(bool, site)                {}
func reachable(site)                      {}
func buggify(site, int32) bool            { return false }
func buggifyDelay(site) bool              { return false }
func knob(_ site, def, _, _ int64) int64  { return def }
func verdict(VerdictKind, string, string) {}
func setupComplete()                      {}
func lifecycleEvent(string)               {}

// IsSimulated reports whether the program runs under Patina: never, in a
// build without the `patina` tag.
func IsSimulated() bool { return false }

var (
	fallbackMu  sync.Mutex
	fallbackRng = rand.New(rand.NewPCG(0, 0))
)

// Rng is a 64-bit draw. Outside Patina it is a fixed-seed stream, so callers
// still get reproducible values without touching OS entropy.
func Rng() uint64 {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	return fallbackRng.Uint64()
}

// Param is the run parameter key; outside Patina there are none.
func Param(string) (string, bool) { return "", false }
