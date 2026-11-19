// Package patina is Patina's SDK for Go: invariants, coverage sites, fault points, knobs and
// marks, reported to a Patina run through one reserved system call. Pure Go: no cgo, no build
// tag. Outside Patina the kernel answers the call ENOSYS; the first call learns that, and
// from then on every method is a load and a branch, so code ships the SDK unconditionally.
//
// Sites are declared once, as package-level values, so a run knows every site before main
// runs, whether or not it is ever reached:
//
//	var sorted = patina.Always("ledger-sorted")
//	var retried = patina.Sometimes("request-retried")
//	var dropFlush = patina.Buggify("flush-early-drop")
//
//	func settle(l []int) {
//		if dropFlush.Fires() {
//			return
//		}
//		sorted.Check(slices.IsSorted(l), "len ", len(l))
//	}
//
// Under Patina an Always that sees false ends the run with outcome violation and the message
// "label: detail". A passing check reports only the first time it is evaluated in a process (a
// Sometimes also the first time it holds), so a passing check costs one load. A fault point
// fires only with `patina run --buggify`, on evaluations chosen by the seed and its label
// alone; `--fault point:LABEL=PERMILLE` forces one point's rate.
//
// The wire is documented in sdk/c/patina.h of the Patina repository.
package patina

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode/utf8"
	"unsafe"
)

const (
	sysPatina    = 0x7061
	version      = 1
	helloBuggify = 1 << 16

	opHello   = 1
	opAssert  = 2
	opBuggify = 3
	opKnob    = 4
	opDelay   = 5
	opMark    = 6
	opDeclare = 7
	opControl = 10

	kindAlways    = 1
	kindSometimes = 2
	kindReachable = 3
	kindBuggify   = 4
	kindKnob      = 5
	kindDelay     = 6
	kindUnreach   = 7

	never    = 2
	hdrLen   = 32
	labelMax = 255
	textMax  = 4096

	// Site state bits: reported evaluated, reported held, never fires.
	bitEval  = 1
	bitHeld  = 2
	bitQuiet = 4
	bitAll   = bitEval | bitHeld | bitQuiet
)

// state: 0 not asked; else stAsked plus stOn (under Patina) and stBuggify.
var state atomic.Uint32

const (
	stAsked   = 1
	stOn      = 2
	stBuggify = 4
)

func sys(op uintptr, b []byte) int64 {
	var p unsafe.Pointer
	if len(b) > 0 {
		p = unsafe.Pointer(&b[0])
	}
	r, _, errno := syscall.Syscall(sysPatina, op, uintptr(p), uintptr(len(b)))
	if errno != 0 {
		return -int64(errno)
	}
	return int64(r)
}

func get() uint32 {
	if s := state.Load(); s != 0 {
		return s
	}
	r := sys(opHello, nil)
	ok := r >= 0 && r&0xffff == version
	if r >= 0 && !ok {
		fmt.Fprintln(os.Stderr, "patina: unknown SDK protocol version; the SDK is inert")
	}
	s := uint32(stAsked)
	if ok {
		s |= stOn
		if r&helloBuggify != 0 {
			s |= stBuggify
		}
	}
	state.Store(s)
	return s
}

// IsSimulated reports whether the process runs under Patina.
func IsSimulated() bool { return get()&stOn != 0 }

// call sends one payload; a is the header's first word, read back on success (a knob).
func call(op uintptr, kind uint8, cond bool, label, text string, a, b, c int64) (int64, int64) {
	if len(label) > labelMax {
		label = label[:labelMax]
	}
	if len(text) > textMax {
		// Cut on a character boundary, as the report shows it.
		n := textMax
		for n > 0 && !utf8.RuneStart(text[n]) {
			n--
		}
		text = text[:n]
	}
	buf := make([]byte, hdrLen+len(label)+len(text))
	buf[0] = kind
	if cond {
		buf[1] = 1
	}
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(label)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(text)))
	binary.LittleEndian.PutUint64(buf[8:], uint64(a))
	binary.LittleEndian.PutUint64(buf[16:], uint64(b))
	binary.LittleEndian.PutUint64(buf[24:], uint64(c))
	copy(buf[hdrLen:], label)
	copy(buf[hdrLen+len(label):], text)
	r := sys(op, buf)
	return r, int64(binary.LittleEndian.Uint64(buf[8:]))
}

// sdkPackage is this package's import path, which its frames' function names start with.
const sdkPackage = "github.com/JacobHayes/patina/go/patina"

type site struct {
	label string
	bits  atomic.Uint32
}

func (s *site) declare(kind uint8, label string) {
	if label == "" || len(label) > labelMax || !utf8.ValidString(label) {
		panic(fmt.Sprintf("patina: site label %q must be 1 to %d bytes of UTF-8", label, labelMax))
	}
	s.label = label
	if get()&stOn == 0 {
		s.bits.Store(bitAll)
		return
	}
	// The declaration is the first frame outside this package.
	where := ""
	pcs := make([]uintptr, 16)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if !strings.HasPrefix(f.Function, sdkPackage+".") {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
			break
		}
		if !more {
			break
		}
	}
	call(opDeclare, kind, false, label, where, 0, 0, 0)
}

// report sends a check. detail is formatted here, only for a failure, and never retained, so
// a caller's variadic slice stays on its stack.
func (s *site) report(kind uint8, cond bool, detail []any) {
	if get()&stOn == 0 {
		s.bits.Store(bitAll)
		return
	}
	b := uint32(bitEval)
	if cond {
		b |= bitHeld
	}
	s.bits.Or(b)
	text := ""
	if !cond && len(detail) > 0 {
		text = fmt.Sprint(detail...)
	}
	call(opAssert, kind, cond, s.label, text, 0, 0, 0)
}

func (s *site) point(op uintptr, kind uint8, a int64) bool {
	if s.bits.Load()&bitQuiet != 0 {
		return false
	}
	if get()&stBuggify == 0 {
		s.bits.Store(bitAll)
		return false
	}
	r, _ := call(op, kind, false, s.label, "", a, 0, 0)
	if r == never {
		s.bits.Or(bitQuiet)
	}
	return r == 1
}

// AlwaysSite is an invariant: its condition must hold every time it is checked.
type AlwaysSite struct{ site }

// Always declares an invariant site. Call it once per label, at package level.
//
//go:noinline
func Always(label string) *AlwaysSite {
	a := &AlwaysSite{}
	a.declare(kindAlways, label)
	return a
}

// Check reports cond and returns it. Under Patina a false cond ends the run as a violation;
// detail, formatted as fmt.Sprint does and only on a failure, names the failing instance.
func (a *AlwaysSite) Check(cond bool, detail ...any) bool {
	if !cond || a.bits.Load()&bitEval == 0 {
		a.slow(cond, detail)
	}
	return cond
}

// slow keeps Check small enough to inline.
//
//go:noinline
func (a *AlwaysSite) slow(cond bool, detail []any) { a.report(kindAlways, cond, detail) }

// UnreachableSite is a point that must not be reached. A run that never reaches it is not
// reported as unmet.
type UnreachableSite struct{ site }

// Unreachable declares a point that must not be reached. Call it once per label, at package
// level.
//
//go:noinline
func Unreachable(label string) *UnreachableSite {
	u := &UnreachableSite{}
	u.declare(kindUnreach, label)
	return u
}

// Reached reports that the point was reached: under Patina the run ends as a violation with
// "label: detail", detail formatted as fmt.Sprint does.
func (u *UnreachableSite) Reached(detail ...any) { u.report(kindUnreach, false, detail) }

// SometimesSite is a coverage oracle: its condition should hold on some runs.
type SometimesSite struct{ site }

// Sometimes declares a coverage site. Call it once per label, at package level.
//
//go:noinline
func Sometimes(label string) *SometimesSite {
	s := &SometimesSite{}
	s.declare(kindSometimes, label)
	return s
}

// Check notes the site evaluated, and held when cond is true. It returns cond.
func (s *SometimesSite) Check(cond bool) bool {
	if b := s.bits.Load(); b&bitEval == 0 || cond && b&bitHeld == 0 {
		s.slow(cond)
	}
	return cond
}

//go:noinline
func (s *SometimesSite) slow(cond bool) { s.report(kindSometimes, cond, nil) }

// ReachableSite is a coverage oracle for a point some run should reach.
type ReachableSite struct{ site }

// Reachable declares a reachability site. Call it once per label, at package level.
//
//go:noinline
func Reachable(label string) *ReachableSite {
	r := &ReachableSite{}
	r.declare(kindReachable, label)
	return r
}

// Mark notes the site reached.
func (r *ReachableSite) Mark() {
	if r.bits.Load()&bitEval == 0 {
		r.report(kindReachable, true, nil)
	}
}

// BuggifySite is a fault point: a path the program can take, taken on seed-chosen evaluations.
type BuggifySite struct{ site }

// Buggify declares a fault point. Call it once per label, at package level.
//
//go:noinline
func Buggify(label string) *BuggifySite {
	b := &BuggifySite{}
	b.declare(kindBuggify, label)
	return b
}

// Fires reports whether the point fires on this evaluation at the run's default rate. Outside
// Patina, and in a run without --buggify, it never does.
func (b *BuggifySite) Fires() bool { return b.point(opBuggify, kindBuggify, -1) }

// FiresWithProb is Fires at probability p (0 to 1) instead of the run default.
func (b *BuggifySite) FiresWithProb(p float64) bool {
	return b.point(opBuggify, kindBuggify, int64(math.Round(min(max(p, 0), 1)*1000)))
}

// DelaySite sleeps a seeded virtual time on seed-chosen evaluations.
type DelaySite struct{ site }

// BuggifyDelay declares a delay point. Call it once per label, at package level.
//
//go:noinline
func BuggifyDelay(label string) *DelaySite {
	d := &DelaySite{}
	d.declare(kindDelay, label)
	return d
}

// Delay sleeps between 1 ms and 5 s of virtual time (never real time) when the point fires,
// and reports whether it did.
func (d *DelaySite) Delay() bool { return d.point(opDelay, kindDelay, 0) }

// DelayUpTo is Delay with the sleep at most max nanoseconds.
func (d *DelaySite) DelayUpTo(maxNs int64) bool { return d.point(opDelay, kindDelay, maxNs) }

// KnobSite is a tunable a run sets within bounds, so each seed explores a configuration.
type KnobSite struct {
	site
	def, low, high int64
}

// Knob declares a tunable whose value is def outside Patina or without --buggify and, with
// it, a seed-chosen value in [low, high] for an active point. Call it once per label, at
// package level.
//
//go:noinline
func Knob(label string, def, low, high int64) *KnobSite {
	k := &KnobSite{def: def, low: low, high: high}
	k.declare(kindKnob, label)
	return k
}

// Value is the knob's value for this run.
func (k *KnobSite) Value() int64 {
	if get()&stBuggify == 0 {
		return k.def
	}
	r, v := call(opKnob, kindKnob, false, k.label, "", k.def, k.low, k.high)
	if r != 0 {
		return k.def
	}
	return v
}

// Mark names a point in the run's log.
func Mark(label string) {
	if get()&stOn != 0 {
		call(opMark, kindReachable, false, label, "", 0, 0, 0)
	}
}

// Control makes a control call in a run with several machines, e.g. Control("net cut a b"),
// with the words of patina ctl: nil, or the errno Patina answered (EPERM outside the driver's
// node, ENOENT for an unknown node, EINVAL for other words, EOPNOTSUPP for a later feature),
// or ENOSYS outside Patina.
func Control(words string) error {
	if get()&stOn == 0 {
		return syscall.ENOSYS
	}
	if len(words) == 0 || len(words) > textMax {
		return syscall.EINVAL
	}
	if r := sys(opControl, []byte(words)); r < 0 {
		return syscall.Errno(-r)
	}
	return nil
}

// SetupComplete marks the end of setup: with faults-after-setup, no fault fires before it.
func SetupComplete() { Mark("setup-complete") }
