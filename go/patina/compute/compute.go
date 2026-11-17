//go:build linux && (amd64 || arm64)

// Package compute gives a Go program compute points under Patina: a scheduling point, and
// virtual time, at every integer and string comparison the compiler instruments. Two lines:
//
//	import _ "github.com/JacobHayes/patina/go/patina/compute"
//
//	CGO_ENABLED=0 go build -gcflags=all=-d=libfuzzer ./cmd/app
//
// The flag makes the compiler call a hook before each integer comparison and each string
// comparison (strings.Compare, ==, strings.EqualFold) in every package it builds, the standard
// library included; the Go runtime and its internal packages are never instrumented. This
// package defines the hooks (runtime.libfuzzerTraceCmp1 and its nine siblings) by
// //go:linkname, without cgo and without a patched toolchain.
//
// Without the flag nothing calls the hooks: the linker drops them and the program is the
// stock program. With the flag and without this package the link fails, fail closed:
//
//	reference to undefined builtin "runtime.libfuzzerTraceCmp8" from package "..."
//
// means the program does not import this package (a blank import in package main is
// enough). A toolchain that refuses the //go:linkname fails the link naming one of the
// runtime.libfuzzer* symbols. `go test` binaries cannot use the flag with this package: the
// testing package's internal/fuzz defines the same symbols. Build a main package instead.
//
// Each hook call is an event. Under Patina an event decrements one word of the program's own
// memory, the cell, which the runtime refills; when it reaches 0 the thread enters the
// runtime with one raw system call and the seed may switch threads there. Each event costs
// 1 ns of virtual time. Outside Patina the first event's call fails (ENOSYS) and every hook
// is a load and a branch after it. The wire and the cell are documented in
// sdk/c/patina_compute.c of the Patina repository, which this package mirrors.
//
// The hooks run wherever the compiler put a comparison: on any goroutine, on the system
// stack, in code the runtime calls back (timers, finalizers, sync's pool cleanup during a
// stop of the world). So they are nosplit, allocate nothing, write no pointer (no write
// barrier), and compare nothing in Go (a comparison here would call a hook): the event, the
// hello and the system call are in assembly (compute_amd64.s, compute_arm64.s). After a
// compute point a hook may yield to a pending preemption (see preempt).
package compute

import _ "unsafe" // for go:linkname

// event counts one event: the cell's fast path, and its slow path when the cell runs out. It
// reports whether the slow path made a compute point while the runtime has asked the
// goroutine to stop (its stack guard is the runtime's preemption mark).
//
//go:nosplit
func event() bool

// preempt yields to the runtime's preemption request. Go preempts a goroutine that runs a loop
// without calls by a signal, and only where the signal finds it at an asynchronous safe point.
// Under Patina a signal is delivered when a thread leaves the runtime, which for a compute point
// is inside event: never a safe point. A spin-wait whose waker needs the same P (GOMAXPROCS=1,
// or every P busy) would never be preempted. So after a point, if the runtime has asked, the
// hook calls this function: its stack-check prologue takes the runtime's own preemption path
// (morestack), which yields when the goroutine may be preempted and returns otherwise. A
// goroutine's guard holds the mark only on a goroutine's own stack, never on the system or
// signal stack; between entersyscall and exitsyscall the mark is set too, but no instrumented
// code runs there (the syscall package's wrappers compare nothing).
//
//go:noinline
func preempt() { preemptCall() }

// preemptCall makes preempt a function with calls, which always has a stack check.
//
//go:noinline
func preemptCall() {}

//go:linkname libfuzzerTraceCmp1 runtime.libfuzzerTraceCmp1
//go:nosplit
func libfuzzerTraceCmp1(arg0, arg1 uint8, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceCmp2 runtime.libfuzzerTraceCmp2
//go:nosplit
func libfuzzerTraceCmp2(arg0, arg1 uint16, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceCmp4 runtime.libfuzzerTraceCmp4
//go:nosplit
func libfuzzerTraceCmp4(arg0, arg1 uint32, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceCmp8 runtime.libfuzzerTraceCmp8
//go:nosplit
func libfuzzerTraceCmp8(arg0, arg1 uint64, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceConstCmp1 runtime.libfuzzerTraceConstCmp1
//go:nosplit
func libfuzzerTraceConstCmp1(arg0, arg1 uint8, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceConstCmp2 runtime.libfuzzerTraceConstCmp2
//go:nosplit
func libfuzzerTraceConstCmp2(arg0, arg1 uint16, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceConstCmp4 runtime.libfuzzerTraceConstCmp4
//go:nosplit
func libfuzzerTraceConstCmp4(arg0, arg1 uint32, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerTraceConstCmp8 runtime.libfuzzerTraceConstCmp8
//go:nosplit
func libfuzzerTraceConstCmp8(arg0, arg1 uint64, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerHookStrCmp runtime.libfuzzerHookStrCmp
//go:nosplit
func libfuzzerHookStrCmp(arg0, arg1 string, fakePC uint) {
	if event() {
		preempt()
	}
}

//go:linkname libfuzzerHookEqualFold runtime.libfuzzerHookEqualFold
//go:nosplit
func libfuzzerHookEqualFold(arg0, arg1 string, fakePC uint) {
	if event() {
		preempt()
	}
}
