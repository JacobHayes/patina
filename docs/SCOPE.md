# Scope and priorities

What Patina builds next, what it refuses for now, and how to tell the two apart.
[INTENTS.md](../INTENTS.md) says what Patina is for; this page says what earns
work *now*. Builders cite it when they propose new surface, and reviewers check
proposals against it.

## Who Patina serves first

Applications whose bugs hide in time, scheduling, storage, the network or
crashes, across the stack, not only systems software:

- **Applications and services:** web backends, daemons, CLIs and tools that keep
  state on disk, talk over the network, run timers or use threads and async.
- **Systems software:** storage engines, embedded databases, write-ahead logs,
  replicated and distributed services. Patina supports them, with a caveat. This
  class usually has mature verification already (model checkers, formal
  methods), and its conformance demands are strict. Patina's pitch there is speed
  and reach: cheap, fast simulation of the real binary. It states its fidelity
  limits rather than claiming parity with those tools.

A suspected bug that turns out to be a Patina modelling gap is tolerable while
the model matures, provided the run's evidence lets it be root-caused and
confirmed outside the harness (see the skill's "a red verdict is a hypothesis").

**Languages, in order:** Rust; then Python and Go, each through its own
integration path. C and C++ are supported as the substrate those languages
stand on (runtimes, native extensions, libraries), not as targets of their own.

**Not now** (a named refusal, not a partial model):

- GUI applications. Terminal UIs come before GUIs when this reopens.
- JIT-compiled and managed runtimes (JVM, V8, .NET).
- Privileged or kernel-adjacent tools: containers, eBPF, ptrace, setuid.
  Applications that use io_uring *under the hood* are of interest later;
  io_uring as a product surface is not.
- Binaries not built with Patina's shim, including static binaries. They are
  refused at the pre-run audit. A preload profile for stock dynamically linked
  binaries is planned; static binaries wait for a target that needs them.

## Rules for new surface

1. **Evidence before breadth.** A new modelled call, mode or platform path cites a
   target workload that needs it: a description of the program shape, the named
   stop or profile hot spot it hit, and a minimal reproducer (MRE) when one can
   be made. The program itself need not be named. "Linux has it" is not evidence.
2. **"No" is cheap.** Outside the target profile, the answer is a clear named
   stop. Fail-closed exists so that saying no costs nothing.
3. **Determinism first, speed a close second.** Speed is a design goal. Designs
   and reviews state their cost on the hot path, and performance work is ranked
   by measured call frequency in target workloads, not by guesswork.
4. **Every feature pays rent.** Count its platform special cases, test time and
   trace-format impact. A feature that needs a special case per platform is
   redesigned or refused.
5. **Value before surface.** The next user-visible wins are:
   - running a project's own test suite unmodified;
   - multi-machine fault testing.

   Other work ranks behind what those two turn up.

## Where the evidence comes from

Patina's repository stays self-contained: its own testbeds and synthetic
workloads. Real target programs are exercised *outside* it, each through the
onboarding loop in the [agent skill](./skills/patina-dst.md):

1. Run the program's own test suite natively.
2. Run it under Patina with no faults, then classify every difference as a
   known limit or a Patina bug.
3. Only then add faults.

What comes back into the repository is anonymous:

- named stops that fired, and how often;
- hot calls;
- MREs, reduced into testbeds or conformance rows.

The broad syscall-conformance arc was the right move while every new program hit
a wall of gaps. Coverage is now broad enough that more breadth has diminishing
returns, so new coverage follows target workloads.

**Culling** is measured, not a campaign. Surface that no target exercises is a
candidate for removal when it carries significant complexity, or when cutting it
unlocks an architectural simplification.

## Platforms

Linux x86_64, Linux arm64 and macOS arm64 are all first-class.

- **One semantic core,** with a thin port per platform behind one interface:
  interception, startup hook, process-lifecycle vehicle, wait primitive and ABI
  translation. Never scattered `cfg` special cases.
- **macOS is a second ABI, not a copy of Linux.** Patina on macOS presents Darwin
  behaviour.
- **Parity:** a capability is done on every first-class platform, or it names the
  missing platform as a tracked, scheduled gap with a reason. Platform-neutral
  parts ship everywhere in the same change.
