# Patina Validation

What Patina validates, how to run it, which guarantees the evidence supports, and
where that evidence stops. The tests are the index of individual checks: this
document names directories and evidence shapes, not test functions.

## Principles

1. **Test observable contracts.** Seeds, traces, replay failures, virtual effects
   and CLI behavior are public contracts. Internal conventions are enforced by
   types, visibility or lints, never by tests that scan or patch source text.
2. **Nondeterminism fails visibly.** A missing driver, malformed trace,
   incompatible fingerprint, mismatched operation or unconsumed replay event fails
   the run. There is no permissive fallback.
3. **Repetitions are independent.** Reproducibility means separate processes
   produce the same bytes, not that one object answers twice.
4. **Replay is stricter than a seed rerun.** It checks the exact ordered stream of
   boundary operations.
5. **A check that cannot fail is a bug.** Detectors are proven by a planted
   failure (red before, green after); knobs report whether they fired.

## Running it

| Command | What it runs |
|---|---|
| `mise run check` | the local landing gate: fmt, clippy (host and the other OS family's cfgs), docs, packaging, `cargo nextest run --workspace` (including the native acceptance and conformance tests), doctests, WASI validation, cross-target smoke, and the testbeds |
| `mise run check:native-abi` | just the native ABI integration tests |
| `mise run smoke` | native, WASI and cross-target smoke checks |
| `mise run conformance` | syscall conformance scenarios, natively and under Patina |
| `mise run conformance:coverage` | registry entries no scenario covers or excludes (a report; exits 1 while any remain) |
| `mise run audit-corpus` | ecosystem symbol-audit corpus against committed per-platform expectations |
| `mise run bench` | native-versus-Patina overhead measurement (not a gate) |

CI runs the workspace suite and testbeds on Linux x86_64 and aarch64 and on
macOS, plus the audit corpus. Evidence is platform-local: a Linux run does not
verify the Darwin legs, and trace hashes are not compared across operating
systems.

## Where the tests live

- **Crate unit tests** (`crates/*/src`, `crates/*/tests`): ABI serialization,
  each driver, scheduler policies, trace validation, runtime modes, reducers, the
  import audit and instruction scan, the syscall registry.
- **CLI end-to-end** (`crates/cargo-patina/tests/end_to_end/`): fixture packages
  built and run through `cargo patina` in separate processes: record/replay,
  branching, faults, SDK reports, campaigns, minimization, help and flags.
- **Native acceptance** (`crates/cargo-patina/tests/native_*.rs`, guests in
  `testbeds/native-boundary/`): ABI, workloads, containment, raw syscalls,
  signals, whole-run tracing and conformance. The map is in
  `testbeds/native-boundary/README.md`.
- **Syscall conformance** (`crates/patina-conformance`): one scenario per
  behavior, run natively (the oracle) and under Patina through every vehicle the
  architecture has.
- **WASI** (`crates/patina-wasi-host`, `scripts/validate-wasi.sh`): real
  `wasm32-wasip1` probes.
- **Cross-target** (`scripts/smoke-cross-target.sh`): one ordinary `std` program
  compared across WASI, native and replay, plus a canonical result literal.
- **Testbeds** (`testbeds/`): dogfooding guests (workq, pubsub, FIFO IPC, cap-std,
  rustix, macro adopter, multiproc, Go) driven through the CLI; see
  `testbeds/README.md`.

## Capability levels

| Level | Scope | Status |
|---|---|---|
| V0 | workspace quality: the `mise run check` gate | standing |
| V1 | deterministic vertical slice at the explicit `Context` boundary | complete |
| V2 | cooperative scheduling, SimNet, wrappers, branching, async executor | complete |
| V3 | WASI Preview 1: the whole audited import surface | complete |
| V4 | native linked-shim target: interposition, audit gate, threads, reactors, SUD | partial |
| V5 | trace hardening, crash models, host capture, minimization, budgets | partial |
| V6 | cooperative-SUT SDK (`buggify!`, `always!`, `sometimes!`), native and WASI | partial |
| V7 | directed exploration: PCT, swarm, starvation, coverage-guided campaigns | partial |

A level is complete only when all its checks pass; higher levels never weaken
lower ones.

## Core guarantees and their oracles

**Seed determinism.** The same seed produces the same result and the same trace
bytes in independent processes, and some entropy-dependent result differs across
seeds. Oracle: byte comparison of repeated runs' output and traces, across
explicit-context, WASI, native and testbed guests.

**Strict record/replay.** A recorded run replays flag-free to the same output and
consumes every event. Replay checks, in order: structure, native build identity
(executable and `cargo-patina` digests), compatibility fingerprint, operation
equality at every boundary call, driver outcome equality, and no trailing events.
A bundle of any other format version is refused. Oracle: replay of real
recordings plus planted mutations of each field, which must fail by name.

**Fail-closed containment (native).** A guest reaches the host only through
modeled effects. Before exec, a default-deny import audit refuses any unknown
symbol, and an instruction scan refuses raw syscalls, timestamp-counter,
entropy and thread-pointer instructions outside the managed paths. At run time,
interposed-but-unsupported calls abort loudly, and on Linux SUD traps inline
syscalls. Oracles: one planted escape per class
(`crates/patina-target/ESCAPE-CLASSES.md`), and on Linux a whole-run `strace`
pass over a `std` guest that must show no host effect syscalls, with a planted
`openat` proving the pass can fail.

**Host-equivalent Linux semantics.** A modeled syscall answers as the pinned
kernel does. Oracle: the conformance scenarios, comparing a native run's
observations live against the same scenario under Patina, exact except for each
scenario's declared normalizations and gaps. The comparison is authoritative only
on the pinned system (Ubuntu 24.04, kernel 6.8, glibc 2.39) and report-only
elsewhere.

**Fault and exploration knobs are not inert.** Every fault, schedule, swarm and
buggify knob is recorded in the trace, authoritative on replay, folded into the
fingerprint where it changes behavior, and accepted by every family or refused by
name. Each knob emits a report, and a knob that never fired is a warning or a
`VACUOUS_*` campaign class. Oracle: table-driven per-knob tests from the one
knob declaration, and vacuity tests per class.

**Crash consistency.** `CrashFs` rolls back to the durable image with seeded torn
writes, and native `--fs-crash-at` restarts a fresh incarnation whose handoff
replays against its recorded digest (`docs/fs-crash-restart-protocol.md`).
Oracle: the fs-crash unit suite and native crash-restart record/replay.

**Liveness.** A wedged run, frozen-clock churn or call-free compute starving a
timed peer stops with a `PATINA_VIOLATION liveness` finding and a replayable
terminal prefix. Oracle: planted spins (main thread, worker, allocator-held,
small stack) and parked/single-task controls that must not fire.

**Campaign classification.** The campaign classifier reads only the structured
`patina.result/v1` envelope, never guest text, and a reproduction it prints must
reproduce (`NONDETERMINISM` otherwise). Oracle: `cargo patina campaign --selftest`,
which fires every class from planted envelopes.

**SDK inertness.** Outside a Patina build every SDK macro is a no-op, and with
buggify off a rebuilt guest reproduces its canonical result. Oracle: the
`patina-dst` crate's own tests built without `cfg(patina)`, and a testbed's
canonical seed hash.

A failure report keeps the command, seed, trace bundle, Patina and Rust
versions, target triple and fingerprint.

## Known gaps

- **macOS inline syscalls.** No runtime containment check exists: `ktrace`
  cannot ground a sound gate. macOS relies on the import audit and instruction
  scan, which miss commpage time reads and novel encodings.
- **Darwin heap and main-stack addresses** vary between same-seed runs. libmalloc
  seeds its regions from an exec-time string the shim cannot reach, and the
  runtime shares that heap because Darwin's linker has no `--wrap`. Image and
  thread-stack addresses are fixed.
- **Tuned detector constants.** The vacuous-schedule floor and
  `SCHEDULE_MIN_BOUNDARIES` are calibrated numbers; a change in std's thread
  scaffolding cost could cause silent false negatives.
- **macOS guest `dlsym`** of a blocked symbol the shim does not define (e.g.
  `killpg`) has no detector. It needs a guest that hand-writes `dlsym`.
- **`mmap(MAP_SHARED)` without the POSIX layer** is invisible to the symbol
  audit.
- **Signal handlers leaving by `siglongjmp`/`setcontext`** while interrupting a
  shim call skip live shim frames. This is unsupported until the
  [signal frame safety](docs/arcs/signal-frame-safety.md) port lands. Ambient host
  signals are outside the model.
- **Multi-process.** Process spawning is a non-goal: the spawn family deny-traps.
  `testbeds/multiproc` pins each workload's first refusal on x86_64 Linux; arm64
  and Darwin baselines are pending.
- **Conformance coverage** is not exhaustive: `mise run conformance:coverage`
  lists the registry entries still uncovered.
- **Filesystem allocation detail.** ext4 extent blocks, volume free-block
  accounting and the volume page cache are not modeled. `CrashFs` renames are
  always atomic, and directory-durability loss covers explicitly created entries
  only.
- **Custom allocators.** Multi-threaded jemalloc has no automated end-to-end test.
- **Scope.** One record path is one finalized context, so multi-test aggregation
  is unsupported. Arbitrary host DNS, arbitrary FFI, dynamic loading and full
  POSIX compatibility are outside the confidence boundary. Native support covers
  single Rust sources and whole Cargo packages, not a recompiled deterministic
  `std`.
