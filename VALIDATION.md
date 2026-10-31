# Patina Validation

What Patina validates, how to run it, which guarantees the evidence supports, and
where that evidence stops. The tests are the index of individual checks: this
document names directories and evidence shapes, not test functions.

## Principles

1. **Test observable contracts.** Seeds, traces, replay failures, virtual effects
   and CLI behavior are public contracts. Internal conventions are enforced by
   types, visibility or lints, never by tests that scan or patch source text.
2. **Nondeterminism fails visibly.** A malformed trace,
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
| `mise run check` | the local landing gate: fmt, clippy (host and the other OS family's cfgs), docs, packaging, `cargo nextest run --workspace` (including the native acceptance and conformance tests), doctests, the native smoke, and the testbeds |
| `mise run check:native-abi` | just the native ABI integration tests |
| `mise run smoke` | native smoke checks |
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
- **Native smoke** (`scripts/smoke-native.sh`): one ordinary `std` program
  compared across seeds, record and replay, and cold and warm builds, plus a
  canonical result literal.
- **Testbeds** (`testbeds/`): dogfooding guests (workq, pubsub, FIFO IPC, cap-std,
  rustix, macro adopter, multiproc, Go) driven through the CLI; see
  `testbeds/README.md`.

## Capability levels

| Level | Scope | Status |
|---|---|---|
| V0 | workspace quality: the `mise run check` gate | standing |
| V1 | deterministic vertical slice at the explicit `Context` boundary | complete |
| V2 | cooperative scheduling, SimNet, wrappers, branching, async executor | complete |
| V3 | native linked-shim target: interposition, audit gate, threads, reactors, SUD | partial |
| V4 | trace hardening, crash models, host capture, minimization, budgets | partial |
| V5 | cooperative-SUT SDK (`buggify!`, `always!`, `sometimes!`) | partial |
| V6 | directed exploration: PCT, swarm, coverage-guided campaigns | partial |

A level is complete only when all its checks pass; higher levels never weaken
lower ones.

## Core guarantees and their oracles

**Seed determinism.** The same seed produces the same result and the same trace
bytes in independent processes, and some entropy-dependent result differs across
seeds. Oracle: byte comparison of repeated runs' output and traces, across
explicit-context, native and testbed guests.

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
`VACUOUS` campaign class naming its plane. Oracle: table-driven per-knob tests from the one
knob declaration, and vacuity tests per class.

**Crash consistency.** `CrashFs` rolls metadata back to the last ext4-style
journal commit and tears in-place overwrites per block with a seeded coin; an `fsync`, `sync` or `syncfs` failed by an injected EIO or ENOSPC drops
the dirty pages from writeback and reports once per open description per check,
as Linux's `errseq` does (`fsync` and a `WAIT`ing `sync_file_range` the file's,
`syncfs` the volume's), and `posix_fadvise(DONTNEED)` drops clean pages so a
re-read sees the disk;
and native `--machine-crash-permille`/`--process-crash-permille` restart a fresh incarnation whose handoff
replays against its recorded digest (`docs/crash-restart-protocol.md`).
Oracle: the fs-crash unit suite, native crash-restart record/replay, and a
native store that fails closed after a targeted (`--fs-error-at`) writeback
failure and re-reads the disk.

**Liveness.** A wedged run, frozen-clock churn or call-free compute starving a
timed peer stops with a `PATINA_VIOLATION liveness` finding and a replayable
terminal prefix. Oracle: planted spins (main thread, worker, allocator-held,
small stack) and parked/single-task controls that must not fire.

**Campaign classification.** The campaign classifier reads only the structured
`patina.result/v1` envelope, never guest text, and a reproduction it prints must
reproduce (`NONDETERMINISM` otherwise). Oracle: the campaign classifier unit tests,
which fire every class from planted envelopes.

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
  shim call are unsupported where delivery still runs over shim Rust frames
  (libc doors); only the trap handlers deliver from C. `native_signals`
  (`signals/frame_abandon.c`, `planted-faults` shim) pins each such delivery
  origin. Ambient host signals are outside the model.
- **Multi-process.** Process spawning is a non-goal: the spawn family deny-traps.
  `testbeds/multiproc` pins each workload's first refusal on x86_64 Linux; arm64
  and Darwin baselines are pending.
- **Conformance coverage** is Linux only and not exhaustive:
  `mise run conformance:coverage` lists the registry entries no scenario covers
  and no exclusion accounts for.
- **Filesystem allocation detail.** ext4 extent blocks, volume free-block
  accounting and page-cache residency are not modeled: `cachestat` counts every
  page of a file cached (a page `DONTNEED` dropped, or one over a hole never
  read, included), and `DONTNEED` leaves every page of a mapped file. A failed
  writeback loses all the dirty pages it covers, and a failed `sync`/`syncfs`
  still commits the metadata. A process-crash restart boots from the
  page cache as its disk, so pages a failed writeback dropped, and writeback
  errors nobody saw, do not reach the restarted incarnation. `CrashFs` models
  ext4 only: `fdatasync` commits like `fsync` (and so does every write through
  an `O_SYNC`/`O_DSYNC` description), background writeback (dirty expiry,
  memory pressure) never writes data on its own, and `O_DIRECT` is not
  modelled: an open asking for it stops the run by name.
- **Custom allocators.** Multi-threaded jemalloc has no automated end-to-end test.
- **Scope.** One record path is one finalized context, so multi-test aggregation
  is unsupported. Arbitrary host DNS, arbitrary FFI, dynamic loading and full
  POSIX compatibility are outside the confidence boundary. Native support covers
  single Rust sources and whole Cargo packages, not a recompiled deterministic
  `std`.
