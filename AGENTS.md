# Agent guidance

Patina runs an unmodified Linux program (x86_64 or arm64) under a seed that decides scheduling, time,
randomness, faults and crashes. This file is what a builder needs: where things are, how to
check and land, and the rules that hold everywhere.

## Documents

| Document | For |
|---|---|
| [README.md](README.md) | users: install, first run, outcomes |
| [docs/GUIDE.md](docs/GUIDE.md) | users: every workflow, with real output |
| [ARCHITECTURE.md](ARCHITECTURE.md) | how it works, each part pointing at its module; limits |
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | measured results: claim, command, date, host, result |
| [examples/README.md](examples/README.md) | one small program per kind of bug |

Flags and commands: `patina --help --format json` is the source of truth (`cli.rs`, which
the parser reads too). Docs describe the present; history is in git. A change to behaviour
updates the docs in the same commit.

## Layout

- `crates/patina-proto`: what the runtime and supervisor agree on (no_std).
- `crates/patina-rt`: the in-guest runtime, its own workspace, built for the host's bare target
  (`x86_64-unknown-none`, `aarch64-unknown-none-softfloat`) by `crates/patina-cli/build.rs` and
  embedded in the binary. What differs by architecture (entry, the syscall stub, the signal
  frame, the clone trampoline, instruction sites, the spin probe's stepper, the guest copy) is
  in `src/arch/<arch>/`, both exporting the same names (`src/arch/mod.rs`).
- System call numbers by name: `proto::nr` (generated, one table per architecture); structure
  layouts and flags that differ by architecture: `proto::abi`; arm64's successor decoder and
  signal-frame records: `proto::step`, `proto::sigrec` (tested on every host).
- `crates/patina-cli`: the `patina` binary: launcher, supervisor, CLI.
- SDKs: `crates/patina` (Rust), `sdk/c/patina.h`, `go/patina`, `sdk/python/patina.py`.
- `tests/AREA/*.sh`: check scripts; `tests/guests/`: the programs they run. A script marked
  `arch=x86_64` in its `#@` line is skipped on other machines (`tests/run.py`): the branch
  counter scripts, x86-only instructions, a seed found on x86_64, and evidence scripts not
  yet run on arm64; each says why in its header or in docs/EVIDENCE.md.
- `examples/`: small programs, one bug each; `testbeds/pubsub`: a larger tokio program for the release tier.

Host: Linux x86_64 or arm64 (arm64: ARCHITECTURE "Limits"), unprivileged user namespaces
(`patina doctor` says what is missing, and on Ubuntu 24.04 and later prints the AppArmor
profile command). rustup installs the pinned toolchain; mise
supplies Go. arm64 changes are developed against a Linux arm64 VM and accepted on the hosted
arm runner (`check-arm64`). On hosts that restrict unprivileged user namespaces, dev builds need
a profile for the paths they run from (`patina doctor` prints it); a copy run from elsewhere
(a scratch directory, an install prefix) is refused there until its path has one.

## Checks and landing

- **Tiers**: `quick` gates every landing (target 5 minutes on the arm64 runner, fails above 10;
  `scripts/land` fails it past half that on four sandboxes here); `./check AREA` runs an area's
  quick and `area` scripts while working on it; `release` gates a release and runs nightly
  (examples at 200 seeds, a determinism matrix, F2, pubsub, the node, signal, mapping and
  rewrite sweeps, install, doctor, replay; fails above 10 minutes); `evidence` is by hand.
  `./check list` shows every script; each tier run ends with its time and share of the ceiling.
- **Quick scripts are smoke checks of seconds**: per area the cheapest check that catches a gross
  break, on a seed or two. Sweeps over many seeds, planted-bug matrices and `verify --vary`
  repetitions go in `area` or `release` (or run fuller there: scripts see `CHECK_TIER`). A new
  quick script states its expected time on the arm64 runner in its header.
- **The gate is `mise run check`**: fmt, clippy `-D warnings`, `tests/lint.py`, `./check quick`;
  CI runs it on x86_64 (`check`) and arm64 (`check-arm64`). **Land with `scripts/land BRANCH`**
  (`--dry-run` first): it rebases, runs the gate, pushes BRANCH, needs both jobs green on the
  first attempt, fast-forwards `main` and deletes BRANCH. Never move `main` by hand. A change to
  `crates/patina-rt` or `crates/patina-proto` also runs `./check counters` there: CI's x86_64
  runners have no CPU whose branch counters are supported, so a host that has one is the only
  place their exactness is checked (land says whether it ran or was skipped).
- **A check tests the build it just made.** `./check` stops on a failed patina or guest build;
  `tests/run.py` prints the build under test and refuses a binary older than its sources. A
  planted break that does not compile proves nothing unless the check failed on it.
- **Scripts run strict.** `tests/run.py` runs every check script under `bash -euo pipefail`
  (`inherit_errexit`) whatever its first line; every other script says `set -euo pipefail;
  shopt -s inherit_errexit` (`install.sh` and `examples/checks/` stay POSIX `sh`, `set -eu`).
  An expected failure is written out (`if ! cmd`, `cmd || [ $? = 1 ]`, `st=0; cmd || st=$?`);
  `tests/lint.py` rejects what strict mode cannot see: `|| true` on a pipe or a captured value,
  a negated pipe, `$(...)` that `[ ]` passes on failure, `rm -r "$VAR"` without `:?`, plain `sh`.
- **Doc transcripts are checked.** A fenced block in README.md, docs/GUIDE.md or
  examples/README.md that shows what a command prints carries `<!-- transcript NAME ... -->`
  (or `<!-- no-run NAME: REASON -->`) and runs in the quick tier (a sweep of many runs is
  `release-only`): exactly on the kind of host its numbers were written on, with numbers as N
  elsewhere (`tests/docs/transcripts.py` says how to mark one). A doc change that shows output
  passes `./check docs` (`./check release` for a release-only block).
- **Evidence is never a gate.** A claim shown by volume (many seeds, a matrix, a soak) is a
  `tests/AREA/evidence-*.sh` script run once by hand (`./check evidence NAME`); its command,
  date, host and result go into `docs/EVIDENCE.md`. Nothing in quick, an area or CI calls it.
- **Budgets are fixed by cutting.** Over budget, shrink a script or move it to `area`. Never
  raise a budget, add a shard or add a retry. No script re-runs another area's scripts.
- Every script declares `#@ tier=TIER[,TIER] budget=SECONDS slots=N` (and `arch=MACHINE` when
  it runs on one architecture only) and must fail on a planted break: show it red, then green.
- **No wall clock, fixed sleeps or pinned seeds in tests** (`tests/lint.py`): assert virtual
  time, poll for the condition, search a seed range. An exception says why on its line.
- Builders run under a resource wrapper (memory cap, CPU weight, a scratch-size cap) and delete
  their scratch at hand-back; sweeps keep only failures.

A run that differs between repeats of one seed is a determinism bug until proven otherwise:
find it, never retry it.

## Rules

- **Fail closed.** An effect Patina does not control is a refusal or a named stop, never a
  silent pass-through to the host.
- **Structure before tests.** Make the bad state unrepresentable first; then a lint; then a
  behavioural test. Never scan or patch source text in a test, and never assert wording or
  counts of docs (the one exception: `./check docs`, our docs' transcripts against our tool).
- **Enforcement earns its cost.** Every test and gate is code to maintain; protect what is
  likely, costly and silent, with the smallest mechanism.
- **Detection before fixes.** A new bug class gets a check that fires before the fix lands.
- **No cruft.** No aliases, compatibility paths or engine flags; migrate every caller and doc
  in the same change.
- **The core is guest-agnostic.** No program-specific names or branches in `crates/`.
- **New surface needs a program that needs it**: the stop it hit and a small reproducer.
  Outside that, the answer is a clear refusal. A system call's pointer arguments are
  described in its table row (`ins`, `outs`, `refs`): the runtime refuses those that point
  into its own region.
- Shell scripts fail loudly and never pass vacuously. Quote durations only when measured.
