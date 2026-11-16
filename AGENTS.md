# Agent guidance

Patina runs an unmodified Linux x86_64 program under a seed that decides scheduling, time,
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
- `crates/patina-rt`: the in-guest runtime, its own workspace, built for `x86_64-unknown-none`
  by `crates/patina-cli/build.rs` and embedded in the binary.
- `crates/patina-cli`: the `patina` binary: launcher, supervisor, CLI.
- SDKs: `crates/patina` (Rust), `sdk/c/patina.h`, `go/patina`, `sdk/python/patina.py`.
- `tests/AREA/*.sh`: check scripts; `tests/guests/`: the programs they run.
- `examples/`: small programs, one bug each; `testbeds/pubsub`: a larger tokio program for the nightly job.

Host: Linux x86_64, `bwrap`, unprivileged user namespaces (`patina doctor` says what is
missing). rustup installs the pinned toolchain; mise supplies Go.

## Checks and landing

- **Landing is `mise run check`**: `cargo fmt --check`, clippy with `-D warnings`, then
  `./check quick`. Quick's budget is 5 minutes and it fails above 10. CI runs exactly this.
  Land by pushing the branch; when CI is green, fast-forward `main`.
- **Evidence is never a gate.** A claim shown by volume (many seeds, a matrix, a soak) is a
  `tests/AREA/evidence-*.sh` script run once by hand (`./check evidence NAME`); its command,
  date, host and result go into `docs/EVIDENCE.md`. Nothing in quick, an area or CI calls it.
- **Budgets are fixed by cutting.** Over budget, shrink a script or move it to `area`. Never
  raise a budget, add a shard or add a retry. No script re-runs another area's scripts.
- Every script declares `#@ tier=quick|area|nightly|evidence budget=SECONDS slots=N` and must
  fail on a planted break: show it red, then green.
- `./check AREA` runs one area; `./check nightly` is the scheduled job
  (`testbeds/pubsub` at 200 seeds, not required); `./check list` shows every script.

A run that differs between repeats of one seed is a determinism bug until proven otherwise:
find it, never retry it.

## Rules

- **Fail closed.** An effect Patina does not control is a refusal or a named stop, never a
  silent pass-through to the host.
- **Structure before tests.** Make the bad state unrepresentable first; then a lint; then a
  behavioural test. Never scan or patch source text in a test, and never assert wording or
  counts of docs.
- **Enforcement earns its cost.** Every test and gate is code to maintain; protect what is
  likely, costly and silent, with the smallest mechanism.
- **Detection before fixes.** A new bug class gets a check that fires before the fix lands.
- **No cruft.** No aliases, compatibility paths or engine flags; migrate every caller and doc
  in the same change.
- **The core is guest-agnostic.** No program-specific names or branches in `crates/`.
- **New surface needs a program that needs it**: the stop it hit and a small reproducer.
  Outside that, the answer is a clear refusal.
- Shell scripts fail loudly and never pass vacuously. Quote durations only when measured.
