# Agent Guidance

**Patina** is an experimental deterministic execution and simulation-testing
(DST) runtime. It runs an unmodified Linux x86_64 executable: a runtime inside
each guest process traps every system call, the real kernel does the work in a
per-run bwrap sandbox, and one supervisor decides order, time, randomness,
faults and crashes from the seed. This file is what a builder needs: where
truth lives, how to build, check and land, and the invariants that hold
everywhere.

## Document map

| Document | Read it for |
|---|---|
| [crates/patina-cli/ENGINE.md](./crates/patina-cli/ENGINE.md) | how the engine works, each part pointing at its module |
| [docs/EVIDENCE.md](./docs/EVIDENCE.md) | what the engine has been shown to do: each claim, its command, date, host and result |
| [docs/SCOPE.md](./docs/SCOPE.md) | who Patina serves first and the rules new surface must meet |
| [README.md](./README.md) | the user-facing surface; must stay honest about status |
| Nearest `AGENTS.md` | the testbeds have their own |

When you change architecture or user-visible behavior, update the docs in the
same change. Docs describe the current state; history lives in git.
`AGENTS.local.md`, if present, holds local maintainer recipes and is gitignored.

## Layout

- `crates/patina-proto`: what the runtime and the supervisor must agree on (no_std).
- `crates/patina-rt`: the in-guest runtime, no_std, built for `x86_64-unknown-none`
  in its own workspace by `crates/patina-cli/build.rs` and embedded in the binary.
- `crates/patina-cli`: the `patina` binary (launcher, supervisor, CLI).
- `tests/<area>/`: the check scripts; `tests/guests/`: their guests.
- `crates/patina`, `go/patina`, `testbeds/`, `examples/`: not built yet (each
  README says so); they return when they are rebuilt on this engine.

Host requirements: Linux x86_64, `bwrap` on `PATH`, and unprivileged user
namespaces usable by bwrap (on Ubuntu 24.04:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`). The runtime
runs from a file under `$XDG_CACHE_HOME/patina` (default `~/.cache/patina`),
which must allow exec.

## Build, check and land

rustup installs the toolchain `rust-toolchain.toml` pins; mise supplies Go for
the Go guests.

- **The landing gate is `mise run check`**: `cargo fmt --check`,
  `cargo clippy -D warnings`, then `./check quick` (budget 5 minutes, fails above
  10). CI runs exactly this on one GitHub runner (`CHECK_SLOTS=4`).
- `./check AREA` runs one area (a directory under `tests/`) while you work on it;
  `./check list` lists every script with its tier and budget.
- Every check script declares `#@ tier=quick|area|evidence budget=SECONDS slots=N`
  in its header and must fail on a planted break: show it red, then green.
- **Evidence is never a gate.** A claim shown by volume (many seeds, a matrix, a
  soak) is run once by hand (`./check evidence NAME`, under
  `tests/<area>/evidence-*.sh`); its command, date, host and result go into
  `docs/EVIDENCE.md`. Nothing in `quick`, an area or CI calls it.
- **Budgets are fixed. Over budget, cut**: move a quick script to `area` or
  shrink it. Never raise a budget, add a shard, or add a retry. No script re-runs
  another area's scripts.
- Land by pushing the branch; when CI is green, fast-forward `main`. Keep
  commits targeted and linear.

A run that differs between repeats of one seed is a determinism bug until proven
otherwise: fix it, never retry it.

## Project doctrine

- **Fail closed, loudly.** An effect Patina does not control is a refusal or a
  named abort, never a silent fallback to the host.
- **Structure before tests.** Enforce an invariant by construction first: make
  the bad state unrepresentable (types, visibility, one choke point); failing
  that, a compiler or lint rule; only then a behavioural test that drives the
  product. Never scan or patch source text in a test.
- **Enforcement earns its cost.** Every test, lint, fixture and gate is code to
  read, run and maintain. Protect invariants whose violation is likely, costly
  and silent, with the smallest mechanism that does it, and stop there.
- **Detection before fixes.** A new bug class gets a detector that provably
  fires (red before, green after) with or before the point fix.
- **No cruft.** No deprecation aliases, compatibility shims, engine flags or dual
  code paths: migrate every caller and doc in the same change.
- **Determinism claims are verified, not asserted.** Byte-identical repeats and
  seed variation are the evidence; a check that cannot fail is a bug.
- **Core patina is guest-agnostic.** No guest-specific names or branches in
  `crates/`. What one guest needs lives in its test, example or harness.

## Conventions

- Write docs in clear, concise, present-tense language.
- Shell scripts are loud on failure and never pass vacuously.
- Measure rather than guess: quote a duration only when observed, and answer
  status questions from fresh evidence (logs, CI, the process table).
