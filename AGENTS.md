# Agent Guidance

**Patina** is an experimental deterministic execution and simulation-testing
(DST) runtime. This file is what a builder needs: where truth lives, how to
build, test and land, and the invariants that hold everywhere.

## Document map

| Document | Read it for |
|---|---|
| [INTENTS.md](./INTENTS.md) | goals, non-goals, trade-offs, design principles |
| [docs/SCOPE.md](./docs/SCOPE.md) | who Patina serves first and the rules new surface must meet; cite it when proposing new surface |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | crate boundaries, targets, drivers, traces, the native shim |
| [VALIDATION.md](./VALIDATION.md) | what is validated, the guarantees and their oracles, known gaps |
| [README.md](./README.md), [TUTORIAL.md](./TUTORIAL.md), [USAGE-MODES.md](./USAGE-MODES.md), `llms.txt` | the user-facing surface; must stay honest about status |
| [docs/skills/patina-dst.md](./docs/skills/patina-dst.md) | the skill handed to agents *using* Patina; it teaches how to discover the surface, not a flag catalog |
| [crates/patina-target/ESCAPE-CLASSES.md](./crates/patina-target/ESCAPE-CLASSES.md) | the guest-escape taxonomy behind the audit gate |
| Nearest `AGENTS.md` | the native shim and the testbeds each have their own |

When you change intent, architecture or user-visible behavior, update the docs
in the same change. Docs describe the current state; history lives in git.
`AGENTS.local.md`, if present, holds local maintainer recipes and is gitignored.

## Build, test and land

rustup installs the toolchain `rust-toolchain.toml` pins; mise supplies nextest
and ast-grep, so run cargo and the repository scripts through `mise run` or
`mise exec --`.

1. **Iterate** with `mise run check`: format, host clippy, then the tests you
   name. Its arguments go to nextest (`-p patina-dst-runtime`,
   `-p cargo-patina --test native_abi`, `-E 'test(/replay/)'`); with none it
   runs the workspace suite. `patina` embeds the shim's C sources, so
   rebuild it after touching the C layer.
2. **Land** by pushing the branch. CI is the gate: the suite and the testbeds
   on Linux x86_64 and aarch64 and on macOS. When it is green, fast-forward
   `main`. Keep commits targeted and linear.
3. **Before pushing a broad change** you can run `mise run check:full`:
   everything this host can check, including clippy for the other platforms'
   cfgs and the testbeds. It is there to save a CI round trip, not a required
   step.
4. **Get an independent review** before landing a change to the native shim,
   to record/replay or scheduling determinism, or to the containment boundary
   (audit, instruction scan, traps). Other changes land on green CI.
5. **Release** by setting the workspace version (`workspace.package` and the
   `workspace.dependencies` entries in `Cargo.toml`, and the tags the README
   and tutorial show), landing that, and pushing the tag `vX.Y.Z` on it:
   `.github/workflows/release.yml` builds, smokes and publishes. Run that
   workflow by hand first; it does everything but publish.

A test that flakes under Patina is a determinism bug until proven otherwise:
fix it, never retry it. Prove a behavior change with a planted failure: the
check must go red without the fix.

## The CLI

`patina` is verb-first (`build`, `run`, `test`, `audit`, `replay`,
`campaign`, `coverage`, `trace`, `minimize`, `syscalls`). Never guess a flag:
ask the binary, whose help is progressive (the index, then per-verb detail).

```sh
cargo run -q -p cargo-patina -- --help [--format json]
cargo run -q -p cargo-patina -- run --help [--format json]
```

The registry in `crates/cargo-patina/src/help.rs` and its `help/` modules is the
single source for the help text and the parsers: add a flag there and nowhere
else. `PATINA_<FLAG>` defaults a registry flag and is derived for free;
`PATINA_RT_*` is the supervisor-to-guest control plane, and a new control-plane
variable takes that prefix. Execution verbs accept `--format json`
(`patina.result/v1`); prefer it when parsing results.

## Project doctrine

- **Fail closed, loudly.** An unmodeled effect is a refusal or a named abort,
  never a silent fallback to the host.
- **Structure before tests.** Enforce an invariant by construction first: make
  the bad state unrepresentable (types, visibility, one choke point); failing
  that, a compiler or lint rule; only then a behavioural test that drives the
  product. Never scan or patch source text in a test. Need a fault for a test?
  Use a test-only hook compiled into the product, not a patched copy.
- **Enforcement earns its cost.** Every test, lint, fixture and gate is code to
  read, run and maintain. Protect invariants whose violation is likely, costly
  and silent, with the smallest mechanism that does it, and stop there. A
  review finding is an input, not a mandate: decline a fix whose machinery
  outweighs the risk, and say why.
- **Detection before fixes.** A new bug class gets a detector that provably
  fires (red before, green after) with or before the point fix. A false
  positive from an observer is fixed in the observer, never suppressed.
- **No cruft.** No deprecation aliases, compatibility shims or dual code paths:
  migrate every caller and doc in the same change.
- **Determinism claims are verified, not asserted.** Byte-identical repeats,
  record-to-replay identity and seed variation are the evidence; a check that
  cannot fail is a bug.
- **Core patina is guest-agnostic.** No testbed- or guest-specific identifiers
  or workaround branches in `crates/*`. What one guest needs for classification
  or configuration belongs in its campaign spec or testbed scripts.

## Conventions

- Crate directories are `crates/patina-*`; published packages are
  `patina-dst-*` (`crates/patina-runtime` is `patina-dst-runtime`), and the SDK
  at `crates/patina` is `patina-dst`, used as `patina_dst::`.
- The two families are **cargo** (an in-process Cargo package or test) and
  **native** (a shim-linked binary).
- Write docs in clear, concise, present-tense language.
- Shell scripts are loud on failure and never pass vacuously.
- Measure rather than guess: quote a duration only when observed, and answer
  status questions from fresh evidence (logs, CI, the process table).
- When hunting bugs with Patina, a clean result counts only behind oracles
  proven live; report it with that evidence.
