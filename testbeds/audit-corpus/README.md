# audit-corpus — the ecosystem symbol-audit corpus (strict-xfail)

Twenty minimal reproducers (MREs), one per widely-used crate, each built and
audited through the packaged native path (`cargo patina audit`). The corpus is a
**strict-xfail gate**: the residual set of unsupported native imports for each
crate is pinned in a committed, per-platform expectation file, and any deviation
in **either** direction fails the gate. It is the standing punchlist for the
symbol-classification / interposition work — every dirty entry is an item still
to be covered, and every clean entry is a promise that must not regress.

## Layout

```
audit-corpus/
  crates/<name>/            one standalone MRE package per crate
    Cargo.toml              has its OWN empty [workspace] table -> NOT a member
                            of the root Patina workspace
    Cargo.lock              committed, version-pinned (see "Bumping" below)
    src/main.rs             the reproducer (exercises the crate's escaping path)
  expected/
    <name>.macos.txt        recorded macOS expectation (this file's contents are
                            either the single word CLEAN, or sorted
                            `symbol class` lines)
    <name>.linux.txt        Linux expectation — ships as a PLACEHOLDER until the
                            coordinator records it on real Linux
  run.sh                    the gate (compare / --update / --selftest)
  README.md                 this file
```

The 20 crates: `chrono crossbeam dashmap flate2 getrandom lazy_static libc
memmap2 mimalloc num_cpus once_cell parking_lot rand rayon regex sha2 socket2
sysinfo time zstd`. (`snmalloc` is deliberately excluded — it needs `cmake` to
build and is not part of this corpus.)

Each MRE is its **own** cargo workspace (an empty `[workspace]` table at the top
of its `Cargo.toml`), exactly like `testbeds/rustix-default`. That keeps `cargo`
inside a crate from touching the root manifest and lets each carry its own
committed `Cargo.lock`, so the audited surface is version-pinned. The root
workspace uses an explicit `members` list and never picks these up (`cargo
metadata` on the root shows no `mre_*` packages).

## The expectation format

An expectation file is one of:

* the single word `CLEAN` — the shim covers everything; the audit reports no
  unsupported imports; **or**
* a sorted list of `symbol class` lines, one per residual unsupported import,
  e.g.

  ```
  localtime_r time
  ```

`# comments` and blank lines are allowed and ignored on read. On macOS the
recorded symbol is the real libc name — the audit's one leading-underscore
mangling (`_localtime_r`) is stripped during normalization; Linux ELF names are
recorded verbatim.

## The contract (STRICT, both directions)

For each crate, on the current platform:

| committed expectation | actual audit | result |
|---|---|---|
| `CLEAN` | clean | PASS |
| `CLEAN` | dirty | **FAIL** — regression (something the shim covered now escapes) |
| dirty | byte-identical | PASS |
| dirty | any difference (new symbol, dropped symbol, changed class, or now CLEAN) | **FAIL** — drift |
| missing, on a *recorded* platform | — | **FAIL** loudly |
| placeholder, on a *recorded* platform | — | **FAIL** loudly |

Improvements never pass silently. A crate getting cleaner, or a symbol being
reclassified into a sharper class, is real progress — but it must be **claimed**
by re-recording the expectation (`--update`) and committing the diff. That is
what makes this xfail-**strict**: the punchlist can only shrink deliberately.

### Placeholder platforms (Linux until recorded)

The audited symbol surface differs by platform (glibc / `linux_raw` names, no
leading-underscore mangling on Linux), so Linux expectations must be recorded on
real Linux hardware — never predicted from macOS. Until then every
`expected/*.linux.txt` is a `PLACEHOLDER-NOT-YET-RECORDED` sentinel. While
**every** file for a platform is a placeholder, `run.sh` treats that platform as
"not yet recorded": it prints a loud SKIP notice and exits 0, so CI does not go
red merely because Linux has not been recorded. The **first** real recording for
a platform flips it to strict — from then on a missing or still-placeholder file
for any crate is a loud FAIL.

## Usage

Run from anywhere; paths are resolved from the script location.

```sh
testbeds/audit-corpus/run.sh            # build + audit all, compare, PASS/FAIL table, nonzero on any fail
testbeds/audit-corpus/run.sh --update   # re-record THIS platform's expectations (the claim mechanism)
testbeds/audit-corpus/run.sh --selftest # prove both drift directions fire (tampered copies in $TMPDIR)
```

`run.sh` builds the workspace `cargo-patina` (release) first, then audits each
MRE by absolute directory path — the same invocation pattern the other testbeds
use. Network access to crates.io may be needed the first time (CI runners have
it); thereafter the pinned lockfiles + cargo cache make it offline.

### Recording Linux expectations (coordinator, on real Linux x86_64)

```sh
testbeds/audit-corpus/run.sh --update   # regenerates expected/*.linux.txt
git add testbeds/audit-corpus/expected/*.linux.txt
# review the diff, then commit
```

## Self-test (detection-first)

`run.sh --selftest` audits one reliably-dirty crate (`time`) once, then proves —
on **copies** in `$TMPDIR`, never touching a committed file — that the strict
comparison fails in every direction it must:

* a positive control (identical expectation) PASSes;
* an **injected** fake symbol FAILs (catches a shrinking punchlist claimed
  without re-recording);
* a **dropped** real symbol FAILs (catches a growing residual);
* a `CLEAN` expectation over a dirty actual FAILs (catches a regression).

If any direction fails to fire, the selftest itself fails — the gate cannot
silently stop detecting drift.

## Bumping crate versions

The audited surface is pinned by each MRE's committed `Cargo.lock`. To move a
crate to a newer release (e.g. to re-audit after an upstream change):

1. Bump the dependency requirement in `crates/<name>/Cargo.toml` if needed
   (many MREs use a caret requirement like `"0.1"`; tighten to `"=x.y.z"` only
   when pinning an exact upstream version matters).
2. Regenerate that MRE's lockfile:
   ```sh
   ( cd testbeds/audit-corpus/crates/<name> && cargo update )      # move within the requirement
   # or, to rebuild the lock from scratch:
   ( cd testbeds/audit-corpus/crates/<name> && cargo generate-lockfile )
   ```
3. Re-record the affected expectations and review the diff:
   ```sh
   testbeds/audit-corpus/run.sh --update   # on each platform that is recorded
   ```
4. Commit the `Cargo.toml`, `Cargo.lock`, and `expected/*.txt` changes together
   so the pinned surface and its recorded expectation stay in lockstep.

To add a crate: create `crates/<name>/` (Cargo.toml with its own `[workspace]`
table + `src/main.rs`), `cargo generate-lockfile` in it, add `<name>` to the
`CORPUS` array in `run.sh`, then `--update` on each recorded platform.

## CI

`run.sh` runs on the **stable macOS** and **stable Linux x86_64** jobs only —
`msrv` and the arm runners are skipped to bound cost (the audited symbol surface
is toolchain-independent, and Linux arm shares the x86_64 expectation once
recorded). On Linux the gate self-SKIPs (exit 0, loud notice) until the
coordinator records `expected/*.linux.txt`.
