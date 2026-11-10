# audit-corpus — the ecosystem symbol-audit corpus

Twenty minimal reproducers (MREs), one per widely-used crate, each built and
audited through the packaged native path (`patina audit`). Every one must audit
clean: a reproducer whose audit reports an unsupported native import fails the
gate. One more crate, `selftest-dynamic-loading`, imports a dynamic loader the
shim never defines (`dlmopen` on Linux, `dlopen_preflight` on macOS) and must be
refused: it is the leg that shows the audit can fail.

## Layout

```
audit-corpus/
  crates/<name>/            one standalone MRE package per crate
    Cargo.toml              has its OWN empty [workspace] table -> NOT a member
                            of the root Patina workspace
    Cargo.lock              committed, version-pinned (see "Bumping" below)
    src/main.rs             the reproducer (exercises the crate's escaping path)
  run.sh                    the gate
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

## Usage

```sh
testbeds/audit-corpus/run.sh
```

`run.sh` builds the workspace `patina` (release) first, then audits each
crate under `crates/` by absolute directory path. Network access to crates.io
may be needed the first time; thereafter the pinned lockfiles and the cargo
cache make it offline.

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
3. Run `testbeds/audit-corpus/run.sh` and commit the `Cargo.toml` and
   `Cargo.lock` changes together.

To add a crate: create `crates/<name>/` (Cargo.toml with its own `[workspace]`
table + `src/main.rs`) and `cargo generate-lockfile` in it; `run.sh` audits
every directory under `crates/`.

## CI

`run.sh` runs on the Linux x86_64 job and the macOS job.
