# Patina tutorial: catch a planted bug with buggify, then replay and render it

This walkthrough takes a small `std` Rust program, instruments it with Patina's
cooperative-SUT SDK (`buggify!`), sweeps seeds until a planted bug fires, then
records that run, replays it byte-for-byte, and renders its timeline to a
self-contained HTML page. Every command here is run against the current CLI.

Prerequisites: build the CLI once from the workspace root — `cargo build
--release -p cargo-patina` — and use `target/release/cargo-patina` (shown as
`cargo patina` below). No extra toolchain is needed for the native target.

## 1. A small program with a latent bug

Create a standalone package `ledger/` (its own empty `[workspace]` keeps it out of
the Patina workspace):

`ledger/Cargo.toml`
```toml
[workspace]
[package]
name = "ledger"
version = "0.1.0"
edition = "2021"
publish = false
[[bin]]
name = "ledger"
path = "src/main.rs"
[dependencies]
# Path to your checkout's crates/patina (package name `patina-dst`, used as
# `patina_dst::` in code). The SDK's default features are the dependency-light
# macro set; a plain `cargo build` leaves every macro a no-op.
patina-dst = { path = "../patina/crates/patina" }
```

`ledger/src/main.rs`
```rust
// A tiny append-only ledger with a LATENT bug: a rare "batch-commit" path
// appends the next entry out of order, breaking the sorted-prefix invariant. The
// bug only triggers when that rare path runs -- exactly the path buggify forces.
// An end-of-run consistency check catches it and exits nonzero (a clean exit, so
// the recorded trace finalizes and can be replayed and rendered).
fn main() {
    patina_dst::lifecycle::setup_complete();
    let mut durable: Vec<u64> = Vec::new();
    for i in 0..8u64 {
        if patina_dst::buggify!("batch-commit") {
            let last = durable.len();
            durable.push(i);
            if last >= 1 {
                durable.swap(last, last - 1); // BUG: reorders two committed entries
            }
        } else {
            durable.push(i);
        }
    }
    let ok = durable.iter().enumerate().all(|(i, v)| *v as usize == i);
    if ok {
        println!("LEDGER_OK entries={}", durable.len());
    } else {
        println!("BUG_CAUGHT reordered ledger={durable:?}");
        std::process::exit(1);
    }
}
```

`buggify!("batch-commit")` returns `true` only on a rare, *seed-deterministic*
path. Outside Patina (a plain `cargo build && ./ledger`) it is always `false`, so
the program behaves normally and ships with the instrumentation inert.

## 2. Build it for the deterministic runtime

```
$ cargo patina build ./ledger --output ./ledger/ledger
PATINA_NATIVE_BUILD output=/.../ledger/ledger
```

`build` links the deterministic shim below your program and injects the cfgs that
route the SDK macros to the runtime.

## 3. Run it — a clean seed and a catching seed

Most seeds do not activate the site or do not fire it, so the invariant holds:

```
$ cargo patina run ./ledger/ledger --seed 0 --buggify
LEDGER_OK entries=8
```

Buggify is seeded by the run seed, so a different seed takes the rare path:

```
$ cargo patina run ./ledger/ledger --seed 5 --buggify
BUG_CAUGHT reordered ledger=[0, 1, 3, 2, 4, 6, 5, 7]      # exit 1
```

On stderr you also get the SDK report — proof the site was actually exercised
(not a vacuous "all clean"):

```
PATINA_SDK_REPORT enabled=1 fire_permille=250 activation_permille=250 ... \
  sites_registered=1 sites_activated=1 total_firings=2 ... site=batch-commit|fault|...|@src/main.rs:9
```

You can inventory the static instrumentation from the `ledger/` workspace, and
join a run's SDK report back to that inventory. Capture stderr from any run and
feed it to `sites --exercised`:

```
$ cargo patina run ./ledger/ledger --seed 5 --buggify 2> ./sdk.stderr
$ cargo patina sites --no-cache --site batch-commit --exercised ./sdk.stderr
== sites static inventory ==
...
src/main.rs:9 fault driven id=batch-commit label=batch-commit ... exercised(reg=1 evals=8 fires=2 ...)
```

For native edge coverage, build with yield points, write a covmap, then use the
read-only coverage report to symbolize and roll it up by crate/module/function:

```
$ cargo patina build ./ledger --yield-points --output ./ledger/ledger-yp
$ cargo patina run ./ledger/ledger-yp --seed 5 --buggify --coverage-out ./ledger/run.covmap
$ cargo patina coverage ./ledger/ledger-yp ./ledger/run.covmap --focus ledger --top 10
```

A longer `campaign` over a yield-point binary automatically accumulates the union
under `<out-dir>/coverage/`; inspect it with
`cargo patina coverage ./ledger/ledger-yp <out-dir>`. The campaign report is tied
to the recorded artifact hash, so passing a different binary fails closed instead
of producing a mismatched symbol rollup.

Catching seeds are build-specific (the instrumentation shapes the decision
space), so sweep for one rather than hardcoding it.

## 4. Sweep seeds automatically

`explore` builds once and runs that same artifact across a range of seeds,
stopping at the first failure:

```
$ cargo patina explore run ./ledger/ledger --buggify --seeds 50
PATINA_EXPLORE_FAILURE seed=5 exit=1 repro="cargo patina run ./ledger/ledger --buggify --seed 5"
```

(A clean sweep instead ends with `PATINA_EXPLORE_COMPLETE start=0 seeds=50`.)
The repro string is also present in the `patina.result/v1` `message` field under
`--format json`.

## 5. Record the catching run

Recording captures the seed, the buggify config, and the guest arguments into the
trace, so the reproduction needs no flags later:

```
$ cargo patina run ./ledger/ledger --seed 5 --buggify --record ./bug.patina
BUG_CAUGHT reordered ledger=[0, 1, 3, 2, 4, 6, 5, 7]      # exit 1
```

The trace is compact JSON — inspect it with `jq . bug.patina` if you like.

## 6. Replay it — byte-for-byte, flag-free

```
$ cargo patina replay ./ledger/ledger ./bug.patina
BUG_CAUGHT reordered ledger=[0, 1, 3, 2, 4, 6, 5, 7]      # exit 1, identical
```

No `--seed` or `--buggify`: the trace is authoritative. If you rebuild the binary
incompatibly, replay fails closed on the fingerprint rather than lying.

## 7. Render the timeline

Add `--render` to write a self-contained HTML timeline (open it in any browser —
no assets, no network):

```
$ cargo patina replay ./ledger/ledger ./bug.patina --render ./bug.html
```

`bug.html` shows per-task lanes over the trace, a metadata panel (seed, buggify
config, active sites), per-task rollups, and a notable-events list. Rendering
only reads the trace, so the replay hash is unchanged whether or not you pass
`--render`.

For CLI-only inspection of an existing trace, use `trace info` and a filtered
`trace events` dump:

```
$ cargo patina trace info ./bug.patina
$ cargo patina trace events ./bug.patina --notable
$ cargo patina trace stats ./bug.patina
$ cargo patina trace diff ./bug.patina ./bug.patina
$ cargo patina trace events ./bug.patina --kind filesystem --first 20 --format json
```

`trace diff` exits 0 for identical traces and 1 when metadata or events diverge.
The last command emits `patina.trace.events/v1` JSON Lines: a header, one object
per emitted event (raw `operation`/`outcome` intact), and a matched/emitted
summary.

Prefer a one-shot failure report? `--report OUT.html` renders the timeline *only
when the run fails*, leading with a failure summary:

```
$ cargo patina run ./ledger/ledger --seed 5 --buggify --record ./bug.patina --report ./report.html
```

## 8. Keep a point-solution guard under plain cargo test

For a permanent per-PR guard, enable the `patina-dst` `macros` feature in
`dev-dependencies` and annotate a zero-argument test:

```rust
#[patina_dst::test(seeds = 20, buggify)]
fn ledger_stays_sorted_under_faults() {
    // ordinary test code using the crate's helpers and dev-dependencies
}
```

Plain `cargo test` finds `cargo-patina` through `PATINA_CLI` or `PATH`, rebuilds
the same libtest target shim-linked, and runs only that test with one libtest
thread. A failing seed panics with both repro commands:

```text
reproduce:
  cargo patina test . --harness-target my_crate --exact ledger_stays_sorted_under_faults --seed 5
  cargo patina replay target/patina/dst/.../guest target/patina/dst/.../seed-5.patina
```

If `cargo-patina` is not discoverable, the test fails loudly instead of skipping.

## 9. Machine-readable output for agents

Any verb accepts `--format json`. Most emit one result envelope on stdout (schema
`patina.result/v1`) with the guest output folded in; `coverage` emits
`patina.coverage/v1`, and `trace events` uses streaming JSON Lines:

```
$ cargo patina run ./ledger/ledger --seed 5 --buggify --record ./bug.patina --format json
{"schema":"patina.result/v1","verb":"run","family":"native","result":"violation",
 "exit_code":1,"seed":5,"trace":{"path":"./bug.patina","format_version":4,
 "event_count":...,"metadata":{...}},"markers":["..."],
 "result_line":"BUG_CAUGHT reordered ledger=[0, 1, 3, 2, 4, 6, 5, 7]", ...}
```

`result` is `ok | violation | failure | error`. The selector is `--format`
(not `--output`, which is the build/minimize artifact path).

## Where to go next

- Add fault injection: `--fs-crash-at`, `--fs-error-permille`,
  `--fs-short-permille`, `--net-drop-permille`, `--net-jitter-nanos`,
  `--sleep-jitter-nanos`. They are seed-driven, default off, and recorded into
  the trace like buggify — so replay reproduces them flag-free.
- Vary the *workload* across campaign generations from inside the guest: a
  campaign varies patina-side seeds (scheduler, faults, buggify) per generation
  but keeps guest argv fixed by design. A guest that wants a different logical
  workload per generation should derive its workload parameters from the
  deterministic entropy stream (seed an application RNG from bytes the runtime
  provides — e.g. `rand` under native, `random_get` under WASI) instead of argv.
  That way every generation is still reproducible from its patina seed alone,
  and replay needs no extra flags.
- Make atomics-only race windows schedulable: `cargo patina build --yield-points`.
- Shrink a failing trace to its essence: `cargo patina minimize bug.patina
  --output small.patina -- ./oracle`.
- See `llms.txt` for the full CLI/SDK map and `testbeds/workq` (a durable work
  queue: WAL crash-recovery, SimNet faults, buggify) for the flagship end-to-end
  demonstration.
