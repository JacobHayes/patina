# buggify-wasi — the WASI cooperative-SUT (buggify) dogfood

A small `wasm32-wasip1` fixture proving the buggify SDK works on WASI at full
parity with native. The guest (`src/main.rs`) exercises every cooperative-SUT
site kind the `patina_sdk` wasm import surface carries — `buggify!`,
`buggify_with_prob!`, `buggify_delay!`, `buggify_knob!`, `sometimes!`,
`reachable!`, `always!`, `rng()`, and the lifecycle markers — and prints a
`WASI_BUGGIFY_DIGEST` line that is a pure function of the run seed and the
buggify decisions, so record/replay reproduces it byte-for-byte and distinct
seeds diverge it.

What it proves:

- guest-side buggify lowering on WASI: `cargo patina build --target wasi`
  injects `--cfg patina`, under which the SDK macros lower to the `patina_sdk`
  host import module (a plain `cargo build --target wasm32-wasip1` leaves the
  macros no-ops and the import table free of `patina_sdk` — the no-leakage
  contract, stated in `Cargo.toml`);
- buggify sites register and fire under `cargo patina campaign --buggify`,
  and every `sometimes!`/`reachable!` oracle is satisfied across the campaign;
- record→replay byte-identity with buggify active (the campaign's
  reproduction check).

The fixture carries **no planted defect**: a clean campaign is all-OK. The
`always!` oracle is plantable on demand (below) to show the violation path; the
detectors themselves are RED-proven by the `cargo-patina` end-to-end tests, not
re-proven here.

## Running

The campaign is a `cargo patina campaign` spec (`campaign.json`: 40
generations with buggify on), from the repository root:

```sh
export CARGO_TARGET_DIR=target/testbeds/buggify-wasi
cargo patina build testbeds/buggify-wasi --target wasi
cargo patina campaign target/testbeds/buggify-wasi/wasm32-wasip1/debug/buggify-wasi-fixture.wasm \
  --spec testbeds/buggify-wasi/campaign.json --out-dir target/testbeds/buggify-wasi/campaign
```

One run by hand (`build` prints the artifact path):

```sh
cargo patina run target/testbeds/buggify-wasi/wasm32-wasip1/debug/buggify-wasi-fixture.wasm \
  --seed 7 --buggify --record /tmp/bw.patina
cargo patina replay target/testbeds/buggify-wasi/wasm32-wasip1/debug/buggify-wasi-fixture.wasm /tmp/bw.patina
```

Plant the `always!` violation (the WASI mirror of the native abort — the run
reports a `PATINA_VERDICT ... kind=violation` line and traps):

```sh
cargo patina run target/testbeds/buggify-wasi/wasm32-wasip1/debug/buggify-wasi-fixture.wasm \
  --seed 7 --buggify -- violate
```

## Conventions

- Standalone cargo workspace (empty `[workspace]` table), dependency tree =
  `patina-dst` and nothing else.
- The clean-run marker is `WASI_BUGGIFY_DIGEST …` on stdout.
