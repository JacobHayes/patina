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
- the `PATINA_SDK_REPORT` line parses into the same shared campaign classifier
  (`../buggify-campaign.sh`) the native sweeps use;
- per-generation record→replay byte-identity with buggify active.

The fixture carries **no planted defect**: a clean campaign is all-OK. The
`always!` oracle is plantable on demand (below) to show the violation path; the
detectors themselves are RED-proven by the `cargo-patina` end-to-end tests and
the shared selftest, not re-proven here.

## Running

The campaign (builds `cargo-patina` and the fixture, then runs generations
whose seed and buggify knobs derive from `SHA-256("wasi-buggify-<G>")` — the
whole campaign reproduces from the range alone):

```sh
./wasi-buggify-sweep.sh                # generations 1..40
./wasi-buggify-sweep.sh 1 10          # a shorter range
./wasi-buggify-sweep.sh --dry-run 3   # print gen 3's derived config, no run
./wasi-buggify-sweep.sh --selftest    # shared campaign-layer selftest
./wasi-buggify-sweep.sh --help        # full help, env knobs, exit codes
```

Output accumulates under `out-wasi-buggify/` (override with
`WASI_BUGGIFY_OUT=DIR`); failing generations keep their `gen-N/` dir with the
config, output, and trace.

One run by hand, from the repository root (`build` prints the artifact path):

```sh
cargo patina build testbeds/buggify-wasi --target wasi
cargo patina run testbeds/buggify-wasi/target/wasm32-wasip1/debug/buggify-wasi-fixture.wasm \
  --seed 7 --buggify --record /tmp/bw.patina
cargo patina replay testbeds/buggify-wasi/target/wasm32-wasip1/debug/buggify-wasi-fixture.wasm /tmp/bw.patina
```

Plant the `always!` violation (the WASI mirror of the native abort — the run
emits `PATINA_ALWAYS_VIOLATION` and traps):

```sh
cargo patina run testbeds/buggify-wasi/target/wasm32-wasip1/debug/buggify-wasi-fixture.wasm \
  --seed 7 --buggify --arg violate
```

## Conventions

- Standalone cargo workspace (empty `[workspace]` table), dependency tree =
  `patina-dst` and nothing else.
- The clean-run marker is `WASI_BUGGIFY_DIGEST …` on stdout; the sweep
  classifies buggify markers first, then a hard-crash guard, then requires the
  digest for OK.
- A `sometimes!` site reached but never satisfied across the whole campaign
  exits 7 (`SOMETIMES_UNMET`), per the shared campaign layer.
