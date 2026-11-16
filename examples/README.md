# Examples

- `ledger`: a Rust program using the SDK (`crates/patina`). A `buggify!` point takes a rare
  path with a bug, and an `always!` invariant catches it. Natively the program prints the
  sorted ledger; under `patina run --buggify` some seeds end with outcome `violation` and
  `ledger-sorted`:

  ```sh
  cargo build --release --manifest-path examples/ledger/Cargo.toml
  for s in 1 2 3 4 5 6; do
    patina run --seed $s --buggify --guest examples/ledger/target/release -- /guest/ledger
  done
  ```

- `quickstart`: a job runner whose results come back in finishing order, not job order; its
  test fails only on some schedules. `lib.fixed.rs` is the fix.

The SDK guests in `tests/guests/sdk` are the smallest guest per language (C, Rust, Go,
Python).
