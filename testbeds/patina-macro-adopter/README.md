# patina-macro-adopter

Standalone adopter-shaped crate for `#[patina_dst::test]`.

The fixture depends on `patina-dst` with the default-off `macros` feature in
`dev-dependencies`, then runs the attribute through plain `cargo test` commands.
Its battery builds and stages under `CARGO_TARGET_DIR`, defaulting to
`../../target/testbeds/patina-macro-adopter` when run from the repository root;
it must not create `testbeds/patina-macro-adopter/target`. It covers:

- a passing two-seed DST test;
- a planted seeded failure whose panic output must include the seed, a
  `cargo patina test` repro, and a `cargo patina replay` repro;
- a PATH-scrubbed run with `PATINA_CLI` unset, proving a missing CLI is a loud
  test failure rather than a skip.

Run from the repository root:

```sh
testbeds/patina-macro-adopter/run.sh
```
