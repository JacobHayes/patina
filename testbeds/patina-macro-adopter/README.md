# patina-macro-adopter

Standalone adopter-shaped crate for `#[patina_dst::test]`.

The fixture depends on `patina-dst` with the default-off `macros` feature in
`dev-dependencies`, then runs the attribute through plain `cargo test` commands.
Its battery covers:

- a passing two-seed DST test;
- a planted seeded failure whose panic output must include the seed, a
  `cargo patina test` repro, and a `cargo patina replay` repro;
- a PATH-scrubbed run with `PATINA_CLI` unset, proving a missing CLI is a loud
  test failure rather than a skip.

Run from the repository root:

```sh
testbeds/patina-macro-adopter/run.sh
```
