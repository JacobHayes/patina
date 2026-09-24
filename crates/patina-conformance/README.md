# patina-dst-conformance

Linux syscall conformance scenarios with the host kernel as the live oracle
(design: `docs/arcs/syscall-conformance.md`). Unpublished; it exists for
`crates/cargo-patina/tests/native_conformance.rs`.

A scenario is a plain Rust function over the `Probe` call API
(`src/scenarios/<family>/<name>.rs`). Every scenario is built into one probe
binary, `conformance-probe <scenario> --vehicle libc|syscall|raw --dir DIR
[--strict]`, which writes one typed JSON event per observed call. Each
scenario's test runs it natively and under `cargo patina` through every
vehicle it has, and compares the two streams exactly, apart from the
normalizations the scenario declares at its call sites (allocated numbers,
identities, clock readings, documented alternative answers) and its declared
gaps. A gap is a strict expected failure (`Failure::Differs` with the exact
patina values, or `Failure::Stops` with the exact point, ending and
diagnostic): the test fails when patina fails differently, and when patina
starts passing, until the gap is removed. A patina run that completes is also
recorded and replayed and run directly under strace.

A scenario declares the registry rows it covers (`covers`, `asserts_absent`),
the libc symbols its `libc` vehicle goes through, its gaps, and the facts its
recorded trace must show; `EXCLUSIONS` lists registry entries deliberately
left without a scenario. `mise run conformance` runs the tests;
`mise run conformance:coverage` lists every registry entry of this target that
neither a scenario nor an exclusion accounts for, and exits 1 while any remain.

Adding a scenario: write `src/scenarios/<family>/<name>.rs` with its `run`
function and `SCENARIO` declaration, list it in `catalog::SCENARIOS`, add its
`#[test]` to `native_conformance.rs`, run the test, and declare what patina
does differently as gaps naming the responsible code.
