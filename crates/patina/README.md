# patina-dst (Rust SDK)

State invariants, mark rare paths and expose fault points to a Patina run. One reserved system
call carries every call; outside Patina the kernel answers `ENOSYS`, the first call learns it,
and from then on each macro is a load and a branch. No dependencies, `no_std`. The feature
`compute` (off by default) adds the hooks for compute points (`src/compute.rs`).

```rust
if patina_dst::buggify!("batch-commit") { /* a rare path the real system can take */ }
patina_dst::always!(ledger.is_sorted(), "ledger-sorted", "after {entry}");
patina_dst::sometimes!(ledger.len() > 4, "ledger-grew");
patina_dst::reachable!("recovery-ran");
let batch = patina_dst::knob!("batch-size", 64, 1, 1024);
patina_dst::delay!("pre-heartbeat-stall");
patina_dst::setup_complete(); // in a run with `setup = "mark"` under [run]
```

A failed `always!` ends the run with outcome `violation` and `label: detail`. Fault points
fire only in a run with `--faults buggify`, on evaluations chosen from the seed and the label. Every
call is in the run's boundary log, so replay checks it. The crate docs (`src/lib.rs`) have the
details; `sdk/c/patina.h` documents the wire.
