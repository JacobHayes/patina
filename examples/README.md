# Examples

Five small programs, each with one bug that ordinary runs rarely hit, and the one `patina`
command that finds it. Each builds with its own language's tool and nothing else. Run the
commands from the repository root. Each program takes `fixed` as its first argument to run
without the bug; the same sweep with `fixed` added at the end is `ok` on every seed.

A sweep directory holds one sweep: running the same command again runs only what is missing,
and running it with `fixed` added (or after a rebuild) replaces the old runs.

## quickstart (Rust): a race found by scheduling

Three jobs run on threads; their results must come back in job order. They come back in the
order the threads finished.

```sh
cargo build --manifest-path examples/quickstart/Cargo.toml
patina sweep --seeds 1..20 --out patina-out/quickstart -- examples/quickstart/target/debug/jobs
```

Expected: `failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101`, on about 14 of the 20 seeds.

## ledger (Rust, SDK): a rare path found by a fault point

`commit` has a batch path, marked with `buggify!`, that swaps two entries; `always!` says the
ledger stays sorted. `--buggify` lets the seed take that path.

```sh
cargo build --release --manifest-path examples/ledger/Cargo.toml
patina sweep --seeds 1..20 --buggify --out patina-out/ledger -- examples/ledger/target/release/ledger
```

Expected: `violation always: ledger-sorted`, on about 4 of the 20 seeds.

## journal-py (Python, SDK): a short write found by disk faults

The program appends 200 entries with `os.write` and ignores the count it returns. The SDK's
`Always` checks the file read back.

```sh
patina sweep --seeds 1..20 --faults disk --out patina-out/journal-py \
  --mount examples/journal-py:/guest --mount sdk/python:/sdk --env PYTHONPATH=/sdk \
  -- python3 /guest/journal.py
```

Expected: `violation always: journal-intact`, about 12 of the 20 seeds, with `faults in every
failing run: fs-short`.

## acklog-c (C, SDK): lost data found by machine crashes

The log acknowledges a record without syncing it. After a crash and restart, recovery checks
that every acknowledged record is still there.

```sh
cc -I sdk/c -o acklog examples/acklog-c/acklog.c
patina sweep --seeds 1..20 --crash machine --out patina-out/acklog -- ./acklog
```

Expected: `violation always: acked-records-kept`, about 6 of the 20 seeds.

## bank-go (Go, SDK): a double deposit found by network faults

An HTTP server and its client in one program. The client retries a deposit whose connection
was reset; the server may already have applied it. `--faults net` finds it too, on about
10 of 20 seeds; `--fault net-reset-permille=50` below fixes the reset rate.

```sh
go build -C examples/bank-go -o "$PWD/bank"
patina sweep --seeds 1..20 --fault net-reset-permille=50 --out patina-out/bank -- ./bank
```

Expected: `violation always: balance-matches-deposits`, about 11 of the 20 seeds.

`tests/examples/01-examples.sh` runs these sweeps and their fixed variants in the quick check.
