# Examples

Eight small programs, each with one bug that ordinary runs rarely hit, and the one `patina`
command that finds it. Each builds with its own language's tool and nothing else. Run the
commands from the repository root. Each program takes `fixed` as its first argument to run
without the bug; the same sweep with `fixed` added at the end is `ok` on every seed.

A sweep directory holds one sweep: running the same command again runs only what is missing,
and running it with `fixed` added (or after a rebuild) replaces the old runs.

The commands are the same on x86_64 and arm64. The counts of finding seeds below are
x86_64's; seeds are per architecture, so on arm64 the same sweeps find each bug on a different
number of the 20 seeds (on the arm64 runner: quickstart 15, ledger 4, journal-py 7, acklog 2,
bank 11, stats-cp 6, serve 7).

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

Expected: `violation always: ledger-sorted: after N`, on about 4 of the 20 seeds.

## journal-py (Python, SDK): a short write found by disk faults

The program appends 200 entries with `os.write` and ignores the count it returns. The SDK's
`Always` checks the file read back.

```sh
patina sweep --seeds 1..20 --faults disk --out patina-out/journal-py \
  --mount examples/journal-py:/guest --mount sdk/python:/sdk --env PYTHONPATH=/sdk \
  -- python3 /guest/journal.py
```

Expected: `violation always: journal-intact: N bytes`, about 12 of the 20 seeds, with `faults in every
failing run: fs-short`.

## acklog-c (C, SDK): lost data found by machine crashes

The log acknowledges a record without syncing it. After a crash and restart, recovery checks
that every acknowledged record is still there.

```sh
cc -I sdk/c -o acklog examples/acklog-c/acklog.c
patina sweep --seeds 1..20 --crash machine --out patina-out/acklog -- ./acklog
```

Expected: `violation always: acked-records-kept: N acknowledged, N stored`, about 6 of the 20 seeds.

## kvlog-c (C, no SDK): lost data found by a check from outside

The same bug as acklog's, in a program with no SDK: it prints `ack I` once record I is
written and never syncs it. `examples/checks/acked-kept` runs after each run, outside the
simulation, and compares the last record acknowledged before each machine crash with the
tree the crash left ([Checks from outside the program](../docs/GUIDE.md#checks-from-outside-the-program)).

```sh
cc -o kvlog examples/kvlog-c/kvlog.c
patina sweep --seeds 1..30 --crash machine:10 --check examples/checks/acked-kept --out patina-out/kvlog -- ./kvlog
```

Expected: `violation check: acked-record-lost: acknowledged N, N stored after the crash`, 9 of
the 30 seeds (counted on x86_64 only); runs that did not crash are not judged.

## bank-go (Go, SDK): a double deposit found by network faults

An HTTP server and its client in one program. The client retries a deposit whose connection
was reset; the server may already have applied it. `--faults net` finds it too, on about
10 of 20 seeds; `--fault net-reset-permille=50` below fixes the reset rate.

```sh
go build -C examples/bank-go -o "$PWD/bank"
patina sweep --seeds 1..20 --fault net-reset-permille=50 --out patina-out/bank -- ./bank
```

Expected: `violation always: balance-matches-deposits: balance N, deposits N`, about 11 of the 20 seeds.

## stats-c (C, compute points): a race with no system call in it

Four workers update shared statistics without their lock. The update makes no system call, so
the stock build runs it the same way on every seed. Rebuilt with clang's coverage flags and the
hook file, its threads also switch inside computation
([the guide](../docs/GUIDE.md#deeper-search-rebuilt-code)).

```sh
cc -O2 -pthread -o stats examples/stats-c/stats.c
patina sweep --seeds 1..20 --out patina-out/stats -- ./stats
clang -O2 -pthread -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime \
  -o stats-cp examples/stats-c/stats.c sdk/c/patina_compute.c
patina sweep --seeds 1..20 --out patina-out/stats-cp -- ./stats-cp
```

Expected: the stock sweep `ok` on every seed; the rebuilt one `failure exit: lost updates: N of N jobs counted; exit 1`, on about 8 of the 20 seeds.

## serve-c (C, SDK): a check-then-use race found by path swaps

The program serves `public/report.txt` ten times and refuses a symlink there, so that a link
planted in `public/` cannot make it serve a file from elsewhere. It checks the name with
`lstat` and then opens the name. `--fault path-swap-permille` lets the seed change a path
between a check of it and its use, as another process could
([the guide](../docs/GUIDE.md#path-swaps)).

```sh
cc -I sdk/c -o serve examples/serve-c/serve.c
patina sweep --seeds 1..20 --fault path-swap-permille=300 --out patina-out/serve -- ./serve
```

Expected: `violation always: served-only-public: N bytes`, about 5 of the 20 seeds, with
`faults in every failing run: path-swap`. The fixed program opens with `O_NOFOLLOW` and serves
only the file it checked.

`tests/examples/01-examples.sh` runs these sweeps and their fixed variants in the quick check.
