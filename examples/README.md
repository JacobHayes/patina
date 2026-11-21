# Examples

Nine small programs, each with one bug that ordinary runs rarely hit, and the one `patina`
command that finds it. Each builds with its own language's tool and nothing else. Run the
commands from the repository root. Each program takes `fixed` as its first argument to run
without the bug; the same sweep with `fixed` added at the end is `ok` on every seed.

A sweep directory holds one sweep: running the same command again runs only what is missing,
and running it with `fixed` added (or after a rebuild) replaces the old runs.

The commands are the same on x86_64 and arm64. The output below is x86_64's, from a checkout
at `/tmp/patina` (as in the README's first run); seeds are per architecture, so on arm64 the
same sweeps find each bug on another number of seeds.

## quickstart (Rust): a race found by scheduling

Three jobs run on threads; their results must come back in job order. They come back in the
order the threads finished.

<!-- transcript quickstart
setup: rm examples/quickstart && mkdir -p examples/quickstart/target/debug && cp "$GUESTS/examples/jobs" examples/quickstart/target/debug/
skip: 1
exit: 1
-->
```sh
cargo build --manifest-path examples/quickstart/Cargo.toml
patina sweep --seeds 1..20 --out patina-out/quickstart -- examples/quickstart/target/debug/jobs
```

```text
...
patina sweep: 20 runs, 14 findings in 1 group, 6 ok   (0.2s, 8 jobs)
outcomes: failure 14, ok 6

failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101
  14 of 20 runs   first: seed 1   replayed: identical
  example: panicked at src/main.rs:28:5: assertion `left == right` failed: results out of job order
  rerun:  patina run --seed 1 -- /tmp/patina/examples/quickstart/target/debug/jobs
  replay: patina replay /tmp/patina/patina-out/quickstart/seed-1
  explain: patina explain /tmp/patina/patina-out/quickstart/seed-1
```

## ledger (Rust, SDK): a rare path found by a fault point

`commit` has a batch path, marked with `buggify!`, that swaps two entries; `always!` says the
ledger stays sorted. `--buggify` lets the seed take that path.

<!-- transcript ledger
setup: rm examples/ledger && mkdir -p examples/ledger/target/release && cp "$GUESTS/examples/ledger" examples/ledger/target/release/
skip: 1
exit: 1
-->
```sh
cargo build --release --manifest-path examples/ledger/Cargo.toml
patina sweep --seeds 1..20 --buggify --out patina-out/ledger -- examples/ledger/target/release/ledger
```

```text
...
patina sweep: 20 runs, 4 findings in 1 group, 16 ok   (0.2s, 8 jobs)
outcomes: ok 16, violation 4

violation always: ledger-sorted: after N
  4 of 20 runs   first: seed 1   replayed: identical
  example: ledger-sorted: after 2
  rerun:  patina run --seed 1 --buggify -- /tmp/patina/examples/ledger/target/release/ledger
  replay: patina replay /tmp/patina/patina-out/ledger/seed-1
  explain: patina explain /tmp/patina/patina-out/ledger/seed-1
```

## journal-py (Python, SDK): a short write found by disk faults

The program appends 200 entries with `os.write` and ignores the count it returns. The SDK's
`Always` checks the file read back.

<!-- transcript journal-py
exit: 1
-->
```sh
patina sweep --seeds 1..20 --faults disk --out patina-out/journal-py \
  --mount examples/journal-py:/guest --mount sdk/python:/sdk --env PYTHONPATH=/sdk \
  -- python3 /guest/journal.py
```

```text
...
patina sweep: 20 runs, 11 findings in 1 group, 9 ok   (0.2s, 8 jobs)
outcomes: ok 9, violation 11

violation always: journal-intact: N bytes
  11 of 20 runs   first: seed 2   replayed: identical
  example: journal-intact: 7081 bytes
  faults in every failing run: fs-short      in none: fs-error, fsync-error
  rerun:  patina run --seed 2 --env PYTHONPATH=/sdk --mount /tmp/patina/examples/journal-py:/guest --mount /tmp/patina/sdk/python:/sdk --faults disk -- python3 /guest/journal.py
  replay: patina replay /tmp/patina/patina-out/journal-py/seed-2
  explain: patina explain /tmp/patina/patina-out/journal-py/seed-2
```

## acklog-c (C, SDK): lost data found by machine crashes

The log acknowledges a record without syncing it. After a crash and restart, recovery checks
that every acknowledged record is still there.

<!-- transcript acklog
exit: 0 1
-->
```sh
cc -I sdk/c -o acklog examples/acklog-c/acklog.c
patina sweep --seeds 1..20 --crash machine --out patina-out/acklog -- ./acklog
```

```text
...
patina sweep: 20 runs, 6 findings in 1 group, 14 ok   (0.2s, 8 jobs)
outcomes: ok 14, violation 6

violation always: acked-records-kept: N acknowledged, N stored
  6 of 20 runs   first: seed 3   replayed: identical
  example: acked-records-kept: 23 acknowledged, 0 stored
  faults in every failing run: crash      in none: -
  rerun:  patina run --seed 3 --crash machine -- /tmp/patina/acklog
  replay: patina replay /tmp/patina/patina-out/acklog/seed-3
  explain: patina explain /tmp/patina/patina-out/acklog/seed-3
```

## kvlog-c (C, no SDK): lost data found by a check from outside

The same bug as acklog's, in a program with no SDK: it prints `ack I` once record I is
written and never syncs it. `examples/checks/acked-kept` runs after each run, outside the
simulation, and compares the last record acknowledged before each machine crash with the
tree the crash left ([Checks from outside the program](../docs/GUIDE.md#checks-from-outside-the-program)).

<!-- transcript kvlog
exit: 0 1
-->
```sh
cc -o kvlog examples/kvlog-c/kvlog.c
patina sweep --seeds 1..30 --crash machine:10 --check examples/checks/acked-kept --out patina-out/kvlog -- ./kvlog
```

```text
...
patina sweep: 30 runs, 9 findings in 1 group, 21 ok   (0.3s, 8 jobs)
outcomes: ok 21, violation 9
check: judged 13 of 30 runs: 4 passed, 9 failed; 17 not judged (no crash in this run 17)

violation check: acked-record-lost: acknowledged N, N stored after the crash
  9 of 30 runs   first: seed 2   replayed: identical
  example: acked-record-lost: acknowledged 22, 21 stored after the crash
  faults in every failing run: crash      in none: -
  rerun:  patina run --seed 2 --crash machine:10 --check examples/checks/acked-kept -- /tmp/patina/kvlog
  replay: patina replay /tmp/patina/patina-out/kvlog/seed-2
  explain: patina explain /tmp/patina/patina-out/kvlog/seed-2
```

Runs that did not crash are not judged.

`examples/checks/confined`, `examples/checks/no-symlink-escape` and
`examples/checks/synced-before-mark` judge what a program did
rather than what it left, from `patina log events` ([Checks from outside the
program](../docs/GUIDE.md#checks-from-outside-the-program)).

## upcase-c (C, no SDK): wrong output found against a faults-off run

The program writes a text in upper case to `out.txt` and exits 1 on every error, but checks
`write` for -1 only: a short write loses the rest of a block and it still exits 0. One run
without faults is the reference; `--ok-exit 1` lets the clean failures end `ok`, and
`examples/checks/same-tree` compares each run's final work tree with the reference's
(`patina log tree`; [Faults off versus on](../docs/GUIDE.md#faults-off-versus-on)).

<!-- transcript upcase
exit: 0 0 1
-->
```sh
cc -o upcase examples/upcase-c/upcase.c
patina run --seed 1 --out patina-out/upcase-ref -- ./upcase
patina sweep --seeds 1..40 --faults disk --ok-exit 1 --check 'examples/checks/same-tree patina-out/upcase-ref' --out patina-out/upcase -- ./upcase
```

```text
...
patina sweep: 40 runs, 9 findings in 1 group, 31 ok (4 by --ok-exit)   (0.3s, 8 jobs)
outcomes: ok 31, violation 9
check: judged 36 of 40 runs: 27 passed, 9 failed; 4 not judged (clean-failure 4)

violation check: wrong-output: Files want/out.txt and got/out.txt differ
  9 of 40 runs   first: seed 5   replayed: identical
  faults in every failing run: fs-short      in none: fs-error, fsync-error
  rerun:  patina run --seed 5 --faults disk --check 'examples/checks/same-tree patina-out/upcase-ref' --ok-exit 1 -- /tmp/patina/upcase
  replay: patina replay /tmp/patina/patina-out/upcase/seed-5
  explain: patina explain /tmp/patina/patina-out/upcase/seed-5
```

The same sweep without `--ok-exit` and `--check` reports only the clean failures.

## bank-go (Go, SDK): a double deposit found by network faults

An HTTP server and its client in one program. The client retries a deposit whose connection
was reset; the server may already have applied it. `--faults net` finds it too, on about
10 of 20 seeds; `--fault net-reset-permille=50` below fixes the reset rate.

<!-- transcript bank
setup: cp "$GUESTS/examples/bank" .
skip: 1
exit: 1
-->
```sh
go build -C examples/bank-go -o "$PWD/bank"
patina sweep --seeds 1..20 --fault net-reset-permille=50 --out patina-out/bank -- ./bank
```

```text
...
patina sweep: 20 runs, 11 findings in 1 group, 9 ok   (0.3s, 8 jobs)
outcomes: ok 9, violation 11

violation always: balance-matches-deposits: balance N, deposits N
  11 of 20 runs   first: seed 2   replayed: identical
  example: balance-matches-deposits: balance 23, deposits 20
  faults in every failing run: net-reset      in none: -
  rerun:  patina run --seed 2 --fault net-reset-permille=50 -- /tmp/patina/bank
  replay: patina replay /tmp/patina/patina-out/bank/seed-2
  explain: patina explain /tmp/patina/patina-out/bank/seed-2
```

## stats-c (C, compute points): a race with no system call in it

Four workers update shared statistics without their lock. The update makes no system call, so
the stock build runs it the same way on every seed. Rebuilt with clang's coverage flags and the
hook file, its threads also switch inside computation
([the guide](../docs/GUIDE.md#deeper-search-rebuilt-code)).

<!-- transcript stats
exit: 0 0 0 1
-->
```sh
cc -O2 -pthread -o stats examples/stats-c/stats.c
patina sweep --seeds 1..20 --out patina-out/stats -- ./stats
clang -O2 -pthread -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime \
  -o stats-cp examples/stats-c/stats.c sdk/c/patina_compute.c
patina sweep --seeds 1..20 --out patina-out/stats-cp -- ./stats-cp
```

```text
...
patina sweep: 20 runs, 8 findings in 1 group, 12 ok   (0.2s, 8 jobs)
outcomes: failure 8, ok 12
compute points: /tmp/patina/stats-cp (edges, accesses)

failure exit: lost updates: N of N jobs counted; exit 1
  8 of 20 runs   first: seed 2   replayed: identical
  example: lost updates: 198 of 200 jobs counted
  rerun:  patina run --seed 2 -- /tmp/patina/stats-cp
  replay: patina replay /tmp/patina/patina-out/stats-cp/seed-2
  explain: patina explain /tmp/patina/patina-out/stats-cp/seed-2
```

The stock sweep before it is `ok` on every seed.

## serve-c (C, SDK): a check-then-use race found by path swaps

The program serves `public/report.txt` ten times and refuses a symlink there, so that a link
planted in `public/` cannot make it serve a file from elsewhere. It checks the name with
`lstat` and then opens the name. `--fault path-swap-permille` lets the seed change a path
between a check of it and its use, as another process could
([the guide](../docs/GUIDE.md#path-swaps)).

<!-- transcript serve
exit: 0 1
-->
```sh
cc -I sdk/c -o serve examples/serve-c/serve.c
patina sweep --seeds 1..20 --fault path-swap-permille=300 --out patina-out/serve -- ./serve
```

```text
...
patina sweep: 20 runs, 5 findings in 1 group, 15 ok   (0.1s, 8 jobs)
outcomes: ok 15, violation 5

violation always: served-only-public: N bytes
  5 of 20 runs   first: seed 4   replayed: identical
  example: served-only-public: 66 bytes
  faults in every failing run: path-swap      in none: -
  rerun:  patina run --seed 4 --fault path-swap-permille=300 -- /tmp/patina/serve
  replay: patina replay /tmp/patina/patina-out/serve/seed-4
  explain: patina explain /tmp/patina/patina-out/serve/seed-4
```

The fixed program opens with `O_NOFOLLOW` and serves
only the file it checked.

`tests/examples/01-examples.sh` runs these sweeps and their fixed variants in the quick check
(kvlog-c and upcase-c: `tests/oracles/01-checks.sh`).
