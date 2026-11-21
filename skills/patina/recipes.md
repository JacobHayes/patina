# Recipes

Each recipe runs one of the small programs in the Patina repository's `examples/` (or its
tests), from the repository root; put your program, its inputs and its oracle in their place.

## A tool that writes files: crash consistency

`kvlog` appends records to `data.log` and prints `ack I` once record I is written, without an
fsync. Its promise: an acknowledged record survives a power loss. No SDK in it, so a checker
compares each incarnation's last `ack` with the file the crash left
(`examples/checks/acked-kept`, twenty lines of shell):

<!-- transcript files
exit: 0 1 1
-->
```sh
cc -o kvlog examples/kvlog-c/kvlog.c
patina sweep --seeds 1..30 --crash machine:10 --check examples/checks/acked-kept --out patina-out/kvlog -- ./kvlog
patina sweep --seeds 1..2 --crash-points=50 --crash machine --check examples/checks/acked-kept --out patina-out/kvlog-branch -- ./kvlog
```

The first finds the lost record in some seeds; `--crash-points` tries crash points one by one. The
same sweeps of `./kvlog fixed` (fsync before the ack) are clean. For your tool: run it as
production does (its arguments, a starting tree with `--work DIR`), state its promise, check
that promise after each crash, and make sure it can restart on what the crash left.

## A multithreaded program: schedules

`jobs` runs three jobs on threads and expects their results in job order. Seeds alone find it:

<!-- transcript threads
setup: cp "$GUESTS/examples/jobs" .
exit: 1
-->
```sh
patina sweep --seeds 1..20 --out patina-out/jobs -- ./jobs
```

A race with no system call inside it, here two threads adding to a counter with a plain load
and store, is found the same way: threads also switch inside computation.

<!-- transcript points
arch: x86_64
setup: cp "$GUESTS/rw-races" races
skip: 1
exit: 1
-->
```sh
cc -O2 -pthread -o races tests/guests/rewrite/races.c
patina sweep --seeds 1..20 --out patina-out/races -- ./races lms
```

## A client and server on loopback: network faults

`bank` is an HTTP server and its client in one Go program; the client retries a deposit whose
connection was reset, which the server may already have applied. An SDK `always` checks the
balance. The server and client must both run inside the run (one program, or programs it
starts):

<!-- transcript net
setup: cp "$GUESTS/examples/bank" .
skip: 1
exit: 1
-->
```sh
go build -C examples/bank-go -o "$PWD/bank"
patina sweep --seeds 1..20 --faults net --out patina-out/bank -- ./bank
```

For a server that is a separate program, start it from a wrapper script given after `--`,
wait for its port, then run the client and check the result.

## A replicated store on nodes: partitions and crashes

`q3.py` (in `tests/guests/nodes`) is a store on three nodes; with `nosync` a node acknowledges a
write before it is on disk. The driver, the command after `--`, writes and reads through the
nodes and exits 1 on a lost write.

<!-- transcript nodes
dir: /tmp/q3
setup: mkdir g && cp "$GUESTS/q3.py" "$GUESTS/patina.py" g/
setup: for n in n1 n2 n3; do printf '[node.%s]\ncmd = ["python3", "/guest/q3.py", "%s", "nosync"]\n\n' $n $n; done | sed '$d' >patina.toml
-->
```text
$ cat patina.toml
[node.n1]
cmd = ["python3", "/guest/q3.py", "n1", "nosync"]

[node.n2]
cmd = ["python3", "/guest/q3.py", "n2", "nosync"]

[node.n3]
cmd = ["python3", "/guest/q3.py", "n3", "nosync"]
```

<!-- transcript nodes-sweep
dir: /tmp/q3
exit: 1
release-only: a sweep of eight runs of a three-node cluster
-->
```sh
patina sweep --seeds 1..8 --mount g:/guest --faults cluster --fault crash-gap-ms=2000..10000 -- python3 /guest/q3.py driver 30
```

`--faults cluster` adds link faults, partitions, pauses, clock skew and machine crashes
(seldom in a short run: `crash-gap-ms` makes them frequent). Without `nosync` the same sweep is
clean. A group's `nodes:` line says which nodes were down or partitioned in its failing runs.
The driver here prints its `FAIL:` line to stdout, so the signature is only `exit 1`: a driver
that writes the failure to stderr gets a signature that names it.

## A test suite: one run per test

`--cases FILE` runs each line of FILE once per seed, each its own run, grouped per test:

<!-- transcript suite
dir: /tmp/suite
setup: cp "$REPO/tests/docs/fixtures/casedemo/"* .
exit: 0 1
-->
```text
$ cat tests.txt
python3 -m unittest test_store.Store.test_write
python3 -m unittest test_store.Store.test_counter
$ patina sweep --seeds 1..10 --cases tests.txt --mount .:/guest --env PYTHONPATH=/guest
...
patina sweep: 20 runs, 10 findings in 1 group, 10 ok   (0.3s, 8 jobs)
outcomes: failure 10, ok 10

[python3 -m unittest test_store.Store.test_counter] failure exit: AssertionError: N != N; exit 1
  10 of 20 runs   first: seed 1, case 2   replayed: identical
  example: AssertionError: 3 != 2
  rerun:  patina run --seed 1 --config /tmp/suite/patina-out/sweep/seed-1/2-test_store.Store.test_counter/run.json -- python3 -m unittest test_store.Store.test_counter
  replay: patina replay /tmp/suite/patina-out/sweep/seed-1/2-test_store.Store.test_counter
  explain: patina explain /tmp/suite/patina-out/sweep/seed-1/2-test_store.Store.test_counter
```

Write the cases file with one loop over the runner's own listing. Go: `go test -c -o pkg.test`,
then one line `./pkg.test -test.run '^NAME$'` per name of `./pkg.test -test.list .`. Rust: the
loop in the guide's "Test suites" over `cargo test --no-run` binaries. A Go test's failure is
on its stdout, so read `inc-0/stdout` of the group's run.
