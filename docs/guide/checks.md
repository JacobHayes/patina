# Checks: what makes a run a finding

A sweep reports only runs that end other than `ok`. Choose the cheapest check that sees the bug
you are after, add it before sweeping, and make it fail once. The examples use
`examples/upcase-c`: it writes a text in upper case to `out.txt` and exits 1 on any error, but
it checks `write` only for -1, so a short write loses part of the file and it still exits 0.
`examples/` is in the repository (https://github.com/JacobHayes/patina), not in the binary:
run the examples from a checkout's root, or copy a checker from there.

## The exit status

A nonzero exit (`failure`), a signal (`crash`), a hang or deadlock (`liveness`) and a failed
SDK assertion (`violation`) need nothing added. The panic line, or else the last line of
stderr, becomes the group's signature, so make it say what broke. A program without the SDK can
print a line starting `INVARIANT ` to stderr and exit nonzero: that line names the finding.

Under faults a correct program often fails cleanly: it reports the error and exits. A plain disk
sweep of `upcase` finds only those:

<!-- transcript upcase-plain
dir: /tmp/upcase
exit: 0 1
-->
```text
$ cc -o upcase examples/upcase-c/upcase.c
$ patina sweep --seeds 1..80 --faults disk -- ./upcase
...
patina sweep: 80 runs, 4 findings in 3 groups, 76 ok   (1.0s, 8 jobs)
outcomes: failure 4, ok 76
...
```

`--ok-exit 1` says exit 1 is a handled failure: such a run ends `ok` (stop `ok-exit`) and a
check still judges it. `--ok-exit 1:fs-error,fsync-error` allows it only in a run where one of
those fault classes injected; `--ok-exit any` allows every status. Name only statuses the
program documents as a clean failure: a Rust panic exits 101, so `--ok-exit 1` keeps panics
findings; a signal is never `ok`, nor is a status after an `INVARIANT ` line.

<!-- transcript ok-exit-class
dir: /tmp/upcase
-->
```text
$ patina sweep --seeds 1..100 --faults disk --ok-exit 1:fs-error,fsync-error -- ./upcase
...
patina sweep: 100 runs, 0 findings in 0 groups, 100 ok (5 by --ok-exit)   (0.5s, 8 jobs)
outcomes: ok 100
```

Every run is `ok` now, which proves nothing about the file it wrote. That needs a check.

## A check script: `--check 'CMD ARGS'`

After each run that ends `ok`, Patina runs `CMD ARGS RUNDIR` on the host, as you, from the
directory patina was started in (paths in `CMD ARGS` are relative to it). `CMD ARGS` is split
into words as a shell would, without expansion; name a shell to get one (`--check 'sh -c
"..."'`). The checker gets:

| | |
|---|---|
| `RUNDIR` | its last argument: `run.json`, `result.json`, `boot-K/stdout`, `boot-K/stderr`, `boot-K/post-crash/` |
| `PATINA_SEED`, `PATINA_EXIT` | the seed; the program's exit status |
| `PATINA_CASE`, `PATINA_CASE_ID` | with `--cases`: the case's line and its id |
| `PATINA` | the `patina` running it, for `"$PATINA" log tree` and `"$PATINA" log events` |

It answers by its exit status:

| Exit | The run |
|---|---|
| 0 | stays `ok` |
| 1 | `violation`: the first line of stdout, `LABEL: detail` or `LABEL [KEY]: detail`, names the finding |
| 77 | stays `ok`, not judged: the first line, `CLASS: detail`, says why (no crash in this run, a clean failure) |
| anything else, a signal, past `[run] check-timeout` | `error`: a broken checker is never a pass |

The label is kept as written and numbers in the detail become `N`, so one bug is one group
however many runs hit it: put what tells findings apart in the label, or in `[KEY]` (the detail
then stays out of the signature). The checker must be a function of the run directory: no wall
clock, no network, no reference that moves; a replay that judges differently ends `error`, stop
`check-unstable`. Its output is in `RUNDIR/check.out`.

What it can read: `boot-K/stdout` and `stderr` (boot K: one per start of the program);
`boot-K/post-crash/`, the files a machine crash left; `patina log tree RUNDIR/boot-K DIR`, the
disk that start ended with; `patina log events RUNDIR`, everything the program did as JSON
lines (`patina guide failures`).

Here the reference is the faults-off run of seed 1, and `examples/checks/same-tree` compares
the tree each run leaves with it, and does not judge a clean failure:

<!-- transcript upcase-check
dir: /tmp/upcase
exit: 0 1
-->
```text
$ patina run --seed 1 --out patina-out/ref -- ./upcase
ok (exit): the program exited 0
guest: exit 0
run directory: /tmp/upcase/patina-out/ref
replay: patina replay /tmp/upcase/patina-out/ref
$ patina sweep --seeds 1..100 --faults disk --ok-exit 1 --check 'examples/checks/same-tree patina-out/ref' -- ./upcase
sweep: /tmp/upcase/patina-out/sweep holds another sweep (other settings: ok-exit); replacing it
new: violation check: wrong-output: Files want/out.txt and got/out.txt differ   (seed 2: patina replay /tmp/upcase/patina-out/sweep/seed-2)
sweep: replaying the first seed of 1 finding
sweep: 12.0 MiB kept in /tmp/upcase/patina-out/sweep
patina sweep: 100 runs, 21 findings in 1 group, 79 ok (5 by --ok-exit)   (0.5s, 8 jobs)
outcomes: ok 79, violation 21
check: judged 95 of 100 runs: 74 passed, 21 failed; 5 not judged (clean-failure 5)

violation check: wrong-output: Files want/out.txt and got/out.txt differ
  21 of 100 runs   first: seed 2   replayed: identical
  faults in every failing run: fs-short      in none: fs-error, fsync-error
  rerun:  patina run --seed 2 --faults disk --check 'examples/checks/same-tree patina-out/ref' --ok-exit 1 -- /tmp/upcase/upcase
  replay: patina replay /tmp/upcase/patina-out/sweep/seed-2
  explain: patina explain /tmp/upcase/patina-out/sweep/seed-2
```

`examples/checks/` has more: `same-output REF` (stdout and exit status against a reference
sweep), `acked-kept` (every acknowledged record survives a crash), `confined ROOT...` and
`no-symlink-escape ROOT...` (where the program wrote and opened files), `synced-before-mark
FILE PREFIX` (nothing unsynced at a promise the program marked). A program's output that does
not depend on the schedule needs one reference run; otherwise sweep the reference over the same
seeds with `--keep all` and compare `REF/seed-$PATINA_SEED`. One `--check` per run: several
checks are one script that prints the first failure. A checker that names `PATINA_CHECK_SERVE`
in its file is started once per job and asked about each run on its stdin (one JSON line in,
`pass`, `fail LABEL: detail` or `skip CLASS: detail` out): `examples/checks/same-output.py`.

## Assertions in the program: the SDK

Where you can edit the code, an assertion checks the invariant where it holds. Outside Patina
every SDK call does nothing, so it can stay in production builds (`patina guide sdk`):

| | Rust | C | Go | Python |
|---|---|---|---|---|
| must hold | `always!(c, "l", ...)` | `PATINA_ALWAYS(c, "l", d)` | `Always("l").Check(c, ...)` | `Always("l").check(c, d)` |
| must hold in some run | `sometimes!(c, "l")` | `PATINA_SOMETIMES(c, "l")` | `Sometimes("l").Check(c)` | `Sometimes("l").check(c)` |
| setup is done | `setup_complete()` | `patina_setup_complete()` | `SetupComplete()` | `setup_complete()` |
| faults are done | `faults_done()` | `patina_faults_done()` | `FaultsDone()` | `faults_done()` |
| a promise, for a checker | `mark(s)` | `patina_mark(s)` | `Mark(s)` | `mark(s)` |

A failed `always` ends the run `violation`, named by its label. A `sometimes` or `reachable`
that no run of a sweep met makes the sweep `vacuous`: put one where the interesting state is (a
retry taken, a recovery run), so a sweep that never got there says so. Faults act only after
`setup_complete()` (in a run that declares `setup = "mark"`) and before `faults_done()`: the
setup is not under test and the final checks see a quiet system; `--setup` and `--finally` do
the same with commands (`patina guide faults`). `mark("ack 17")` records a promise in the log;
`examples/checks/synced-before-mark` then checks that its data was synced first.

## Prove the check can fail

A checker that lost a file or a variable passes everything and looks exactly like a correct
program. Before trusting a clean sweep, run the check on a program that is wrong by
construction:

<!-- transcript planted
dir: /tmp/upcase
exit: 1
-->
```sh
patina run --check 'examples/checks/same-tree patina-out/ref' -- /bin/sh -c 'echo wrong >out.txt'
```

A sweep whose check never failed says so (`check: every judged run passed and no --known !ID
entry shows that this check can fail`). With `--cases`, keep one case that is wrong by
construction and name it in the `--known` file as `!ID PATTERN`: a sweep in which it does not
fail ends `vacuous` (`patina guide sweeps`). After changing only the checker, `patina report
--recheck DIR` judges the kept runs again without running them.
