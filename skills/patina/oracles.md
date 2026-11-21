# Oracles: what a run checks

A sweep finds only what ends a run non-`ok`. Pick the cheapest check that sees the bug you are
after, add it before sweeping, and show once that it can fail. The commands below use
`upcase`, a program that writes an upper-case text to `out.txt` and exits 1 on any error, but
checks `write` only for -1: a short write loses part of the file and it still exits 0.

## 1. The exit status

Assertions, panics and a nonzero exit on an inconsistency already work. The last line of
stderr (or the panic line) becomes the group's signature, so make it say what broke. A program
without an SDK can write a line starting `INVARIANT ` to stderr and exit nonzero: that line is
the signature, and it stays a finding even under `--ok-exit`.

Under faults a correct program often fails cleanly: it reports the error and exits. A plain
disk-fault sweep of `upcase` reports only those clean failures:

<!-- transcript plain
dir: /tmp/oracle
setup: cp "$GUESTS/examples/upcase" .
exit: 1
-->
```text
$ patina sweep --seeds 1..80 --faults disk -- ./upcase
...
patina sweep: 80 runs, 4 findings in 3 groups, 76 ok   (1.3s, 8 jobs)
outcomes: failure 4, ok 76
...
```

`--ok-exit 1` says exit 1 is a handled failure (`--ok-exit 1:fs-error,fsync-error`: only in a
run where one of those faults fired). Name only statuses the program documents as a clean
failure; a signal is never `ok`. Now every run is `ok`, which proves nothing about the output:

<!-- transcript ok-exit
dir: /tmp/oracle
-->
```text
$ patina sweep --seeds 1..80 --faults disk --ok-exit 1:fs-error,fsync-error -- ./upcase
...
patina sweep: 80 runs, 0 findings in 0 groups, 80 ok (4 by --ok-exit)   (0.4s, 8 jobs)
outcomes: ok 80
```

## 2. A check script: `--check 'CMD ARGS'`

After each run that ends `ok`, Patina runs `CMD ARGS RUNDIR` on the host, as you, from the
directory patina was started in, with `PATINA_SEED`, `PATINA_EXIT` and `PATINA` (the patina
binary) set. It answers by exit status:

| Exit | Meaning |
|---|---|
| 0 | pass |
| 1 | finding: the first stdout line `LABEL: detail` names it (numbers in the detail become N, so one bug is one group) |
| 77 | not judged: the first line `CLASS: detail` says why (no crash in this run, a clean failure) |
| anything else | `error`: a broken checker is never a pass |

What it can read in `RUNDIR`: `inc-K/stdout`, `inc-K/stderr` (incarnation K, one per start of
the program); `inc-K/post-crash/` (the files a machine crash left, which the next start
recovers from); `result.json`; `patina log tree RUNDIR/inc-K DIR` (the work tree that start
ended with); `patina log events RUNDIR` (what the program did, as JSON lines). It must be a
function of the run directory: no wall clock, no network, no reference that changes.

Here the reference is a faults-off run, and the check compares the file each run leaves with it:

<!-- transcript check
dir: /tmp/oracle
exit: 0 0 0 0 1
-->
```sh
patina run --seed 1 --out patina-out/ref -- ./upcase
patina log tree patina-out/ref/inc-0 ref
cat > check-out <<'EOF'
#!/bin/sh
# check-out RUNDIR: a run that exits 0 leaves the out.txt of the faults-off run.
[ "$PATINA_EXIT" = 0 ] || { echo "clean-failure: exit $PATINA_EXIT"; exit 77; }
t=$(mktemp -d) || exit 2
"$PATINA" log tree "$1/inc-0" "$t/tree" || exit 2
if cmp -s "$t/tree/out.txt" ref/out.txt; then s=0; else s=1; fi
rm -r "$t"
[ $s = 0 ] || { echo "wrong-output: out.txt differs from the faults-off run's"; exit 1; }
EOF
chmod +x check-out
patina sweep --seeds 1..40 --faults disk --ok-exit 1 --check ./check-out -- ./upcase
```

The sweep now reports `violation check: wrong-output: ...` in the runs where a short write
fired (`faults in every failing run: fs-short`). Skipping clean failures (exit 77) leaves them
unjudged: if the program promises something for them too (a message, an untouched file), check
that instead of skipping. `examples/checks/` in the Patina repository
has ready checkers: `same-tree` (this comparison), `same-output` (stdout against a reference
sweep), `acked-kept` (acknowledged records survive a crash), `confined` and
`no-symlink-escape` (where a program wrote and opened files), `synced-before-mark`.

## 3. The SDK, when you can edit the code

Outside Patina every SDK call is a no-op, so it can stay in production builds.

| Language | Add | Invariant |
|---|---|---|
| Rust | `patina-dst = { git = "https://github.com/JacobHayes/patina", tag = "vX.Y.Z" }` | `patina_dst::always!(cond, "label", "{detail}")` |
| C | `#include "patina.h"` (`sdk/c`, one header) | `PATINA_ALWAYS(cond, "label", detail)` |
| Go | `go get github.com/JacobHayes/patina/go/patina@vX.Y.Z` | `patina.Always("label").Check(cond, detail...)` |
| Python | `sdk/python/patina.py` on `PYTHONPATH` | `patina.Always("label").check(cond, detail)` |

- `always` must hold; `unreachable` must not be reached: either ends the run `violation`.
- `sometimes(cond, label)` and `reachable(label)` must hold or be hit in at least one run of the
  sweep, or the sweep ends `vacuous`. Put one where the interesting state is (a retry taken, a
  recovery run, a leader changed): a sweep that never got there found nothing there.
- `buggify(label)` is a fault point the seed turns on under `--buggify`: take the rare path
  (a retry, a slow branch, an early timeout) only where the real program can.
- `setup_complete()` marks the end of setup; with `--fault faults-after-setup=1`, faults and
  crash points start there.
- `mark("ack 17")` records a promise in the log for a checker to verify against what reached
  the disk (`examples/checks/synced-before-mark`).

## 4. Prove the check can fail

A checker that lost a file or a variable passes everything, and looks exactly like a correct
program. Before trusting a clean sweep, make the check fail once: run it against a program
that is wrong by construction, or plant the bug in a copy.

<!-- transcript planted
dir: /tmp/oracle
exit: 1
-->
```sh
patina run --check ./check-out -- /bin/sh -c 'echo wrong >out.txt'
```

For a corpus run with `--cases`, keep one case that is wrong by construction and name it in a
`--known` file as `!ID PATTERN`: every sweep then fails (`vacuous`) if the check stops firing.
A sweep with a check that never failed says so: `check: every judged run passed and no --known
!ID entry shows that this check can fail`.

After changing only the checker, `patina report --recheck OUT` judges the kept runs again
without running them (a sweep with a checker keeps what it needs).
