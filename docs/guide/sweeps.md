# Sweeps: seeds, test suites, kept runs, known findings

`patina sweep` runs many seeds in parallel, each a normal `patina run`, and groups the failing
runs by signature: the outcome, what stopped the run, and its first line of evidence, with
numbers made `N` so one bug over many seeds is one group.

| Option | |
|---|---|
| `--seeds 1..200,250` | a range, a list or both (default `1..100`) |
| `-j N` | runs at once (default the CPUs, at most 8) |
| `--out DIR` | the sweep directory (default `patina-out/sweep`) |
| `--max-findings N`, `--budget SECONDS` | stop early |
| `--keep fail\|all` | whose logs to keep (below) |
| `--cases FILE` | one run per line of FILE per seed (below) |
| `--known FILE` | findings that do not fail the sweep (below) |
| `--crash-points`, `--crash-points=N` | one run per crash point per seed (`patina guide crashes`) |

A sweep directory holds one sweep. The same command again runs only the runs it lacks (more
seeds, or after an interrupt); a changed program or setting replaces the directory, so edit,
rebuild and run the same command. Use one `--out` per experiment. A changed checker does not
rerun anything: the runs are judged again from their logs.

The summary prints the first three groups in full and the others one line each, numbered;
`patina report --group N DIR` prints one in full, `patina report DIR` the whole summary again,
and `report.json` in the sweep directory has every group with its runs. `--keep fail` (the
default) keeps the logs of each group's first three runs, and with a checker every run the
checker read; any other run keeps `run.json` and `result.json`, and its seed reproduces it.

## Test suites: `--cases`

A test suite is many tests, best run each alone. `--cases FILE` runs each line of FILE once per
seed, each its own run; a line is a whole command, quoted as in a shell. Given a command after
`--`, a line instead fills `{}` in it.

<!-- transcript cases
dir: /tmp/casedemo
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
  rerun:  patina run --seed 1 --config /tmp/casedemo/patina-out/sweep/seed-1/2-test_store.Store.test_counter/run.json -- python3 -m unittest test_store.Store.test_counter
  replay: patina replay /tmp/casedemo/patina-out/sweep/seed-1/2-test_store.Store.test_counter
  explain: patina explain /tmp/casedemo/patina-out/sweep/seed-1/2-test_store.Store.test_counter
```

A line may start with its own settings, up to a word `--`: `--disk DIR[:GUEST]`, `--mount`,
`--env`, `--stdin` as for `patina run`, and --name NAME, the case's id (a line number moves when
a line is added above it, a name does not):

```text
--disk cases/grep-basic/t:/work/t --name grep-basic -- /h/harness grep-basic
```

Write the file with one loop over the runner's own listing. Rust test binaries:

<!-- no-run cargo-cases: a Rust project of your own -->
```sh
for b in $(cargo test --no-run --message-format=json | jq -r 'select(.profile.test and .executable) | .executable'); do
  "$b" --list --format terse | sed -n "s|: test\$||; s|^|$b --exact |p"
done > tests.txt
patina sweep --seeds 1..5 --cases tests.txt
```

Go: `go test -c -o pkg.test`, then one line `./pkg.test -test.run '^NAME$'` per name that
`./pkg.test -test.list .` prints. A finding named by a label (an `always`, a check's label) is
one group over every case it appears in; any other is grouped per case.

## Known findings: `--known FILE`

A finding already known (being fixed, or a library's to fix) need not fail every sweep. Each
line of the file is `ID PATTERN`; `*` matches any text, and a pattern starting with `[` also
matches the case. A known finding is counted and listed, and only a new one makes the exit
status 1. An entry written `!ID` must match: a case wrong by construction, with a `!` entry,
proves on every sweep that the check can fail, and the sweep is `vacuous` when it does not.
Here `calc OP A B` gets two operations wrong, and a checker compares each answer with `sh`'s:

<!-- transcript known
dir: /tmp/calc
setup: cp "$REPO/tests/docs/fixtures/calc/"* .
exit: 0 1
-->
```text
$ cat known.txt
# ID, then a pattern: * matches any text; a pattern starting with [ also matches the case.
sub-clamps  violation check: wrong-sub: *
!planted    [*planted*] violation check: wrong-*
mul-zero    violation check: wrong-mul: got 1, want 0
$ patina sweep --seeds 1..2 --cases cases.txt --mount /tmp/calc:/demo --check ./same-as-sh --known known.txt
...
known: 8 runs (sub-clamps 6, planted 2); 6 new, in 1 group

violation check: wrong-mul: got N, want N
  6 of 56 runs, 3 cases   first: seed 1, case 19 [/bin/sh /demo/calc mul 1 0]   replayed: identical
...
known: mul-zero matched no run; with its numbers written as the signature writes them it matches "violation check: wrong-mul: got N, want N" (an exit status keeps its digits, other numbers are N)
```

A pattern matches the signature as the report prints it, with numbers as `N`: an entry that
would match written that way says so, as `mul-zero` does. A pattern ending ` {faults: *fs-short*}`
also matches the faults that fired in the run. `[sweep] known = "FILE"` makes a file the
default. `patina report --known FILE DIR` applies a file to runs already made.

## Judging again: `patina report --recheck`

After changing only the checker, or a table it reads, `patina report --recheck DIR` judges the
kept runs again without running them, then prints the report. Here case 4 differs from the
reference by design, and the checker skips the cases `chk/expected.txt` names:

<!-- transcript recheck
dir: /tmp/judge
setup: cp -r "$REPO/tests/docs/fixtures/judge/." .
exit: 0 1 0 0
-->
```sh
patina sweep --seeds 1 --keep all --cases corpus.txt --out patina-out/ref -- sh -c {}
patina sweep --seeds 1..2 --cases corpus.txt --check 'chk/diff patina-out/ref' -- bash -c {}
echo 4 >> chk/expected.txt
patina report --recheck patina-out/sweep
```

```text
recheck: judged 8 runs again in 0.0s
patina report: 8 runs, 0 findings in 0 groups, 8 ok
outcomes: ok 8
check: judged 6 of 8 runs: 6 passed, 0 failed; 2 not judged (expected 2)
check: every judged run passed and no --known !ID entry shows that this check can fail
```

This is the triage loop for a corpus compared with a reference: a correct difference goes in the
checker's table of expected differences (it answers 77, `expected: ...`), a known bug in the
`--known` file, and a new bug is reproduced with its group's `rerun:` line.

## If a sweep finds nothing

In order of what helps most: more seeds (a narrow window is one seed in thousands);
`--crash-points` for a crash window; `--faults buggify`, or `--fault buggify:LABEL=1000` to fire
one fault point every time; a lower crash rate (`--fault crash-permille=1`) to reach later
points; a range of crash positions you know (`--fault crash-at=A..B`); a rebuild with compute
points for a race far from any point (`patina guide scheduling`). Then report what was varied
and what the check could detect: a clean sweep is not "no bugs".
