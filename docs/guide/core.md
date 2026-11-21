# Patina: find, reproduce and explain rare bugs in a Linux program

Patina runs an unmodified Linux program many times, each run under a seed that decides thread
order, the clock, randomness, and the disk, network and crash faults the program meets. The
same seed gives the same run, so a failure seen once in a thousand runs becomes a command that
reproduces it. Patina reports a run only when a check fails: a nonzero exit, a signal, a hang,
a failed assertion, or a checker of your own. Use it for crash safety and durability, error
handling under faults, concurrency, distributed systems, and flaky failures. This guide is
built into the binary and describes this version: `patina guide TOPIC` for detail, `patina
COMMAND --help` for every option.

## The workflow

**1. Check the host.** `patina doctor` must end with `this host can run patina`. Otherwise do
the fix it prints, or ask the user to (the AppArmor step needs root): `patina guide limits`.

**2. Run the program once.** Everything after `--` is the program and its arguments:

<!-- transcript first-run
dir: /tmp/app
setup: cp "$GUESTS/examples/acklog" app
-->
```text
$ patina run -- ./app
ok (exit): the program exited 0
guest: exit 0
run directory: /tmp/app/patina-out/run-0
replay: patina replay /tmp/app/patina-out/run-0
```

It starts in an empty, writable `/work` (its working directory and `HOME`), sees the host's
`/usr` and its own directory read-only, and no network beyond the run. Give it inputs with
`--work DIR` (copied in as the starting `/work`), `--mount SRC:DST`, `--env K=V`, `--stdin
FILE`; a `not in the sandbox:` line names what to mount. The program after `--` is found on the
host; a script that exists only in `/work` runs as `sh ./script`. Make this run end `ok` before going on: anything else
is a setup problem.

**3. Write the check first.** A sweep reports only runs that end other than `ok`. If the bug
you are after would still exit 0 (lost data, a wrong file, a double apply), add a check before
sweeping, and make it fail once on purpose (plant the bug, or point it at a wrong answer): a
check that cannot fail proves nothing. `patina guide checks`.

| What a failure looks like | What to add |
|---|---|
| a panic, an assertion, a signal, a nonzero exit, a hang | nothing |
| a clean error exit under faults | `--ok-exit N` for the statuses the program documents |
| wrong output or lost data with exit 0 | `--check 'CMD ARGS'` (a script on the host), or an SDK `always` |

**4. Choose what to vary**, one kind at a time, starting from the bug you suspect:

| Suspected bug | Add | Read |
|---|---|---|
| a race, a deadlock, an ordering | nothing: every seed is another schedule | `patina guide scheduling` |
| error handling of file I/O | `--faults disk` | `patina guide faults` |
| durability, recovery after power loss | `--crash-points`; for a long program `--faults crash` | `patina guide crashes` |
| a client and server | `--faults net` | `patina guide faults` |
| several machines | nodes, then `--faults net,partition,pause,clock,crash` | `patina guide nodes` |
| the program's own rare paths | SDK fault points and `--faults buggify` | `patina guide sdk` |

**5. Sweep small, then grow.** Exit status 0: every run `ok`; 1: findings; 2: Patina could
not do what was asked (`vacuous`, `unsupported`, `error`, ...), which is never a pass.

<!-- transcript sweep
dir: /tmp/app
exit: 1
-->
```text
$ patina sweep --seeds 1..20 --faults crash -- ./app
...
patina sweep: 20 runs, 5 findings in 1 group, 15 ok   (0.5s, 8 jobs)
outcomes: ok 15, violation 5

violation always: acked-records-kept: N acknowledged, N stored
  5 of 20 runs   first: seed 2   replayed: identical
  example: acked-records-kept: 7 acknowledged, 0 stored
  faults in every failing run: crash      in none: -
  rerun:  patina run --seed 2 --faults crash -- /tmp/app/app
  replay: patina replay /tmp/app/patina-out/sweep/seed-2
  explain: patina explain /tmp/app/patina-out/sweep/seed-2
```

Then `--seeds 1..200`, `1..2000`: a narrow window is found in one seed of thousands. `-j N`
shares a busy host; `--max-findings 1` and `--budget SECONDS` stop early. The same command
again runs only the seeds it lacks; a rebuilt program starts the sweep afresh. `patina guide
sweeps`.

**6. Read the groups, not the logs.** A group is one bug: its signature, how many runs hit it,
its lowest seed (already replayed once) and the commands for that run. On a run directory:

- `patina explain RUNDIR`: the run as a short story, ending with the event to stop at;
- `patina minimize RUNDIR`: the fewest fault settings that still fail the same way;
- `patina debug RUNDIR`: the run stopped under gdb just before that event;
- `patina replay RUNDIR`: the same run again, compared record by record;
- `patina report DIR`: the summary again (`report.json` has every group);
- `patina verify --seed N ...`: one seed under varied host conditions.

`patina guide failures`.

**7. Triage each group, in this order.** (1) The harness or the check is wrong (a missing
input, a checker bug). (2) A Patina limit: `unsupported`, a `refused:` call, `internal`
(`patina guide limits`). (3) A setting stronger than the program promises (a fault it need not
survive, a clean exit `--ok-exit` should name). (4) A real bug. To check a fix, run the
group's `rerun:` line against the rebuilt program, then the same sweep command.

**8. Report what you found, and what you did not look for.** A finding: its `rerun:` line,
`patina --version` and the architecture, the `patina explain` lines that show the cause,
`patina minimize`'s command. A clean sweep: the seeds, the fault classes, what the check could
detect, and what was not tried (no crashes, no rebuilt code). Never weaken a check or change
the program to make a sweep pass; put a finding you will not fix now in a `--known` file.

Keep run output out of your context: read the summary, `report.json`, `result.json` and
`patina explain`, not `boundary.log`. Delete `patina-out` when done.

## Topics

- `patina guide checks`: exit status, `--ok-exit`, `--check`, SDK assertions; proving a check can fail
- `patina guide faults`: the fault classes, the keys, and when faults act
- `patina guide crashes`: crash consistency: crash points and what a crash leaves on disk
- `patina guide scheduling`: where threads switch, and what is not covered
- `patina guide nodes`: several machines in one run, and `patina ctl`
- `patina guide sweeps`: seeds, test suites, kept runs, known findings
- `patina guide failures`: reading a failing run: explain, debug, replay, logs
- `patina guide sdk`: the SDK in Rust, C, Go and Python
- `patina guide limits`: host setup, containers, CI, and what Patina refuses
- `patina guide config`: every `patina.toml` key
- `patina guide outcomes`: every outcome and exit status

`patina guide --list` lists them; `patina guide --format md` prints the markdown they are written
in. `patina skill DIR` writes a small skill that points coding agents here.
