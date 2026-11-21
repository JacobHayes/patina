---
name: patina
description: Find, reproduce and explain rare bugs in a Linux program with Patina, which runs it under many seeds that each decide thread scheduling, time, randomness, disk and network faults, machine crashes and node partitions, and replays any seed exactly. Use when asked to test crash safety, durability, error handling under faults, concurrency or a distributed system; to reproduce a flaky failure; or when a task mentions patina or deterministic simulation testing.
---

# Patina

Patina runs an unmodified Linux program (any language) many times; each run's seed decides
thread order, the clock, randomness and the faults it meets, and replays exactly. Use it when a
bug is rare, depends on timing, faults or crashes, or needs a reproducer. `patina COMMAND
--help` is authoritative for your build; the repository's `docs/GUIDE.md` has every workflow.

## Limits: check these before spending time

- Linux only (on a Mac: a Linux arm64 VM, 4 KiB pages, kernel 6.12+). It needs unprivileged
  user namespaces: on Ubuntu 24.04+ each patina executable path needs an AppArmor profile,
  installed once as root (`patina doctor` prints the command). A copy at another path ends
  `internal` until it has one: use the installed binary. Docker's default profile refuses it.
- No outside network: loopback and the run's own nodes only; names come from `/etc/hosts`.
  Every server and client the test needs must run inside the run.
- Threads switch only at system calls and spin-waits. A race on plain memory with no system
  call between the accesses never shows without `--preempt points` (or a rebuild with compute
  points); code generated at run time (a JIT) gets no points at all.
- Computing does not advance virtual time in stock code: only `--timeout` (wall seconds) cuts
  a CPU-bound loop. The one crash-modelled disk is the work tree `/work` (cwd and `HOME`).
- A seed replays only on the same kind of host, with the same patina build and program binary.
- A call Patina does not model ends the run `unsupported`, naming it; a call it refuses gets an
  error code and is listed under `refused:`. Neither is a bug in the program.

## Workflow

1. **Host.** `patina doctor` must end `this host can run patina`; otherwise do the fix it
   prints or tell the user (the AppArmor step needs root). Note `patina --version`.
2. **First run.** The program starts in an empty `/work`; only the host's `/usr` and the
   program's own directory are visible (read-only). Give inputs with `--mount SRC:DST`, `--work
   DIR` (the starting `/work`), `--env K=V`, `--stdin FILE`. A first run that is not `ok` is a
   setup problem to fix before sweeping (a `not in the sandbox:` line says what to mount).

<!-- transcript first-run
dir: /tmp/app
setup: cp "$GUESTS/examples/acklog" app
-->
```text
$ patina doctor | tail -n 1
this host can run patina
$ patina run -- ./app
ok (exit): the program exited 0
guest: exit 0
run directory: /tmp/app/patina-out/run-0
replay: patina replay /tmp/app/patina-out/run-0
```

3. **Oracle first.** A sweep reports only runs that end non-`ok`: a nonzero exit, a signal, a
   hang or deadlock (`liveness`), a failed SDK `always`, or a `--check` script's finding. If
   the bug you are after would still exit 0 (lost or wrong data, a double apply), add a check
   before sweeping, and prove it can fail once (break the program or the check on purpose).
   [oracles.md](oracles.md) shows each kind; a sweep without an oracle proves little.
4. **Choose what to vary**, smallest first ([faults.md](faults.md); worked shapes for a
   file-writing tool, threads, a client and server, nodes, a test suite: [recipes.md](recipes.md)):

   | Suspected bug | Add |
   |---|---|
   | ordering, races, deadlock | nothing (seeds vary the schedule); `--preempt points` for races on plain memory |
   | error handling of file I/O | `--faults disk`, with `--ok-exit N` for documented clean failures |
   | durability, recovery | `--crash machine` (the program must recover from `/work` on restart), then `--branch` |
   | client/server | `--faults net` |
   | several machines | nodes in `patina.toml`, then `--faults cluster` |
   | the program's own fault points | `--buggify` |

5. **Sweep small**, then grow seeds. Exit status 0: all `ok`; 1: findings; 2: Patina could not
   do what you asked (`vacuous`, `unsupported`, `error`, ...), never a pass.

<!-- transcript sweep
dir: /tmp/app
exit: 1
-->
```text
$ patina sweep --seeds 1..20 --crash machine -- ./app
...
patina sweep: 20 runs, 6 findings in 1 group, 14 ok   (0.2s, 8 jobs)
outcomes: ok 14, violation 6

violation always: acked-records-kept: N acknowledged, N stored
  6 of 20 runs   first: seed 3   replayed: identical
  example: acked-records-kept: 23 acknowledged, 0 stored
  faults in every failing run: crash      in none: -
  rerun:  patina run --seed 3 --crash machine -- /tmp/app/app
  replay: patina replay /tmp/app/patina-out/sweep/seed-3
  explain: patina explain /tmp/app/patina-out/sweep/seed-3
```

6. **Read groups, not logs.** A group is one bug: signature, run count, lowest seed and the
   `rerun:` line that reproduces it (run it from the sweep's directory: a `--check` path in it is
   relative); `report.json` in the sweep directory has every group
   (`patina report DIR` reprints them). On a group's run directory: `patina explain` (the story
   and the event to stop at), `patina minimize` (the fewest faults that still fail), `patina
   debug` (gdb stopped just before that event).

<!-- transcript understand
dir: /tmp/app
exit: 0 0 0 0 1
-->
```sh
jq -r '.groups[] | "\(.count) \(.signature)\n  \(.rerun)"' patina-out/sweep/report.json
run=$(jq -r '.groups[0].first.dir' patina-out/sweep/report.json)
patina explain "$run"
patina minimize "$run"
patina verify --seed "$(jq .groups[0].first.seed patina-out/sweep/report.json)" --runs 3 --vary cpu,aslr --crash machine -- ./app
```

7. **Triage** each group in order: (1) a harness or oracle bug (wrong checker, missing input);
   (2) a Patina limit (`unsupported`, `refused:` calls, `internal`); (3) a setting stronger than
   the program promises (a fault it need not survive, a missing `--ok-exit`); (4) a real bug.
   `patina verify` (above) repeats one seed on a varied host: identical runs rule out flakes.
8. **Check a fix** with the group's `rerun:` line against the rebuilt program (`patina
   replay` refuses a changed binary), then the same sweep command, which starts afresh.

## Outcomes

| Outcome | Exit | Means | Do |
|---|---|---|---|
| `ok` | 0 | passed every check it had | nothing; the check decides what this proves |
| `violation` | 1 | an SDK `always`/`unreachable`, or `--check`, failed | triage |
| `failure` | 1 | nonzero exit not in `--ok-exit` | triage; under faults, is it a clean failure? |
| `crash` | 1 | killed by a signal | triage |
| `liveness` | 1 | all threads blocked, virtual `--time-limit` passed, or `--log-limit` reached (`log-limit`) | triage: deadlock or lost wakeup |
| `unsupported` | 2 | Patina does not model what the program did | report the named call; do not hide it |
| `timeout` | 2 | wall `--timeout` passed | a CPU-bound loop or a hang outside virtual time |
| `nondeterministic` | 2 | a replay differed from its run | a Patina bug: keep the run directory, report it |
| `internal` | 2 | Patina or the host failed | run `patina doctor` |
| `vacuous` | 2 | a fault, SDK site or check never had anything to act on | fix the setup; `--allow-unmet` only with a reason |
| `error` | 2 | the program cannot run, or the checker broke | fix the command or the checker |

## Habits

- Keep output out of your context: read the summary, `report.json`, `result.json` and
  `patina explain` (`--full` for every line), not `boundary.log`. A run's output is in
  `RUNDIR/inc-0/stdout` and `stderr` (`inc-1/` after a restart); a sweep keeps it only for
  failing runs, the first three of each finding (`--keep fail`): for any other, run its seed again with `patina run --seed N`.
- Budget: start at `--seeds 1..20`, then grow; `--max-findings 1`, `--budget SECONDS`, `-j N`
  on a shared host; `--keep none` for large sweeps. One `--out DIR` per experiment: the same
  command resumes it, a changed program replaces it.
- Never edit the program or weaken the check to make a sweep pass; a finding you will not fix
  now goes in a `--known FILE` (see the guide), so new ones still fail the sweep.
- A clean sweep is not "no bugs": report what was varied, what the oracle could detect and
  what was not tried. Hand a finding over as its `rerun:` line, `patina --version` and the
  architecture, the `patina explain` lines that show the cause, `patina minimize`'s command.
- Delete `patina-out/` (your `--out` directories) when done; `patina cache clear` too.
- Also: `patina recheck DIR` judges kept runs again with a changed checker; `patina log events
  RUNDIR` exports a run as JSON lines; `patina table` says what Patina does with each system
  call; `patina ctl` scripts the network inside a run with nodes ([faults.md](faults.md)).
