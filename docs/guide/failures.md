# Failures: reading a failing run

Start from the group in the sweep's summary: its signature, its `example:` line, the fault
classes in every failing run, and its run directory. Then, on that directory:

| Command | What it gives |
|---|---|
| `patina explain RUNDIR` | the run as a short story, and the event to stop at |
| `patina minimize RUNDIR` | the fewest fault settings that still fail the same way, and their command |
| `patina debug RUNDIR` | the run replayed and stopped under gdb just before that event |
| `patina replay RUNDIR` | the run again, every system call compared with the recorded one |
| `patina verify --seed N ...` | one seed run several times while the host varies |

`examples/acklog-c` writes a record, then its acknowledgement, and fsyncs only the
acknowledgements. One crash run of it:

<!-- transcript crash
dir: /tmp/acklog
setup: cp -f "$GUESTS/examples/acklog" .
exit: 1
exact-only: one seed's run
-->
```text
$ patina run --seed 3 --faults crash -- ./acklog
violation (always): acked-records-kept: 21 acknowledged, 0 stored
faults injected: 1 (crash 1)
last injected:
  seq 124 t=100000ms crash kind=machine point=91 object=/work/acks.log lost: 0 missing, 2 changed, 0 back
run directory: /tmp/acklog/patina-out/run-3
replay: patina replay /tmp/acklog/patina-out/run-3
explain: patina explain /tmp/acklog/patina-out/run-3
```

## The story: `patina explain`

<!-- transcript explain
dir: /tmp/acklog
exact-only: the run of seed 3 above
-->
```text
$ patina explain patina-out/run-3
violation (always): acked-records-kept: 21 acknowledged, 0 stored
seed 3: 283 events, 30 story lines; showing all 11
data: the first 128 bytes of each read, write, send and receive, from a replay identical to the run (patina-out/run-3/explain)

      48  +      0.046 ms  main  disk: create /work/data.log, create /work/acks.log, fsync the directory /work
      55  +      0.053 ms  main  assert acked-records-kept
      56  +      0.054 ms  main  disk: write /work/data.log (8 bytes at 0), write /work/acks.log (8 bytes at 0), fsync /work/acks.log
     119  +      0.115 ms        ... the line above, 21 times in all, until here
     122  +      0.118 ms  main  disk: write /work/data.log (8 bytes at 168), write /work/acks.log (8 bytes at 168)
     124  +      0.120 ms        at the crash /work/acks.log had 1 write not followed by an fsync (22 writes, 21 fsyncs in all)
     124  +      0.120 ms        at the crash /work/data.log had 22 writes not followed by an fsync (22 writes, 0 fsyncs in all)
     124  +      0.120 ms        CRASH machine at crash point 91; lost: 2 changed (/work/acks.log, /work/data.log)
     124  +      0.120 ms        the machine starts again (incarnation 1)
     181  +  14761.109 ms  main  disk: fsync the directory /work
     211  +  14761.135 ms  main  assert acked-records-kept
stop at: event 211 (main assert acked-records-kept); its record: patina log events patina-out/run-3 --from 211 --to 211
```

Each line is an event number, virtual time since the start, who (a thread, `main`, `t1`, ...;
a node's name with nodes) and what: messages with the bytes sent, disk changes, faults,
crashes, output, the end. Repeats are folded. `--full` prints every line; `--from SEQ --to SEQ`
picks a window. A race in the program's own memory leaves no trace in the log: the story then
says the threads were switched in computation, and `patina log events RUNDIR --types
preempt,call` lists where.

## Stopping the world: `patina debug`

`patina debug RUNDIR` replays the run, stops every thread and process just before the stop event
(`--at SEQ`, `--at call:NAME`, `--at crash`, ... for another), and starts gdb attached to the
process about to act, with the program's symbols. Read anything, set breakpoints, continue: the
session is the recorded run until it writes memory or registers, and the end says whether it
stayed identical. In gdb, `patina procs` lists the other processes and `patina attach PID`
moves to one. `--no-gdb` prints how to attach another debugger. It needs gdb 12 or later, and a
host that lets a user debug their own processes (`patina doctor` checks it).

## Replay, verify, and checking a fix

`patina replay RUNDIR` runs the seed again and compares every record: `identical`, or
`nondeterministic` and the first differing record, which is a Patina bug unless the host's files
changed. It refuses a rebuilt program and a run of another Patina build. `patina verify` runs one
seed several times, moving it across CPUs, under load, with address randomization and in another
sandbox, and checks the runs are identical:

<!-- transcript verify
dir: /tmp/acklog
setup: cp -f "$GUESTS/examples/acklog" .
exit: 1
exact-only: one seed's run
-->
```text
$ patina verify --seed 3 --runs 3 --faults crash -- ./acklog
run 0: cpu 8 aslr off load on env base violation a6f8fbcb6b6345b9 switches 0
run 1: cpu 16 aslr on load on env base violation a6f8fbcb6b6345b9 switches 0
run 2: cpu 0 aslr off load on env base violation a6f8fbcb6b6345b9 switches 0
identical: 3 runs in /tmp/acklog/patina-out/verify-3
violation (always): acked-records-kept: 21 acknowledged, 0 stored
```

To check a fix, run the group's `rerun:` line against the rebuilt program: it names the program
by path and carries the seed, the faults, the checker and the case. Then run the same sweep
command again.

## The run directory

| File | |
|---|---|
| `run.json` | the seed, the settings, the program's SHA-256: `patina run --config RUNDIR/run.json` reruns it |
| `result.json` | the outcome, `stop`, `message`, `signature`; `faults` (the plan, what was injected), `crashes`, `sdk` (every site), `refused` (calls answered with an error), `nodes` |
| `inc-K/stdout`, `inc-K/stderr` | the program's output in incarnation K (one per start) |
| `inc-K/post-crash/` | the files a machine crash left |
| `check.out` | the checker's output |

<!-- transcript result-json
dir: /tmp/acklog
exact-only: the run of seed 3 above
-->
```text
$ jq '{outcome, stop, message, incarnations}' patina-out/run-3/result.json
{
  "outcome": "violation",
  "stop": "always",
  "message": "acked-records-kept: 21 acknowledged, 0 stored",
  "incarnations": 2
}
```

The logs, read by `patina log`:

- `patina log ops RUNDIR/inc-0`: every change to `/work`, in order;
- `patina log tree RUNDIR/inc-0 DIR`: the work tree that incarnation ended with, written to DIR
  (`--post-crash`: the one its crash left);
- `patina log events RUNDIR`: the whole run as JSON lines for `jq` or a checker: system calls
  with their paths, file operations, faults, crashes, marks, node and network events (`--types
  op,crash` keeps those; every line has `type`, `seq` and `t`, virtual nanoseconds);
- `patina log dump LOG --from SEQ --to SEQ` and `patina log diff LOG LOG`: the raw boundary log,
  and the first record where two differ.

<!-- transcript events
dir: /tmp/acklog
exact-only: the run of seed 3 above
-->
```text
$ patina log events patina-out/run-3 --types crash
{"type":"header","v":1,"seed":3,"work":"/work","incarnations":2}
{"type":"crash","inc":0,"seq":124,"t":100000120074,"slot":0,"kind":"machine","point":91,"lost":{"back":0,"changed":2,"missing":0,"paths":["/work/acks.log","/work/data.log"]}}
```

A run a sweep did not keep has no logs; its seed reproduces it with `patina run --seed N`.
Types and fields of the event stream are only ever added: a reader ignores what it does not know.
