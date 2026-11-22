---
name: patina
description: Find, reproduce and explain rare bugs in a Linux program with Patina, a deterministic simulation tester that runs the program under many seeds, each deciding thread scheduling, time, disk and network faults, machine crashes and network partitions, and replays any seed exactly. Use when asked to test crash safety, durability, error handling under faults, concurrency or a distributed system; to reproduce a flaky or intermittent failure; or when a task mentions patina or deterministic simulation testing.
---

# Patina

Patina runs an unmodified Linux program, in any language, many times; each run's seed decides
thread order, the clock, randomness and the faults the program meets, so a rare failure becomes
a seed that replays exactly. It reports only what a check detects, so most of the work is
choosing what to vary and what to check.

Use it for bugs that depend on timing, faults or crashes: lost or corrupt data after a crash,
wrong handling of I/O errors, races and deadlocks, distributed systems under partitions, and
flaky tests that need a reproducer. It is not for logic bugs a plain test finds, performance
work, or programs that need the outside network or a host other than Linux.

## How to use it

1. Run `patina guide` first and follow it. The guidance is built into the binary and matches
   the installed version, so it is the only source to trust for commands and options; it names
   the topic to read next, as `patina guide TOPIC`.
2. If anything fails to start, run `patina doctor` and do what it says, or tell the user what
   needs root.

Habits that hold in every version:

- Write the check before sweeping, and make it fail once on purpose: a check that cannot fail
  proves nothing.
- Keep run output out of your context: read summaries and the commands' short reports, not
  raw logs.
- Report what was varied and what the checks could detect, not only what was found: a clean
  sweep is not "no bugs".
