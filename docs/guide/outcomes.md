# Outcomes: how a run ends, and the exit status

Every run ends in one outcome, and the exit status of `patina` follows from it: 0 for `ok`, 1 for
a finding in the program, 2 when Patina could not do what was asked, which is never a pass. A
sweep exits 1 if any new finding, else 2 if any run could not be judged, else 0. `result.json`
has the outcome and `stop`, a short word for what ended the run (`always`, `exit`, `deadlock`,
`log-limit`, `check`, ...).

<!-- generated: outcomes (crates/patina-cli/src/outcome.rs); a unit test keeps it equal -->
| Outcome | Exit | Means |
|---|---|---|
| `ok` | 0 | the program exited 0 (or with a status `--ok-exit` names) and failed no check; what that proves is what the checks could detect |
| `violation` | 1 | a check failed: an SDK `always` or `unreachable`, or the `--check` command answered 1 |
| `liveness` | 1 | every thread blocked (deadlock), `[run] time-limit` of virtual time passed, the log reached `[run] log-limit` (livelock), or a machine was not ready again within `patina ctl settle`'s limit |
| `failure` | 1 | the program exited nonzero with a status `--ok-exit` does not name |
| `crash` | 1 | the program died on a signal |
| `unsupported` | 2 | the program did something Patina does not model; the message names it. Not a bug in the program |
| `timeout` | 2 | `--timeout` of wall time passed: a loop in code without points, or a hang outside virtual time |
| `nondeterministic` | 2 | a replay differed from its run: a Patina bug. Keep the run directory and report it |
| `internal` | 2 | Patina failed, or the host refused a resource: run `patina doctor` |
| `vacuous` | 2 | something asked for never happened: a fault you named, an SDK `sometimes`, `reachable` or fault point, a check that judged no run, a `!ID` known finding |
| `error` | 2 | the command could not be carried out: the program cannot run, a machine was never ready (stop `ready`), or the `--check` command broke or answered differently on replay |
<!-- end generated -->

A finding to triage is `violation`, `liveness`, `failure` or `crash`. `unsupported`, `internal`
and `nondeterministic` are about Patina, not the program: say so when reporting, and keep the run
directory of a `nondeterministic` one.
