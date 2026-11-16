# 1. `patina sweep`, `report` and `minimize` on a guest with two planted bugs: one finding per
#    bug however many seeds hit it, each replayed identically; a run inside a sweep equals the
#    same seed run alone; the bug-free guest exits 0; an unmet `sometimes` is vacuous unless
#    allowed; --cases makes one run per (case, seed) and `report` over separate `patina run`
#    directories gives the sweep's groups; a host file changing under the replay makes the
#    group nondeterministic; an interrupted sweep leaves no process and no partial run;
#    minimize keeps only the fault setting the finding needs.
#@ tier=quick budget=60 slots=4
set -eu
exec python3 -I "$(dirname "$0")/lib/sweep.py"
