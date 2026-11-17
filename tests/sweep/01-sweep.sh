# 1. `patina sweep`, `report` and `minimize` on a guest with two planted bugs: one finding per
#    bug however many seeds hit it (numbers in the guest's message do not split it), each
#    replayed identically, announced with its lowest seed; a replay does not add a run; the
#    same sweep resumes and a changed argument or program replaces it; a run inside a sweep equals the
#    same seed run alone; the bug-free guest exits 0; an unmet `sometimes` is vacuous unless
#    allowed, as is a fault point that never fired under --buggify; --cases makes one run per
#    (case, seed), `report` over separate `patina run` directories gives the sweep's groups,
#    and lines that are whole commands find the same; a host file changed before a replay makes
#    it nondeterministic; a livelock ends log-limit at the same record twice, and a sweep of it
#    keeps bounded bytes whose cut logs still replay; an interrupted sweep leaves no process and no partial run;
#    minimize keeps only the fault setting the finding needs, and its rerun command reproduces it.
#@ tier=quick budget=60 slots=4 arch=x86_64
set -eu
exec python3 -I "$(dirname "$0")/lib/sweep.py"
