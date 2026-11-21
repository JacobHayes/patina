# 2. Fault points, coverage across seeds, children, setup: a point named with buggify:LABEL
#    fires alone and is false with no buggify setting; one seed gives one set of decisions, and
#    adding a second point leaves the first one's decisions alone (draws keyed by label);
#    buggify:LABEL=1000 fires every time and =0 never; a `sometimes` holds on some seeds and not
#    others; a child started by fork and one by execve report into the run's table; with any
#    fault configured, no point fires before `setup-complete` (run.json: faults-held) and all
#    do after; a violation replays identically.
#@ tier=quick budget=30
exec python3 -I "$(dirname "$0")/lib/points.py"
