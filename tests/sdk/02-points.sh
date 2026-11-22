# 2. Fault points, coverage across seeds, children, a probe: a point named with buggify:LABEL
#    fires alone and is false with no buggify setting; one seed gives one set of decisions, and
#    adding a second point leaves the first one's decisions alone (draws keyed by label);
#    buggify:LABEL=1000 fires every time and =0 never; a `sometimes` holds on some seeds and not
#    others; a child started by fork and one by execve report into the run's table; with
#    main's `ready` probe waiting for a file the program creates, no point fires before the
#    probe passes and all do after, the rerun line reproduces the run, and a sweep's runs are
#    those single runs at -j 1 and -j 8; a violation replays identically.
#@ tier=quick budget=30
exec python3 -I "$(dirname "$0")/lib/points.py"
