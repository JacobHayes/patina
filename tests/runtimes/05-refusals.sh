# language runtimes item 5: for each runtime, every Deny hit and refused path (outcome.refused and Deny-class
# traps in the boundary log), with the run's outcome showing that none blocked progress: one
# seed-1 run of each runtime and shell, none `unsupported` (Stop) or `internal`. (language runtimes counted
# every outcome of its whole check run; this is the representative run of each.)
# Item 6 ("changes needed to the program or its build: none") is the build.sh of each workload:
# stock toolchain commands with no patina-specific flag (printed below).
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"

echo "== representative runs (seed 1, one per runtime and shell)"
run go-static "$RUNS/go-n2" 1 --cpus 2 -- /guest/go-static all
run cpython "$RUNS/py-r" 1 -- /usr/bin/python3 /guest/w5.py all
run tokio-mt "$RUNS/tk-r" 1 -- /guest/tokio-mt local
run shell-pipeline "$RUNS/sh-r" 1 -- /bin/sh /guest/w6.sh
run shell-pipeline "$RUNS/bash-r" 1 -- /bin/bash /guest/w6.sh
for r in go-n2 py-r tk-r sh-r bash-r; do
    stats "$RUNS/$r" | python3 -I -c '
import json, sys
s = json.loads(sys.stdin.read())
print("%-7s class %-6s stop %d  deny %s  refused %s" % (sys.argv[1], s["class"], s["stop"], s["deny"], s["refused"]))
' "$r"
    c=$(field "$RUNS/$r/result.json" outcome)
    case $c in unsupported | internal) fail "$r: class $c ($(field "$RUNS/$r/result.json" message))" ;; esac
done

echo "== item 6: the build commands (no patina-specific flag, patch or library)"
for b in go-static cpython tokio-mt shell-pipeline; do
    echo "-- tests/guests/$b/build.sh"
    grep -v '^#' "$HERE/../guests/$b/build.sh" | grep -v '^set -eu$' | grep -v '^$'
done
finish
