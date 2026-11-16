#!/bin/sh
# Sweep driver:
#   tests/storage/lib/sweep.sh WORKLOAD SEEDS... -- [patina run options] -- /guest/prog args...
# WORKLOAD names the guest directory $PATINA_WORKLOADS/WORKLOAD. SEEDS are numbers or ranges A-B. Runs the seeds in
# parallel ($SWEEP_JOBS, default 6, one core each), collects every result.json into
# $SWEEP_OUT/outcomes/SEED.json (and the last incarnation's stderr tail into SEED.err),
# writes $SWEEP_OUT/summary.tsv (seed, outcome, message, digest, incarnations, crashes,
# wall_ms) and prints a table of outcome x message counts plus the sweep's wall time.
# Run directories: $SWEEP_OUT/run-SEED. $SWEEP_KEEP: fail (default: keep runs whose outcome
# is not ok, delete the rest), all, none. Every run is under ulimit -f and timeout.
set -eu
[ $# -ge 4 ] || { echo "usage: sweep.sh WORKLOAD SEEDS... -- [patina options] -- /guest/prog args" >&2; exit 2; }
: "${PATINA:?}" "${SWEEP_OUT:?}"
wl=$1; shift
seeds=
while [ $# -gt 0 ] && [ "$1" != -- ]; do
    case $1 in
        *-*) seeds="$seeds $(seq "${1%-*}" "${1#*-}")" ;;
        *) seeds="$seeds $1" ;;
    esac
    shift
done
[ "${1:-}" = -- ] || { echo "sweep.sh: missing -- before patina options" >&2; exit 2; }
shift
guests=${PATINA_WORKLOADS:?}/$wl
[ -d "$guests" ] || { echo "sweep.sh: no guest directory $guests" >&2; exit 2; }
mkdir -p "$SWEEP_OUT/outcomes"
ulimit -f "${SWEEP_FSIZE:-8000000}"
export PATINA SWEEP_OUT SWEEP_KEEP="${SWEEP_KEEP:-fail}" SWEEP_TIMEOUT="${SWEEP_TIMEOUT:-600}" guests
t0=$(date +%s.%N)
# Each seed: one patina run; arguments after the seed are the patina options.
printf '%s\n' $seeds | xargs -P "${SWEEP_JOBS:-6}" -I{} sh -c '
    s=$1; shift
    o=$SWEEP_OUT/run-$s
    rm -rf "$o"
    st=0
    timeout "$SWEEP_TIMEOUT" "$PATINA" run --seed "$s" --out "$o" --mount "$guests":/guest:copy "$@" >/dev/null 2>"$SWEEP_OUT/outcomes/$s.patinaerr" || st=$?
    if [ ! -f "$o/result.json" ]; then
        echo "{\"outcome\":\"patina-error\",\"message\":\"exit $st\",\"seed\":$s,\"crashes\":[],\"incarnations\":0,\"digest\":\"\",\"wall_ms\":0}" >"$SWEEP_OUT/outcomes/$s.json"
        exit 0
    fi
    rm -f "$SWEEP_OUT/outcomes/$s.patinaerr"
    cp "$o/result.json" "$SWEEP_OUT/outcomes/$s.json"
    last=$(ls -d "$o"/inc-* | sort -t- -k2 -n | tail -1)
    tail -c 4000 "$last/stderr" >"$SWEEP_OUT/outcomes/$s.err" 2>/dev/null || true
    cls=$(jq -r .outcome "$o/result.json")
    case $SWEEP_KEEP in
        all) ;;
        none) rm -rf "$o" ;;
        *) [ "$cls" = ok ] && rm -rf "$o" ;;
    esac
    exit 0
' sh {} "$@"
t1=$(date +%s.%N)
python3 -I - "$SWEEP_OUT" "$t0" "$t1" $seeds <<'PY'
import json, os, sys, collections
out, t0, t1 = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
seeds = [int(s) for s in sys.argv[4:]]
rows, table = [], collections.Counter()
for s in seeds:
    o = json.load(open(os.path.join(out, "outcomes", "%d.json" % s)))
    det = (o.get("message") or "").splitlines()[0][:90] if o.get("message") else ""
    rows.append((s, o["outcome"], det, o.get("digest", ""), o.get("incarnations", 0), len(o.get("crashes", [])), o.get("wall_ms", 0)))
    table[(o["outcome"], det)] += 1
with open(os.path.join(out, "summary.tsv"), "w") as f:
    f.write("seed\toutcome\tmessage\tdigest\tincarnations\tcrashes\twall_ms\n")
    for r in rows:
        f.write("\t".join(map(str, r)) + "\n")
wall = t1 - t0
print("%-10s %6s  %s" % ("outcome", "count", "message"))
for (c, d), n in sorted(table.items(), key=lambda x: (-x[1], x[0])):
    print("%-10s %6d  %s" % (c, n, d))
fails = [r[0] for r in rows if r[1] != "ok"]
print("seeds %d, not ok %d, crashes %d, sweep wall %.1f s, %.2f runs/s; first not-ok seeds: %s" % (
    len(rows), len(fails), sum(r[5] for r in rows), wall, len(rows) / wall if wall else 0, fails[:12]))
PY
