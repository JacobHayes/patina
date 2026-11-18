# Evidence: wall time per run, native against patina, with syscalls (traps) and switches per run,
# for all four runtimes. Median (min-max) of 5 runs each; patina runs are seeds 1-5, faults off;
# native runs are the same command in a bwrap sandbox shaped like patina's (lib.inc `native`), not
# pinned. Runs that do not end ok are reported, not timed.
#@ tier=evidence budget=600 slots=8
. "$(dirname "$0")/lib.inc"

measure() {
    name=$1; wl=$2; shift 2
    opts=""
    while [ "$1" != -- ]; do opts="$opts $1"; shift; done
    shift
    : >"$RUNS/cost-$name.native"
    for k in 1 2 3 4 5; do native "$RUNS/cost-$name-native.out" "$W/$wl" "$@" >>"$RUNS/cost-$name.native"; done
    for k in 1 2 3 4 5; do run "$wl" "$RUNS/cost-$name-$k" "$k" $opts --config "$("$PATINA_CFG" stall-ms=3000)" -- "$@"; done
    python3 -I - "$RUNS" "$name" <<'PY'
import json, sys
runs, name = sys.argv[1], sys.argv[2]
nat = sorted(int(x) for x in open("%s/cost-%s.native" % (runs, name)).read().split())
os_ = [json.load(open("%s/cost-%s-%d/result.json" % (runs, name, k))) for k in range(1, 6)]
ok = [o for o in os_ if o["outcome"] == "ok"]
def mm(v):
    v = sorted(v)
    return "%d (%d-%d)" % (v[len(v) // 2], v[0], v[-1]) if v else "-"
print("%-10s native wall ms %-16s patina wall ms %-16s traps %-20s switches %-18s ok %d/5 %s" % (
    name, mm(nat), mm([o["wall_ms"] for o in ok]), mm([o["sched"]["traps"] for o in ok]),
    mm([o["sched"]["switches"] for o in ok]), len(ok), "" if len(ok) == 5 else "(not ok: %s)" % [o["outcome"] for o in os_ if o["outcome"] != "ok"]))
PY
    for k in 1 2 3 4 5; do rm -rf "${RUNS:?}/cost-$name-$k"; done
}

measure go go-static -- /guest/go-static all
measure cpython cpython -- /usr/bin/python3 /guest/w5.py all
measure tokio tokio-mt -- /guest/tokio-mt local
measure tokio-tcp tokio-mt -- /guest/tokio-mt net
measure sh shell-pipeline -- /bin/sh /guest/w6.sh
measure bash shell-pipeline -- /bin/bash /guest/w6.sh
uptime
finish
