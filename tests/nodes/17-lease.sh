# 17. Nodes: a lease-based primary/backup service under pauses, partitions and clock steps,
# and a last-writer-wins register under clock skew. lease.py (tests/guests/nodes: a store
# that grants the lease and fences writes, two replicas p1 and p2 that check their lease on
# their monotonic clock with a safety margin, the driver writing and reading through whichever
# holds it): correct, no seed of the sweep loses an acknowledged write, accepts a stale
# primary's or answers a stale read, under the seed's pauses, and under partitions with the
# driver stepping the replicas' clocks back. Its planted bugs, each found in most seeds by its
# own class and in none without it: `nofence` (no fencing: a replica paused after its check
# resumes after another took the lease and writes as primary) under pauses; `realtime` (the
# lease measured on time.time(): a replica cut off from the store, its clock stepped back,
# answers stale reads) under partitions and steps. lww.py (a register on two nodes stamped by a
# hybrid logical clock) keeps every acknowledged put under clock-skew-ms; with `wallclock`
# (each node stamps with its own clock only) a node behind the other loses a later put, found
# in most seeds and in none without skew. Each failing group's first run replays identically.
#@ tier=area,release budget=200 slots=6
# arm64 (CI runner): about 100 s.
. "$(dirname "$0")/lib.inc"
o=$RUNS/17-lease; mkdir -p "$o"
PAUSES="--fault pause-gap-ms=1000..8000@p1 --fault pause-gap-ms=1000..8000@p2 --fault pause-ms=100..4000@p1 --fault pause-ms=100..4000@p2"
PARTS="--fault partition-gap-ms=1000..5000 --fault partition-ms=1000..6000"
SKEW="--fault clock-skew-ms=0..2000"

# sweep NAME GUEST NODES BUG DRIVER-ARGS [patina options]: seeds 1-16 of GUEST on NODES (BUG:
# ok, or a planted bug given to every node).
sweep() {
    _name=$1; _g=$2; _nodes=$3; _bug=$4; _args=$5; shift 5
    _f=$o/$_name.toml; : >"$_f"
    for _n in $_nodes; do
        if [ "$_bug" = ok ]; then conf "$_f" "$_n" python3 "/guest/$_g" "$_n"
        else conf "$_f" "$_n" python3 "/guest/$_g" "$_n" "$_bug"; fi
    done
    _st=0
    # shellcheck disable=SC2086
    timeout 600 "$PATINA" sweep --seeds 1..16 -j 6 --keep fail --out "$o/$_name" --config "$_f" "$@" \
        --mount "$PATINA_GUESTS":/guest:copy -- python3 "/guest/$_g" driver $_args >"$o/$_name.txt" 2>&1 || _st=$?
    [ -f "$o/$_name/report.json" ] || { tail -20 "$o/$_name.txt"; die "sweep $_name: no report (exit $_st)"; }
}
failures() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"].get("failure", 0))' "$o/$1/report.json"; }
clean() {
    [ "$(field "$o/$1/report.json" outcomes)" = '{"ok": 16}' ] || die "$1: $(field "$o/$1/report.json" outcomes)"
    echo "$1: 16 of 16 seeds ok"
}
found() {
    n=$(failures "$1")
    [ "$n" -ge 8 ] || die "$1: found in only $n of 16 seeds"
    r=$(python3 -I -c 'import json,sys
g=[g for g in json.load(open(sys.argv[1]))["groups"] if g["outcome"] == "failure"]
print(" ".join(x["replay"]["result"] for x in g if x["replay"]))
sys.exit(0 if g and all(x["replay"] and x["replay"]["result"] == "identical" for x in g) else 1)' "$o/$1/report.json") \
        || die "$1: a first failing run did not replay identically: $r"
    l=$(cat "$o/$1"/seed-*/inc-0/stdout | sed -n 's/^FAIL: \([a-z ]*\):.*/\1/p' | sort | uniq -c | tr -s ' \n' ' ')
    echo "$1: found in $n of 16 seeds:$l; replayed: $r"
}
control() {
    [ "$(failures "$1")" = 0 ] || die "$1: found in $(failures "$1") seeds without its class"
    echo "$1: found in none of 16 seeds"
}

L="s p1 p2"
# shellcheck disable=SC2086
{
sweep ok-pauses lease.py "$L" ok 60 $PAUSES; clean ok-pauses
sweep ok-steps lease.py "$L" ok "60 steps" $PARTS; clean ok-steps
sweep nofence lease.py "$L" nofence 60 $PAUSES; found nofence
sweep nofence-control lease.py "$L" nofence 60; control nofence-control
sweep realtime lease.py "$L" realtime "60 steps" $PARTS; found realtime
sweep realtime-control lease.py "$L" realtime 60 $PARTS; control realtime-control
sweep lww-ok lww.py "a b" ok 20 $SKEW; clean lww-ok
sweep wallclock lww.py "a b" wallclock 20 $SKEW; found wallclock
sweep wallclock-control lww.py "a b" wallclock 20; control wallclock-control
}
