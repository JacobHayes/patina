# 2. `--preempt points`: the runtime applies plans to stock programs (ARCHITECTURE "Load-time
# rewriting"), with a plan cache of its own under RUNS.
#  a. each differential guest (C static and static-PIE, C++ and Rust static, Go) prints its
#     native output; its plan was applied and points were taken; seeds 1 and 2 each repeat
#     identical under --vary cpu,load,aslr,sandbox,repeat, and their digests differ (the points
#     move the schedule);
#  b. go-race-stock (compute-gap=8) and rs-race-stock (compute-gap=2), stock builds of a
#     check-then-act on atomics with no system call in the window, end `failure` on some seed of
#     1-40 and 1-80; without points nothing can switch inside that window: only a compute point
#     can (the window has no system call or pause), and a run without them has none (no
#     `compute` in result.json);
#  c. deadline-stock (a timer due inside a loop with no system call: compute-stall without
#     points) ends ok: the timer fired inside the loop, 10 to 12 virtual ms after it was armed;
#  d. go-race-stock seed 1 (compute-gap=8) repeats identical under --vary cpu: its runtime reads
#     cpuid leaf 1 at start (the APIC id, which differs by core, is left in a register a point
#     records), and the plan's cpuid sites answer core 0's;
#  e. the plan cache: the first run makes the program's plan, the next hits it; a byte of the
#     plan file changed (same size, its modification time put back) makes the next run rebuild
#     it, with the first run's digest.
#@ tier=quick budget=60 slots=4 arch=x86_64
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    if not isinstance(v, dict) or k not in v: print("-"); sys.exit()
    v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }
G=$PATINA_GUESTS
o=$RUNS/02-points
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
pts() { "$PATINA" run --preempt points "$@" >/dev/null 2>&1 || true; }

# a. Four verifies at a time.
for g in rw-c rw-c-spie rw-cxx rw-rs rw-go; do
    "$G/$g" >"$o/$g.want"
    printf '%s 1\n%s 2\n' "$g" "$g" >>"$o/a.jobs"
done
export PATINA G o
xargs -P 4 -L 1 bash -euo pipefail -c '"$PATINA" verify --preempt points --seed "$2" --runs 3 \
    --vary cpu,load,aslr,sandbox,repeat --out "$o/$1-$2" -- "$G/$1" >"$o/$1-$2.txt" 2>&1 || true' sh <"$o/a.jobs"
for g in rw-c rw-c-spie rw-cxx rw-rs rw-go; do
    for s in 1 2; do
        grep -q '^identical' "$o/$g-$s.txt" || die "a. $g seed $s: $(grep -m1 -v '^run ' "$o/$g-$s.txt")"
        cmp -s "$o/$g.want" "$o/$g-$s/run-0/inc-0/stdout" || die "a. $g seed $s: output differs from the native run"
        [ "$(field "$o/$g-$s/run-0/result.json" rewrite.applied)" -ge 1 ] && [ "$(field "$o/$g-$s/run-0/result.json" rewrite.points)" -ge 1 ] ||
            die "a. $g seed $s: no plan applied or no point taken ($(field "$o/$g-$s/run-0/result.json" rewrite))"
    done
    d1=$(field "$o/$g-1/run-0/result.json" digest)
    d2=$(field "$o/$g-2/run-0/result.json" digest)
    [ "$d1" != - ] && [ "$d1" != "$d2" ] || die "a. $g: seeds 1 and 2 have one digest"
done
echo "a. 5 guests: native output, identical under --vary cpu,load,aslr,sandbox,repeat, seeds 1 and 2 differ (rw-go seed 1: $(field "$o/rw-go-1/run-0/result.json" rewrite.points) points)"

# b. Four runs at a time, stopping at the first group of four with a failure.
hunt() {
    name=$1 max=$2; shift 2
    first="" n=0
    while [ -z "$first" ] && [ "$n" -lt "$max" ]; do
        for s in $(seq $((n + 1)) $((n + 4))); do pts --seed "$s" --out "$o/$name-$s" "$@" & done
        wait
        for s in $(seq $((n + 1)) $((n + 4))); do
            case $(field "$o/$name-$s/result.json" outcome) in
                failure) [ -n "$first" ] || first=$s ;;
                ok) ;;
                *) die "b. $name seed $s: $(res "$o/$name-$s")" ;;
            esac
        done
        n=$((n + 4))
    done
    [ -n "$first" ] || die "b. $name: no failure in seeds 1-$n under --preempt points"
    echo "b. $name: failure first on seed $first ($(tail -1 "$o/$name-$first/inc-0/stdout"))"
}
hunt go-race 40 --fault compute-gap=8 -- "$G/compute/go-race-stock"
hunt rs-race 80 --fault compute-gap=2 -- "$G/compute/rs-race-stock"
for g in go-race-stock rs-race-stock; do
    "$PATINA" run --seed 1 --fault compute-gap=2 --out "$o/traps-$g" -- "$G/compute/$g" >/dev/null 2>&1 || true
    out=$(field "$o/traps-$g/result.json" outcome)
    cp=$(field "$o/traps-$g/result.json" compute)
    [ "$out" != - ] && [ "$cp" = - ] ||
        die "b. $g without points: $(res "$o/traps-$g"), compute $(field "$o/traps-$g/result.json" compute)"
done
echo "b. without points neither race window holds a switch"

# c. The guest exits 0 only if its loop ended 10 to 12 virtual ms after the arming.
pts --seed 1 --timeout 30 --out "$o/deadline" -- "$G/compute/deadline-stock" deadline 10
[ "$(field "$o/deadline/result.json" outcome)" = ok ] || die "c. deadline-stock: $(res "$o/deadline")"
echo "c. deadline-stock: $(tail -1 "$o/deadline/inc-0/stdout")"

# d.
"$PATINA" verify --preempt points --seed 1 --fault compute-gap=8 --runs 3 --vary cpu --out "$o/cpu" -- "$G/compute/go-race-stock" >"$o/cpu.txt" 2>&1 || true
grep -q '^identical' "$o/cpu.txt" || die "d. go-race-stock under --vary cpu: $(grep -m1 -v '^run ' "$o/cpu.txt")"
[ "$(field "$o/cpu/run-0/result.json" rewrite.cpuid)" -ge 1 ] || die "d. no cpuid answered"
echo "d. go-race-stock identical on 3 cores ($(field "$o/cpu/run-0/result.json" rewrite.cpuid) cpuid answered)"

# e. rw-c's plan: made by a. (the cache is this script's), hit now, rebuilt after a change.
cache() { python3 -I -c 'import json,sys
print(" ".join(i["cache"] for i in json.load(open(sys.argv[1]))["rewrite"]["images"]))' "$1/result.json"; }
pts --seed 1 --out "$o/hit" -- "$G/rw-c"
[ "$(cache "$o/hit")" = hit ] || die "e. second use of rw-c's plan: $(cache "$o/hit"), not hit"
plan=$(ls "$XDG_CACHE_HOME"/patina/plans/"$(sha256sum "$G/rw-c" | cut -c1-64)"-*.plan)
python3 -I -c 'import os,sys
p=sys.argv[1]; st=os.stat(p); b=bytearray(open(p,"rb").read()); b[-1]^=0xff
open(p,"wb").write(b); os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))' "$plan"
pts --seed 1 --out "$o/changed" -- "$G/rw-c"
[ "$(cache "$o/changed")" = rebuilt ] || die "e. a changed plan file: $(cache "$o/changed"), not rebuilt"
d1=$(field "$o/rw-c-1/run-0/result.json" digest)
d2=$(field "$o/changed/result.json" digest)
[ "$d1" != - ] && [ "$d1" = "$d2" ] || die "e. the rebuilt plan's run differs from the first"
echo "e. plan cache: made, hit, a changed entry rebuilt (same digest)"
