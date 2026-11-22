# 2. Load-time points (the default): the runtime applies plans to stock programs (ARCHITECTURE "Load-time
# rewriting"), with a plan cache of its own under RUNS.
#  a. each differential guest (C static and static-PIE, C++ and Rust static, Go) prints its native output; its plan was applied and points were taken; seeds 1 and 2 each repeat
#     identical under --vary cpu,load,aslr,sandbox,repeat, and their digests differ (the points
#     move the schedule);
#  b. go-race-stock (compute-gap=8) and rs-race-stock (compute-gap=2), stock builds of a
#     check-then-act on atomics with no system call in the window, end `failure` on some seed of
#     1-40 and 1-80; with [sched] preempt = "traps" nothing can switch inside that window: only a compute point
#     can (the window has no system call or pause), and a run without them has none (no
#     `compute` in result.json);
#  c. deadline-stock (a timer due inside a loop with no system call: compute-stall without
#     points) ends ok: the timer fired inside the loop, 10 to 12 virtual ms after it was armed;
#  d. go-race-stock seed 1 (compute-gap=8) repeats identical under --vary cpu: on x86_64 its
#     runtime reads cpuid leaf 1 at start (the APIC id, which differs by core, is left in a
#     register a point records), and the plan's cpuid sites answer core 0's; on arm64 it reads
#     the processor's identity registers, which the kernel answers;
#  e. the plan cache: the first run makes the program's plan, the next hits it; a byte of the
#     plan file changed (same size, its modification time put back) makes the next run rebuild
#     it, with the first run's digest;
#  f. a plan is made once across processes: two cold runs of one program that both find its
#     entry held wait for it, and one of them makes the plan, the other uses it; a cold sweep
#     makes its program's plans before its runs start, so none of its runs makes one;
#  g. a held entry whose holder is stopped (it keeps its flock) is waited for at most its bound
#     (5 s for rw-c), not to the run's timeout: the run names the holder's pid and the lock on
#     stderr, makes the plan itself outside the cache (`bypassed`, the entry left unwritten) and
#     has a.'s digest. About 6 s on the arm64 runner, nearly all of it the bound.
#@ tier=quick,release budget=60 slots=2
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
. "$(dirname "$0")/../json.inc"
field() { field_opt "$@"; }
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }
G=$PATINA_GUESTS
o=$RUNS/02-points
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
pts() { "$PATINA" run "$@" >/dev/null 2>&1 || true; }

# a. Four verifies at a time.
guests="rw-c rw-c-spie rw-cxx rw-rs rw-go"
for g in $guests; do
    "$G/$g" >"$o/$g.want"
    printf '%s 1\n%s 2\n' "$g" "$g" >>"$o/a.jobs"
done
export PATINA G o
xargs -P 4 -L 1 bash -euo pipefail -c '"$PATINA" verify --seed "$2" --runs 3 \
    --vary cpu,load,aslr,sandbox,repeat --out "$o/$1-$2" -- "$G/$1" >"$o/$1-$2.txt" 2>&1 || true' sh <"$o/a.jobs"
for g in $guests; do
    for s in 1 2; do
        grep -q '^identical' "$o/$g-$s.txt" || die "a. $g seed $s: $(grep -m1 -v '^run ' "$o/$g-$s.txt")"
        cmp -s "$o/$g.want" "$o/$g-$s/run-0/boot-1/stdout" || die "a. $g seed $s: output differs from the native run"
        [ "$(field "$o/$g-$s/run-0/result.json" rewrite.applied)" -ge 1 ] && [ "$(field "$o/$g-$s/run-0/result.json" rewrite.points)" -ge 1 ] ||
            die "a. $g seed $s: no plan applied or no point taken ($(field "$o/$g-$s/run-0/result.json" rewrite))"
    done
    d1=$(field "$o/$g-1/run-0/result.json" digest)
    d2=$(field "$o/$g-2/run-0/result.json" digest)
    [ "$d1" != - ] && [ "$d1" != "$d2" ] || die "a. $g: seeds 1 and 2 have one digest"
done
echo "a. $guests: native output, identical under --vary cpu,load,aslr,sandbox,repeat, seeds 1 and 2 differ (rw-go seed 1: $(field "$o/rw-go-1/run-0/result.json" rewrite.points) points)"

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
    [ -n "$first" ] || die "b. $name: no failure in seeds 1-$n under"
    echo "b. $name: failure first on seed $first ($(tail -1 "$o/$name-$first/boot-1/stdout"))"
}
hunt go-race 40 --fault compute-gap=8 -- "$G/compute/go-race-stock"
hunt rs-race 80 --fault compute-gap=2 -- "$G/compute/rs-race-stock"
for g in go-race-stock rs-race-stock; do
    "$PATINA" run --config "$("$PATINA_CFG" preempt=traps)" --seed 1 --fault compute-gap=2 --out "$o/traps-$g" -- "$G/compute/$g" >/dev/null 2>&1 || true
    out=$(field "$o/traps-$g/result.json" outcome)
    cp=$(field "$o/traps-$g/result.json" compute)
    [ "$out" != - ] && [ "$cp" = - ] ||
        die "b. $g without points: $(res "$o/traps-$g"), compute $(field "$o/traps-$g/result.json" compute)"
done
echo "b. without points neither race window holds a switch"

# c. The guest exits 0 only if its loop ended 10 to 12 virtual ms after the arming.
pts --seed 1 --timeout 30 --out "$o/deadline" -- "$G/compute/deadline-stock" deadline 10
[ "$(field "$o/deadline/result.json" outcome)" = ok ] || die "c. deadline-stock: $(res "$o/deadline")"
echo "c. deadline-stock: $(tail -1 "$o/deadline/boot-1/stdout")"

# d.
"$PATINA" verify --seed 1 --fault compute-gap=8 --runs 3 --vary cpu --out "$o/cpu" -- "$G/compute/go-race-stock" >"$o/cpu.txt" 2>&1 || true
grep -q '^identical' "$o/cpu.txt" || die "d. go-race-stock under --vary cpu: $(grep -m1 -v '^run ' "$o/cpu.txt")"
if [ "$(uname -m)" = x86_64 ]; then
    [ "$(field "$o/cpu/run-0/result.json" rewrite.cpuid)" -ge 1 ] || die "d. no cpuid answered"
    echo "d. go-race-stock identical on 3 cores ($(field "$o/cpu/run-0/result.json" rewrite.cpuid) cpuid answered)"
else
    echo "d. go-race-stock identical on 3 cores"
fi

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

# f. In a fresh cache, this script holds rw-c's entry lock (its name: the plan made above) while
#    two runs start, until both wait on it.
base=$(basename "$plan" .plan)
fresh=$o/cache-f
mkdir -p "$fresh/patina/plans"
made() { python3 -I -c 'import json,sys
print(sum(i["cache"] == "made" for d in sys.argv[1:] for i in json.load(open(d + "/result.json"))["rewrite"]["images"]))' "$@"; }
exec 9>"$fresh/patina/plans/$base.lock"
flock 9
inode=$(stat -c %i "$fresh/patina/plans/$base.lock")
# The runs do not inherit the held lock (descriptor 9).
XDG_CACHE_HOME=$fresh pts --seed 1 --out "$o/lock-1" -- "$G/rw-c" 9>&- &
p1=$!
XDG_CACHE_HOME=$fresh pts --seed 1 --out "$o/lock-2" -- "$G/rw-c" 9>&- &
p2=$!
waiting=0
for _ in $(seq 600); do
    waiting=$(awk -v i=":$inode " 'index($0, "->") && index($0, i) { n++ } END { print n + 0 }' /proc/locks)
    [ "$waiting" -lt 2 ] || break
    kill -0 "$p1" 2>/dev/null || kill -0 "$p2" 2>/dev/null || break
    sleep 0.1
done
exec 9>&-
wait "$p1" "$p2"
[ "$waiting" -ge 2 ] || die "f. the two runs did not both wait on the entry ($waiting waiting)"
[ "$(made "$o/lock-1" "$o/lock-2")" = 1 ] || die "f. two runs that waited on one entry made its plan $(made "$o/lock-1" "$o/lock-2") times"
XDG_CACHE_HOME=$o/cache-sweep "$PATINA" sweep --seeds 1..4 -j 4 --keep all \
    --out "$o/sweep" -- "$G/rw-c" >"$o/sweep.txt" 2>&1 || true
runs=$(find "$o/sweep" -name result.json -path '*seed-*' -printf '%h\n' | sort)
[ -n "$runs" ] || die "f. the sweep left no run: $(tail -3 "$o/sweep.txt")"
# shellcheck disable=SC2086
[ "$(made $runs)" = 0 ] || die "f. runs of a cold sweep made $(made $runs) plans"
echo "f. a plan made once: two cold runs, one makes it; a cold sweep's runs make none"

# g. A helper takes rw-c's entry lock in a fresh cache and stops itself holding it (continued,
#    it exits).
held=$o/cache-g
mkdir -p "$held/patina/plans"
lockf=$held/patina/plans/$base.lock
python3 -I -c 'import fcntl,os,signal,sys
f=open(sys.argv[1],"w"); fcntl.flock(f, fcntl.LOCK_EX); os.kill(os.getpid(), signal.SIGSTOP)' "$lockf" &
holder=$!
for _ in $(seq 600); do
    state=$(ps -o state= -p "$holder")
    [ "$state" != T ] || break
    sleep 0.1
done
[ "$state" = T ] || die "g. the helper did not stop holding the lock"
st=0
XDG_CACHE_HOME=$held "$PATINA" run --seed 1 --out "$o/held" -- "$G/rw-c" >/dev/null 2>"$o/held.err" || st=$?
kill -CONT "$holder"
wait "$holder"
[ "$(field "$o/held/result.json" outcome)" = ok ] || die "g. a run behind a stopped holder (exit $st): $(res "$o/held"); $(cat "$o/held.err")"
[ "$(cache "$o/held")" = bypassed ] || die "g. a run behind a stopped holder: rw-c's plan $(cache "$o/held"), not bypassed"
grep -q "process $holder " "$o/held.err" && grep -qF "$lockf" "$o/held.err" ||
    die "g. stderr names neither the holder ($holder) nor the lock: $(cat "$o/held.err")"
[ ! -e "$held/patina/plans/$base.plan" ] || die "g. the run wrote the entry another process holds"
d1=$(field "$o/rw-c-1/run-0/result.json" digest)
d2=$(field "$o/held/result.json" digest)
[ "$d1" != - ] && [ "$d1" = "$d2" ] || die "g. the plan made outside the cache gives another digest than a."
echo "g. a stopped holder: the run planned rw-c itself after the bound, same digest"
