# 5. Walks (load-time points, the test input `PATINA_TEST_COMPUTE_WALK`; ARCHITECTURE "Load-time rewriting"): a
# switch at a load-time point is taken a drawn number of instructions past it, single-stepped.
#  a. rw-races lms (tests/guests/rewrite/races.c: a load and a store with no site between them)
#     loses an update on some seed of 1-8 with walks, and on none of them without: a plain
#     point stops before the load or after the store, never between;
#  b. the first such seed repeats identical under --vary cpu,load,aslr,sandbox,repeat, and so
#     do the differential guests in C, C++, Rust and Go with many
#     walks (identical, walks taken); `patina replay` of a run with walks is identical;
#  c. rw-fid with walks of 1 or 2 instructions on half the switches: a fault in the relocated
#     atomic (a point at every site: a walk from its count runs into the fault), a timer signal
#     in fid_spin and fork print what they print natively, and so does rw-races sys with walks
#     of up to 16 (system calls in a loop, then a read that blocks: walks run into both); walks
#     were taken in each and some cut by a runtime entry (the fault, a system call); and
#     rw-races flags (x86_64 `pushf` and a later `popf`): no saved copy has the trap flag.
#@ tier=quick,release budget=60 slots=3
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
. "$(dirname "$0")/../json.inc"
field() { field_opt "$@"; }
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }
G=$(realpath "$PATINA_GUESTS")
o=$RUNS/05-walks
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
pts() { "$PATINA" run "$@" >/dev/null 2>&1 || true; }
# The longest walk is a test input (AGENTS.md): PATINA_TEST_COMPUTE_WALK.

# a. Four seeds at a time, with and without walks.
first=""
for s in $(seq 1 8); do
    PATINA_TEST_COMPUTE_WALK=16 pts --seed "$s" --fault compute-gap=2..64 --out "$o/w-$s" -- "$G/rw-races" lms &
    PATINA_TEST_COMPUTE_WALK=0 pts --seed "$s" --fault compute-gap=2..64 --out "$o/n-$s" -- "$G/rw-races" lms &
    [ $((s % 2)) = 1 ] || wait
done
wait
for s in $(seq 1 8); do
    case $(field "$o/w-$s/result.json" outcome) in
        failure) [ -n "$first" ] || first=$s ;;
        ok) ;;
        *) die "a. lms seed $s with walks: $(res "$o/w-$s")" ;;
    esac
    [ "$(field "$o/n-$s/result.json" outcome)" = ok ] || die "a. lms seed $s without walks: $(res "$o/n-$s")"
done
[ -n "$first" ] || die "a. lms: no lost update in seeds 1-8 with walks"
grep -q LOST-UPDATE "$o/w-$first/boot-1/stdout" || die "a. lms seed $first: $(cat "$o/w-$first/boot-1/stdout")"
echo "a. lms: lost update first on seed $first with walks ($(field "$o/w-$first/result.json" rewrite.walks) walks), none in seeds 1-8 without"

# b.
guests="rw-c rw-cxx rw-rs rw-go"
{ echo "rw-races $first lms"; for g in $guests; do echo "$g 3"; done; } >"$o/b.jobs"
export PATINA G o
xargs -P 4 -L 1 bash -euo pipefail -c 'n=$1 s=$2; shift 2
    w=compute-gap=2..64 PATINA_TEST_COMPUTE_WALK=16
    [ "$n" = rw-races ] || w=compute-gap=64..256 PATINA_TEST_COMPUTE_WALK=32
    export PATINA_TEST_COMPUTE_WALK
    "$PATINA" verify --seed "$s" --fault "$w" --runs 3 --vary cpu,load,aslr,sandbox,repeat \
        --out "$o/v-$n" -- "$G/$n" "$@" >"$o/v-$n.txt" 2>&1 || true' sh <"$o/b.jobs"
for n in rw-races $guests; do
    grep -q '^identical' "$o/v-$n.txt" || die "b. $n: $(grep -m1 -v '^run ' "$o/v-$n.txt")"
    [ "$(field "$o/v-$n/run-0/result.json" rewrite.walks)" -ge 1 ] || die "b. $n: no walk taken"
done
"$PATINA" replay "$o/v-rw-go/run-0" >"$o/replay.txt" 2>&1 || true
grep -q '^identical' "$o/replay.txt" || die "b. replay: $(head -1 "$o/replay.txt")"
echo "b. lms seed $first, $guests identical under --vary cpu,load,aslr,sandbox,repeat (rw-go: $(field "$o/v-rw-go/run-0/result.json" rewrite.walks) walks); replay identical"

# c.
c_cmd() { case $1 in sys | flags) echo "$G/rw-races $1" ;; *) echo "$G/rw-fid $1" ;; esac; }
for m in fault timer fork sys flags; do
    # shellcheck disable=SC2046
    $(c_cmd $m) | sort >"$o/$m.want"
    for s in 1 2; do
        case $m in fault) f=compute-gap=1 w=2 ;;
            sys | flags) f=compute-gap=2..16 w=16 ;;
            *) f=compute-gap=64..256 w=2 ;; esac
        # shellcheck disable=SC2046
        PATINA_TEST_COMPUTE_WALK=$w pts --seed "$s" --fault "$f" --out "$o/$m-$s" -- $(c_cmd $m) &
    done
    wait
done
line=""
for m in fault timer fork sys flags; do
    walks=0 cut=0
    for s in 1 2; do
        [ "$(field "$o/$m-$s/result.json" outcome)" = ok ] || die "c. $m seed $s: $(res "$o/$m-$s")"
        sort "$o/$m-$s/boot-1/stdout" | cmp -s "$o/$m.want" - ||
            die "c. $m seed $s: $(head -2 "$o/$m-$s/boot-1/stdout") (natively $(head -1 "$o/$m.want"))"
        walks=$((walks + $(field "$o/$m-$s/result.json" rewrite.walks)))
        cut=$((cut + $(field "$o/$m-$s/result.json" rewrite.walks_cut)))
    done
    [ "$walks" -ge 1 ] || die "c. $m: no walk taken"
    case $m in fault|sys) [ "$cut" -ge 1 ] || die "c. $m: no walk cut by a runtime entry ($walks walks)" ;; esac
    line="$line $m ($walks walks, $cut cut)"
done
echo "c. as natively with walks:$line"
