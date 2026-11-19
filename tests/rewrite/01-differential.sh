# 1. The rewriter's differential (ARCHITECTURE "Load-time rewriting"). Each static guest of
# tests/guests/rewrite (C static and static-PIE, C++, Rust, Go) is planned twice (the plans must be
# byte-identical; the second from another directory on one CPU), the plan is checked by the
# independent verifier and against objdump's decode, and a copy with the plan applied
# (`__rewrite --standalone`) runs natively: its output equals the original's in each of RUNS_EACH
# runs, and its counts do run (a copy whose cell starts at 1000 events stops on SIGILL). x86_64
# only: elsewhere `__rewrite` and `patina run --preempt points` must refuse cleanly (exit 2, no
# signal, nothing run) and the script says SKIP.
#@ tier=quick budget=60
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
o=$RUNS/01-differential
rm -rf "${o:?}"
mkdir -p "$o/elsewhere"
machine=$(uname -m)
if [ "$machine" != x86_64 ]; then
    st=0
    "$PATINA" __rewrite "$PATINA_GUESTS/hello-static" >"$o/out" 2>"$o/err" || st=$?
    [ "$st" = 2 ] || die "__rewrite on $machine: exit $st, not a clean refusal (2)"
    st=0
    "$PATINA" run --preempt points --out "$o/run" -- "$PATINA_GUESTS/hello-static" >"$o/out" 2>"$o/err" || st=$?
    [ "$st" = 2 ] && [ ! -e "$o/run" ] ||
        die "--preempt points on $machine: exit $st, not a clean refusal: $(head -2 "$o/err")"
    echo "SKIP: the rewriter is x86_64 only (__rewrite and --preempt points refused cleanly on $machine)"
    exit 0
fi
RUNS_EACH=5
for g in rw-c rw-c-spie rw-cxx rw-rs rw-go; do
    f=$PATINA_GUESTS/$g
    [ -x "$f" ] || die "missing guest $f"
    "$PATINA" __rewrite "$f" --plan "$o/$g.plan" >"$o/$g.report"
    (cd "$o/elsewhere" && taskset -c 0 "$PATINA" __rewrite "$f" --plan "$o/$g.plan2" >/dev/null)
    cmp -s "$o/$g.plan" "$o/$g.plan2" || die "$g: two plans of one file differ"
    "$PATINA" __rewrite --verify "$f" "$o/$g.plan" >"$o/$g.verify" 2>&1 || die "$g: the verifier rejects the plan ($(head -3 "$o/$g.verify"))"
    "$PATINA" __rewrite --sites "$o/$g.plan" >"$o/$g.sites"
    objdump -d -w "$f" | python3 -I "$HERE/lib/objdump_sites.py" "$o/$g.sites" >"$o/$g.check"
    grep -q ' disagree=0$' "$o/$g.check" || die "$g: patched instructions objdump decodes otherwise: $(head -3 "$o/$g.check")"
    "$PATINA" __rewrite --standalone "$f" "$o/$g.rw" >/dev/null
    "$f" >"$o/$g.want"
    for i in $(seq "$RUNS_EACH"); do
        "$o/$g.rw" >"$o/$g.got" || die "$g: rewritten copy, run $i: exit $?"
        cmp -s "$o/$g.want" "$o/$g.got" || die "$g: rewritten copy, run $i: output differs"
    done
    "$PATINA" __rewrite --standalone "$f" "$o/$g.few" --events 1000 >/dev/null
    # The exit status of the copy, negative for a signal (python3: no shell job message).
    st=$(ulimit -c 0; timeout 60 python3 -I -c 'import subprocess as s, sys
print(s.run(sys.argv[1:], stdout=s.DEVNULL, stderr=s.DEVNULL).returncode)' "$o/$g.few")
    [ "$st" = -4 ] || die "$g: a copy with 1000 events ended with $st, not SIGILL: its counts did not run"
    rm "$o/$g.rw" "$o/$g.few" "$o/$g.plan2"
    awk -v g="$g" '$1 == "sites" && $2 == "back-branch" {print g ": back-branches " $NF " (" $4 " " $5 " " $7 ")"}' "$o/$g.report"
done
echo "$RUNS_EACH runs each: identical output"
