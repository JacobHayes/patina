# 1. The rewriter's differential (ARCHITECTURE "Load-time rewriting"). Each static guest of
# tests/guests/rewrite (C static and static-PIE, C++, Rust, Go) is planned twice (the plans must be
# byte-identical; the first on 8 threads, the second on one thread from another directory on one
# CPU: the parallel parts merge to the sequential order's bytes), the plan is checked by the
# independent verifier and against objdump's decode, and a copy with the plan applied
# (`__rewrite --standalone`) runs natively: its output equals the original's in each of RUNS_EACH
# runs, and its counts do run (a copy whose cell starts at 1000 events stops on its trap: x86_64
# `hlt`, SIGSEGV; arm64 `udf`, SIGILL). On x86_64
# and arm64; each guest is built on the architecture it runs on.
#@ tier=quick budget=60
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
o=$RUNS/01-differential
rm -rf "${o:?}"
mkdir -p "$o/elsewhere"
RUNS_EACH=5
arch=$(uname -m)
for g in rw-c rw-c-spie rw-cxx rw-rs rw-go; do
    f=$PATINA_GUESTS/$g
    [ -x "$f" ] || die "missing guest $f"
    "$PATINA" __rewrite "$f" --plan "$o/$g.plan" --threads 8 >"$o/$g.report"
    (cd "$o/elsewhere" && taskset -c 0 "$PATINA" __rewrite "$f" --plan "$o/$g.plan2" --threads 1 >/dev/null)
    cmp -s "$o/$g.plan" "$o/$g.plan2" || die "$g: two plans of one file differ (8 threads, 1 thread)"
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
    want=-11
    [ "$arch" != aarch64 ] || want=-4
    [ "$st" = "$want" ] || die "$g: a copy with 1000 events ended with $st, not $want (its trap's signal): its counts did not run"
    rm "$o/$g.rw" "$o/$g.few" "$o/$g.plan2"
    awk -v g="$g" '$1 == "sites" && $2 == "back-branch" {print g ": back-branches " $NF " (" $4 " " $5 " " $7 ")"}' "$o/$g.report"
done
echo "$RUNS_EACH runs each: identical output"
