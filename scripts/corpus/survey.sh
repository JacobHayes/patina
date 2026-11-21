#!/bin/bash
# scripts/corpus/survey.sh NAME [PHASE...]: run the workload wl/NAME.sh natively and under Patina;
# each phase appends one line (or a few) to $CORPUS/runs/NAME/summary.txt and prints it.
#
# Phases (default: native same sweep verify disk net):
#   native  the workload outside Patina, in its own session, with the guest's environment
#   base    one run of seed 1 with $BASE (another patina, a release), its outcome and refusals
#   same    seed 1 three times: outcome, refusals, distinct digests, stdout against native
#   sweep   seeds 1..N (header `seeds`, default 20): outcomes and distinct digests
#   verify  patina verify --vary cpu,load,aslr
#   disk, net  a fault sweep with that preset, seeds 1..N (header `fseeds`, default 10)
#
# Environment: CORPUS, a scratch directory (runs go to $CORPUS/runs, replaced per workload);
# PROGS, the directory that holds the programs the workloads name (default $CORPUS/programs);
# PATINA, the patina under test (default `patina`); BASE, for the base phase.
#
# Workload headers: `# programs: DIR...` (each $PROGS/DIR mounted read-only at its own path),
# `# flags: ...` (more patina flags), `# run: KEY = VALUE` (a `[run]` setting, written to the
# patina.toml every phase reads), `# seeds: N`, `# fseeds: N`.
set -euo pipefail; shopt -s inherit_errexit
here=$(cd "$(dirname "$0")" && pwd)
name=${1:?usage: survey.sh NAME [PHASE...]}; shift
phases=${*:-native same sweep verify disk net}
CORPUS=${CORPUS:?a scratch directory}
PROGS=${PROGS:-$CORPUS/programs}
PATINA=${PATINA:-patina}
wl=$here/wl/$name.sh
[ -f "$wl" ] || { echo "no workload $wl" >&2; exit 2; }
out=$CORPUS/runs/$name
rm -rf "${out:?}"
mkdir -p "$out"
cd "$out"
hdr() { sed -n "s/^# $1: //p" "$wl" | head -1; }
opts=(--mount "$here/wl:/guest" --env GUEST=/guest --env "PROGS=$PROGS")
read -r -a progs <<<"$(hdr programs)"
for d in "${progs[@]}"; do opts+=(--mount "$PROGS/$d:$PROGS/$d"); done
read -r -a flags <<<"$(hdr flags)"
opts+=("${flags[@]}")
run=$(hdr run)
[ -z "$run" ] || printf '[run]\n%s\n' "$run" >patina.toml
seeds=$(hdr seeds); seeds=${seeds:-20}
fseeds=$(hdr fseeds); fseeds=${fseeds:-10}
sum=$out/summary.txt
log() { echo "$*" | tee -a "$sum"; }
res() { jq -r '[.outcome, .stop, .digest, (.wall_ms|tostring), ((.message // "")|.[0:200])] | join(" | ")' "$1/result.json"; }
refused() { jq -r '"  refused: " + ((.refused // []) | join(", "))' "$1/result.json" | tee -a "$sum"; }
for ph in $phases; do
    case $ph in
    native)
        d=$(mktemp -d "$out/native.XXXX")
        t0=$EPOCHREALTIME; st=0
        # Its own session: what it leaves running is stopped by session afterwards.
        (cd "$d" && exec setsid env -i HOME="$d" PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
            GUEST="$here/wl" PROGS="$PROGS" timeout 600 "$wl" >"$out/native.out" 2>"$out/native.err") & sp=$!
        wait $sp || st=$?
        pkill -s $sp || [ $? = 1 ]
        log "native: exit $st, wall $(awk -v a="$t0" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.2f", b - a }') s"
        rm -rf -- "${d:?}" ;;
    base)
        st=0; "${BASE:?the patina to compare with}" run --seed 1 --out base "${opts[@]}" -- /guest/"$name".sh >base.txt 2>&1 || st=$?
        log "base seed 1: $(res base)"
        refused base
        rm -f base/inc-*/boundary.log ;;
    same)
        for i in 1 2 3; do
            st=0; "$PATINA" run --seed 1 --out same-$i "${opts[@]}" -- /guest/"$name".sh >same-$i.txt 2>&1 || st=$?
            log "seed 1 #$i: $(res same-$i)"
        done
        refused same-1
        n=$(for i in 1 2 3; do jq -r .digest same-$i/result.json; done | sort -u | wc -l)
        log "same-seed digests distinct: $n"
        if [ -f native.out ]; then
            if cmp -s native.out same-1/inc-0/stdout; then log "stdout vs native: same"; else log "stdout vs native: differs"; fi
        fi
        rm -f same-2/inc-*/boundary.log same-3/inc-*/boundary.log ;;
    sweep)
        st=0; "$PATINA" sweep --seeds 1..$seeds -j 6 --keep fail --out sweep "${opts[@]}" -- /guest/"$name".sh >sweep.txt 2>&1 || st=$?
        n=$(cat sweep/seed-*/result.json | jq -r .digest | sort -u | wc -l)
        log "sweep 1..$seeds (exit $st): $(grep -m1 '^outcomes:' sweep.txt || [ $? = 1 ]); distinct digests $n" ;;
    verify)
        st=0; "$PATINA" verify --seed 1 --runs 3 --vary cpu,load,aslr --out verify "${opts[@]}" -- /guest/"$name".sh >verify.txt 2>&1 || st=$?
        log "verify (exit $st): $(grep -E '^(identical|differ|nondeterministic)' verify.txt | awk 'NR <= 3' | tr '\n' ';')"
        rm -f verify/run-*/inc-*/boundary.log ;;
    disk | net)
        st=0; "$PATINA" sweep --seeds 1..$fseeds -j 6 --keep fail --faults "$ph" --out "f$ph" "${opts[@]}" -- /guest/"$name".sh >"f$ph.txt" 2>&1 || st=$?
        log "faults $ph 1..$fseeds (exit $st): $(grep -m1 '^outcomes:' "f$ph.txt" || [ $? = 1 ])"
        sed -n '/^outcomes:/,$p' "f$ph.txt" | sed '1d; /^ *\(rerun\|replay\):/d; s/^/  /' | awk 'NR <= 24' >>"$sum" ;;
    *) echo "unknown phase $ph" >&2; exit 2 ;;
    esac
done
