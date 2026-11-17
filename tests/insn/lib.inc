# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# Guests write small outputs; a runaway one stops at 2 GB.
ulimit -f 4000000

die() { echo "FAIL: $*"; exit 1; }

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json
field() { python3 -I -c 'import json,sys
v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

# The machine: x86_64 or aarch64 (the guests in x86 assembly have arm64 twins of one name).
ARCH=$(uname -m)
# INSN_ARGS: more `patina run` options for patina_run and verify (word-split).
INSN_ARGS=${INSN_ARGS:-}

# prog NAME: /guest/NAME, or NAME itself when it is an absolute path
prog() { case $1 in /*) echo "$1" ;; *) echo "/guest/$1" ;; esac; }

patina_run() { # out seed guest args...
    out=$1; seed=$2; g=$(prog "$3"); shift 3
    rm -rf "${out:?}"
    mkdir -p "$(dirname "$out")"
    # shellcheck disable=SC2086
    timeout 300 "$PATINA" run --seed "$seed" --out "$out" $INSN_ARGS --mount "$PATINA_GUESTS":/guest:copy -- "$g" "$@" >/dev/null || [ -f "$out/result.json" ] || die "patina run $g: no result.json"
}

# verify OUT SEED RUNS GUEST ARGS...: patina verify --vary cpu exits 0 and, independently, the
# run directories hold one digest and one stdout.
verify() {
    out=$1; seed=$2; n=$3; g=$(prog "$4"); shift 4
    rm -rf "${out:?}"
    mkdir -p "$(dirname "$out")"
    # shellcheck disable=SC2086
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$n" --vary cpu --out "$out" $INSN_ARGS --mount "$PATINA_GUESTS":/guest:copy -- "$g" "$@" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || die "$g seed $seed: verify exit $? ($(tail -3 "$out.verify.txt"))"
    d=$(for i in $(seq 0 $((n - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct digests"
    d=$(for i in $(seq 0 $((n - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct stdout files"
    c=$(grep -o 'cpu [0-9]*' "$out.verify.txt" | sort -u | wc -l)
    echo "$g seed $seed: $n identical runs on $c cores, digest $(field "$out/run-0/result.json" digest)"
}

# Drop the boundary logs of a verify directory (the digests stay in result.json).
trim() { for f in "$1"/run-*/inc-0/boundary.log; do rm -f "$f"; done; }
