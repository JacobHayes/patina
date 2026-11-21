# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# No guest output or log may grow without bound (dash counts in 512-byte blocks: 1 GB). Soft
# limit only: 10-earlier runs scripts that raise it again (blocking I/O sets 8000000).
ulimit -S -f 2000000

. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"
die() { echo "FAIL: $*"; exit 1; }

# run_ok OUT SEED cmd...: one run, outcome ok.
run_ok() {
    out=$1; seed=$2; shift 2
    rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $* (seed $seed): no result.json"
    [ "$(field "$out/result.json" outcome)" = ok ] || die "$* (seed $seed): class $(field "$out/result.json" outcome): $(field "$out/result.json" message)"
}

# verify_ok OUT SEED RUNS VARY cmd...: patina verify says identical; independently one digest and
# one stdout over the run directories; the first run is ok.
verify_ok() {
    out=$1; seed=$2; runs=$3; vary=$4; shift 4
    # Quick tier: two runs, the reference and one varied in each way asked; more in the area tier.
    [ "${CHECK_TIER:-}" != quick ] || [ "$runs" -le 2 ] || runs=2
    rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
    timeout 3600 "$PATINA" verify --seed "$seed" --runs "$runs" --vary "$vary" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "$@" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || { tail -5 "$out.verify.txt"; die "verify $* (seed $seed): exit $?"; }
    n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct digests"
    n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct stdout files"
    [ "$(field "$out/run-0/result.json" outcome)" = ok ] || die "$* seed $seed: class $(field "$out/run-0/result.json" outcome)"
    echo "seed $seed: $runs identical runs ($vary), digest $(field "$out/run-0/result.json" digest)"
}

# native OUT cmd...: the same command outside the runtime, in the sandbox a run gets (`patina
# __native`, the guests at /guest), on the 4 CPUs a guest sees by default: a program that sizes
# itself by the CPU count, as GNU sort starts a thread per CPU, uses as many PIDs as under
# patina whatever the host has. stdout to OUT.
native() {
    out=$1; shift
    cpus=$(python3 -I -c 'import os; c = sorted(os.sched_getaffinity(0)); print(",".join(map(str, c[:4])) if len(c) >= 4 else "")')
    [ -n "$cpus" ] || die "native: needs 4 CPUs to run as the guest sees them"
    timeout 300 taskset -c "$cpus" "$PATINA" __native --mount "$PATINA_GUESTS:/guest" -- "$@" >"$out" 2>"$out.err"
}

# counts RUN: processes created and execs, from the boundary log (main + Forked records of
# processes + VforkStart; Exec records).
counts() {
    "$PATINA" log dump "$1/inc-0/boundary.log" | awk '
        $2 == "sup" && $5 == "Forked" && $9 == "0x1," { p++ }
        $2 == "sup" && $5 == "VforkStart" { p++ }
        $2 == "sup" && $5 == "Exec" { e++ }
        END { printf "processes=%d execs=%d\n", p + 1, e }'
}

# no_leftovers DIR: no process of this user still belongs to a run under DIR.
no_leftovers() {
    # leftovers.py exits 1 when it lists processes; exit 1 with no list is its own failure.
    rc=0; left=$(python3 -I "$HERE/../leftovers.py" "$@") || rc=$?
    [ -z "$left" ] || die "processes left from $1: $left"
    [ "$rc" = 0 ] || die "leftovers.py failed (exit $rc)"
    mounts=$(findmnt -rn -o TARGET) || die "findmnt failed"
    m=$(printf '%s\n' "$mounts" | awk '/patina/ {n++} END {print n + 0}')
    [ "$m" = 0 ] || die "$m mounts mention patina"
}
