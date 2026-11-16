# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# No guest output or log may grow without bound (dash counts in 512-byte blocks: 1 GB). Soft
# limit only: 10-earlier runs scripts that raise it again (blocking I/O sets 8000000).
ulimit -S -f 2000000

field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
die() { echo "FAIL: $*"; exit 1; }

# run_ok OUT SEED cmd...: one run, outcome ok.
run_ok() {
    out=$1; seed=$2; shift 2
    rm -rf "$out"; mkdir -p "$(dirname "$out")"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $* (seed $seed): no result.json"
    [ "$(field "$out/result.json" outcome)" = ok ] || die "$* (seed $seed): class $(field "$out/result.json" outcome): $(field "$out/result.json" message)"
}

# verify_ok OUT SEED RUNS VARY cmd...: patina verify says identical; independently one digest and
# one stdout over the run directories; the first run is ok.
verify_ok() {
    out=$1; seed=$2; runs=$3; vary=$4; shift 4
    rm -rf "$out"; mkdir -p "$(dirname "$out")"
    timeout 3600 "$PATINA" verify --seed "$seed" --runs "$runs" --vary "$vary" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "$@" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || { tail -5 "$out.verify.txt"; die "verify $* (seed $seed): exit $?"; }
    n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct digests"
    n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct stdout files"
    [ "$(field "$out/run-0/result.json" outcome)" = ok ] || die "$* seed $seed: class $(field "$out/run-0/result.json" outcome)"
    echo "seed $seed: $runs identical runs ($vary), digest $(field "$out/run-0/result.json" digest)"
}

# native OUT cmd...: the same command outside patina, in a bwrap sandbox shaped like patina's (the
# guest directory at /guest, /usr, a fresh PID namespace, an empty /tmp, and the 4 CPUs a guest
# sees by default: a program that sizes itself by the CPU count, as GNU sort starts a thread per
# CPU, uses as many PIDs as under patina whatever the host has). stdout to OUT.
native() {
    out=$1; shift
    cpus=$(python3 -I -c 'import os; c = sorted(os.sched_getaffinity(0)); print(",".join(map(str, c[:4])) if len(c) >= 4 else "")')
    [ -n "$cpus" ] || die "native: needs 4 CPUs to run as the guest sees them"
    timeout 300 taskset -c "$cpus" bwrap --tmpfs / --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --ro-bind /etc /etc --ro-bind "$PATINA_GUESTS" /guest \
        --proc /proc --dev /dev --tmpfs /tmp --chdir /tmp --unshare-pid --die-with-parent -- "$@" >"$out" 2>"$out.err"
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
    left=$(python3 -I "$HERE/../leftovers.py" "$@" || true)
    [ -z "$left" ] || die "processes left from $1: $left"
    m=$(findmnt | grep -c patina || true)
    [ "$m" = 0 ] || die "$m mounts mention patina"
}
