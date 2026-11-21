#!/bin/sh
# Throwaway: digests of a fixed list of runs, one line per cell.
set -eu
root=$(pwd)

: "${P:?}" "${set:?}"


G=$set/guests W=$set/workloads
out=$(mktemp -d "${TMPDIR:-/tmp}/ledger.XXXXXX")
trap 'rm -rf "$out"' EXIT
n=0
# cell NAME [patina options] -- CMD...   prints "NAME digest outcome"
cell() {
    name=$1; shift
    n=$((n + 1))
    "$P" run --out "$out/$n" "$@" >/dev/null 2>&1 || true
    python3 -I -c 'import json,sys
try:
    r = json.load(open(sys.argv[1] + "/result.json"))
    print(sys.argv[2], r.get("digest"), r.get("outcome", r.get("class")))
except Exception as e:
    print(sys.argv[2], "NO-RESULT", type(e).__name__)' "$out/$n" "$name"
    rm -rf "$out/$n"
}
for seed in 1 2 3; do
    for f in off all; do
        fa=""; [ "$f" = all ] && fa="--faults all"
        # shellcheck disable=SC2086
        {
        cell "hello-static/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/hello-static
        cell "hello-dyn/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/hello-dyn
        cell "fs-tour/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/fs-tour
        cell "sockets/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/sockets all
        cell "sig-basic/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/sig-basic
        cell "sig-frame/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/sig-frame
        cell "fork-exec/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/fork-exec
        cell "exec-matrix/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/exec-matrix
        cell "c-threads/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/c-threads
        cell "insn/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/insn
        cell "udp/$seed/$f" --seed $seed $fa --mount "$G:/guest:copy" -- /guest/udp rpc retry
        cell "tokio-mt/$seed/$f" --seed $seed $fa --mount "$W/tokio-mt:/guest:copy" -- /guest/tokio-mt local
        cell "go-static/$seed/$f" --seed $seed $fa --mount "$W/go-static:/guest:copy" -- /guest/go-static all
        cell "cpython/$seed/$f" --seed $seed $fa --mount "$W/cpython:/guest:copy" -- /usr/bin/python3 /guest/w5.py all
        cell "shell/$seed/$f" --seed $seed $fa --mount "$W/shell-pipeline:/guest:copy" -- /bin/sh /guest/w6.sh
        }
    done
done
echo "cells: $n" >&2
