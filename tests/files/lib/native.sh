#!/bin/bash
# Run a command natively (no runtime) in the sandbox a patina run gets (`patina __native`): the
# same mounts, generated /etc, /work and /tmp tmpfs, /in copied into /work as the supervisor
# copies it, and its environment, with the guests at /guest.
# usage: [STRACE=1] native.sh OUTDIR [--disk DIR] [--env K=V]... -- /guest/prog args...
# stdout and stderr go to OUTDIR/stdout, OUTDIR/stderr; the exit status is the command's.
set -euo pipefail; shopt -s inherit_errexit
out=$1; shift
opts=()
while [ "$1" != -- ]; do
    case $1 in
        --disk|--env) opts+=("$1" "$2"); shift 2 ;;
        *) echo "native.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
shift
mkdir -p "$out"
# STRACE=1: count the command's system calls (strace -f -c) into OUTDIR/strace. The sandbox
# passes the command 0, 1 and 2 only, so the count goes to stderr, which is OUTDIR/strace then.
if [ -n "${STRACE:-}" ]; then
    st=0
    "${PATINA:?}" __native --mount "$PATINA_GUESTS:/guest" "${opts[@]}" -- /usr/bin/strace -f -c -o /dev/stderr "$@" \
        >"$out/stdout" 2>"$out/strace" || st=$?
    exit "$st"
fi
exec "${PATINA:?}" __native --mount "$PATINA_GUESTS:/guest" "${opts[@]}" -- "$@" >"$out/stdout" 2>"$out/stderr"
