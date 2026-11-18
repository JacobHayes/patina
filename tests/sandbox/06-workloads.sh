# W1-W9 and the language runtimes (Go, CPython, tokio, the shells, and the network
# runtimes of the network wire) run unmodified on the sandbox hardening build, each verified as identical runs (seed 1,
# repeat and env variants), with nothing refused that was not refused before sandbox hardening.
#@ tier=area budget=240 slots=4
. "$(dirname "$0")/lib/common.inc"
. "$sandbox/lib/entries.inc"
out=$RUNS/workloads
mkdir -p "$out"
for n in ${SANDBOX_ENTRIES:-$ENTRIES}; do
    entry "$n"
    rm -rf "${out:?}/$n"
    # shellcheck disable=SC2086
    PATINA_PARALLEL=${PATINA_PARALLEL:-4} timeout 3600 "$PATINA" verify --seed 1 --runs 3 --vary env --out "$out/$n" --mount "$GDIR":/guest:copy $OPTS \
        -- $CMD >"$out/$n.txt" 2>&1 || grep -q '^identical: ' "$out/$n.txt" || die "$n: $(tail -3 "$out/$n.txt")"
    c=$(class "$out/$n/run-0")
    [ "$c" = ok ] || die "$n: class $c"
    r=$(jq -r '.refused | join(",")' "$out/$n/run-0/result.json")
    # Refusals sandbox hardening added: requests of open-ended calls (ioctl, fcntl, prctl, sockopt).
    case ",$r," in *,ioctl:*|*,fcntl:*|*,prctl:*|*,sockopt:*) die "$n: refused $r" ;; esac
    echo "$n: 3 runs identical under env ($(digest "$out/$n/run-0")); refused: ${r:-none}"
    rm -rf "${out:?}/$n"
done
