# Evidence (crash-point enumeration): for each base seed, one run without a crash, then one
# child per crash point of it (`--crash machine-at:N`), counting the children that end in
# fjall's journal-entry assertion (F2, docs/EVIDENCE.md "Search quality"). Prints, per seed,
# the crash points, the children, the F2 children and their points, the CPU-seconds in all
# and to the first F2, and the share of children whose post-crash tree repeats an earlier
# child's.
#   ENUM_SEEDS   base seeds to take in order (default 1 to 20); a seed over 10,000 crash points
#                is skipped and the next taken, until ENUM_COUNT (default 3) are enumerated
#   ENUM_DIR ENUM_CMD ENUM_OPTS  the guest directory, command and options (default the debug
#                fjall harness with FJ_N=2000 --buggify)
#   ENUM_JOBS    parallel children (default 6)
#@ tier=evidence budget=1200 slots=6 arch=x86_64
set -eu
: "${PATINA:?}" "${RUNS:?}" "${PATINA_WORKLOADS:?}"
seeds=${ENUM_SEEDS:-$(seq 1 20)}
cmd=${ENUM_CMD:-/guest/fjall-harness-debug}
opts=${ENUM_OPTS:---buggify --env FJ_N=2000}
export PATINA RUNS opts cmd G="${ENUM_DIR:-$PATINA_WORKLOADS/fjall-harness}"
ulimit -f 4000000
die() { echo "FAIL: $*"; exit 1; }
out=$RUNS/enum; mkdir -p "$out"
tried=0
for s in $seeds; do
    [ "$tried" -lt "${ENUM_COUNT:-3}" ] || break
    b=$out/base-$s
    # shellcheck disable=SC2086
    "$PATINA" run --seed "$s" --crash machine:0 --out "$b" --mount "$G":/guest:copy $opts -- $cmd >/dev/null 2>&1 \
        || [ -f "$b/result.json" ] || die "seed $s: the base run failed"
    pts=$(jq '.faults.counts.crash.eligible // 0' "$b/result.json")
    [ "$pts" -gt 0 ] || die "seed $s: the base has no crash point ($(jq -r .outcome "$b/result.json"))"
    [ "$pts" -le 10000 ] || { echo "seed $s: $pts crash points, skipped"; rm -rf "$b"; continue; }
    seq 1 "$pts" >"$out/points-$s"
    base_ms=$(jq .wall_ms "$b/result.json"); echo "$base_ms" >>"$out/base-ms"
    rm -rf "$b"
    : >"$out/children-$s.tsv"
    # One child per point: its line is point, crash seq, outcome, F2 (1/0), wall_ms, tree digest.
    xargs -P "${ENUM_JOBS:-6}" -I{} sh -c '
        s=$1 q=$2 c=$RUNS/enum/child-$1-$2
        timeout 600 "$PATINA" run --seed "$s" --crash "machine-at:$q" --out "$c" --mount "$G":/guest:copy $opts -- $cmd >/dev/null 2>&1 || true
        if [ -f "$c/result.json" ]; then
            jq -r --arg q "$q" "[\$q, (.crashes[0].seq // \"-\"), .outcome, (if ((.signature // \"\") | test(\"journal/entry.rs\")) then 1 else 0 end), .wall_ms, (.crashes[0].tree_digest // \"-\")] | @tsv" "$c/result.json"
        else
            printf "%s\t-\tpatina-error\t0\t0\t-\n" "$q"
        fi
        rm -rf "$c"
    ' sh "$s" {} <"$out/points-$s" >>"$out/children-$s.tsv"
    python3 -I - "$out/children-$s.tsv" "$s" "$pts" "$base_ms" <<'PY'
import sys, collections
rows = sorted((l.rstrip("\n").split("\t") for l in open(sys.argv[1])), key=lambda r: int(r[0]))
s, pts, base_ms = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
crashed = [r for r in rows if r[1] != "-"]
f2 = [r for r in rows if r[3] == "1"]
ms = [int(r[4]) for r in rows]
first = next((i for i, r in enumerate(rows) if r[3] == "1"), None)
to_first = base_ms + sum(ms[: first + 1]) if first is not None else None
trees = collections.Counter(r[5] for r in crashed)
rep = sum(n - 1 for n in trees.values())
outc = collections.Counter(r[2] for r in rows)
print("seed %s: crash points %d, children %d (crashed %d), F2 %d at points %s, CPU-s %.1f (base %.2f), to first F2 %s, children repeating a tree %.0f%%, outcomes %s" % (
    s, pts, len(rows), len(crashed), len(f2), [int(r[0]) for r in f2], (base_ms + sum(ms)) / 1000, base_ms / 1000,
    "%.1f" % (to_first / 1000) if to_first is not None else "-", 100 * rep / max(len(crashed), 1), dict(outc)))
PY
    # Every child must crash at its point; the rows with no crash name the child's outcome.
    n=$(awk -F'\t' '$2 != "-"' "$out/children-$s.tsv" | wc -l)
    [ "$n" = "$pts" ] || die "seed $s: $n of $pts children crashed; the others: $(awk -F'\t' '$2 == "-" {printf "%s %s; ", $1, $3}' "$out/children-$s.tsv" | head -c 400)"
    tried=$((tried + 1))
done
[ "$tried" -gt 0 ] || die "every seed was skipped"
b=$(awk '{t += $1} END {print t}' "$out/base-ms")
cat "$out"/children-*.tsv | awk -F'\t' -v b="$b" '{ms += $5; f += $4} END { ms += b; printf "all seeds: %d children, %d F2, %.1f CPU-s (bases included), %.2e F2 runs per CPU-s\n", NR, f, ms / 1000, f / (ms / 1000) }'
