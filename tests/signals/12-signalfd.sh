# 12. sig-fd: signalfd as Linux has it (reads and their records, flags, a mask update, poll,
#     select, level- and edge-triggered epoll, wake-ups of a blocking read, poll and epoll_wait
#     by another process's signal, thread- and process-directed signals, fork and exec; the
#     guest checks each). Seeds 1-20: every run ok; seed 1 identical over 3 runs. Where kcmp
#     fails (tests/no-kcmp.py), a mask update cannot tell which descriptors share the file: the
#     run ends internal, never with the update applied to some of them.
#@ tier=quick budget=30 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/12-signalfd
mkdir -p "$o"
echo "/guest/sig-fd" >"$o/cases"
st=0
timeout 300 "$PATINA" sweep --seeds 1..20 --cases "$o/cases" -j 4 --config "$("$PATINA_CFG" time-limit=60)" --keep fail \
    --out "$o/sweep" --mount "$PATINA_GUESTS":/guest:copy >"$o/sweep.txt" 2>&1 || st=$?
outcomes=$(jq -cS .outcomes "$o/sweep/report.json")
echo "sig-fd seeds 1-20: $outcomes (sweep exit $st)"
[ "$outcomes" = '{"ok":20}' ] || { tail -30 "$o/sweep.txt"; die "not every run ok"; }
rm -rf "${o:?}/v"
timeout 300 "$PATINA" verify --seed 1 --runs 3 --out "$o/v" --mount "$PATINA_GUESTS":/guest:copy -- /guest/sig-fd \
    >"$o/verify.txt" 2>&1 || die "verify exit $?: $(tail -3 "$o/verify.txt")"
grep '^identical: ' "$o/verify.txt"
python3 -I "$(dirname "$0")/../no-kcmp.py" "$PATINA" run --seed 1 --out "$o/nokcmp" \
    --mount "$PATINA_GUESTS":/guest:copy -- /guest/sig-fd >/dev/null 2>&1 || [ -f "$o/nokcmp/result.json" ]
[ "$(field "$o/nokcmp/result.json" outcome)" = internal ] ||
    die "without kcmp: $(field "$o/nokcmp/result.json" outcome): $(field "$o/nokcmp/result.json" message)"
echo "without kcmp: internal"
