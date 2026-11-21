# 6. F5 (a short read is not retried: UnexpectedEof). A sweep of seeds 1-48 with
# fs-short-permille=20 (about one seed in three reaches it, which ones depending on the host: 10
# seeds missed it about once in a hundred) must end at least one run
# `iterate-failed` or `reopen-failed` on an UnexpectedEof, with fs-short injected in every
# failing run of that group; the same seed without faults passes.
#@ tier=quick budget=15
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/f5
"$PATINA" sweep --seeds 1..48 -j 4 --out "$o" --mount "$W/fjall-harness":/guest:copy --fault fs-short-permille=20 \
    -- /guest/fjall-harness-debug >"$o.txt" 2>&1 || [ -f "$o/report.json" ] || die "sweep: $(tail -2 "$o.txt")"
g='[.groups[] | select(.signature | test("^violation always: (iterate|reopen)-failed(: |$)"))][0]'
s=$(jq -r "$g.first.seed // empty" "$o/report.json")
[ -n "$s" ] || die "F5: no seed of 1-48 failed reading ($(grep '^outcomes' "$o.txt"))"
[ "$(jq -c "$g.faults.every" "$o/report.json")" = '["fs-short"]' ] || die "F5: attribution $(jq -c "$g.faults" "$o/report.json")"
case "$(field "$o/seed-$s/result.json" message)" in
    *UnexpectedEof*) ;;
    *) die "F5 seed $s: not an UnexpectedEof error: $(field "$o/seed-$s/result.json" message)" ;;
esac
c=$RUNS/f5-control-$s
run fjall-harness "$c" "$s" -- /guest/fjall-harness-debug
[ "$(field "$c/result.json" outcome)" = ok ] || die "F5 control seed $s: $(field "$c/result.json" message)"
echo "F5: $(jq -r "$g | \"\(.signature): \(.count) of 10 seeds\"" "$o/report.json"); seed $s UnexpectedEof; control ok"
