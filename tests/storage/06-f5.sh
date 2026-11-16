# 6. F5 (a short read is not retried: UnexpectedEof). short-permille=20 seed 3; control:
# seed 3 without faults passes.
#@ tier=quick budget=15
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/f5-3
run fjall-harness "$o" 3 --fault short-permille=20 -- /guest/fjall-harness-debug
case "$(field "$o/outcome.json" detail)" in
    "INVARIANT iterate-failed"|"INVARIANT reopen-failed") ;;
    *) die "F5: $(field "$o/outcome.json" detail)" ;;
esac
grep -q 'UnexpectedEof' "$o/inc-0/stderr" || die "F5: not an UnexpectedEof error"
c=$RUNS/f5-control-3
run fjall-harness "$c" 3 -- /guest/fjall-harness-debug
[ "$(field "$c/outcome.json" class)" = ok ] || die "F5 control: $(field "$c/outcome.json" detail)"
echo "F5 seed 3: $(field "$o/outcome.json" detail) (UnexpectedEof); control ok"
