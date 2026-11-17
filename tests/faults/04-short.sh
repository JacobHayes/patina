# 4. Short transfers (fs-short-permille=200): correct read/write loops give the right file,
# code assuming full counts gives a detectably wrong one; identical across runs.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
for mode in correct naive; do
    o=$RUNS/04/$mode
    verify "$o" 1 3 "" --fault fs-short-permille=200 -- /guest/short "$mode"
    out=$(cat "$o/run-0/inc-0/stdout")
    echo "$mode: $out ($(field "$o/run-0/result.json" faults.injected) short transfers injected)"
    case $mode in
        correct) echo "$out" | grep -q "^copy OK" || die "correct loops: $out" ;;
        naive) echo "$out" | grep -q "^copy BAD" || die "naive code not detected: $out" ;;
    esac
done
