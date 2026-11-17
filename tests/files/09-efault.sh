# 9. Bad and boundary pointers (efault: small, unmapped, the runtime's range, read-only, off
#    the end of a mapping) to a spread of calls: every one answers EFAULT, as natively, and
#    the runtime never faults on a guest pointer (a fault there ends the run internal).
#@ tier=quick budget=15 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/09-efault
mkdir -p "$o"
native "$o/native" -- /guest/efault || die "native efault exit $?"
timeout 120 "$PATINA" run --seed 1 --out "$o/patina" --mount "$PATINA_GUESTS":/guest:copy -- /guest/efault >/dev/null || true
[ "$(field "$o/patina/result.json" outcome)" = ok ] || die "patina efault: $(field "$o/patina/result.json" outcome): $(field "$o/patina/result.json" message)"
diff "$o/native/stdout" "$o/patina/inc-0/stdout" || die "differs from native"
echo "efault: $(grep -c EFAULT "$o/patina/inc-0/stdout") calls answer EFAULT, as natively"
