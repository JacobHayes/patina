# 3. Differential: fs-tour natively (the sandbox, no runtime) and under patina give the same output once
#    timestamps, device numbers and anonymous-object inode numbers are masked.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/03-differential
mkdir -p "$o"
native "$o/native" -- /guest/fs-tour || die "native fs-tour exit $?"
timeout 120 "$PATINA" run --seed 1 --out "$o/patina" --mount "$PATINA_GUESTS":/guest:copy -- /guest/fs-tour >/dev/null
[ "$(field "$o/patina/result.json" outcome)" = ok ] || die "patina fs-tour: $(field "$o/patina/result.json" outcome)"
python3 -I "$LIB/mask.py" "$o/native/stdout" >"$o/native.masked"
python3 -I "$LIB/mask.py" "$o/patina/inc-0/stdout" >"$o/patina.masked"
diff "$o/native.masked" "$o/patina.masked" >"$o/diff" || { head -20 "$o/diff"; die "masked outputs differ"; }
echo "differential: $(wc -l <"$o/patina.masked") lines equal after masking"
