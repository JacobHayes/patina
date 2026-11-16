# Evidence: the frame a handler receives, field by field, from the kernel (native run) and
# from the runtime (under patina). The only differences allowed are the runtime's
# normalisations: XSAVE in-use bits set for every AVX..PKRU component, and the bytes the
# kernel leaves as stack garbage (sigcontext reserved1, legacy FXSAVE reserved) zeroed.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-frame
mkdir -p "$o"
(cd "$o" && "$PATINA_GUESTS/sig-frame" >native.txt)
patina_run "$o/patina" 1 sig-frame
[ "$(field "$o/patina/outcome.json" class)" = ok ] || die "patina run: $(field "$o/patina/outcome.json" class)"
cp "$o/patina/inc-0/stdout" "$o/patina.txt"
diff "$o/native.txt" "$o/patina.txt" >"$o/diff.txt" || true
cat "$o/diff.txt"
fields=$(grep '^[<>]' "$o/diff.txt" | awk '{print $2, $3}' | sort -u | tr '\n' ';')
echo "differing fields: $fields"
allowed="fp.hdr.xstate_bv fp.legacy_reserved_416_464_zero mc.reserved1_zero"
for f in $(grep '^[<>]' "$o/diff.txt" | awk '{print $3}' | sort -u); do
    case " $allowed " in *" $f "*) ;; *) die "field $f differs" ;; esac
done
# The normalised values themselves: zeros, and every xfeature bit in use.
grep -q 'fp.hdr.xstate_bv' "$o/patina.txt" || die "no xstate line"
for tag in onstack plain; do
    xf=$(awk -v t=$tag '$1 == t && $2 == "fp.sw.xfeatures" {print $3}' "$o/patina.txt")
    bv=$(awk -v t=$tag '$1 == t && $2 == "fp.hdr.xstate_bv" {print $3}' "$o/patina.txt")
    [ "$xf" = "$bv" ] || die "$tag: xstate_bv $bv, xfeatures $xf"
    for z in mc.reserved1_zero fp.legacy_reserved_416_464_zero; do
        [ "$(awk -v t=$tag -v z=$z '$1 == t && $2 == z {print $3}' "$o/patina.txt")" = 1 ] || die "$tag $z"
    done
done
echo "frame layout identical to the kernel's apart from the normalised fields"
