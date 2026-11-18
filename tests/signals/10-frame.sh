# Evidence: the frame a handler receives, field by field, from the kernel (native run) and
# from the runtime (under patina). The only differences allowed are the runtime's
# normalisations: the bytes the kernel leaves as stack garbage zeroed (x86_64: sigcontext
# reserved1, legacy FXSAVE reserved, the padding in uc_stack; arm64: the unused bytes after
# uc_sigmask, the padding after pstate, the records area after its terminator), and the state
# whose form is the kernel's history: x86_64, the XSAVE in-use bits set for every AVX..PKRU
# component; arm64, the SVE record in its header form when nothing beyond the FP/SIMD
# registers is set. The guest (sig-frame, or its arm64 twin) prints the fields of its machine.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-frame
mkdir -p "$o"
# Natively as uid/gid 1000, the ids the sandbox gives the guest (si_uid is in the frame).
(cd "$o" && bwrap --dev-bind / / --unshare-user --uid 1000 --gid 1000 --die-with-parent -- "$PATINA_GUESTS/sig-frame" >native.txt)
patina_run "$o/patina" 1 sig-frame
[ "$(field "$o/patina/result.json" outcome)" = ok ] || die "patina run: $(field "$o/patina/result.json" outcome)"
cp "$o/patina/inc-0/stdout" "$o/patina.txt"
diff "$o/native.txt" "$o/patina.txt" >"$o/diff.txt" || true
cat "$o/diff.txt"
fields=$(awk '/^[<>]/ {print $2, $3}' "$o/diff.txt" | sort -u | tr '\n' ';')
echo "differing fields: $fields"
allowed="fp.hdr.xstate_bv fp.legacy_reserved_416_464_zero mc.reserved1_zero uc_stack.pad uc.unused_zero mc.pad_zero rec.tail_zero rec.sve.size rec.sve.beyond_fpsimd"
for f in $(awk '/^[<>]/ {print $3}' "$o/diff.txt" | sort -u); do
    case " $allowed " in *" $f "*) ;; *) die "field $f differs" ;; esac
done
# The normalised values themselves.
if ! grep -q 'fp.hdr.xstate_bv' "$o/patina.txt"; then
    # arm64: zeros, and an SVE record whose form differs only where nothing beyond FP/SIMD is set.
    grep -q '^onstack rec.order fpsimd,' "$o/patina.txt" || die "no record list"
    for tag in onstack plain; do
        for z in uc.unused_zero mc.pad_zero rec.tail_zero; do
            [ "$(awk -v t=$tag -v z=$z '$1 == t && $2 == z {print $3}' "$o/patina.txt")" = 1 ] || die "$tag $z"
        done
        if grep -q "^[<>] $tag rec.sve.size " "$o/diff.txt"; then
            [ "$(awk -v t=$tag '$1 == t && $2 == "rec.sve.beyond_fpsimd" {print $3}' "$o/native.txt")" = 0 ] ||
                die "$tag: the SVE record's form differs with state beyond FP/SIMD set"
        fi
    done
    # The SVE rule itself: a full record only with state beyond FP/SIMD set.
    ! grep -q ' rec.sve.beyond_fpsimd 0$' "$o/patina.txt" || die "a full SVE record with nothing beyond FP/SIMD set"
    echo "frame layout identical to the kernel's apart from the normalised fields"
    exit 0
fi
for tag in onstack plain; do
    xf=$(awk -v t=$tag '$1 == t && $2 == "fp.sw.xfeatures" {print $3}' "$o/patina.txt")
    bv=$(awk -v t=$tag '$1 == t && $2 == "fp.hdr.xstate_bv" {print $3}' "$o/patina.txt")
    # Every enabled component from x87 to PKRU (bits 0-9) is in use; later ones (AMX) are
    # left as the kernel wrote them.
    [ $((xf & 0x3ff)) = $((bv & 0x3ff)) ] || die "$tag: xstate_bv $bv, xfeatures $xf"
    for z in mc.reserved1_zero fp.legacy_reserved_416_464_zero; do
        [ "$(awk -v t=$tag -v z=$z '$1 == t && $2 == z {print $3}' "$o/patina.txt")" = 1 ] || die "$tag $z"
    done
    [ "$(awk -v t=$tag '$1 == t && $2 == "uc_stack.pad" {print $3}' "$o/patina.txt")" = 0 ] || die "$tag uc_stack.pad"
done
echo "frame layout identical to the kernel's apart from the normalised fields"
