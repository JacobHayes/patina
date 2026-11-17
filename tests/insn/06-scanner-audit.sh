# 6. False-positive audit of the scanner. For libc, ld.so, libstdc++, libcrypto, the CPython
# binary, a static Go binary, a Rust binary (and the instruction channels guests): every
# candidate classified independently of the rule as a real instruction or data, against the
# runtime's rule (patina __insn-scan runs the same proto::insn code). They must agree on every
# candidate. x86: byte candidates (0F C7 /6|/7, register form; F3 90) against objdump's linear
# sweep, and the rule's length decoder against objdump's for every instruction. arm64: word
# candidates (RNDR, RNDRRS, the four pause hints, PACGA) in executable sections against the
# literal loads that read them and the `$d` mapping symbols (libffi and libgcrypt added: they
# have `isb` sites). The whole-system census is evidence-census.sh.
#@ tier=area budget=120
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-scanner-audit
mkdir -p "$o"
G=$PATINA_GUESTS
if [ "$ARCH" = x86_64 ]; then
    files="/lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libstdc++.so.6
 /lib/x86_64-linux-gnu/libcrypto.so.3 $(readlink -f /usr/bin/python3) $G/insn-go-hello $G/go-sig $G/hello-rs
 $G/insn $G/insn-jit $G/insn-cpuid"
else
    L=/usr/lib/aarch64-linux-gnu
    files="$(readlink -f /lib/ld-linux-aarch64.so.1) $L/libc.so.6 $(readlink -f $L/libstdc++.so.6)
 $(readlink -f $L/libcrypto.so.3) $(readlink -f $L/libffi.so.8) $(readlink -f $L/libgcrypt.so.20)
 $(readlink -f /usr/bin/python3) $G/insn-go-hello $G/hello-rs $G/insn $G/insn-jit"
fi
for f in $files; do [ -f "$f" ] || die "missing $f"; done
# shellcheck disable=SC2086
python3 -I "$HERE/lib/census.py" --tsv $files >"$o/census.tsv"
# shellcheck disable=SC2086
"$PATINA" __insn-scan $files >"$o/scan.tsv"
echo "== instruction-site census (candidates classified without the rule)"
awk -F'\t' '$1 == "count" && $4 != "real=0" {print "  " $2 " " $3 " " $4}' "$o/census.tsv"
echo "== scanner candidates: objdump vs the rule"
python3 -I "$HERE/lib/audit.py" "$o/census.tsv" "$o/scan.tsv" | tee "$o/audit.txt" | sed 's/^/  /'
tail -1 "$o/audit.txt" | grep -q 'disagree=0' || die "the rule disagrees with objdump"
[ "$ARCH" = x86_64 ] || exit 0
echo "== decoder lengths vs objdump"
for f in $files; do
    r=$(objdump -d -w -z "$f" | "$PATINA" __insn-scan --decode-check | tail -1)
    echo "  $f $r"
    echo "$r" | grep -q 'mismatches=0' || die "decoder: $r"
done
