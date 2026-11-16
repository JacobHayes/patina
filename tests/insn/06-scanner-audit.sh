# 6. False-positive audit of the scanner. For libc, ld.so, libstdc++, libcrypto, the CPython
# binary, a static Go binary, a Rust binary (and the instruction channels guests): every byte candidate
# (0F C7 /6|/7, register form; F3 90) classified by objdump's linear sweep as a real instruction or
# bytes inside another instruction/data, against the runtime's rule (patina __insn-scan runs the
# same proto::insn code). They must agree on every candidate. The decoder the rule sweeps
# with must give objdump's length for every instruction of these files.
#@ tier=area budget=120
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-scanner-audit
mkdir -p "$o"
G=$PATINA_GUESTS
files="/lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libstdc++.so.6
 /lib/x86_64-linux-gnu/libcrypto.so.3 $(readlink -f /usr/bin/python3) $G/insn-go-hello $G/go-sig $G/hello-rs
 $G/insn $G/insn-jit $G/insn-cpuid"
# shellcheck disable=SC2086
python3 -I "$HERE/lib/census.py" --tsv $files >"$o/census.tsv"
# shellcheck disable=SC2086
"$PATINA" __insn-scan $files >"$o/scan.tsv"
echo "== instruction-site census (byte patterns classified by objdump)"
awk -F'\t' '$1 == "count" && $4 != "real=0" {print "  " $2 " " $3 " " $4}' "$o/census.tsv"
echo "== scanner candidates: objdump vs the rule"
python3 -I "$HERE/lib/audit.py" "$o/census.tsv" "$o/scan.tsv" | tee "$o/audit.txt" | sed 's/^/  /'
tail -1 "$o/audit.txt" | grep -q 'disagree=0' || die "the rule disagrees with objdump"
echo "== decoder lengths vs objdump"
for f in $files; do
    r=$(objdump -d -w -z "$f" | "$PATINA" __insn-scan --decode-check | tail -1)
    echo "  $f $r"
    echo "$r" | grep -q 'mismatches=0' || die "decoder: $r"
done
