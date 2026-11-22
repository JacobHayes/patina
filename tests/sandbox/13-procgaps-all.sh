# 13. The procgaps guest's every part at once (scheduling attributes, clone namespaces, the
# task link count, /proc directories and the policy through them, statfs of the sandbox's
# tmpfs): three runs under cpu and aslr variation identical, ending ok.
#@ tier=area,release budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/procgaps-all
mkdir -p "$out"
vfy all 3 cpu,aslr "$G17" -- /guest/procgaps all
r=$out/all/run-0
[ "$(class "$r")" = ok ] || die "all: $(class "$r"): $(detail "$r"); $(grep -m3 FAIL "$r/boot-1/stdout")"
