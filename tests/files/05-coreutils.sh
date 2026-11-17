# 5. coreutils as direct guests on an input tree: ok, identical over 3 runs, and equal to a
#    native run after masking file times, device numbers and mktemp's random names.
#@ tier=area budget=120
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/05-coreutils
mkdir -p "$o"
t=$o/tree
tree "$t"
i=0
while IFS= read -r cmd; do
    i=$((i + 1))
    set -f; set -- $cmd; set +f
    verify_ok "$o/c$i" 1 "" 3 --work "$t" -- "$@"
    native "$o/n$i" --work "$t" -- "$@" || die "native $cmd: exit $?"
    python3 -I "$LIB/mask_text.py" "$o/n$i/stdout" >"$o/n$i.masked"
    python3 -I "$LIB/mask_text.py" "$o/c$i/run-0/inc-0/stdout" >"$o/c$i.masked"
    diff "$o/n$i.masked" "$o/c$i.masked" >"$o/d$i" || { head "$o/d$i"; die "$cmd: differs from native"; }
    echo "ok $cmd ($(wc -l <"$o/c$i.masked") lines)"
done <<'CMDS'
/usr/bin/ls -la /work
/usr/bin/ls -laRi /work/a
/usr/bin/stat /work/a/f00 /work/a/link /work/d /work/big.txt
/usr/bin/cat /work/a/b/f01 /work/d/f03
/usr/bin/cp -av /work/a /work/a2
/usr/bin/mv -v /work/a /work/z
/usr/bin/rm -rv /work/a
/usr/bin/mkdir -pv /work/p/q/r
/usr/bin/ln -sv a/b/f01 /work/l
/usr/bin/touch -d 2027-03-04T05:06:07 /work/a/f00 /work/new
/usr/bin/du -a /work
/usr/bin/df /work
/usr/bin/find /work -newer /work/a/f00
/usr/bin/sha256sum /work/big.txt /work/a/f00 /work/e/f/f04
/usr/bin/sort -S 1M --parallel=1 -T /tmp /work/big.txt
/usr/bin/mktemp -p /tmp
/usr/bin/mktemp -d
CMDS
