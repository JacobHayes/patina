# 8. Every row has a reason, and patina table shows no Stop for any call that strace -c reports
#    for items 1, 5 and 6 run natively.
#@ tier=area budget=60
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/08-table
mkdir -p "$o"
"$PATINA" table >"$o/table.md"
# rows: | nr | name | class | strength | reason |
awk -F' [|] ' '/^[|] [0-9]/ && $3 != "Stop" && $5 ~ /^ *[|]? *$/ {print; bad=1} END {exit bad}' "$o/table.md" \
    || die "a written row has no reason"
t=$o/tree
python3 -I "$LIB/mktree.py" "$t"
[ -x /usr/bin/strace ] || die "strace not installed"
i=0
trace() { # name [--root DIR] -- cmd...
    i=$((i + 1))
    n=$1; shift
    mkdir -p "$o/s$i"
    STRACE=1 native "$o/s$i" "$@" || true
    grep -q 'calls *errors *syscall' "$o/s$i/strace" || die "$n: no strace summary"
    awk '/^-+ /{f=!f; next} f && NF>=4 {print $NF}' "$o/s$i/strace" >>"$o/calls.raw"
}
trace fs-tour -- /guest/fs-tour
while IFS= read -r cmd; do
    set -f; set -- $cmd; set +f
    trace "$cmd" --root "$t" -- "$@"
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
trace python -- /usr/bin/python3 -c 'exec(open("/guest/pyscript.py").read())'
sort -u "$o/calls.raw" | grep -v '^total$' >"$o/calls"
bad=0
while read -r c; do
    cls=$(awk -F' [|] ' -v c="$c" '$2==c {print $3}' "$o/table.md")
    case $cls in
        Stop) [ "$c" = execve ] && continue  # performed once by the runtime's loader, never by these guests
              echo "Stop: $c"; bad=1 ;;
        "") echo "no row: $c"; bad=1 ;;
    esac
done <"$o/calls"
[ $bad = 0 ] || die "calls used natively show Stop"
echo "table: $(wc -l <"$o/calls") distinct calls used natively, none Stop"
