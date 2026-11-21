# 8. A sweep keeps a run's work trees packed (`live.tree.zst`; `post-crash.tree.zst` in a run no
#    checker reads) and every reader of them reads the packed run as the run left it: against
#    the same seed's replay (which writes the trees whole, and must be identical), `log tree` of
#    every incarnation and node disk, `log tree --post-crash` of every crash, `log ops --check`
#    and `log events` (what a machine crash lost). In a run a checker judged, `post-crash/`
#    stays whole: the checker run by hand, `report --recheck --check` with a checker run per run and with one that serves read
#    what the replay's post-crash/ holds. The packed trees are smaller than the trees by a wide
#    margin, the sweep's "kept" line is the bytes left under its directory, and `--keep all`
#    keeps the trees as the run wrote them.
#@ tier=area,release budget=30 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
die() { echo "FAIL: $*"; exit 1; }
rm -rf "${RUNS:?}/kept-trees"
mkdir -p "$RUNS/kept-trees" && cd "$RUNS/kept-trees"

# A guest with a compressible work tree: a 1 MB file, fsynced, then an unsynced line and a new
# file each incarnation (a machine crash may lose those); it exits with its argument.
prog='import os, sys
inc = int(os.environ.get("PATINA_INCARNATION", "0"))
rows = b"".join(b"row %08d status=active payload=%s\n" % (i, b"x" * 40) for i in range(16000))
fd = os.open("db", os.O_RDWR | os.O_CREAT, 0o644)
os.pwrite(fd, rows, 0)
os.fsync(fd)
os.pwrite(fd, b"unsynced %d\n" % inc, len(rows))
os.close(fd)
os.makedirs("d", exist_ok=True)
open("d/n%d" % inc, "w").write("x")
sys.exit(int(sys.argv[1]))'
crash=(--crash machine:300 --fault max-incarnations=3)
# The listing of every crash's post-crash/ and its contents, for the checkers below.
cat >listing <<'EOF'
#!/bin/sh
cd "$1" || exit 2
for p in $(find . -name post-crash -type d | LC_ALL=C sort); do
    (cd "$p" && find . | LC_ALL=C sort && find . -type f | LC_ALL=C sort | xargs cat)
done | sha256sum | cut -c1-16
EOF
printf '#!/bin/sh\nexit 0\n' >pass
printf '#!/bin/sh\necho "post: $(%s/listing "$1")"\nexit 1\n' "$PWD" >judge
printf '#!/bin/sh\n# PATINA_CHECK_SERVE\nwhile read -r l; do\n  d=$(echo "$l" | jq -r .rundir)\n  echo "fail post: $(%s/listing "$d")"\ndone\n' "$PWD" >serve
chmod +x listing pass judge serve

# sweep OUT KEEP STATUS [FLAGS] -- CMD: seeds 1..4 checked by `pass`, exit STATUS.
sweep() {
    out=$1 keep=$2 want=$3; shift 3
    rc=0
    "$PATINA" sweep --seeds 1..4 -j 4 --keep "$keep" --check ./pass --out "$out" "$@" >"$out.txt" 2>&1 || rc=$?
    [ "$rc" = "$want" ] || die "sweep $out: exit $rc: $(tail -3 "$out.txt")"
}
# crashed OUT: the first run of sweep OUT that crashed.
crashed() {
    for d in "$1"/seed-*; do
        [ "$(jq '.crashes | length' "$d/result.json")" -ge 1 ] && { echo "$d"; return; }
    done
    echo "FAIL: no seed of 1..4 of $1 crashed: $(jq -c .incarnations "$1"/seed-*/result.json)" >&2
    exit 1
}

# same RUN RAW: every reader of RUN's trees reads what RAW (its replay) holds; prints a summary.
same() {
    r=$1 raw=$2
    st=0; "$PATINA" replay "$r" --out "$raw" >"$raw.txt" 2>&1 || st=$?
    grep -q '^identical' "$raw.txt" || die "replay of $r: exit $st: $(head -3 "$raw.txt")"
    n=0 p=0
    for inc in $(cd "$raw" && find . -name live.tree -printf '%h\n' | LC_ALL=C sort); do
        rm -rf t-a t-b
        "$PATINA" log tree "$r/$inc" t-a || die "log tree $r/$inc"
        "$PATINA" log tree "$raw/$inc" t-b || die "log tree $raw/$inc"
        diff -r t-a t-b >/dev/null || die "log tree $r/$inc differs from its replay's"
        n=$((n + 1))
        [ -d "$raw/$inc/post-crash" ] || continue
        rm -rf t-a
        "$PATINA" log tree --post-crash "$r/$inc" t-a || die "log tree --post-crash $r/$inc"
        diff -r t-a "$raw/$inc/post-crash" >/dev/null || die "log tree --post-crash $r/$inc differs from its replay's post-crash/"
        p=$((p + 1))
    done
    [ "$p" -ge 1 ] || die "$raw: no post-crash tree"
    "$PATINA" log ops --check "$r" >"$raw.ops" 2>&1 || die "log ops --check $r: $(tail -2 "$raw.ops")"
    "$PATINA" log events "$r" >"$raw.ev.a" && "$PATINA" log events "$raw" >"$raw.ev.b" || die "log events $r"
    cmp -s "$raw.ev.a" "$raw.ev.b" || die "log events of $r differ from its replay's: $(diff "$raw.ev.a" "$raw.ev.b" | head -4)"
    echo "$n trees and $p post-crash trees read as the replay wrote them"
}

# Failures: every tree packed.
sweep fail fail 1 "${crash[@]}" -- /usr/bin/python3 -I -c "$prog" 1
# The kept line is the bytes under the sweep's directory (to its one decimal; report.json comes after).
shown=$(sed -n 's/^sweep: \([0-9.]*\) \([KMG]i\)\{0,1\}B kept in .*/\1 \2/p' fail.txt)
[ -n "$shown" ] || die "no kept line: $(tail -2 fail.txt)"
under=$(find fail -type f ! -path fail/report.json -printf '%s\n' | awk '{s += $1} END {print s}')
awk -v s="$shown" -v u="$under" 'BEGIN {split(s, a, " "); m = a[2] == "Ki" ? 1024 : a[2] == "Mi" ? 1048576 : a[2] == "Gi" ? 1073741824 : 1; d = a[1] * m - u; exit !(d < 0.05 * m + 1 && -d < 0.05 * m + 1)}' ||
    die "the sweep said $shown kept, $under bytes are under its directory"
whole=$(find fail -name live.tree -o -name post-crash -type d)
[ -z "$whole" ] || die "a kept failure keeps an unpacked tree: $whole"
run=$(crashed fail)
same "$run" raw >same-fail.txt
grep -q '"type":"crash".*"lost"' raw.ev.a || die "log events $run: no crash with what it lost"
psize=$(find "$run" -name live.tree.zst -printf '%s\n' | sort -n | tail -1)
size=$(find raw -name live.tree -printf '%s\n' | sort -n | tail -1)
[ $((psize * 4)) -lt "$size" ] || die "a packed tree of $psize bytes for $size"

# Runs a checker judged: live trees packed, post-crash/ whole, read by a checker as the run left
# it, by hand and judging again.
sweep checked fail 0 "${crash[@]}" -- /usr/bin/python3 -I -c "$prog" 0
run=$(crashed checked)
packed=$(find "$run" -name '*.zst') dirs=$(find "$run" -name post-crash -type d)
case $packed in *live.tree.zst*) ;; *) die "a checked run kept no packed live tree: $packed" ;; esac
case $packed in *post-crash*) die "a checked run's post-crash/ was packed: $packed" ;; esac
[ -n "$dirs" ] || die "a checked run that crashed kept no post-crash/"
same "$run" craw >same-checked.txt
want="post: $(./listing craw)"
rc=0; line=$(./judge "$run") || rc=$?
[ "$rc $line" = "1 $want" ] || die "the checker by hand: exit $rc, '$line'; the replay's post-crash/ is '$want'"
for k in ./judge ./serve; do
    rc=0
    "$PATINA" report --recheck --check "$k" "$run" >recheck.txt 2>&1 || rc=$?
    got=$(jq -r '"\(.check.label): \(.check.detail)"' "$run/result.json")
    [ "$got" = "$want" ] || die "recheck --check $k: the checker read '$got', the replay's post-crash/ is '$want' (exit $rc: $(tail -2 recheck.txt))"
done

# Nodes: each node's disks are packed and read the same way.
cat >d.toml <<'EOF'
[node.a]
cmd = ["python3", "/guest/disk.py", "a"]
[node.b]
cmd = ["python3", "/guest/disk.py", "b"]
EOF
sweep nodes fail 1 --config d.toml --mount "$PATINA_GUESTS":/guest:copy -- /bin/sh -c 'python3 /guest/disk.py driver 2; exit 1'
node=$(find nodes -path '*/node/a/inc-1/post-crash.tree.zst')
[ -n "$node" ] || die "no packed node disk: $(find nodes -path '*/node/a/*' | head -3)"
same nodes/seed-1 nraw >same-nodes.txt

# --keep all: the trees as the run wrote them.
sweep all all 1 "${crash[@]}" -- /usr/bin/python3 -I -c "$prog" 1
packed_all=$(find all -name '*.zst') whole_all=$(find all -name live.tree)
[ -z "$packed_all" ] && [ -n "$whole_all" ] || die "--keep all packed a tree: $packed_all"
echo "ok: failures: $(cat same-fail.txt); checked: $(cat same-checked.txt), its post-crash/ read by hand and by recheck with a checker per run and one that serves; nodes: $(cat same-nodes.txt); packed $psize bytes for $size; kept line ${shown}B"
