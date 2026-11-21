# 8. Nodes: each node's work tree is a disk of its own, with its own operation log
# (`node/NAME/inc-K/`). Four nodes store through shared mappings of files with the same inode
# numbers at once (tests/guests/faults/mapshare: `alternate`): each node's stores are logged
# in its own log, none in the driver's, and the self-check passes on every disk; the same
# under the seed's machine crashes, where every crash ends a disk, its log closed by a `Crash`
# record after what the node's mappings held, and, outside the quick tier, under its process
# kills.
#@ tier=quick budget=60 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-disks; mkdir -p "$o"
rm -f "$o/m.toml" "$o/loop.toml"
for n in a b c d; do
    conf "$o/m.toml" "$n" /guest/mapshare alternate
    conf "$o/loop.toml" "$n" sh -c "while :; do /guest/mapshare alternate >/dev/null; done"
done
check_disks() {
    [ "$(field "$1/result.json" self_check.verdict)" = pass ] || die "$1: self-check: $(field "$1/result.json" self_check)"
    k=$("$PATINA" log ops "$1/inc-0" | awk '/MmapDirty/ { c++ } END { print c + 0 }')
    [ "$k" = 0 ] || die "$1: the driver's log holds a node's stores"
    for n in a b c d; do
        k=$("$PATINA" log ops "$1/node/$n/inc-0" | awk '/MmapDirty/ { c++ } END { print c + 0 }')
        [ "$k" -gt 0 ] || die "$1: node $n's stores are not in its log"
    done
}
run_ok "$o/plain" 1 --config "$o/m.toml" -- sleep 2
check_disks "$o/plain"
if [ "${CHECK_TIER:-}" != quick ]; then
    run_ok "$o/process" 2 --config "$o/loop.toml" --crash process --fault crash-gap-ms=5..50 --fault down-ms=10..50 -- sleep 0.25
    check_disks "$o/process"
fi
# The quick tier's run is shorter: fewer crashes, each still ending a disk.
t=0.25; [ "${CHECK_TIER:-}" != quick ] || t=0.15
run_ok "$o/machine" 3 --config "$o/loop.toml" --crash machine --fault crash-gap-ms=5..50 --fault down-ms=10..50 -- sleep $t
check_disks "$o/machine"
disks=$(ls -d "$o"/machine/node/*/inc-* | while read -r d; do [ -f "$d/oplog.meta" ] && echo "$d"; done | wc -l)
ended=$(for d in "$o"/machine/node/*/inc-*; do [ -f "$d/oplog.meta" ] && "$PATINA" log ops "$d" | tail -1; done | grep -c ' Crash ')
[ "$ended" -ge 4 ] || die "machine crashes: only $ended disks end with a Crash record"
echo "shared-mapping stores logged per node, self-check passes on every disk: plain, machine crashes ($disks disks, $ended ended by a crash)$([ "${CHECK_TIER:-}" = quick ] || echo ", process kills")"
