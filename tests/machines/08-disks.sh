# 8. Machines: each machine has a disk of its own, with its own operation log
# (`machine/NAME/boot-K/`). Four machines store through shared mappings of files with the same inode
# numbers at once (tests/guests/faults/mapshare: `alternate`): each machine's stores are logged
# in its own log, none in main's, and the self-check passes on every disk; the same
# under the seed's machine crashes, where every crash ends a disk, its log closed by a `Crash`
# record after what the machine's mappings held, and, outside the quick tier, under its process
# kills.
#@ tier=quick budget=60 slots=1
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-disks; mkdir -p "$o"
rm -f "$o/m.toml" "$o/loop.toml"
for n in a b c d; do
    conf "$o/m.toml" "$n" /guest/mapshare alternate
    conf "$o/loop.toml" "$n" sh -c "while :; do /guest/mapshare alternate >/dev/null; done"
done
check_disks() {
    [ "$(field "$1/result.json" self_check.verdict)" = pass ] || die "$1: self-check: $(field "$1/result.json" self_check)"
    k=$("$PATINA" log ops "$1/boot-1" | awk '/MmapDirty/ { c++ } END { print c + 0 }')
    [ "$k" = 0 ] || die "$1: main's log holds a machine's stores"
    for n in a b c d; do
        k=$("$PATINA" log ops "$1/machine/$n/boot-1" | awk '/MmapDirty/ { c++ } END { print c + 0 }')
        [ "$k" -gt 0 ] || die "$1: machine $n's stores are not in its log"
    done
}
run_ok "$o/plain" 1 --config "$o/m.toml" -- sleep 2
check_disks "$o/plain"
# The fault runs' time grows with their virtual length; 0.15 s already holds several kills or
# crashes, each ending a disk.
if [ "${CHECK_TIER:-}" != quick ]; then
    run_ok "$o/process" 2 --config "$o/loop.toml" --faults kill --fault crash-gap-ms=5..50 --fault down-ms=10..50 -- sleep 0.15
    check_disks "$o/process"
fi
run_ok "$o/machine" 3 --config "$o/loop.toml" --faults crash --fault crash-gap-ms=5..50 --fault down-ms=10..50 -- sleep 0.15
check_disks "$o/machine"
disks=$(ls -d "$o"/machine/machine/*/boot-* | while read -r d; do [ -f "$d/oplog.meta" ] && echo "$d"; done | wc -l)
ended=$(for d in "$o"/machine/machine/*/boot-*; do [ -f "$d/oplog.meta" ] && "$PATINA" log ops "$d" | tail -1; done | grep -c ' Crash ')
[ "$ended" -ge 4 ] || die "machine crashes: only $ended disks end with a Crash record"
echo "shared-mapping stores logged per machine, self-check passes on every disk: plain, machine crashes ($disks disks, $ended ended by a crash)$([ "${CHECK_TIER:-}" = quick ] || echo ", process kills")"
