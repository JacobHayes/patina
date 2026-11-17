#!/bin/sh
# Change 4: the guest directory, /etc/ld.so.cache and /etc/alternatives are copies on sandbox
# tmpfs, not bind mounts: their metadata (inode numbers, times, blocks, device) is the
# sandbox's. Two copies of the guest directory on the host with different inode numbers,
# times and paths give the same stat output and digest. /usr stays a bind (see docs/EVIDENCE.md sandbox hardening).
#@ tier=quick budget=20 slots=1
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/copy
mkdir -p "$out"
rm -rf "$out/ga" "$out/gb"
mkdir -p "$out/ga" "$out/gb"
cp -p "$G17/hostcopy" "$out/ga/"
cp "$G17/hostcopy" "$out/gb/hostcopy.tmp"
mv "$out/gb/hostcopy.tmp" "$out/gb/hostcopy"
touch -d '2001-01-01 00:00:00' "$out/gb/hostcopy" "$out/gb"
for k in a b; do
    rm -rf "$out/run-$k"
    timeout 300 "$PATINA" run --seed 1 --out "$out/run-$k" --mount "$out/g$k":/guest:copy -- /guest/hostcopy >/dev/null 2>&1 || true
    [ "$(class "$out/run-$k")" = ok ] || die "hostcopy $k: $(class "$out/run-$k") $(detail "$out/run-$k")"
done
[ "$(stat -c %i "$out/ga/hostcopy")" != "$(stat -c %i "$out/gb/hostcopy")" ] || die "the two host copies share an inode"
cmp -s "$out/run-a/inc-0/stdout" "$out/run-b/inc-0/stdout" || die "hostcopy: stat output depends on the host files"
[ "$(digest "$out/run-a")" = "$(digest "$out/run-b")" ] || die "hostcopy: digests differ"
grep -q '^open /.patina/guest/hostcopy -1 errno 2$' "$out/run-a/inc-0/stdout" || die "hostcopy: the copy source is reachable"
echo "hostcopy: two host copies (different inodes, times, paths): same stat of /guest, ld.so.cache, alternatives; same digest"
