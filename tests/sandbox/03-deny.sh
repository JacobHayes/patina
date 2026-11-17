#!/bin/sh
# Change 3: deny by default. Requests of ioctl, fcntl, prctl and socket options that no row
# lists are refused with their documented errno and recorded; paths are resolved by the
# runtime before the policy decides (symlinks and relative names cannot walk into /proc,
# /sys or /dev), and the determinism hardening checks after the call (by the mount of what was reached) are
# gone. The determinism hardening reproducers of B7 (procescape) still pass.
#@ tier=quick budget=30 slots=4
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/deny
mkdir -p "$out"
refused() { jq -c '.refused' "$1/result.json"; }
# Unlisted requests: refused, recorded, the same in every run.
vfy denyprobe 3 repeat "$G17" -- /guest/denyprobe
d=$out/denyprobe/run-0
awk '/^(ioctl FS|fcntl|prctl|getsockopt SO_[CPM]|setsockopt|getsockopt SOL_IP)/ { n++; if ($(NF-1) != "r=-1") bad++ }
     END { exit !(n == 13 && bad == 0) }' "$d/inc-0/stdout" || die "denyprobe: an unlisted request was not refused"
grep -q '^getsockopt SO_TYPE (listed) *r=0' "$d/inc-0/stdout" || die "denyprobe: a listed option was refused"
for k in '"ioctl:0x80087601"' '"fcntl:1024"' '"prctl:30"' '"sockopt:1:57"' '"sockopt:0:1"'; do
    refused "$d" | grep -q "$k" || die "denyprobe: $k not recorded"
done
echo "denyprobe: 13 unlisted requests refused (ENOTTY, EINVAL, ENOPROTOOPT) and recorded; listed ones pass"
# Path walks out of the policy's view: every attempt refused (ENOENT, or ELOOP for a loop),
# never a descriptor of the supervisor's.
vfy pathescape 3 repeat "$G17" -- /guest/pathescape
s=$out/pathescape/run-0/inc-0/stdout
awk '/^chdir \/ / { next } { n++; if (!($(NF-1) == "r=-1" && ($NF == "errno=2" || $NF == "errno=40"))) { bad++; print } }
     END { exit !(n == 28 && bad == 0) }' "$s" || die "pathescape: a walk was not refused"
refused "$out/pathescape/run-0" | grep -q '"/proc/1/fd/3001"' || die "pathescape: refusal not recorded"
echo "pathescape: 28 walks through symlinks, relative names and magic links refused"
# B7: the supervisor's /proc entries through symlinks and dot-dot, from two run
# directories: same stdout and digest.
for k in a b; do
    rm -rf "$out/procescape-$k"
    timeout 300 "$PATINA" run --seed 1 --out "$out/procescape-$k" --mount "$G12":/guest:copy -- /guest/procescape >/dev/null 2>&1 || true
done
cmp -s "$out/procescape-a/inc-0/stdout" "$out/procescape-b/inc-0/stdout" || die "procescape: stdout depends on the run directory"
[ "$(digest "$out/procescape-a")" = "$(digest "$out/procescape-b")" ] || die "procescape: digests differ"
awk '{ if ($0 ~ /fd=[0-9]/ && $0 !~ /fd=-1/) bad++ } END { exit bad > 0 }' "$out/procescape-a/inc-0/stdout" || die "procescape: an escape opened"
echo "B7 procescape: every escape refused, same stdout and digest from two run directories"
