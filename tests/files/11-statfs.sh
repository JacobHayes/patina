# 11. statfs, fstatfs and statvfs on every mount (statfs guest): two runs under --vary cpu are
#     identical, and nothing reported comes from the host. Every sandbox tmpfs (`/`, `/dev/shm`
#     on `/dev`, `/work`, `/tmp`, `/guest`) reports the configured tmpfs size (default
#     256 MiB) and 2^20 inodes, its free counts the size minus what the run used; the
#     superblock id is 0 everywhere. A `/` or `/dev` sized from the host's RAM (a tenth or
#     half of it) fails here on any host.
#@ tier=quick budget=10 slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/11-statfs
verify_ok "$o" 1 cpu 2 -- /guest/statfs
out=$o/run-0/inc-0/stdout
size=$((256 << 20))
for m in / /dev/shm /work /tmp /guest; do
    line=$(grep "^statfs $m type=" "$out" | head -1)
    [ -n "$line" ] || die "statfs $m: $(grep "^statfs $m " "$out")"
    awk -v size=$size -v m="$m" '{ for (i = 3; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] } }
        END { used = f["blocks"] - f["bfree"]
              if (f["type"] != "0x1021994" || f["blocks"] * f["bsize"] != size || f["bavail"] != f["bfree"] ||
                  used < 0 || f["files"] != 1048576 || f["fsid"] != "0:0") { print "statfs " m ": " $0; exit 1 } }' <<<"$line" ||
        die "a sandbox tmpfs does not report the configured size"
done
grep -E '^f?statfs .* fsid=' "$out" | grep -v ' fsid=0:0 ' && die "a superblock id shows"
grep -q '^statvfs / .* blocks=65536 .* fsid=0 ' "$out" || die "statvfs /: $(grep '^statvfs' "$out")"
# 1 MiB written to /dev/shm uses 256 of its blocks.
before=$(grep '^statfs /dev/shm ' "$out" | head -1 | sed 's/.* bfree=\([0-9]*\) .*/\1/')
after=$(grep '^statfs /dev/shm ' "$out" | tail -1 | sed 's/.* bfree=\([0-9]*\) .*/\1/')
[ $((before - after)) = 256 ] || die "/dev/shm free blocks went from $before to $after after 1 MiB"
echo "statfs: 2 runs identical under --vary cpu; every sandbox tmpfs reports $size bytes, 2^20 inodes, fsid 0"
