#!/bin/sh
# Regression tests for the differences determinism hardening found and fixed (docs/EVIDENCE.md, "Differences").
# Each runs the attack guest that first showed the difference under the variant that exposed it.
#@ tier=quick budget=60 slots=4
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/regress
mkdir -p "$out"
G=$PATINA_ATTACK_GUESTS
vfy() { # vfy NAME RUNS VARY -- guest...
    n=$1; r=$2; v=$3; shift 4
    rm -rf "$out/$n"
    PATINA_PARALLEL=${PATINA_PARALLEL:-4} timeout 900 "$PATINA" verify --seed 1 --runs "$r" --vary "$v" --out "$out/$n" \
        --guest "$G" -- "$@" >"$out/$n.txt" 2>&1 || die "$n: $(tail -3 "$out/$n.txt")"
    echo "$n: $r runs identical under $v ($(digest "$out/$n/run-0"))"
    rm -rf "$out/$n"
}
# Socket cookies, network-namespace cookie, socket timestamps, peer pidfds: host-global
# counters and the host clock (differ between any two runs before the fix).
vfy sockprobe 3 sandbox -- /guest/sockprobe
# The launcher's umask, signal dispositions, rlimits, cwd and environment (env variant).
vfy envprobe 4 env -- /guest/envprobe
# Supervisor links reached through a symlink to /proc/1 (paths of the run directory differ
# between runs with different --out): the escapes are refused, so stdout is the same.
for k in a b; do
    rm -rf "$out/procescape-$k"
    timeout 300 "$PATINA" run --seed 1 --out "$out/procescape-$k" --guest "$G" -- /guest/procescape >/dev/null 2>&1 || true
done
cmp -s "$out/procescape-a/inc-0/stdout" "$out/procescape-b/inc-0/stdout" || die "procescape: stdout depends on the run directory"
[ "$(digest "$out/procescape-a")" = "$(digest "$out/procescape-b")" ] || die "procescape: digests differ"
echo "procescape: same stdout and digest from two run directories"
# The launcher's RLIMIT_FSIZE (30 MB, in 512-byte blocks) is enforced by the host kernel: the
# run ends as infra, not as a guest-visible EFBIG.
rm -rf "$out/fsize"
(ulimit -f 60000; timeout 300 "$PATINA" run --seed 1 --out "$out/fsize" --guest "$G" -- /guest/fillfs /work 40 >/dev/null 2>&1 || true)
[ "$(class "$out/fsize")" = infra ] || die "fsize: class $(class "$out/fsize"), expected infra"
echo "fsize: a launcher file-size limit ends the run as infra"
# In-flight unix sockets (a garbage cycle) are counted in the outcome (bucket D label).
rm -rf "$out/scm"
timeout 300 "$PATINA" run --seed 1 --out "$out/scm" --guest "$G" -- /guest/scmrights >/dev/null 2>&1 || true
n=$(sed -n 's/.*"unix_sockets_in_flight":\([0-9]*\).*/\1/p' "$out/scm/outcome.json")
[ "${n:-0}" -gt 0 ] || die "scmrights: unix_sockets_in_flight not set"
echo "scmrights: unix_sockets_in_flight $n"
# Descriptor exhaustion does not depend on the launcher's soft limit.
for n in 1024 4096; do
    rm -rf "$out/fd$n"
    (ulimit -Sn $n; timeout 300 "$PATINA" run --seed 1 --out "$out/fd$n" --guest "$G" -- /guest/fdexhaust >/dev/null 2>&1 || true)
done
[ "$(digest "$out/fd1024")" = "$(digest "$out/fd4096")" ] || die "fdexhaust: depends on the launcher's nofile limit"
echo "fdexhaust: same digest with launcher nofile 1024 and 4096"
# stdout's block count follows the size, not a host filesystem's preallocation (XFS trimmed it
# in the background after 300 s, so it moved within a long run). Since sandbox hardening stdout is a memfd.
rm -rf "$out/stdo"
timeout 300 "$PATINA" run --seed 1 --out "$out/stdo" --guest "$G" -- /guest/stdoutprobe >/dev/null 2>&1 || true
awk '/^step/ { n++; if ($6 != int(($4 + 4095) / 4096) * 8) bad++ } END { exit !(n == 40 && bad == 0) }' "$out/stdo/inc-0/stderr" ||
    die "stdoutprobe: stdout block counts are not derived from the size"
rm -rf "$out/stdo"
echo "stdoutprobe: 40 fstat(1) block counts follow the size"
# MADV_COLLAPSE answered 0 or EAGAIN with the host's huge-page state; now refused (recorded).
vfy memprobe 4 repeat -- /guest/memprobe
rm -rf "$out/mp"
timeout 300 "$PATINA" run --seed 1 --out "$out/mp" --guest "$G" -- /guest/memprobe >/dev/null 2>&1 || true
grep -q '"madvise:collapse"' "$out/mp/outcome.json" || die "memprobe: MADV_COLLAPSE not refused"
echo "memprobe: MADV_COLLAPSE refused and recorded"
# FS_IOC_FSGETXATTR on stdout: XFS's extent count moved with writeback under load.
vfy envprobe-load 4 load,aslr -- /guest/envprobe
# A process that exits with data just written to wire sockets: the supervisor read their
# hidden ends while the kernel was still closing the exiting process's descriptors, so a FIN
# was seen or not (W8 seed 4 with network faults, every few runs). Exit barrier first now.
wl W8
rm -rf "$out/w8"
# shellcheck disable=SC2086
timeout 900 "$PATINA" verify --seed 4 --runs 6 --vary repeat --out "$out/w8" --guest "$GDIR" $FAULTS -- $CMD \
    >"$out/w8.txt" 2>&1 || die "W8 seed 4 faults on: $(tail -3 "$out/w8.txt")"
echo "W8 seed 4 faults on: 6 runs identical ($(digest "$out/w8/run-0"))"
rm -rf "$out/w8"
