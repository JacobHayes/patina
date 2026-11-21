# What made digests differ between hosts (CI runners, containers) before sandbox hardening's fixes, each held
# by construction now: host files read as owned by the overflow id whoever launched the run;
# every mount's device reads as its index and the mount table carries no host mount flags and
# no launcher uid or gid (tmpfs's uid=, gid= options name the host's ids); the
# CPU count is fixed; registers a call does not read are not recorded; and a launcher that
# already runs under a seccomp filter (a container's profile) still gets the runtime's filter
# stacked on it, with the same digest.
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/crosshost
mkdir -p "$out"
run() { # run NAME [wrapper...]: one run of the crosshost guest, class ok
    n=$1; shift
    timeout 120 "$@" "$PATINA" run --seed 1 --out "$out/$n" --mount "$G17":/guest:copy -- /guest/crosshost >/dev/null 2>&1 || true
    [ "$(class "$out/$n")" = ok ] || die "$n: class $(class "$out/$n") ($(detail "$out/$n"))"
}
run plain env
s=$out/plain/inc-0/stdout
grep -q '^stat /usr/bin/sh uid=65534 gid=65534 dev=0:' "$s" || die "host file: $(grep '^stat /usr' "$s")"
grep -q '^stat /work/own uid=1000 gid=1000 dev=0:' "$s" || die "sandbox file: $(grep '^stat /work' "$s")"
grep -q '^cpus 4$' "$s" || die "CPU count: $(grep '^cpus' "$s")"
# mountinfo: "ID PARENT MAJ:MIN ROOT POINT OPTS - FSTYPE SOURCE SUPER"
awk '/^[0-9]+ [0-9]+ [0-9]+:[0-9]+ / { split($3, d, ":"); if (d[1] != 0 || ($6 != "ro" && $6 != "rw") || $0 ~ /[ ,][ug]id=/) { print; bad = 1 } }
     END { exit bad }' "$s" >"$out/mountinfo.bad" || die "mount table: $(head -2 "$out/mountinfo.bad")"
"$PATINA" log dump "$out/plain/inc-0/boundary.log" >"$out/plain.dump"
grep ' getppid ' "$out/plain.dump" >"$out/getppid.txt"
grep -q 'args=\[0x0, 0x0, 0x0, 0x0, 0x0, 0x0\]' "$out/getppid.txt" ||
    die "getppid recorded with leftover registers: $(grep ' getppid ' "$out/plain.dump" | head -1)"
run wrapped "$G17/seccomp-wrap"
lhs=$(digest "$out/wrapped"); rhs=$(digest "$out/plain")
[ "$lhs" = "$rhs" ] || die "under an outer seccomp filter: digest $(digest "$out/wrapped"), plain $(digest "$out/plain")"
echo "crosshost: host files 65534, devices by mount index, 4 CPUs, unread registers not recorded; same digest under an outer seccomp filter ($(digest "$out/plain"))"
