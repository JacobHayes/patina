# Change 1: the guest's stdin, stdout and stderr are sandbox memfds, never host files. The
# determinism hardening reproducers of B10 (stdout block count) and B11 (stdout extent count) and of hole C3
# (the guest changing the launcher's file through fd 1) pass with the per-instance stdio
# rewrites removed from the runtime.
#@ tier=quick budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/stdio
mkdir -p "$out"
# B10: 40 fstat(1) block counts follow the size (the memfd's tmpfs accounting).
rm -rf "${out:?}/stdo"
timeout 300 "$PATINA" run --seed 1 --out "$out/stdo" --mount "$G12":/guest:copy -- /guest/stdoutprobe >/dev/null 2>&1 || true
awk '/^step/ { n++; if ($6 != int(($4 + 4095) / 4096) * 8) bad++ } END { exit !(n == 40 && bad == 0) }' "$out/stdo/inc-0/stderr" ||
    die "stdoutprobe: stdout block counts are not derived from the size"
cmp -s "$out/stdo/inc-0/stdout" /dev/null && die "stdoutprobe: stdout not captured"
echo "B10 stdoutprobe: 40 fstat(1) block counts follow the size; $(wc -c <"$out/stdo/inc-0/stdout") bytes captured"
# B11: stdout's metadata (fstat, statx, FS_IOC_FSGETXATTR) under load and ASLR variation.
vfy envprobe-load 4 load,aslr "$G12" -- /guest/envprobe
# C3: what the guest does to its fd 1 stays in the sandbox: the run directory's stdout file
# keeps the launcher's mode and no guest xattr, while the guest saw its own ftruncate.
rm -rf "${out:?}/fdabuse"
timeout 300 "$PATINA" run --seed 1 --out "$out/fdabuse" --mount "$G12":/guest:copy -- /guest/fdabuse >/dev/null 2>&1 || true
[ "$(class "$out/fdabuse")" = ok ] || die "fdabuse: $(class "$out/fdabuse") $(detail "$out/fdabuse")"
grep -q '^fchmod(1, 0600) *r=0' "$out/fdabuse/inc-0/stderr" || die "fdabuse: guest fchmod did not run"
mode=$(stat -c %a "$out/fdabuse/inc-0/stdout")
[ "$mode" != 600 ] || die "fdabuse: the guest's fchmod reached the run directory"
if command -v getfattr >/dev/null; then
    attrs=$(getfattr -d "$out/fdabuse/inc-0/stdout")
    case $attrs in *determinism*) die "fdabuse: the guest's xattr reached the run directory" ;; esac
fi
grep -q '^stdout size 1073741824' "$out/fdabuse/inc-0/stderr" || die "fdabuse: the guest's own ftruncate is not visible to it"
echo "C3 fdabuse: fchmod, fsetxattr, ftruncate, fallocate and flock on fd 1 act on the sandbox memfd only"
# Output larger than PATINA_STDIO_MAX is not silently cut: the run ends unsupported (output-limit).
rm -rf "${out:?}/big"
PATINA_STDIO_MAX=100000 timeout 300 "$PATINA" run --seed 1 --out "$out/big" --mount "$G12":/guest:copy -- /guest/stdoutprobe >/dev/null 2>&1 || true
[ "$(class "$out/big")" = unsupported ] || die "stdio max: class $(class "$out/big")"
echo "stdio larger than PATINA_STDIO_MAX: unsupported ($(detail "$out/big"))"
rm -rf "${out:?}/stdo" "${out:?}/big" "${out:?}/envprobe-load"
