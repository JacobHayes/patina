# 4. /proc policy: every listed path opened and printed; identical over 4 runs under
#    --vary cpu; /proc/1/environ, /proc/kallsyms, /sys/class/net give ENOENT and are refused.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/04-proc
verify_ok "$o" 1 cpu 4 -- /guest/proc-policy
out=$o/run-0/inc-0/stdout
for p in /proc/1/environ /proc/kallsyms /sys/class/net; do
    grep -qx "== $p open errno 2" "$out" || die "$p did not answer ENOENT"
    field "$o/run-0/outcome.json" refused | grep -q "\"$p\"" || die "$p not in outcome.refused"
done
# every listed path that must open did open (no errno line for it)
for p in /proc/self/maps /proc/self/smaps /proc/self/stat /proc/self/status /proc/self/statm /proc/self/cgroup \
    /proc/self/mountinfo /proc/self/cmdline /proc/self/environ /proc/self/comm /proc/cpuinfo /proc/meminfo /proc/stat \
    /proc/uptime /proc/loadavg /proc/version /proc/sys/kernel/osrelease /proc/sys/kernel/pid_max \
    /proc/sys/kernel/random/uuid /proc/sys/kernel/random/boot_id /proc/sys/vm/overcommit_memory \
    /sys/devices/system/cpu/online /sys/devices/system/cpu/possible /sys/devices/system/cpu/present \
    /sys/kernel/mm/transparent_hugepage/enabled /dev/null; do
    grep -q "^== $p fd " "$out" || die "$p did not open"
done
grep -q '^== opendir /proc/self/task errno' "$out" && die "/proc/self/task did not open"
echo "proc: 4 runs identical under --vary cpu; refused: $(field "$o/run-0/outcome.json" refused)"
