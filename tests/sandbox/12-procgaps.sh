# Calls a headless browser makes, each checked by the procgaps guest against what the kernel
# answers an unprivileged process (the guest prints FAIL and exits 1 where one differs); two
# repeats of each part identical, ending ok.
# - sched: getpriority/setpriority and the sched_* policy calls: getters answer what was set
#   (default SCHED_OTHER, nice 0), a thread, a fork child and an exec inherit it, a lower nice
#   value, a real-time or deadline policy and leaving SCHED_IDLE are refused; the priority
#   range of each policy is the kernel's; membarrier answers ENOSYS and is recorded.
# - clone: CLONE_NEWUSER and every other CLONE_NEW* flag answer EPERM and are recorded.
# - nlink: /proc/self/task's link count is 2 + the threads, by stat, fstat and statx.
# - proc: /proc, /proc/self and /proc/self/fd open as directories; a name relative to one
#   reaches exactly what the absolute path reaches (`..`, magic links, another pid,
#   thread-self, runtime descriptors); listings show only what the policy allows, in a fixed
#   order; none becomes the working directory or travels by SCM_RIGHTS; exec keeps them policed.
#@ tier=quick budget=15 slots=1
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/procgaps
mkdir -p "$out"
refused() { jq -c '.refused' "$1/result.json"; }
for part in sched clone nlink proc; do
    vfy "$part" 2 repeat "$G17" -- /guest/procgaps "$part"
    r=$out/$part/run-0
    [ "$(class "$r")" = ok ] || die "$part: $(class "$r"): $(detail "$r"); $(grep -m3 FAIL "$r/inc-0/stdout")"
done
refused "$out/sched/run-0" | grep -q '"membarrier"' || die "sched: the membarrier refusal is not recorded: $(refused "$out/sched/run-0")"
refused "$out/clone/run-0" | grep -q '"clone"' || die "clone: the refusal is not recorded: $(refused "$out/clone/run-0")"
