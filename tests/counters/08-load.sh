# Exactness under host load. Busy loops run, at nice 10, two on the CPU the counter runs are
# pinned to (so the guest is preempted at ticks, its counter switched out and in) and two
# wherever the kernel puts them,
# for the length of the script. Each counter run must stop where the hops-only run does
# (equal digests) or fail closed (stop pmu-late: an overflow interrupt later than the margin,
# seen on virtual machines); never differ. Recursion at N = 3000 (its page faults are where
# overflow interrupts came latest), and bursts at N = 2100, whose overflows can come faster
# than the kernel lets through, so it throttles (stops) the counter.
#@ tier=area budget=90 slots=4
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
P = ppatina(required=False)
cpus = sorted(os.sched_getaffinity(0))
pin = cpus[-1]
def burner(cpu):
    # Bounded by timeout should this script be killed; stopped below.
    return subprocess.Popen(["nice", "-n", "10", "timeout", "300", "bash", "-c", "while :; do :; done"],
                            preexec_fn=(lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None)
load = [burner(pin), burner(pin)] + [burner(None) for _ in range(2)]
fail, equal, stopped = [], 0, 0
try:
    cases = [(3000, ["recur", "1", "150"]), (2100, ["bursts", "1"])]
    for n, p in cases:
        name = f"{n}-{p[0]}"
        v, a, b, _ = exact(P, f"{RUNS}/{name}", n, 2048, 1024, ["/guest/counters/compute"] + p, opts=[f"host-cpu={pin}"])
        sb = b.get("counters", {}).get("pmu", {})
        stopped += sb.get("stopped") or 0
        print(f"{name}: {v.splitlines()[0]}: hops-only {a['outcome']} {a['digest']}, counter {b['outcome']} {b['digest']} "
              f"({sb.get('alarms')} overflows, {sb.get('stopped')} stopped)")
        if v == "late":
            print(f"  fails closed: {b['message']}")
        elif v != "equal":
            print("  " + "\n  ".join(v.splitlines()[1:]) if "\n" in v else f"  {(b if a['outcome'] == 'ok' else a).get('message')}")
            fail.append(f"{name} {v.splitlines()[0]}")
        elif not sb.get("alarms"):
            fail.append(name + ": no overflow")
        else:
            equal += 1
finally:
    for b in load:
        b.terminate()
    for b in load:
        b.wait()
print(f"under load on CPU {pin}: {equal} equal; {stopped} overflows found the counter stopped; "
      f"perf_event_max_sample_rate {sample_rate()}")
if not equal:
    fail.append("no case compared")
if fail: die("; ".join(fail))
PY
