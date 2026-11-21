import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sdk import GUESTS, PATINA, RUNS, die, run  # noqa: E402

C = ["/guest/sdk-c"]
EXTRA = ["/guest/sdk-extra"]


def bits(r):
    return r.stdout.split()[0].removeprefix("a=")


off = run("02/off", 7, C, "script", flags=["--fault", "buggify:point-a=1000"])
if bits(off) != "0" * 20 or off.site("point-a")["evaluated"] != 0:
    die(f"without --buggify: {off.stdout!r} {off.site('point-a')}")

on = ["--buggify", "--fault", "buggify:point-a=500"]
a = run("02/a", 7, C, "script", flags=on)
b = run("02/b", 7, C, "script", flags=on)
two = run("02/two", 7, C, "script", "two", flags=on + ["--fault", "buggify:point-b=500"])
if bits(a) != bits(b) or a.outcome["digest"] != b.outcome["digest"]:
    die(f"one seed, two decisions: {bits(a)} {bits(b)}")
if set(bits(a)) != {"0", "1"}:
    die(f"point-a at 500 per mille over 20 calls: {bits(a)}")
if bits(two) != bits(a) or two.site("point-b")["evaluated"] != 20:
    die(f"a second point moved the first one's decisions: {bits(a)} -> {bits(two)}")
other = run("02/other", 8, C, "script", flags=on)
if bits(other) == bits(a):
    die(f"seeds 7 and 8 decide alike: {bits(a)}")
print(f"point-a seed 7: {bits(a)} (with point-b too: {bits(two)}); seed 8: {bits(other)}")

for p, want in [("1000", "1" * 20), ("0", "0" * 20)]:
    r = run(f"02/point-{p}", 7, C, "script", flags=["--buggify", "--fault", f"buggify:point-a={p}"])
    if bits(r) != want or r.site("point-a")["held"] != want.count("1"):
        die(f"buggify:point-a={p}: {bits(r)} {r.site('point-a')}")
print("buggify:point-a=1000 fires 20 of 20, =0 none")

# A coin: held on some seeds, not on others. Seeds from 1 until both are seen (at most 64: a
# search, not a rate).
held = {}
for s in range(1, 65):
    held[s] = run(f"02/coin-{s}", s, C, "coin").site("coin")["held"]
    if any(held.values()) and not all(held.values()):
        break
else:
    die(f"coin over seeds 1-64: held on {[s for s, h in held.items() if h]}")
print(f"sometimes(coin) held on seeds {[s for s, h in held.items() if h]} of 1-{s}")

r = run("02/fork", 1, EXTRA, "fork")
for label in ["forked-child", "exec-child", "parent-done"]:
    if r.site(label)["held"] != 1:
        die(f"fork: {label} {r.site(label)}")
print("a forked and an exec'd child report into the run's table")

flags = ["--buggify", "--fault", "buggify:setup-point=1000"]
r = run("02/setup", 1, EXTRA, "setup", flags=flags + ["--fault", "faults-after-setup=1"])
if r.stdout != "before=00000 after=11111\n" or not r.sdk["setup_complete"]:
    die(f"faults-after-setup: {r.stdout!r} {r.sdk['setup_complete']}")
r = run("02/no-setup", 1, EXTRA, "setup", flags=flags)
if r.stdout != "before=11111 after=11111\n":
    die(f"without faults-after-setup: {r.stdout!r}")
print("faults-after-setup: quiet before setup-complete, firing after")

out = os.path.join(RUNS, "02/verify")
# lint-allow: seed — the guest's `fail` mode violates its assertion on every seed
p = subprocess.run([PATINA, "verify", "--seed", "1", "--runs", "2", "--out", out, "--mount", GUESTS + ":/guest:copy",
                    "--", *C, "fail"], capture_output=True, text=True, timeout=120)
# Identical runs: verify ends with the runs' own outcome and its exit status.
if p.returncode != 1 or "identical" not in p.stdout or "violation" not in p.stdout:
    die(f"verify of a violation: exit {p.returncode}: {p.stdout} {p.stderr}")
print("a violation repeats identically")
