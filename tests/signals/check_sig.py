"""Check what a signals guest printed: check_sig.py GUEST STDOUT.

Each guest prints lines "<words> key=value ...". A line is named by its leading words (or,
when it has none, by its first key). The expected values are what a Linux kernel gives the
same program natively."""
import sys

g, path = sys.argv[1], sys.argv[2]
out = open(path).read()
rows = {}
for line in out.splitlines():
    words = [t for t in line.split() if "=" not in t]
    kv = dict(t.split("=", 1) for t in line.split() if "=" in t)
    name = " ".join(words) if words else (next(iter(kv)) if kv else "")
    rows[name] = kv


def fail(msg):
    print(f"{g}: {msg}\n--- stdout ---\n{out}")
    sys.exit(1)


def need(row, **want):
    got = rows.get(row)
    if got is None:
        fail(f"no line '{row}'")
    for k, v in want.items():
        if got.get(k) != str(v):
            fail(f"{row}: {k}={got.get(k)}, want {v}")


if g == "sig-basic":
    need("raise", count=1, code=-6, pid_ok=1)
    need("kill", count=1, code=0, pid_ok=1)
    need("sigqueue", count=2, code=-1, value=4242)
    need("pending", usr1=1, rt1=1, usr2=0)
    # Nested frames run innermost first, so the last handler to run is SIGUSR1's (no value).
    need("unblock", usr1=1, rt1=3, last_value=0)
    need("mask_after", usr1=0)
    need("nest_defer", count=2, max_depth=1)
    need("nest_nodefer", count=4, max_depth=2)
    need("resethand", count=1, dfl=1)
    need("sigsuspend", r=-1, errno_eintr=1, alrm=1, elapsed_s=2, mask_restored=1)
    need("alarm_remaining", alarm_remaining=10)
    need("itimer", expiries=3, elapsed_ms=750, interval_us=250000)
    need("sigtimedwait_timeout", r=-1, eagain=1, elapsed_ms=1500)
    need("sigtimedwait_got", sig_ok=1, value=77, code=-1)
    need("tgkill", threads=4, handled_on_target=4, code=-6)
    sched = [l for l in out.splitlines() if l.startswith("schedule ")]
    if len(sched) != 1 or sum(map(int, sched[0].split()[1:])) != 8:
        fail("schedule line")
    if "done" not in rows:
        fail("not done")
elif g == "sig-alt":
    for who in ("main", "thread"):
        need(f"{who} initial", disabled=1)
        need(f"{who} query", sp_ok=1, size=65536, flags=0)
        need(f"{who} onstack", in_alt=1, ss_onstack=1, eperm=1)
        need(f"{who} plain", in_alt=0, on_thread_stack=1, ss_onstack=0)
        need(f"{who} autodisarm", in_handler_disabled=1, after_sp_ok=1, after_autodisarm=1)
elif g == "sig-fp":
    need("fp", handled=10000, reg_errors=0, exact=1)
    if "x0" in rows.get("ucontext", {}):
        # The arm64 twin: more edits, and a P register where the host has SVE.
        need("ucontext", x0=4242, v31_edited=1, mask_edited=1)
        if rows.get("sve", {}).get("p0_edited") not in ("1", "no-sve"):
            fail("sve: p0 edit")
    else:
        need("ucontext", rax=4242)
elif g == "sig-ctx":
    need("siglongjmp", jumps=3, v=3, blocked_in_handler=1, blocked_after=0)
    need("swapcontext", rounds=5, steps=35)
    need("setcontext", resumed=3)
    need("setret", min="0x8000000000000000", efbig="0xffffffffffffffe5")
elif g == "sig-fault":
    # Two rounds of four faults; the guest prints what the kernel gives for each (the second
    # kind is SIGFPE on x86_64, SIGTRAP on arm64).
    lines = [l.split() for l in out.splitlines() if "want_code=" in l]
    if len(lines) != 8 or len({l[0] for l in lines}) != 4:
        fail(f"{len(lines)} fault lines, want 8 of 4 kinds")
    for l in lines:
        d = dict(p.split("=") for p in l[1:])
        if (d["sig"], d["code"], d["addr_ok"], d["rip_ok"]) != (d["want"], d["want_code"], "1", "1"):
            fail(" ".join(l))
elif g == "sig-restart":
    need("nanosleep", r=-1, eintr=1, handled=1, elapsed_plus_rem_ok=1, rem_s=3)
    need("futex_restart", r=0, handled=2, woken_after_s=3)
    need("futex_norestart", r=-1, eintr=1, handled=3)
    need("futex_timeout", r=-1, eintr=1, handled=4)
elif g == "sig-restart-self":
    need("self_futex_restart", r=-1, eagain=1, handled=1)
    need("self_read_restart", n=1, c="x", handled=2)
    need("self_futex_norestart", r=-1, eintr=1, handled=3)
elif g == "sig-restart-io":
    need("read_restart", n=1, c="x", handled=1)
    need("read_norestart", n=-1, eintr=1, handled=2)
    need("poll_restartflag", r=-1, eintr=1, handled=3)
    need("poll_norestart", r=-1, eintr=1, handled=4)
elif g == "sig-mask":
    need("handler 10")
    need("blocked", sys=1, segv=1, usr1=1, kill=0)
    need("pid_ok", pid_ok=1)
    need("pending", usr1=1, handled=0)
    need("after unblock", handled=1)
    need("still blocked", sys=1, segv=1)
    need("thread inherits", sys=1, segv=1)
elif g == "go-sig":
    if out.split() != ["notified", "true", "ticks>=5", "true", "spun", "true"]:
        fail("notification")
else:
    print(f"unknown guest {g}")
    sys.exit(2)
