"""The SDK test guest in Python: the script of guest.c (modes script [two], fail, coin, loop)."""
import os
import sys

import patina

SCRIPT_START = patina.Reachable("script-start")
UNREACHED = patina.Sometimes("unreached")
BOUNDED = patina.Always("bounded")
HALF_WAY = patina.Sometimes("half-way")
NEVER_HOLDS = patina.Sometimes("never-holds")
POINT_A = patina.Buggify("point-a")
POINT_B = patina.Buggify("point-b")
KNOB_A = patina.Knob("knob-a", 7, 1, 100)
DELAY_A = patina.BuggifyDelay("delay-a")
BEFORE_FAIL = patina.Reachable("before-fail")
MUST_HOLD = patina.Always("must-hold")
AFTER_FAIL = patina.Reachable("after-fail")
COIN = patina.Sometimes("coin")
LOOP_BOUNDED = patina.Always("loop-bounded")


def script(two):
    SCRIPT_START.mark()
    if len(sys.argv) > 1000:
        UNREACHED.check(True)
    for i in range(1000):
        BOUNDED.check(i < 1000, "out of range")
        HALF_WAY.check(i == 500)
        NEVER_HOLDS.check(i > 5000)
    bits = ""
    for _ in range(20):
        bits += "1" if POINT_A.fires() else "0"
        if two:
            POINT_B.fires()
    knob = KNOB_A.value()
    slept = DELAY_A.delay(1000000)
    print(f"a={bits} knob={knob} delay={int(slept)}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "script"
    if mode == "script":
        script(len(sys.argv) > 2 and sys.argv[2] == "two")
    elif mode == "fail":
        BEFORE_FAIL.mark()
        balance = -1
        MUST_HOLD.check(balance >= 0, f"balance {balance}")
        AFTER_FAIL.mark()
    elif mode == "coin":
        COIN.check(os.urandom(1)[0] % 2 == 0)
    elif mode == "loop":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 10_000_000
        sdk = len(sys.argv) > 3 and sys.argv[3] == "sdk"
        acc = 0
        for i in range(n):
            acc = (acc * 31 + i) & 0xFFFFFFFFFFFFFFFF
            if sdk:
                LOOP_BOUNDED.check(acc != 0xFFFFFFFFFFFFFFFF, "saturated")
        print(acc)
    else:
        sys.stderr.write(f"unknown mode {mode}\n")
        sys.exit(2)


main()
