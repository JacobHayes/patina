/* The SDK test guest in C; guest.rs, go/main.go and guest.py do the same script.
 *   script [two]   the shared script: coverage, assertions, a fault point, a knob, a delay;
 *                  prints the fault point's decisions ("two": a second point interleaved)
 *   fail           an `always` fails
 *   unreach        an `unreachable` is reached
 *   coin           a `sometimes` on one random byte
 *   loop N [sdk]   N iterations of a little arithmetic, with a passing `always` if "sdk"  */
#include "patina.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static int script(int two, int argc) {
    PATINA_REACHABLE("script-start");
    if (argc > 1000) PATINA_SOMETIMES(1, "unreached");
    for (int i = 0; i < 1000; i++) {
        PATINA_ALWAYS(i < 1000, "bounded", "out of range");
        PATINA_SOMETIMES(i == 500, "half-way");
        PATINA_SOMETIMES(i > 5000, "never-holds");
    }
    char bits[21] = {0};
    for (int i = 0; i < 20; i++) {
        bits[i] = PATINA_BUGGIFY("point-a") ? '1' : '0';
        if (two) (void)PATINA_BUGGIFY("point-b");
    }
    long long knob = PATINA_KNOB("knob-a", 7, 1, 100);
    int slept = PATINA_DELAY("delay-a", 1000000);
    printf("a=%s knob=%lld delay=%d\n", bits, knob, slept);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "script";
    if (!strcmp(mode, "script")) return script(argc > 2 && !strcmp(argv[2], "two"), argc);
    if (!strcmp(mode, "fail")) {
        PATINA_REACHABLE("before-fail");
        int balance = -1;
        PATINA_ALWAYS(balance >= 0, "must-hold", "balance -1");
        PATINA_REACHABLE("after-fail");
        return 0;
    }
    if (!strcmp(mode, "unreach")) {
        PATINA_UNREACHABLE("never-here", "reached");
        return 0;
    }
    if (!strcmp(mode, "coin")) {
        unsigned char b = 0;
        if (getrandom(&b, 1, 0) != 1) return 2;
        PATINA_SOMETIMES(b % 2 == 0, "coin");
        return 0;
    }
    if (!strcmp(mode, "loop")) {
        long n = argc > 2 ? atol(argv[2]) : 10000000;
        int sdk = argc > 3 && !strcmp(argv[3], "sdk");
        volatile unsigned long acc = 0;
        for (long i = 0; i < n; i++) {
            acc = acc * 31 + (unsigned long)i;
            if (sdk) PATINA_ALWAYS(i >= 0, "loop-bounded", "negative");
        }
        printf("%lu\n", (unsigned long)acc);
        return 0;
    }
    return 2;
}
